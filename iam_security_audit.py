#!/usr/bin/env python3
"""
Read-only AWS IAM credential hygiene audit.

The script generates or retrieves the IAM credential report, evaluates a small
set of credential-hygiene checks, and exports findings to JSON and CSV files.
"""

import argparse
import base64
import csv
import io
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound


DEFAULT_KEY_AGE_DAYS = 90
DEFAULT_INACTIVE_DAYS = 90
REPORT_WAIT_SECONDS = 2
REPORT_MAX_ATTEMPTS = 15


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Run a read-only AWS IAM credential hygiene audit."
    )
    parser.add_argument(
        "--profile",
        help="AWS shared-configuration profile name. Uses the default profile if omitted.",
    )
    parser.add_argument(
        "--key-age-days",
        type=int,
        default=DEFAULT_KEY_AGE_DAYS,
        help=f"Flag active access keys older than this many days (default: {DEFAULT_KEY_AGE_DAYS}).",
    )
    parser.add_argument(
        "--inactive-days",
        type=int,
        default=DEFAULT_INACTIVE_DAYS,
        help=f"Flag IAM users with no observed console or access-key use for this many days (default: {DEFAULT_INACTIVE_DAYS}).",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory for generated JSON and CSV reports (default: reports).",
    )
    args = parser.parse_args()

    if args.key_age_days < 1 or args.inactive_days < 1:
        parser.error("--key-age-days and --inactive-days must be positive integers.")

    return args


def get_iam_client(profile_name):
    try:
        session = boto3.Session(profile_name=profile_name)
        return session.client("iam")
    except ProfileNotFound as error:
        raise RuntimeError(f"AWS profile not found: {profile_name}") from error


def get_credential_report(iam_client):
    try:
        iam_client.generate_credential_report()
    except ClientError as error:
        raise RuntimeError(
            f"Unable to request IAM credential report: {error.response['Error']['Message']}"
        ) from error

    for _ in range(REPORT_MAX_ATTEMPTS):
        try:
            response = iam_client.get_credential_report()
            content = response["Content"]
            if isinstance(content, bytes):
                content = content.decode("utf-8")
            else:
                content = base64.b64decode(content).decode("utf-8")
            return list(csv.DictReader(io.StringIO(content)))
        except iam_client.exceptions.CredentialReportNotPresentException:
            time.sleep(REPORT_WAIT_SECONDS)
        except iam_client.exceptions.CredentialReportNotReadyException:
            time.sleep(REPORT_WAIT_SECONDS)
        except ClientError as error:
            raise RuntimeError(
                f"Unable to retrieve IAM credential report: {error.response['Error']['Message']}"
            ) from error

    raise RuntimeError("Credential report was not ready before the wait limit expired.")


def parse_aws_datetime(value):
    if not value or value in {"N/A", "no_information"}:
        return None

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def days_since(date_value, now):
    if not date_value:
        return None
    return max((now - date_value).days, 0)


def make_finding(severity, check, user_name, resource, details, remediation):
    return {
        "severity": severity,
        "check": check,
        "user_name": user_name,
        "resource": resource,
        "details": details,
        "remediation": remediation,
    }


def assess_root_user(row):
    findings = []

    if row.get("mfa_active", "").lower() != "true":
        findings.append(
            make_finding(
                "HIGH",
                "Root user MFA",
                "<root_account>",
                "AWS account root user",
                "Root user MFA is not enabled.",
                "Enable MFA for the AWS account root user and protect the root credential.",
            )
        )

    if row.get("password_enabled", "").lower() == "true":
        findings.append(
            make_finding(
                "MEDIUM",
                "Root user console password",
                "<root_account>",
                "AWS account root user",
                "The root user console password is enabled.",
                "Avoid routine root-user activity; use least-privileged administrative roles for daily work.",
            )
        )

    return findings


def assess_iam_user(row, now, key_age_days, inactive_days):
    findings = []
    user_name = row.get("user", "<unknown>")
    password_enabled = row.get("password_enabled", "").lower() == "true"
    mfa_active = row.get("mfa_active", "").lower() == "true"

    if password_enabled and not mfa_active:
        findings.append(
            make_finding(
                "HIGH",
                "IAM user MFA",
                user_name,
                f"IAM user/{user_name}",
                "Console password is enabled but MFA is not active.",
                "Enable MFA or migrate human access to federation with temporary credentials.",
            )
        )

    last_activity = []
    password_last_used = parse_aws_datetime(row.get("password_last_used"))
    if password_last_used:
        last_activity.append(password_last_used)

    for key_number in ("1", "2"):
        key_active = row.get(f"access_key_{key_number}_active", "").lower() == "true"
        key_created = parse_aws_datetime(
            row.get(f"access_key_{key_number}_last_rotated")
        )
        key_last_used = parse_aws_datetime(
            row.get(f"access_key_{key_number}_last_used_date")
        )

        if key_last_used:
            last_activity.append(key_last_used)

        if key_active and key_created:
            key_age = days_since(key_created, now)
            if key_age is not None and key_age > key_age_days:
                findings.append(
                    make_finding(
                        "MEDIUM",
                        "Active access key age",
                        user_name,
                        f"IAM user/{user_name} access key {key_number}",
                        f"Active access key is {key_age} days old; threshold is {key_age_days} days.",
                        "Rotate or replace the key, or migrate the workload to an IAM role with temporary credentials.",
                    )
                )

    if not password_enabled and not any(
        row.get(f"access_key_{number}_active", "").lower() == "true"
        for number in ("1", "2")
    ):
        findings.append(
            make_finding(
                "LOW",
                "IAM user without credentials",
                user_name,
                f"IAM user/{user_name}",
                "User has neither a console password nor an active access key.",
                "Confirm the user is still needed; remove unused identities through the approved access-management process.",
            )
        )

    if last_activity:
        most_recent_activity = max(last_activity)
        inactivity_days = days_since(most_recent_activity, now)
        if inactivity_days is not None and inactivity_days > inactive_days:
            findings.append(
                make_finding(
                    "LOW",
                    "Inactive IAM user",
                    user_name,
                    f"IAM user/{user_name}",
                    f"No recorded console or access-key activity for {inactivity_days} days; threshold is {inactive_days} days.",
                    "Confirm the account is still required and remove or disable unused credentials following organizational policy.",
                )
            )

    return findings


def audit_credential_report(rows, key_age_days, inactive_days):
    now = datetime.now(timezone.utc)
    findings = []

    for row in rows:
        if row.get("user") == "<root_account>":
            findings.extend(assess_root_user(row))
        else:
            findings.extend(
                assess_iam_user(row, now, key_age_days, inactive_days)
            )

    return findings


def write_reports(findings, output_dir):
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_path = output_path / f"iam_audit_{timestamp}.json"
    csv_path = output_path / f"iam_audit_{timestamp}.csv"

    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "finding_count": len(findings),
        "findings": findings,
    }

    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    fieldnames = [
        "severity",
        "check",
        "user_name",
        "resource",
        "details",
        "remediation",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as file_handle:
        writer = csv.DictWriter(file_handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(findings)

    return json_path, csv_path


def print_summary(findings, json_path, csv_path):
    severity_order = ("HIGH", "MEDIUM", "LOW")
    counts = {
        severity: sum(
            finding["severity"] == severity for finding in findings
        )
        for severity in severity_order
    }

    print("\nAWS IAM Security Audit Summary")
    print("=" * 32)
    print(f"Total findings: {len(findings)}")
    for severity in severity_order:
        print(f"{severity}: {counts[severity]}")
    print(f"\nJSON report: {json_path}")
    print(f"CSV report:  {csv_path}")


def main():
    args = parse_arguments()

    try:
        iam_client = get_iam_client(args.profile)
        rows = get_credential_report(iam_client)
        findings = audit_credential_report(
            rows,
            args.key_age_days,
            args.inactive_days,
        )
        json_path, csv_path = write_reports(findings, args.output_dir)
        print_summary(findings, json_path, csv_path)
    except NoCredentialsError:
        print(
            "No AWS credentials were found. Configure a local AWS profile or use an approved IAM role.",
            file=sys.stderr,
        )
        sys.exit(2)
    except (ClientError, RuntimeError) as error:
        print(f"Audit failed: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
