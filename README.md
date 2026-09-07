# AWS IAM Security Audit

A read-only Python tool that audits AWS IAM credential hygiene and exports security findings to timestamped JSON and CSV reports.

The audit uses the AWS IAM credential report to identify common identity and credential-management risks. It is designed for learning, portfolio demonstration, and authorized security reviews.

## Features

The script evaluates the following checks:

| Check | Severity | Example finding |
|---|---|---|
| Root user MFA | High | Root account MFA is not enabled. |
| IAM user MFA | High | An IAM user has a console password but does not have MFA enabled. |
| Active access-key age | Medium | An active access key is older than the configured rotation threshold. |
| Inactive IAM users | Low | A user has no observed console or access-key activity within the configured period. |
| Users without credentials | Low | A user has no console password and no active access key. |

The tool creates both JSON and CSV findings reports. It does not print, collect, or store AWS secret access keys, passwords, session tokens, or other secret values.

## Security Boundary

This tool is intentionally **read-only**.

It uses:

- `iam:GenerateCredentialReport`
- `iam:GetCredentialReport`

It does **not** create, update, deactivate, rotate, or delete IAM users, keys, roles, policies, or other AWS resources.

Run the audit only in AWS accounts you own or are explicitly authorized to assess.

## Requirements

- Python 3.10 or later
- An AWS account or authorized AWS environment
- AWS credentials available through an approved local AWS profile, environment, IAM role, or AWS IAM Identity Center workflow
- Permission to generate and retrieve an IAM credential report

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/aodare/aws-iam-security-audit.git
   ```

2. Enter the project directory:

   ```bash
   cd aws-iam-security-audit
   ```

3. Create a Python virtual environment:

   ```bash
   python3 -m venv .venv
   ```

4. Activate the virtual environment:

   **Linux/macOS**

   ```bash
   source .venv/bin/activate
   ```

   **Windows PowerShell**

   ```powershell
   .venv\Scripts\Activate.ps1
   ```

5. Install dependencies:

   ```bash
   python3 -m pip install -r requirements.txt
   ```

## Required IAM Permissions

Attach the following minimal policy to the authorized identity used to run the audit:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport"
      ],
      "Resource": "*"
    }
  ]
}
```

Do not use root-user credentials to run this tool. Prefer a least-privileged IAM role, federated identity, or AWS IAM Identity Center permission set.

## Usage

Run using the default configured AWS credential source:

```bash
python3 iam_security_audit.py
```

Run using a named AWS profile:

```bash
python3 iam_security_audit.py --profile security-audit
```

Set a custom access-key age threshold:

```bash
python3 iam_security_audit.py --key-age-days 60
```

Set a custom inactive-user threshold:

```bash
python3 iam_security_audit.py --inactive-days 120
```

Choose a custom output directory:

```bash
python3 iam_security_audit.py --output-dir audit-results
```

Use multiple options together:

```bash
python3 iam_security_audit.py \
  --profile security-audit \
  --key-age-days 60 \
  --inactive-days 120 \
  --output-dir audit-results
```

## Output

By default, the script writes timestamped reports to the local `reports/` directory:

```text
reports/
├── iam_audit_YYYYMMDDTHHMMSSZ.json
└── iam_audit_YYYYMMDDTHHMMSSZ.csv
```

The `reports/` directory is excluded through `.gitignore` because real audit output may contain sensitive account, IAM-user, and security-posture information.

A safe fictional example is included here:

[View sanitized sample findings](sample-findings.json)

## Example Console Summary

```text
AWS IAM Security Audit Summary
================================
Total findings: 5
HIGH: 2
MEDIUM: 1
LOW: 2

JSON report: reports/iam_audit_20260907T145500Z.json
CSV report:  reports/iam_audit_20260907T145500Z.csv
```

## Project Structure

```text
aws-iam-security-audit/
├── iam_security_audit.py
├── requirements.txt
├── sample-findings.json
├── .gitignore
└── README.md
```

## Findings and Remediation

| Finding | Recommended response |
|---|---|
| Root MFA not enabled | Enable MFA for the AWS account root user and protect root credentials. |
| IAM user without MFA | Enable MFA or move human access to federation and temporary credentials. |
| Active access key exceeds age threshold | Rotate the key, remove it if unused, or migrate the workload to an IAM role. |
| Inactive IAM user | Confirm the identity is required; then disable or remove unused access through approved processes. |
| User without credentials | Confirm the user is still needed and remove unused identities according to policy. |

A finding indicates that the item should be reviewed. It is not proof of compromise or misconfiguration by itself. Validate application ownership, business requirements, approved exceptions, and organizational security policy before taking action.

## Security Notes

- Never commit `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `.env` files, or `~/.aws/credentials`.
- Use IAM roles and temporary credentials instead of long-lived access keys where possible.
- Store application secrets in AWS Secrets Manager or another approved secrets-management system.
- Use least privilege for both the audit identity and every remediated identity.
- Review generated reports carefully before sharing because they may identify IAM users and security-control gaps.
- A `.gitignore` file prevents new local files from being added accidentally, but it cannot remove a secret that has already been committed. Revoke or rotate any exposed credential immediately.

## Skills Demonstrated

- Python scripting and command-line argument handling
- Boto3 and AWS SDK integration
- AWS IAM credential report analysis
- Cloud-security posture assessment
- Least-privilege permission design
- JSON and CSV reporting
- Secure handling of local credentials and security findings
- GitHub documentation and project organization
