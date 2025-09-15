<#
  Harden-PasswordPolicy.ps1
  Purpose: Enforce a strong AWS IAM password policy for all IAM users.

  Usage:
    .\Harden-PasswordPolicy.ps1
    .\Harden-PasswordPolicy.ps1 -ShowPolicy
#>

param(
  [switch]$ShowPolicy = $false
)

$ErrorActionPreference = "Stop"

# Ensure AWS CLI is available and authenticated
try {
  aws --version | Out-Null
  aws sts get-caller-identity | Out-Null
} catch {
  Write-Host "ERROR: AWS CLI not ready. Install and configure first:"
  Write-Host "  https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html#windows"
  Write-Host "  Then run: aws configure"
  exit 1
}

Write-Host "Applying strong password policy..."

# Apply strong password policy
aws iam update-account-password-policy `
  --minimum-password-length 14 `
  --require-symbols `
  --require-numbers `
  --require-uppercase-characters `
  --require-lowercase-characters `
  --max-password-age 90 `
  --password-reuse-prevention 24 `
  --allow-users-to-change-password | Out-Null

Write-Host "✅ Strong password policy enforced."

# Optionally show current policy
if ($ShowPolicy) {
  Write-Host "`nCurrent password policy:"
  aws iam get-account-password-policy
}
