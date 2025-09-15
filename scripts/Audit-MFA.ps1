<#
  Audit-MFA.ps1
  Purpose: List all IAM users and show whether they have MFA enabled.
  Default behavior: print results to the console.
  Optional: add -SaveCsv to also write a CSV (reports\mfa_audit.csv by default).

  Usage:
    .\Audit-MFA.ps1
    .\Audit-MFA.ps1 -SaveCsv
    .\Audit-MFA.ps1 -SaveCsv -OutPath .\reports\mfa_audit_2025-09-15.csv
#>

param(
  [switch]$SaveCsv = $false,
  [string]$OutPath = ".\reports\mfa_audit.csv"
)

$ErrorActionPreference = "Stop"

# Ensure AWS CLI is available and we're logged in
try {
  aws --version | Out-Null
  aws sts get-caller-identity | Out-Null
} catch {
  Write-Host "ERROR: AWS CLI not ready. Install and configure first:"
  Write-Host "  https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html#windows"
  Write-Host "  Then run: aws configure"
  exit 1
}

# Make output predictable for parsing
try { aws configure set output json | Out-Null } catch {}

# Create reports folder if we'll save CSV
if ($SaveCsv) {
  $reportsDir = Split-Path -Parent $OutPath
  if (-not [string]::IsNullOrWhiteSpace($reportsDir)) {
    New-Item -ItemType Directory -Force -Path $reportsDir | Out-Null
  }
}

# Get IAM usernames safely (JSON -> PowerShell array)
$users = aws iam list-users --query "Users[].UserName" --output json | ConvertFrom-Json

if (-not $users -or $users.Count -eq 0) {
  Write-Host "INFO: No IAM users found."
  exit 0
}

# Build results
$results = foreach ($name in $users) {
  $u = ($name | Out-String).Trim()

  # Valid AWS username charset: alphanumerics and +=,.@_-
  if ($u -notmatch '^[A-Za-z0-9+=,.@_-]+$') {
    [pscustomobject]@{
      UserName = $u
      MFA      = "UNKNOWN (invalid characters)"
    }
    continue
  }

  try {
    $mfaCount = aws iam list-mfa-devices --user-name $u --query "length(MFADevices)" --output text 2>$null
    [pscustomobject]@{
      UserName = $u
      MFA      = if ($mfaCount -eq "0") { "NO_MFA" } else { "HAS_MFA" }
    }
  } catch {
    [pscustomobject]@{
      UserName = $u
      MFA      = "ERROR: $($_.Exception.Message)"
    }
  }
}

# Print to screen
$results | Sort-Object UserName | Format-Table -AutoSize

# Optionally write CSV
if ($SaveCsv) {
  $results | Sort-Object UserName | Export-Csv -NoTypeInformation -Encoding UTF8 $OutPath
  Write-Host ""
  Write-Host "CSV written to $OutPath"
}

Write-Host ""
Write-Host "MFA audit complete."
