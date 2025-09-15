<#
 IamToolkit-Explained.ps1
 Goal: Help you harden AWS IAM and generate audit evidence with a guided menu.
 This version is ASCII-only (no emojis) to avoid encoding issues.

 How to use:
   1) Confirm you are logged in: aws sts get-caller-identity
   2) Run this script: .\IamToolkit-Explained.ps1
   3) Pick a menu option. Read the WHY/WHAT notes before confirming.

 GRC Mapping (examples)
   - Strong password policy  -> ISO 27001 A.9.3, CIS 5.x, SOC2 CC6
   - MFA required for users  -> ISO 27001 A.9, CIS 6.3, SOC2 CC6/7
   - Least privilege boundary -> ISO 27001 A.6/A.9, SOC2 CC6
   - Continuous monitoring    -> ISO 27001 A.12, SOC2 CC4/7 (Access Analyzer)
#>

# ------------------- BASIC SETTINGS -------------------
$ErrorActionPreference = "Stop"

# Region for any regional services used later (IAM itself is global)
$Region = $env:AWS_DEFAULT_REGION
if (-not $Region) { $Region = "us-east-1" }

# Resource names we create/use
$MfaPolicyName      = "deny-without-mfa"          # Managed policy: denies actions if user has no MFA
$HumanGroupName     = "human-users"               # Put human users here; policy attached to this group
$BoundaryPolicyName = "permissions-boundary-base" # Optional: caps max privileges for new users/roles
$AccessAnalyzerName = "account-access-analyzer"   # Optional: flags unintended public/cross-account access

# Output folders for reports/policies
$RepoRoot    = Get-Location
$ReportsDir  = Join-Path $RepoRoot "reports"
$PoliciesDir = Join-Path $RepoRoot "policies"
New-Item -ItemType Directory -Force -Path $ReportsDir  | Out-Null
New-Item -ItemType Directory -Force -Path $PoliciesDir | Out-Null

# Explain-Only: if $true, show commands instead of executing them (dry run)
$ExplainOnly = $false
# ------------------------------------------------------

function Say {
  param(
    [string]$Text,
    [ConsoleColor]$Color = [ConsoleColor]::Gray
  )
  $old = $Host.UI.RawUI.ForegroundColor
  $Host.UI.RawUI.ForegroundColor = $Color
  Write-Host $Text
  $Host.UI.RawUI.ForegroundColor = $old
}

function Run {
  <#
    Helper to execute a command or just echo it in ExplainOnly mode.
    Usage: Run "aws iam list-users"
  #>
  param([string]$Cmd)
  if ($ExplainOnly) {
    Say "EXPLAIN-ONLY: $Cmd" ([ConsoleColor]::DarkYellow)
  } else {
    Invoke-Expression $Cmd
  }
}

function Ensure-Aws {
  try {
    aws --version | Out-Null
    aws sts get-caller-identity | Out-Null
  } catch {
    Say "AWS CLI not ready. Install and configure first:" ([ConsoleColor]::Red)
    Say "  https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html#windows" ([ConsoleColor]::Red)
    Say "  Then run: aws configure" ([ConsoleColor]::Red)
    throw
  }
  try { aws configure set output json | Out-Null } catch {}
}

function Ensure-File {
  param([string]$Path,[string]$ContentIfMissing = "")
  if (-not (Test-Path $Path)) {
    if ([string]::IsNullOrEmpty($ContentIfMissing)) {
      throw "Required file not found: $Path"
    } else {
      $ContentIfMissing | Out-File -FilePath $Path -Encoding utf8 -Force
    }
  }
}

function Ensure-MfaPolicyJson {
  <#
    WHY: This policy denies all actions for a user if they have not authenticated with MFA.
         It allows a minimal set of actions to enroll MFA and identify themselves.
    OUTCOME: Put human users in a group that has this policy attached; they must use MFA.
  #>
  $path = Join-Path $PoliciesDir "deny_without_mfa.json"
  $content = @'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyAllActionsIfNoMFA",
    "Effect": "Deny",
    "NotAction": [
      "iam:CreateVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:ListMFADevices",
      "iam:ListVirtualMFADevices",
      "iam:ResyncMFADevice",
      "iam:DeleteVirtualMFADevice",
      "iam:GetUser",
      "sts:GetCallerIdentity",
      "sts:GetSessionToken",
      "iam:ChangePassword"
    ],
    "Resource": "*",
    "Condition": { "BoolIfExists": { "aws:MultiFactorAuthPresent": "false" } }
  }]
}
'@
  Ensure-File -Path $path -ContentIfMissing $content
  return $path
}

function Ensure-BoundaryPolicyJson {
  <#
    WHY: A permissions boundary is a ceiling that limits the maximum permissions any user/role can have.
    OUTCOME: Prevents privilege escalation mistakes.
  #>
  $path = Join-Path $PoliciesDir "permissions_boundary.json"
  $content = @'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyIAMPolicyTampering",
      "Effect": "Deny",
      "Action": [
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:CreatePolicy",
        "iam:DeletePolicy",
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
        "iam:AttachGroupPolicy",
        "iam:PutUserPolicy",
        "iam:PutRolePolicy",
        "iam:PutGroupPolicy",
        "iam:UpdateAssumeRolePolicy",
        "iam:CreateUser",
        "iam:CreateRole",
        "iam:CreateAccessKey",
        "iam:CreateLoginProfile",
        "iam:UpdateLoginProfile",
        "iam:AddUserToGroup",
        "iam:RemoveUserFromGroup",
        "iam:DeleteUser",
        "iam:DeleteRole"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyPassRoleWildcard",
      "Effect": "Deny",
      "Action": "iam:PassRole",
      "Resource": "*"
    },
    {
      "Sid": "DenyOrgAndAccountAdmin",
      "Effect": "Deny",
      "Action": [
        "organizations:*",
        "account:*",
        "sso:*",
        "sso-admin:*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowSafeReadOnlyStarter",
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "s3:Get*",
        "s3:List*",
        "logs:Describe*",
        "logs:Get*",
        "logs:List*",
        "cloudwatch:Describe*",
        "cloudwatch:Get*",
        "cloudwatch:List*",
        "iam:Get*",
        "iam:List*",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
'@
  Ensure-File -Path $path -ContentIfMissing $content
  return $path
}

function Ensure-ManagedPolicy {
  <#
    WHAT: Creates (or reuses) a customer-managed policy from a local JSON file.
    WHY: So you can version-control the policy and re-apply it consistently.
  #>
  param(
    [string]$PolicyName,
    [string]$PolicyFilePath
  )
  $existing = aws iam list-policies --scope Local --query "Policies[?PolicyName=='$PolicyName'].Arn | [0]" --output text
  if (-not $existing -or $existing -eq "None") {
    Say "Creating managed policy '$PolicyName'..." ([ConsoleColor]::Cyan)
    $full = (Resolve-Path $PolicyFilePath).Path
    $cmd = "aws iam create-policy --policy-name `"$PolicyName`" --policy-document `"file://$full`" --query `"Policy.Arn`" --output text"
    if ($ExplainOnly) { Run $cmd; return "<PolicyArnWouldBeHereInRealRun>" }
    return (Invoke-Expression $cmd)
  } else {
    Say "Policy '$PolicyName' already exists: $existing" ([ConsoleColor]::DarkGray)
    return $existing
  }
}

function Ensure-Group {
  <#
    WHAT: Creates (or reuses) an IAM group.
    WHY: Attach one policy and apply it to many human users at once.
  #>
  param([string]$GroupName)
  $exists = $true
  try { aws iam get-group --group-name $GroupName | Out-Null } catch { $exists = false }
  if (-not $exists) {
    Say "Creating group '$GroupName'..." ([ConsoleColor]::Cyan)
    Run "aws iam create-group --group-name `"$GroupName`""
  } else {
    Say "Group '$GroupName' already exists." ([ConsoleColor]::DarkGray)
  }
}

function Ensure-GroupPolicyAttachment {
  <#
    WHAT: Attaches a managed policy to a group if not already attached.
    WHY: Enforce MFA policy across all users in the group.
  #>
  param([string]$GroupName,[string]$PolicyArn,[string]$PolicyName)
  $attached = aws iam list-attached-group-policies --group-name $GroupName `
    --query "AttachedPolicies[?PolicyName=='$PolicyName'] | length(@)" --output text
  if ($attached -eq "0") {
    Say "Attaching '$PolicyName' to '$GroupName'..." ([ConsoleColor]::Cyan)
    Run "aws iam attach-group-policy --group-name `"$GroupName`" --policy-arn `"$PolicyArn`""
  } else {
    Say "'$PolicyName' already attached to '$GroupName'." ([ConsoleColor]::DarkGray)
  }
}

function Action-SetPasswordPolicy {
  <#
    WHAT: Sets a strong account-wide password policy for IAM users.
    WHY: Baseline control required by most frameworks (complexity, rotation, reuse prevention).
  #>
  Say "[Password Policy] Enforcing strong settings..." ([ConsoleColor]::Green)
  $cmd = @"
aws iam update-account-password-policy `
  --minimum-password-length 14 `
  --require-symbols `
  --require-numbers `
  --require-uppercase-characters `
  --require-lowercase-characters `
  --max-password-age 90 `
  --password-reuse-prevention 24 `
  --allow-users-to-change-password
"@
  Run $cmd
  Say "Password policy enforced." ([ConsoleColor]::Green)
}

function Action-SetupMfaEnforcement {
  <#
    WHAT: Creates the deny-without-MFA policy, creates the human-users group,
          and attaches the policy to that group.
    WHY: Any user in this group must use MFA to do anything meaningful.
  #>
  Say "[MFA Enforcement] Creating policy, group, and attachment..." ([ConsoleColor]::Green)
  $mfaJson = Ensure-MfaPolicyJson
  $mfaArn  = Ensure-ManagedPolicy -PolicyName $MfaPolicyName -PolicyFilePath $mfaJson
  Ensure-Group -GroupName $HumanGroupName
  Ensure-GroupPolicyAttachment -GroupName $HumanGroupName -PolicyArn $mfaArn -PolicyName $MfaPolicyName
  Say "Add human IAM users to '$HumanGroupName' so MFA is enforced." ([ConsoleColor]::Yellow)
}

function Action-CreateUser {
  <#
    WHAT: Creates a new IAM user, optional permissions boundary, optional add to MFA group,
          optional console login with temp password.
    WHY: Safe, guided user provisioning with least-privilege guardrails.
  #>
  Say "[Create User] Guided user creation..." ([ConsoleColor]::Green)

  $boundaryJson = Ensure-BoundaryPolicyJson
  $boundaryArn  = Ensure-ManagedPolicy -PolicyName $BoundaryPolicyName -PolicyFilePath $boundaryJson

  $userName = Read-Host "Enter new user name (allowed: A-Za-z0-9+=,.@_-)"
  if ($userName -notmatch '^[A-Za-z0-9+=,.@_-]+$') {
    Say "Invalid username characters." ([ConsoleColor]::Red)
    return
  }

  $useBoundary = Read-Host "Attach permissions boundary '$BoundaryPolicyName'? (y/n)"
  $boundaryArg = if ($useBoundary -match '^(y|yes)$') { "--permissions-boundary `"$boundaryArn`"" } else { "" }

  Say "Creating user '$userName'..." ([ConsoleColor]::Cyan)
  Run "aws iam create-user --user-name `"$userName`" $boundaryArg"

  $addToGroup = Read-Host "Add user to MFA-enforced group '$HumanGroupName'? (y/n)"
  if ($addToGroup -match '^(y|yes)$') {
    Ensure-Group -GroupName $HumanGroupName
    Say "Adding '$userName' to '$HumanGroupName'..." ([ConsoleColor]::Cyan)
    Run "aws iam add-user-to-group --group-name `"$HumanGroupName`" --user-name `"$userName`""
  }

  $createLogin = Read-Host "Create console login profile (temporary password)? (y/n)"
  if ($createLogin -match '^(y|yes)$') {
    $temp = Read-Host "Enter TEMP password (user must change at next login)"
    Say "Creating console login for '$userName' with password reset required..." ([ConsoleColor]::Cyan)
    Run "aws iam create-login-profile --user-name `"$userName`" --password `"$temp`" --password-reset-required"
    Say "Console login created. User will be forced to configure MFA before they can work." ([ConsoleColor]::Green)
  }
}

function Audit-Users-NoMfa {
  # Lists IAM users and whether they have MFA devices attached.
  $users = aws iam list-users --query "Users[].UserName" --output json | ConvertFrom-Json
  foreach ($u in $users) {
    $name = ($u | Out-String).Trim()
    $mfaCount = aws iam list-mfa-devices --user-name $name --query "length(MFADevices)" --output text
    $state = if ($mfaCount -eq "0") { "NO_MFA" } else { "HAS_MFA" }
    [pscustomobject]@{
      UserName = $name
      MFA      = $state
    }
  }
}

function Audit-Users-AdminPolicy {
  # Flags users who have an "Admin/Administrator" managed policy attached.
  $users = aws iam list-users --query "Users[].UserName" --output json | ConvertFrom-Json
  foreach ($u in $users) {
    $name = ($u | Out-String).Trim()
    $hasAdminCount = aws iam list-attached-user-policies --user-name $name `
      --query "AttachedPolicies[?contains(PolicyName, 'Admin') || contains(PolicyName, 'Administrator')]|length(@)" --output text
    $hasAdmin = if ($hasAdminCount -eq "0") { "No" } else { "Yes" }
    [pscustomobject]@{
      UserName       = $name
      HasAdminPolicy = $hasAdmin
    }
  }
}

function Audit-Users-NotInMfaGroup {
  # Shows whether each user is in the MFA-enforced group.
  $users = aws iam list-users --query "Users[].UserName" --output json | ConvertFrom-Json
  $groupUsers = aws iam get-group --group-name $HumanGroupName --query "Users[].UserName" --output json 2>$null | ConvertFrom-Json
  if (-not $groupUsers) { $groupUsers = @() }

  $set = [System.Collections.Generic.HashSet[string]]::new()
  foreach ($g in $groupUsers) { [void]$set.Add( ($g | Out-String).Trim() ) }

  foreach ($u in $users) {
    $name = ($u | Out-String).Trim()
    $inGroup = if ($set.Contains($name)) { "Yes" } else { "No" }
    [pscustomobject]@{
      UserName   = $name
      InMfaGroup = $inGroup
    }
  }
}


function Action-AuditAndExport {
  <#
    WHAT: Runs MFA, Admin, and MFA-group audits and exports CSVs for evidence.
  #>
  Say "[Audit] Running MFA/Admin/MFA-group checks..." ([ConsoleColor]::Green)

  $noMfa   = Audit-Users-NoMfa       | Sort-Object UserName
  $admins  = Audit-Users-AdminPolicy | Sort-Object UserName
  $ingroup = Audit-Users-NotInMfaGroup | Sort-Object UserName

  Say "--- MFA Status ---" ([ConsoleColor]::Yellow);    $noMfa   | Format-Table -AutoSize
  Say "--- Admin Policy ---" ([ConsoleColor]::Yellow);  $admins  | Format-Table -AutoSize
  Say "--- In MFA Group ---" ([ConsoleColor]::Yellow);  $ingroup | Format-Table -AutoSize

  $noMfa   | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $ReportsDir "users_mfa_status.csv")
  $admins  | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $ReportsDir "users_admin_policy.csv")
  $ingroup | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $ReportsDir "users_in_mfa_group.csv")

  Say "Reports saved in '$ReportsDir' (commit these as audit evidence)." ([ConsoleColor]::Green)
}

function Action-EnableAccessAnalyzer {
  <#
    WHAT: Enables Account-level Access Analyzer.
    WHY: Continuously identifies public or cross-account access for monitoring and compliance.
  #>
  Say "[Access Analyzer] Ensuring analyzer exists..." ([ConsoleColor]::Green)

  $exists = aws accessanalyzer list-analyzers --type ACCOUNT `
    --query "analyzers[?name=='$AccessAnalyzerName']|length(@)" --output text

  if ($exists -eq "0") {
    Run "aws accessanalyzer create-analyzer --analyzer-name `"$AccessAnalyzerName`" --type ACCOUNT"
    Say "Access Analyzer enabled ($AccessAnalyzerName)." ([ConsoleColor]::Green)
  } else {
    Say "Access Analyzer already enabled ($AccessAnalyzerName)." ([ConsoleColor]::DarkGray)
  }
}

function Show-Menu {
  Clear-Host
  Say "=== AWS IAM Toolkit (Explained, ASCII-only) ===" ([ConsoleColor]::White)
  Write-Host "[1] Enforce strong password policy      - WHY: baseline control (ISO/CIS/SOC2)"
  Write-Host "[2] Enforce MFA via group and policy     - WHY: block actions without MFA"
  Write-Host "[3] Create user (boundary/MFA/login)     - WHY: safe, guided provisioning"
  Write-Host "[4] Audit (MFA/Admin/MFA group) and export CSVs - WHY: evidence"
  Write-Host "[5] Enable Access Analyzer               - WHY: continuous access findings"
  Write-Host "[9] Toggle Explain-Only mode (currently: $ExplainOnly)"
  Write-Host "[0] Exit"
}

# ---------- MAIN ----------
Ensure-Aws

do {
  Show-Menu
  $choice = Read-Host "Choose an option"
  try {
    switch ($choice) {
      '1' { Action-SetPasswordPolicy; Pause }
      '2' { Action-SetupMfaEnforcement; Pause }
      '3' { Action-CreateUser; Pause }
      '4' { Action-AuditAndExport; Pause }
      '5' { Action-EnableAccessAnalyzer; Pause }
      '9' { $ExplainOnly = -not $ExplainOnly; Say "Explain-Only mode: $ExplainOnly" ([ConsoleColor]::DarkYellow); Pause }
      '0' { break }
      default { Say "Invalid choice." ([ConsoleColor]::Red); Pause }
    }
  } catch {
    Say $_.Exception.Message ([ConsoleColor]::Red)
    Pause
  }
} while ($true)
