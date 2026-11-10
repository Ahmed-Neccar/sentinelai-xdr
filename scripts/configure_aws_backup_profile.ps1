param(
    [ValidatePattern('^[A-Za-z0-9+=,.@_-]{1,64}$')]
    [string]$ProfileName = "sentinelai-backup"
)

$ErrorActionPreference = "Stop"
$AwsDirectory = Join-Path $env:USERPROFILE ".aws"
$CredentialFile = Join-Path $AwsDirectory "sentinelai-backup-credentials"
if (-not (Test-Path -LiteralPath $AwsDirectory)) {
    New-Item -ItemType Directory -Path $AwsDirectory -Force | Out-Null
}
if (Test-Path -LiteralPath $CredentialFile) {
    throw "Credential file already exists at $CredentialFile. Move it aside yourself before replacing it."
}

$AccessKeyId = Read-Host "Dedicated S3 backup access key ID"
if ($AccessKeyId -notmatch '^AKIA[A-Z0-9]{16}$') {
    throw "The access key ID format is invalid. No credential file was written."
}
$SecureSecret = Read-Host "Dedicated S3 backup secret access key" -AsSecureString
$Pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureSecret)
try {
    $Secret = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Pointer)
    if ([string]::IsNullOrWhiteSpace($Secret) -or $Secret.Contains("`n") -or $Secret.Contains("`r")) {
        throw "The secret key is invalid. No credential file was written."
    }
    # AWS secret access keys are 40 characters. Catch a failed paste here instead of
    # at upload time; only the length is reported, never the value.
    if ($Secret -cnotmatch '^[A-Za-z0-9/+]{40}$') {
        throw "The secret key has $($Secret.Length) characters or unexpected symbols; AWS secret access keys are 40 characters. The paste probably did not go through. No credential file was written."
    }

    New-Item -ItemType File -Path $CredentialFile | Out-Null
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $Acl = Get-Acl -LiteralPath $CredentialFile
    $Acl.SetAccessRuleProtection($true, $false)
    $Acl.SetOwner([Security.Principal.NTAccount]::new($Identity))
    $Rule = [Security.AccessControl.FileSystemAccessRule]::new($Identity, "FullControl", "Allow")
    $Acl.SetAccessRule($Rule)
    Set-Acl -LiteralPath $CredentialFile -AclObject $Acl

    $Contents = "[$ProfileName]`naws_access_key_id=$AccessKeyId`naws_secret_access_key=$Secret`n"
    [IO.File]::WriteAllText($CredentialFile, $Contents, [Text.UTF8Encoding]::new($false))
    Write-Output "Dedicated AWS profile saved to $CredentialFile with an ACL limited to $Identity. The secret was not displayed."
} catch {
    Remove-Item -LiteralPath $CredentialFile -Force -ErrorAction SilentlyContinue
    throw
} finally {
    if ($Pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Pointer) }
    $Secret = $null
    $SecureSecret.Dispose()
}
