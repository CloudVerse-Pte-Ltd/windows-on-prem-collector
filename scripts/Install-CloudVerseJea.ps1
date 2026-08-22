#Requires -RunAsAdministrator
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateScript({Test-Path $_ -PathType Container})][string]$InstallDirectory,
  [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_.\\$-]+$')][string]$ServiceAccount,
  [Parameter(Mandatory)][ValidatePattern('^[A-Za-z][A-Za-z0-9.-]{0,63}$')][string]$EndpointName,
  [Parameter(Mandatory)][ValidateSet('SCVMM','LOCAL_HYPERV')][string]$CollectorMode
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$expectedInstallDirectory = Join-Path $env:ProgramFiles 'CloudVerse\DataCenterCollector'
if ([IO.Path]::GetFullPath($InstallDirectory) -ne [IO.Path]::GetFullPath($expectedInstallDirectory)) { throw 'The packaged JEA module requires the standard CloudVerse install directory' }
$sourceModule = Join-Path $InstallDirectory 'scripts\jea\CloudVerseCollector'
$targetModule = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules\CloudVerseCollector'
if (-not (Test-Path (Join-Path $sourceModule '1.0.0\CloudVerseCollector.psm1') -PathType Leaf)) { throw 'Packaged JEA module is missing' }
if (Test-Path $targetModule) { throw 'CloudVerseCollector JEA module already exists; use the signed upgrade procedure' }
$existingEndpoint = Get-PSSessionConfiguration -Name $EndpointName -ErrorAction SilentlyContinue
if ($existingEndpoint) { throw 'Requested JEA endpoint already exists; use the signed upgrade procedure' }
New-Item -ItemType Directory -Path (Split-Path $targetModule -Parent) -Force | Out-Null
Copy-Item -LiteralPath $sourceModule -Destination $targetModule -Recurse
$transcripts = Join-Path $env:ProgramData 'CloudVerse\Transcripts'
New-Item -ItemType Directory -Path $transcripts -Force | Out-Null
$acl = Get-Acl $transcripts
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new('SYSTEM','FullControl','ContainerInherit,ObjectInherit','None','Allow'))
$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new('BUILTIN\Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow'))
Set-Acl -Path $transcripts -AclObject $acl
$configurationDirectory = Join-Path $env:ProgramData 'CloudVerse'
New-Item -ItemType Directory -Path $configurationDirectory -Force | Out-Null
$configuration = Join-Path $configurationDirectory "$EndpointName.pssc"
try {
  $sessionParameters = @{
    Path = $configuration
    SessionType = 'RestrictedRemoteServer'
    LanguageMode = 'NoLanguage'
    TranscriptDirectory = $transcripts
    RoleDefinitions = @{ $ServiceAccount = @{ RoleCapabilities = 'CloudVerseCollector' } }
  }
  if ($CollectorMode -eq 'SCVMM') {
    if ($ServiceAccount -notmatch '^[^\\]+\\[^\\]+\$$') { throw 'SCVMM JEA requires a domain gMSA service account ending in $' }
    $sessionParameters.GroupManagedServiceAccount = $ServiceAccount
  } else {
    $sessionParameters.RunAsVirtualAccount = $true
  }
  New-PSSessionConfigurationFile @sessionParameters
  Register-PSSessionConfiguration -Name $EndpointName -Path $configuration -Force -NoServiceRestart
  Restart-Service WinRM -Force
} catch {
  Unregister-PSSessionConfiguration -Name $EndpointName -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $targetModule -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $configuration -Force -ErrorAction SilentlyContinue
  throw
}
