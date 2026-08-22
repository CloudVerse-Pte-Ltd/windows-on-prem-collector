#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory)][ValidateScript({Test-Path $_ -PathType Container})][string]$PackageDirectory,
  [Parameter(Mandatory)][ValidateScript({Test-Path $_ -PathType Leaf})][string]$ConfigFile,
  [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_.\\$-]+$')][string]$ServiceAccount,
  [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedPackageSha256,
  [string]$InstallDirectory = "$env:ProgramFiles\CloudVerse\DataCenterCollector"
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$package = Join-Path $PackageDirectory 'cloudverse-windows-collector.zip'
if (-not (Test-Path $package -PathType Leaf)) { throw 'Release package is missing' }
if ((Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash -ne $ExpectedPackageSha256.ToUpperInvariant()) { throw 'Release package digest mismatch' }
$signature = Get-AuthenticodeSignature -LiteralPath $PSCommandPath
if ($signature.Status -ne 'Valid') { throw 'Installer must have a valid Authenticode signature' }
if ($PSCmdlet.ShouldProcess($InstallDirectory, 'Install CloudVerse data-center collector')) {
  if (Test-Path $InstallDirectory) { throw 'Install directory already exists; use the signed upgrade procedure' }
  New-Item -ItemType Directory -Path $InstallDirectory | Out-Null
  Expand-Archive -LiteralPath $package -DestinationPath $InstallDirectory
  Copy-Item -LiteralPath $ConfigFile -Destination (Join-Path $InstallDirectory 'collector.config.json')
  $acl = Get-Acl $InstallDirectory
  $acl.SetAccessRuleProtection($true, $false)
  $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new('SYSTEM','FullControl','ContainerInherit,ObjectInherit','None','Allow'))
  $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($ServiceAccount,'ReadAndExecute,Write','ContainerInherit,ObjectInherit','None','Allow'))
  Set-Acl -Path $InstallDirectory -AclObject $acl
  $action = New-ScheduledTaskAction -Execute (Join-Path $InstallDirectory 'node.exe') -Argument 'dist/src/runtime/cli.js run collector.config.json' -WorkingDirectory $InstallDirectory
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId $ServiceAccount -LogonType ServiceAccount -RunLevel Limited
  $settings = New-ScheduledTaskSettingsSet -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName 'CloudVerseDataCenterCollector' -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
  Start-ScheduledTask -TaskName 'CloudVerseDataCenterCollector'
}
