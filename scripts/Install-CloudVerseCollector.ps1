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
$approvedSignerThumbprint = $signature.SignerCertificate.Thumbprint.ToUpperInvariant()
if ($PSCmdlet.ShouldProcess($InstallDirectory, 'Install CloudVerse data-center collector')) {
  if (Test-Path $InstallDirectory) { throw 'Install directory already exists; use the signed upgrade procedure' }
  New-Item -ItemType Directory -Path $InstallDirectory | Out-Null
  Expand-Archive -LiteralPath $package -DestinationPath $InstallDirectory
  foreach ($relative in @(
    'node.exe',
    'dist\src\runtime\cli.js',
    'scripts\operations\Discover-Scvmm.ps1',
    'scripts\operations\Collect-ScvmmInventory.ps1',
    'scripts\operations\Collect-ScvmmPerformance.ps1',
    'scripts\operations\Collect-HypervCimInventory.ps1',
    'scripts\operations\Collect-HypervPerformance.ps1',
    'release-manifest.json',
    'cloudverse-windows-collector.spdx.json'
  )) {
    if (-not (Test-Path (Join-Path $InstallDirectory $relative) -PathType Leaf)) { throw "Release package is incomplete: $relative" }
  }
  Copy-Item -LiteralPath $ConfigFile -Destination (Join-Path $InstallDirectory 'collector.config.json')
  $configuration = Get-Content -LiteralPath (Join-Path $InstallDirectory 'collector.config.json') -Raw | ConvertFrom-Json
  if (-not $configuration.executionBoundary -or @('JEA','WDAC_APPLOCKER') -notcontains $configuration.executionBoundary.kind) { throw 'Configuration must select an explicit JEA or WDAC/AppLocker execution boundary' }
  if ($configuration.executionBoundary.kind -eq 'JEA') {
    if ([string]::IsNullOrWhiteSpace([string]$configuration.executionBoundary.endpointName)) { throw 'JEA endpoint name is required' }
    $jeaFiles = @(
      'scripts\Install-CloudVerseJea.ps1',
      'scripts\jea\CloudVerseCollector\1.0.0\CloudVerseCollector.psm1',
      'scripts\jea\CloudVerseCollector\1.0.0\CloudVerseCollector.psd1',
      'scripts\jea\CloudVerseCollector\1.0.0\RoleCapabilities\CloudVerseCollector.psrc'
    )
    foreach ($relative in $jeaFiles) {
      $path = Join-Path $InstallDirectory $relative
      if (-not (Test-Path $path -PathType Leaf)) { throw "JEA release package is incomplete: $relative" }
      $assetSignature = Get-AuthenticodeSignature -LiteralPath $path
      $assetThumbprint = if ($assetSignature.SignerCertificate) { $assetSignature.SignerCertificate.Thumbprint.ToUpperInvariant() } else { '' }
      if ($assetSignature.Status -ne 'Valid' -or $assetThumbprint -ne $approvedSignerThumbprint) { throw "JEA asset is not signed by the installer signer: $relative" }
    }
  }
  $acl = Get-Acl $InstallDirectory
  $acl.SetAccessRuleProtection($true, $false)
  $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new('SYSTEM','FullControl','ContainerInherit,ObjectInherit','None','Allow'))
  $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($ServiceAccount,'ReadAndExecute,Write','ContainerInherit,ObjectInherit','None','Allow'))
  Set-Acl -Path $InstallDirectory -AclObject $acl
  if ($configuration.executionBoundary.kind -eq 'JEA') {
    & (Join-Path $InstallDirectory 'scripts\Install-CloudVerseJea.ps1') -InstallDirectory $InstallDirectory -ServiceAccount $ServiceAccount -EndpointName ([string]$configuration.executionBoundary.endpointName) -CollectorMode ([string]$configuration.mode)
  }
  $action = New-ScheduledTaskAction -Execute (Join-Path $InstallDirectory 'node.exe') -Argument 'dist/src/runtime/cli.js run collector.config.json' -WorkingDirectory $InstallDirectory
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId $ServiceAccount -LogonType ServiceAccount -RunLevel Limited
  $settings = New-ScheduledTaskSettingsSet -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName 'CloudVerseDataCenterCollector' -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
  Start-ScheduledTask -TaskName 'CloudVerseDataCenterCollector'
}
