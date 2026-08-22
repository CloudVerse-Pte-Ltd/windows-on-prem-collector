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
function Resolve-CloudVerseDataDirectory {
  param([Parameter(Mandatory)][string]$Label, [Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)][string]$CodeDirectory)
  if ([string]::IsNullOrWhiteSpace($Value) -or -not [IO.Path]::IsPathRooted($Value)) { throw "$Label must be an absolute path" }
  $full = [IO.Path]::GetFullPath($Value).TrimEnd('\')
  $root = [IO.Path]::GetPathRoot($full).TrimEnd('\')
  if ($full -eq $root) { throw "$Label cannot be a filesystem root" }
  $code = [IO.Path]::GetFullPath($CodeDirectory).TrimEnd('\')
  if ($full.Equals($code, [StringComparison]::OrdinalIgnoreCase) -or $full.StartsWith($code + '\', [StringComparison]::OrdinalIgnoreCase) -or $code.StartsWith($full + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "$Label must be outside the immutable install tree" }
  return $full
}
function Set-CloudVerseAcl {
  param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Identity, [Parameter(Mandatory)][string]$Rights)
  New-Item -ItemType Directory -Path $Path -Force | Out-Null
  $acl = Get-Acl $Path
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($rule) }
  $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new('SYSTEM','FullControl','ContainerInherit,ObjectInherit','None','Allow'))
  $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new('BUILTIN\Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow'))
  $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($Identity,$Rights,'ContainerInherit,ObjectInherit','None','Allow'))
  Set-Acl -Path $Path -AclObject $acl
}
if ($PSCmdlet.ShouldProcess($InstallDirectory, 'Install CloudVerse data-center collector')) {
  if (Test-Path $InstallDirectory) { throw 'Install directory already exists; use the signed upgrade procedure' }
  New-Item -ItemType Directory -Path $InstallDirectory | Out-Null
  Expand-Archive -LiteralPath $package -DestinationPath $InstallDirectory
  foreach ($relative in @(
    'node.exe',
    'dist\src\runtime\cli.js',
    'scripts\operations\Discover-Scvmm.ps1',
    'scripts\operations\Collect-ScvmmInventory.ps1',
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
  $expectedScriptsDirectory = Join-Path $InstallDirectory 'scripts\operations'
  $expectedManifestPath = Join-Path $InstallDirectory 'release-manifest.json'
  if (-not [IO.Path]::GetFullPath([string]$configuration.scriptsDirectory).Equals([IO.Path]::GetFullPath($expectedScriptsDirectory), [StringComparison]::OrdinalIgnoreCase)) { throw 'scriptsDirectory must select the immutable packaged operations directory' }
  if (-not [IO.Path]::GetFullPath([string]$configuration.manifestPath).Equals([IO.Path]::GetFullPath($expectedManifestPath), [StringComparison]::OrdinalIgnoreCase)) { throw 'manifestPath must select the immutable packaged release manifest' }
  $planePattern = if ($configuration.mode -eq 'SCVMM') { '^scvmm:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$' } elseif ($configuration.mode -eq 'LOCAL_HYPERV') { '^hyperv:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$' } else { throw 'Collector mode is invalid' }
  if (([string]$configuration.managementPlaneUid) -notmatch $planePattern) { throw 'Collector mode and immutable management-plane UUID do not match' }
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
  $stateDirectory = Resolve-CloudVerseDataDirectory -Label 'stateDirectory' -Value ([string]$configuration.stateDirectory) -CodeDirectory $InstallDirectory
  $spoolDirectory = Resolve-CloudVerseDataDirectory -Label 'spoolDirectory' -Value ([string]$configuration.spoolDirectory) -CodeDirectory $InstallDirectory
  if ($stateDirectory.Equals($spoolDirectory, [StringComparison]::OrdinalIgnoreCase)) { throw 'stateDirectory and spoolDirectory must be distinct' }
  $dataDirectories = @($stateDirectory, $spoolDirectory)
  if ($configuration.offlineExportDirectory) { $dataDirectories += Resolve-CloudVerseDataDirectory -Label 'offlineExportDirectory' -Value ([string]$configuration.offlineExportDirectory) -CodeDirectory $InstallDirectory }
  if ($configuration.upload -and $configuration.upload.proxy) {
    if ([string]::IsNullOrWhiteSpace([string]$configuration.upload.proxy.authorizationFile) -or -not [IO.Path]::IsPathRooted([string]$configuration.upload.proxy.authorizationFile)) { throw 'Proxy authorizationFile must be an absolute path inside stateDirectory' }
    $proxyAuthorizationFile = [IO.Path]::GetFullPath([string]$configuration.upload.proxy.authorizationFile)
    if (-not $proxyAuthorizationFile.StartsWith($stateDirectory.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Proxy authorizationFile must be inside stateDirectory' }
    if (-not (Test-Path $proxyAuthorizationFile -PathType Leaf)) { throw 'Proxy authorizationFile is missing' }
  }
  for ($left = 0; $left -lt $dataDirectories.Count; $left++) {
    for ($right = $left + 1; $right -lt $dataDirectories.Count; $right++) {
      $a = $dataDirectories[$left].TrimEnd('\'); $b = $dataDirectories[$right].TrimEnd('\')
      if ($a.Equals($b, [StringComparison]::OrdinalIgnoreCase) -or $a.StartsWith($b + '\', [StringComparison]::OrdinalIgnoreCase) -or $b.StartsWith($a + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Writable data directories must be distinct and non-overlapping' }
    }
  }
  Set-CloudVerseAcl -Path $InstallDirectory -Identity $ServiceAccount -Rights 'ReadAndExecute'
  foreach ($directory in $dataDirectories) { Set-CloudVerseAcl -Path $directory -Identity $ServiceAccount -Rights 'Modify' }
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
