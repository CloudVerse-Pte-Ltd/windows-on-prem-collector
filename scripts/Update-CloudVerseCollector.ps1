#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory)][ValidateScript({Test-Path $_ -PathType Leaf})][string]$PackagePath,
  [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedPackageSha256,
  [string]$InstallDirectory = "$env:ProgramFiles\CloudVerse\DataCenterCollector",
  [string]$TaskName = 'CloudVerseDataCenterCollector'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not [IO.Path]::IsPathRooted($InstallDirectory)) { throw 'InstallDirectory must be absolute' }
$install = [IO.Path]::GetFullPath($InstallDirectory).TrimEnd('\')
$root = [IO.Path]::GetPathRoot($install).TrimEnd('\')
if ($install -eq $root -or -not (Test-Path $install -PathType Container)) { throw 'Existing bounded install directory is required' }
if ((Get-FileHash -LiteralPath $PackagePath -Algorithm SHA256).Hash -ne $ExpectedPackageSha256.ToUpperInvariant()) { throw 'Upgrade package digest mismatch' }
$selfSignature = Get-AuthenticodeSignature -LiteralPath $PSCommandPath
if ($selfSignature.Status -ne 'Valid') { throw 'Upgrade script must have a valid Authenticode signature' }
$approvedSigner = $selfSignature.SignerCertificate.Thumbprint.ToUpperInvariant()
$currentConfigPath = Join-Path $install 'collector.config.json'
if (-not (Test-Path $currentConfigPath -PathType Leaf)) { throw 'Installed collector configuration is missing' }
$configuration = Get-Content -LiteralPath $currentConfigPath -Raw | ConvertFrom-Json
if (-not $configuration.executionBoundary -or @('JEA','WDAC_APPLOCKER') -notcontains $configuration.executionBoundary.kind) { throw 'Installed execution boundary is invalid' }
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
$parent = Split-Path $install -Parent
$upgradeId = [Guid]::NewGuid().ToString('N')
$staging = Join-Path $parent "DataCenterCollector.staging.$upgradeId"
$backup = Join-Path $parent "DataCenterCollector.rollback.$upgradeId"
$jeaModuleRoot = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules\CloudVerseCollector'
$jeaBackup = Join-Path $parent "CloudVerseCollector.JEA.rollback.$upgradeId"
$endpointName = if ($configuration.executionBoundary.kind -eq 'JEA') { [string]$configuration.executionBoundary.endpointName } else { $null }
$oldAcl = Get-Acl $install
$taskStopped = $false; $treeSwapped = $false; $taskActionChanged = $false
$originalActions = @($task.Actions)

function Assert-CloudVerseSignedAsset {
  param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Signer)
  if (-not (Test-Path $Path -PathType Leaf)) { throw "Upgrade package is incomplete: $Path" }
  $signature = Get-AuthenticodeSignature -LiteralPath $Path
  $thumbprint = if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint.ToUpperInvariant() } else { '' }
  if ($signature.Status -ne 'Valid' -or $thumbprint -ne $Signer) { throw "Upgrade asset is not signed by the approved upgrade signer: $Path" }
}

try {
  New-Item -ItemType Directory -Path $staging | Out-Null
  Expand-Archive -LiteralPath $PackagePath -DestinationPath $staging
  foreach ($relative in @('node.exe','dist\src\runtime\cli.js','release-manifest.json','cloudverse-windows-collector.spdx.json','scripts\Install-CloudVerseCollector.ps1','scripts\Install-CloudVerseJea.ps1','scripts\Update-CloudVerseCollector.ps1','scripts\operations\Discover-Scvmm.ps1','scripts\operations\Collect-ScvmmInventory.ps1','scripts\operations\Collect-HypervCimInventory.ps1','scripts\operations\Collect-HypervPerformance.ps1')) {
    if (-not (Test-Path (Join-Path $staging $relative) -PathType Leaf)) { throw "Upgrade package is incomplete: $relative" }
  }
  foreach ($relative in @('scripts\Install-CloudVerseCollector.ps1','scripts\Install-CloudVerseJea.ps1','scripts\Update-CloudVerseCollector.ps1','scripts\operations\Discover-Scvmm.ps1','scripts\operations\Collect-ScvmmInventory.ps1','scripts\operations\Collect-HypervCimInventory.ps1','scripts\operations\Collect-HypervPerformance.ps1')) { Assert-CloudVerseSignedAsset -Path (Join-Path $staging $relative) -Signer $approvedSigner }
  if ($endpointName) {
    foreach ($relative in @('scripts\jea\CloudVerseCollector\1.0.0\CloudVerseCollector.psm1','scripts\jea\CloudVerseCollector\1.0.0\CloudVerseCollector.psd1','scripts\jea\CloudVerseCollector\1.0.0\RoleCapabilities\CloudVerseCollector.psrc')) { Assert-CloudVerseSignedAsset -Path (Join-Path $staging $relative) -Signer $approvedSigner }
  }
  Copy-Item -LiteralPath $currentConfigPath -Destination (Join-Path $staging 'collector.config.json')
  if (-not $PSCmdlet.ShouldProcess($install, 'Transactionally upgrade CloudVerse data-center collector')) { return }
  Stop-ScheduledTask -TaskName $TaskName -ErrorAction Stop; $taskStopped = $true
  if ($endpointName) {
    if (Test-Path $jeaModuleRoot -PathType Container) { Move-Item -LiteralPath $jeaModuleRoot -Destination $jeaBackup }
    if (Get-PSSessionConfiguration -Name $endpointName -ErrorAction SilentlyContinue) { Unregister-PSSessionConfiguration -Name $endpointName -Force -ErrorAction Stop }
  }
  Move-Item -LiteralPath $install -Destination $backup
  Move-Item -LiteralPath $staging -Destination $install; $treeSwapped = $true
  Set-Acl -Path $install -AclObject $oldAcl
  if ($endpointName) { & (Join-Path $install 'scripts\Install-CloudVerseJea.ps1') -InstallDirectory $install -ServiceAccount ([string]$task.Principal.UserId) -EndpointName $endpointName -CollectorMode ([string]$configuration.mode) }
  $validationAction = New-ScheduledTaskAction -Execute (Join-Path $install 'node.exe') -Argument 'dist/src/runtime/cli.js validate collector.config.json' -WorkingDirectory $install
  Set-ScheduledTask -TaskName $TaskName -Action $validationAction | Out-Null; $taskActionChanged = $true
  Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
  $deadline = [DateTime]::UtcNow.AddMinutes(2)
  do { Start-Sleep -Seconds 1; $validationTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop } while ($validationTask.State -eq 'Running' -and [DateTime]::UtcNow -lt $deadline)
  $validationResult = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
  if ($validationTask.State -eq 'Running' -or $validationResult.LastTaskResult -ne 0) { throw 'Upgraded collector validation failed' }
  Set-ScheduledTask -TaskName $TaskName -Action $originalActions | Out-Null; $taskActionChanged = $false
  Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
  [pscustomobject]@{ Status='SUCCEEDED'; InstallDirectory=$install; RollbackDirectory=$backup; PreviousJeaModule=$jeaBackup; TaskName=$TaskName } | ConvertTo-Json -Compress
} catch {
  $upgradeError = $_
  if ($taskActionChanged) { Set-ScheduledTask -TaskName $TaskName -Action $originalActions -ErrorAction SilentlyContinue | Out-Null; $taskActionChanged = $false }
  if ($treeSwapped -and (Test-Path $install -PathType Container)) { Move-Item -LiteralPath $install -Destination "$staging.failed" }
  if (Test-Path $backup -PathType Container) { Move-Item -LiteralPath $backup -Destination $install }
  if ($endpointName) {
    if (Get-PSSessionConfiguration -Name $endpointName -ErrorAction SilentlyContinue) { Unregister-PSSessionConfiguration -Name $endpointName -Force -ErrorAction SilentlyContinue }
    if (Test-Path $jeaModuleRoot -PathType Container) { Remove-Item -LiteralPath $jeaModuleRoot -Recurse -Force }
    if (Test-Path (Join-Path $install 'scripts\Install-CloudVerseJea.ps1') -PathType Leaf) { & (Join-Path $install 'scripts\Install-CloudVerseJea.ps1') -InstallDirectory $install -ServiceAccount ([string]$task.Principal.UserId) -EndpointName $endpointName -CollectorMode ([string]$configuration.mode) }
  }
  if ($taskStopped) { Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue }
  throw $upgradeError
} finally {
  if (Test-Path $staging -PathType Container) { Remove-Item -LiteralPath $staging -Recurse -Force }
}
