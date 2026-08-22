[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateScript({Test-Path $_ -PathType Container})][string]$ScriptsDirectory,
  [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string[]]$ApprovedSignerThumbprint,
  [Parameter(Mandatory)][string]$OutputPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scripts = [ordered]@{}
foreach ($name in @('Discover-Scvmm.ps1','Collect-ScvmmInventory.ps1','Collect-HypervCimInventory.ps1','Collect-HypervPerformance.ps1')) {
  $path = Join-Path $ScriptsDirectory $name
  if (-not (Test-Path $path -PathType Leaf)) { throw "Missing operational script $name" }
  $signature = Get-AuthenticodeSignature -LiteralPath $path
  if ($signature.Status -ne 'Valid' -or $ApprovedSignerThumbprint -notcontains $signature.SignerCertificate.Thumbprint) { throw "Operational script $name is not signed by an approved certificate" }
  $scripts[$name] = [ordered]@{ sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant(); signerThumbprints = @($signature.SignerCertificate.Thumbprint.ToUpperInvariant()) }
}
[ordered]@{ schemaVersion = 1; catalogVersion = '1.0'; scripts = $scripts } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputPath -Encoding utf8NoBOM
