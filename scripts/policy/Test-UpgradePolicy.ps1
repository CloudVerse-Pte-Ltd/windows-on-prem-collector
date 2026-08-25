[CmdletBinding()]
param([Parameter(Mandatory)][ValidateScript({Test-Path $_ -PathType Leaf})][string]$UpgradePath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($UpgradePath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw 'PowerShell parser rejected the collector upgrade script' }
$source = Get-Content -LiteralPath $UpgradePath -Raw
foreach ($required in @(
  'Upgrade package digest mismatch',
  'Upgrade script must have a valid Authenticode signature',
  'Upgrade asset is not signed by the approved upgrade signer',
  'Stop-ScheduledTask -TaskName $TaskName',
  'Move-Item -LiteralPath $install -Destination $backup',
  'Move-Item -LiteralPath $backup -Destination $install',
  'Start-ScheduledTask -TaskName $TaskName',
  "Get-ScheduledTask -TaskName `$ValidationTaskName",
  'Collector and validation task identities must match',
  'Start-ScheduledTask -TaskName $ValidationTaskName',
  'Upgraded collector validation failed',
  "Status='SUCCEEDED'",
  'RollbackDirectory=$backup'
  "`$serviceAccount = `$serviceAccount.TrimEnd([char]'`$') + '`$'"
)) { if (-not $source.Contains($required)) { throw "Upgrade procedure omits transactional invariant: $required" } }
if (([regex]::Matches($source, "Install-CloudVerseJea\.ps1'\).*?\| Out-Null")).Count -ne 2) { throw 'Upgrade procedure must suppress JEA registration output on success and rollback paths' }
if ($source -match 'Remove-Item\s+-(?:Path|LiteralPath)\s+\$(?:install|backup)\b') { throw 'Upgrade procedure must never delete the active or rollback code tree' }
[pscustomobject]@{Upgrade=$UpgradePath; Valid=$true} | ConvertTo-Json -Compress
