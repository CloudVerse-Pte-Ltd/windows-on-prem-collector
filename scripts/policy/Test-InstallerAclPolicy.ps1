[CmdletBinding()]
param([Parameter(Mandatory)][ValidateScript({Test-Path $_ -PathType Leaf})][string]$InstallerPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($InstallerPath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw 'PowerShell parser rejected the collector installer' }
$aclCalls = @($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Set-CloudVerseAcl'}, $true) | ForEach-Object {$_.Extent.Text.Trim()} | Sort-Object)
$expected = @(
  "Set-CloudVerseAcl -Path `$directory -Identity `$effectiveServiceAccount -Rights 'Modify'",
  "Set-CloudVerseAcl -Path `$InstallDirectory -Identity `$effectiveServiceAccount -Rights 'ReadAndExecute'"
) | Sort-Object
if (($aclCalls -join "`n") -ne ($expected -join "`n")) { throw "Installer ACL calls differ from the immutable-code/writable-data contract: $($aclCalls -join '; ')" }
$source = Get-Content -LiteralPath $InstallerPath -Raw
foreach ($required in @('must be outside the immutable install tree','cannot be a filesystem root','Writable data directories must be distinct and non-overlapping','RemoveAccessRuleSpecific','immutable packaged operations directory','immutable packaged release manifest','Proxy authorizationFile must be inside stateDirectory')) { if (-not $source.Contains($required)) { throw "Installer omits data-directory guard: $required" } }
foreach ($required in @('LOCAL_HYPERV JEA requires the installer-managed CloudVerseCollectorSvc identity','RandomNumberGenerator','New-LocalUser','-Password $taskPassword')) { if (-not $source.Contains($required)) { throw "Installer omits managed local service-identity invariant: $required" } }
if ($source.Contains("`$ServiceAccount,'ReadAndExecute,Write'")) { throw 'Service identity must not receive write access to the install tree' }
[pscustomobject]@{Installer=$InstallerPath; AclCalls=$aclCalls; Valid=$true} | ConvertTo-Json -Compress
