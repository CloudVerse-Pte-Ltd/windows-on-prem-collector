[CmdletBinding()]
param([Parameter(Mandatory)][ValidateScript({Test-Path $_ -PathType Leaf})][string]$ModulePath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw 'PowerShell parser rejected the JEA module' }
$expectedFunctions = @(
  'Get-CloudVerseExecutionBoundary',
  'Invoke-CloudVerseHypervInventory',
  'Invoke-CloudVerseHypervPerformance',
  'Invoke-CloudVerseScvmmDiscovery',
  'Invoke-CloudVerseScvmmInventory'
)
$functions = @($ast.FindAll({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]}, $true) | ForEach-Object Name | Sort-Object)
if (($functions -join ',') -ne ($expectedFunctions -join ',')) { throw "JEA function surface differs from the immutable catalog: $($functions -join ',')" }
$namedCommands = @($ast.FindAll({param($node) $node -is [System.Management.Automation.Language.CommandAst]}, $true) | ForEach-Object {$_.GetCommandName()} | Where-Object {$_} | Sort-Object -Unique)
$allowedCommands = @('Export-ModuleMember','Import-Module','Join-Path','Set-StrictMode')
foreach ($command in $namedCommands) { if ($allowedCommands -notcontains $command) { throw "JEA module command is not allowlisted: $command" } }
$source = Get-Content -LiteralPath $ModulePath -Raw
foreach ($requiredImport in @('Import-Module CimCmdlets -ErrorAction Stop','Import-Module Hyper-V -ErrorAction Stop','Import-Module Microsoft.PowerShell.Diagnostics -ErrorAction Stop')) {
  if (-not $source.Contains($requiredImport)) { throw "JEA module omits fixed host read-only module import: $requiredImport" }
}
$dynamicCommands = @($ast.FindAll({param($node) $node -is [System.Management.Automation.Language.CommandAst] -and -not $node.GetCommandName()}, $true))
$expectedOperations = @(
  "& (Join-Path `$operations 'Collect-HypervCimInventory.ps1')",
  "& (Join-Path `$operations 'Collect-HypervPerformance.ps1')",
  "& (Join-Path `$operations 'Collect-ScvmmInventory.ps1') -Server `$Server -Port `$Port -PageNumber `$PageNumber -PageSize `$PageSize",
  "& (Join-Path `$operations 'Discover-Scvmm.ps1') -Server `$Server -Port `$Port"
)
$actualOperations = @($dynamicCommands | ForEach-Object {$_.Extent.Text.Trim()} | Sort-Object)
if (($actualOperations -join "`n") -ne (($expectedOperations | Sort-Object) -join "`n")) { throw 'JEA module dynamic invocation differs from the four reviewed fixed script paths' }
[pscustomobject]@{Module=$ModulePath; Functions=$functions; Operations=$actualOperations; Valid=$true} | ConvertTo-Json -Compress
