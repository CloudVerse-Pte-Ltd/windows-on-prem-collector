[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $ScriptPath,
    [Parameter(Mandatory = $true)] [string[]] $AllowedCommand
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref] $tokens, [ref] $errors)
if ($errors.Count -gt 0) { throw "PowerShell parser rejected $ScriptPath" }
$commands = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Sort-Object -Unique)
$prohibited = @('Add-*', 'Clear-*', 'Disable-*', 'Enable-*', 'Export-*', 'Invoke-Expression', 'Invoke-Command', 'New-*', 'Remove-*', 'Restart-*', 'Set-*', 'Start-*', 'Stop-*', 'Update-*', 'Write-*')
foreach ($command in $commands) {
    if ($AllowedCommand -notcontains $command) { throw "Command is not allowlisted: $command" }
    foreach ($pattern in $prohibited) { if ($command -ne 'Set-StrictMode' -and $command -like $pattern) { throw "Mutation or generic execution command is prohibited: $command" } }
}
[pscustomobject]@{ Script = $ScriptPath; Commands = $commands; Valid = $true } | ConvertTo-Json -Compress
