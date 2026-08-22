Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$operations = Join-Path $env:ProgramFiles 'CloudVerse\DataCenterCollector\scripts\operations'

function Get-CloudVerseExecutionBoundary {
  [CmdletBinding()]
  param()
  [string]$ExecutionContext.SessionState.LanguageMode
}
function Invoke-CloudVerseScvmmDiscovery {
  [CmdletBinding()]
  param([Parameter(Mandatory)][ValidateLength(1,253)][string]$Server, [Parameter(Mandatory)][ValidateRange(1,65535)][int]$Port)
  & (Join-Path $operations 'Discover-Scvmm.ps1') -Server $Server -Port $Port
}
function Invoke-CloudVerseScvmmInventory {
  [CmdletBinding()]
  param([Parameter(Mandatory)][ValidateLength(1,253)][string]$Server, [Parameter(Mandatory)][ValidateRange(1,65535)][int]$Port)
  & (Join-Path $operations 'Collect-ScvmmInventory.ps1') -Server $Server -Port $Port
}
function Invoke-CloudVerseHypervInventory {
  [CmdletBinding()]
  param()
  & (Join-Path $operations 'Collect-HypervCimInventory.ps1')
}
function Invoke-CloudVerseHypervPerformance {
  [CmdletBinding()]
  param()
  & (Join-Path $operations 'Collect-HypervPerformance.ps1')
}
Export-ModuleMember -Function Get-CloudVerseExecutionBoundary,Invoke-CloudVerseScvmmDiscovery,Invoke-CloudVerseScvmmInventory,Invoke-CloudVerseHypervInventory,Invoke-CloudVerseHypervPerformance
