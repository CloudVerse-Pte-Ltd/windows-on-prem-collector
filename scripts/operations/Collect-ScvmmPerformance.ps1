# This script is Authenticode-signed during release and runs only through the fixed catalog.
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateLength(1,253)][string]$Server,
  [Parameter(Mandatory)][ValidateRange(1,65535)][int]$Port
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module VirtualMachineManager -ErrorAction Stop
$vmm = Get-SCVMMServer -ComputerName $Server -TCPPort $Port -ErrorAction Stop
$collectedAt = [DateTime]::UtcNow.ToString('o')
$definitions = @(
  @{ Counter = 'CPUUsage'; Key = 'guest.cpu.usage.percent' },
  @{ Counter = 'MemoryUsage'; Key = 'guest.memory.usage.percent' },
  @{ Counter = 'StorageIOPSUsage'; Key = 'guest.storage.iops' },
  @{ Counter = 'NetworkIOUsage'; Key = 'guest.network.io.bytes_per_second' }
)
$rows = @(); $gaps = @()
foreach ($vm in @(Get-SCVirtualMachine -VMMServer $vmm)) {
  $vmUid = [string]$vm.ID
  $vmName = [string]$vm.Name
  if ($vmUid -notmatch '^[0-9a-fA-F-]{36}$') {
    $gaps += [pscustomobject]@{ code = 'SCVMM_VM_GUID_UNAVAILABLE'; details = @{ vmName = $vmName } }
    continue
  }
  foreach ($definition in $definitions) {
    $dynamicMemoryProperty = $vm.PSObject.Properties['DynamicMemoryEnabled']
    if ($definition.Counter -eq 'MemoryUsage' -and $null -ne $dynamicMemoryProperty -and $dynamicMemoryProperty.Value -eq $false) {
      $gaps += [pscustomobject]@{ code = 'SCVMM_STATIC_MEMORY_USAGE_NOT_INFORMATIVE'; vmUid = $vmUid; metricKey = $definition.Key; details = @{ nativeCounter = $definition.Counter; reason = 'SCVMM reports static-memory VMs as 100 percent' } }
      continue
    }
    try {
      $response = Get-SCPerformanceData -VM $vm -VMMServer $vmm -PerformanceCounter $definition.Counter -TimeFrame Hour -ErrorAction Stop
      $historyProperty = $response.PSObject.Properties['PerformanceHistory']
      $history = if ($null -ne $historyProperty) { @($historyProperty.Value) } else { @($response) }
      if ($history.Count -eq 0) {
        $gaps += [pscustomobject]@{ code = 'SCVMM_COUNTER_NO_HISTORY'; vmUid = $vmUid; metricKey = $definition.Key; details = @{ nativeCounter = $definition.Counter; timeframe = 'Hour' } }
        continue
      }
      $value = [double]$history[$history.Count - 1]
      if ([double]::IsNaN($value) -or [double]::IsInfinity($value) -or $value -lt 0) {
        $gaps += [pscustomobject]@{ code = 'SCVMM_COUNTER_INVALID'; vmUid = $vmUid; metricKey = $definition.Key; details = @{ nativeCounter = $definition.Counter; timeframe = 'Hour' } }
        continue
      }
      $rows += [pscustomobject]@{ vmUid = $vmUid; vmName = $vmName; metricKey = $definition.Key; timestamp = $collectedAt; value = $value; instanceName = $vmUid; counterPath = "SCVMM:Get-SCPerformanceData/$($definition.Counter)/Hour/latest" }
    } catch {
      $gaps += [pscustomobject]@{ code = 'SCVMM_COUNTER_UNAVAILABLE'; vmUid = $vmUid; metricKey = $definition.Key; details = @{ nativeCounter = $definition.Counter; timeframe = 'Hour'; errorType = 'COUNTER_READ_FAILED' } }
    }
  }
}
[pscustomobject]@{ schemaVersion = '1.0'; capability = 'TELEMETRY'; platform = 'HYPERV'; transport = 'SCVMM_PERFORMANCE_DATA'; collectedAt = $collectedAt; historyAvailable = $true; mutationAttempted = $false; rows = $rows; gaps = $gaps } | ConvertTo-Json -Depth 8 -Compress
