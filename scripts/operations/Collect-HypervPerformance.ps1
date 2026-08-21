# This script runs only on the local Hyper-V host and is Authenticode-signed during release.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$collectedAt = [DateTime]::UtcNow.ToString('o')
$vms = @(Get-VM | Select-Object Id, Name)
$definitions = @(
    @{ Path = '\Hyper-V Hypervisor Virtual Processor(*)\% Guest Run Time'; Key = 'guest.cpu.usage.percent'; Scale = 1 },
    @{ Path = '\Hyper-V Dynamic Memory VM(*)\Physical Memory'; Key = 'guest.memory.assigned.bytes'; Scale = 1MB },
    @{ Path = '\Hyper-V Virtual Storage Device(*)\Read Bytes/sec'; Key = 'guest.storage.read.bytes_per_second'; Scale = 1 },
    @{ Path = '\Hyper-V Virtual Storage Device(*)\Write Bytes/sec'; Key = 'guest.storage.write.bytes_per_second'; Scale = 1 }
)
$rows = @(); $gaps = @()
foreach ($definition in $definitions) {
    try {
        $counter = Get-Counter -Counter $definition.Path -SampleInterval 1 -MaxSamples 1
        foreach ($sample in $counter.CounterSamples) {
            if ($sample.InstanceName -eq '_total') { continue }
            $matches = @($vms | Where-Object {
                $sample.InstanceName -eq $_.Name -or
                $sample.InstanceName -like "$($_.Name):*" -or
                $sample.InstanceName -match [regex]::Escape([string]$_.Id)
            })
            if ($matches.Count -ne 1) {
                $gaps += [pscustomobject]@{ code = 'COUNTER_INSTANCE_VM_GUID_UNRESOLVED'; metricKey = $definition.Key; details = @{ instanceName = $sample.InstanceName; matchCount = $matches.Count } }
                continue
            }
            $rows += [pscustomobject]@{ vmUid = [string]$matches[0].Id; vmName = [string]$matches[0].Name; metricKey = $definition.Key; timestamp = $sample.Timestamp.ToUniversalTime().ToString('o'); value = [double]$sample.CookedValue * [double]$definition.Scale; instanceName = [string]$sample.InstanceName; counterPath = [string]$sample.Path }
        }
    } catch {
        $gaps += [pscustomobject]@{ code = 'COUNTER_UNAVAILABLE'; metricKey = $definition.Key; details = @{ errorType = 'COUNTER_READ_FAILED' } }
    }
}
[pscustomobject]@{ schemaVersion = '1.0'; capability = 'TELEMETRY'; platform = 'HYPERV'; transport = 'LOCAL_PERFORMANCE_COUNTERS'; collectedAt = $collectedAt; historyAvailable = $false; mutationAttempted = $false; rows = $rows; gaps = $gaps } | ConvertTo-Json -Depth 8 -Compress
