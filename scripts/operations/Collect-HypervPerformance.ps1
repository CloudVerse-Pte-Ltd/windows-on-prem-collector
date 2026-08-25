# This script runs only on the local Hyper-V host and is Authenticode-signed during release.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$collectedAt = [DateTime]::UtcNow.ToString('o')
$vms = @(); foreach ($vm in @(Get-VM)) {
    $diskNames = @(); foreach ($disk in @(Get-VMHardDiskDrive -VM $vm)) { if ($disk.Path) { $diskNames += [IO.Path]::GetFileName([string]$disk.Path) } }
    $vms += [pscustomobject]@{ Id = $vm.Id; Name = $vm.Name; DiskNames = $diskNames }
}
$definitions = @(
    @{ Set = 'Hyper-V Hypervisor Virtual Processor'; Counter = '% Guest Run Time'; Key = 'guest.cpu.usage.percent'; Scale = 1 },
    @{ Set = 'Hyper-V Dynamic Memory VM'; Counter = 'Physical Memory'; Key = 'guest.memory.assigned.bytes'; Scale = 1MB },
    @{ Set = 'Hyper-V Virtual Storage Device'; Counter = 'Read Bytes/sec'; Key = 'guest.storage.read.bytes_per_second'; Scale = 1 },
    @{ Set = 'Hyper-V Virtual Storage Device'; Counter = 'Write Bytes/sec'; Key = 'guest.storage.write.bytes_per_second'; Scale = 1 }
)
$rows = @(); $gaps = @()
foreach ($definition in $definitions) {
    try {
        $counterPaths = @(); $counterSet = Get-Counter -ListSet $definition.Set -ErrorAction Stop
        foreach ($candidatePath in @($counterSet.PathsWithInstances)) { if ($candidatePath.EndsWith("\$($definition.Counter)", [StringComparison]::OrdinalIgnoreCase)) { $counterPaths += $candidatePath } }
        if ($counterPaths.Count -eq 0) { throw "Counter set has no live instances for $($definition.Counter)" }
        $counter = Get-Counter -Counter $counterPaths -SampleInterval 1 -MaxSamples 1
        foreach ($sample in $counter.CounterSamples) {
            if ($sample.InstanceName -eq '_total') { continue }
            $matches = @()
            foreach ($vm in $vms) {
                $diskMatch = $false; foreach ($diskName in @($vm.DiskNames)) { if ($diskName -and $sample.InstanceName.IndexOf($diskName, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $diskMatch = $true } }
                if ($sample.InstanceName -eq $vm.Name -or $sample.InstanceName -like "$($vm.Name):*" -or $sample.InstanceName -match [regex]::Escape([string]$vm.Id) -or $diskMatch) { $matches += $vm }
            }
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
