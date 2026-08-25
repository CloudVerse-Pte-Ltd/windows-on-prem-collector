# This script runs only on the local Hyper-V host and is Authenticode-signed during release.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Copy-CloudVerseProperties([object]$InputObject, [string[]]$Names) {
    $result = [ordered]@{}
    foreach ($name in $Names) {
        $property = $InputObject.PSObject.Properties[$name]
        $result[$name] = if ($null -eq $property) { $null } else { $property.Value }
    }
    return [pscustomobject]$result
}
$system = Copy-CloudVerseProperties @(Get-CimInstance -Namespace root/cimv2 -ClassName Win32_ComputerSystem)[0] @('Name','Domain','Manufacturer','Model','TotalPhysicalMemory')
$product = Copy-CloudVerseProperties @(Get-CimInstance -Namespace root/cimv2 -ClassName Win32_ComputerSystemProduct)[0] @('UUID')
$systems = @(); foreach ($item in @(Get-CimInstance -Namespace root/virtualization/v2 -ClassName Msvm_ComputerSystem)) { $systems += Copy-CloudVerseProperties $item @('Name','ElementName','Caption','EnabledState','HealthState','OperationalStatus') }
$settings = @(); foreach ($item in @(Get-CimInstance -Namespace root/virtualization/v2 -ClassName Msvm_VirtualSystemSettingData)) { $settings += Copy-CloudVerseProperties $item @('InstanceID','VirtualSystemIdentifier','ElementName','SettingType','VirtualSystemType','ConfigurationDataRoot','SnapshotDataRoot') }
$processors = @(); foreach ($item in @(Get-CimInstance -Namespace root/virtualization/v2 -ClassName Msvm_ProcessorSettingData)) { $processors += Copy-CloudVerseProperties $item @('InstanceID','VirtualQuantity','Reservation','Limit','Weight') }
$memory = @(); foreach ($item in @(Get-CimInstance -Namespace root/virtualization/v2 -ClassName Msvm_MemorySettingData)) { $memory += Copy-CloudVerseProperties $item @('InstanceID','VirtualQuantity','AllocationUnits','Reservation','Limit','Weight') }
$cluster = $null
$clusterNodes = @()
$clusterAvailable = $true
try {
    # MSCluster_Cluster.Id is null on supported Windows Server failover clusters.
    # Get-Cluster exposes the durable cluster GUID backed by the cluster service.
    $cluster = Copy-CloudVerseProperties @(Get-Cluster -ErrorAction Stop)[0] @('Id','Name','Description')
    foreach ($item in @(Get-CimInstance -Namespace root/MSCluster -ClassName MSCluster_Node -ErrorAction Stop)) { $clusterNodes += Copy-CloudVerseProperties $item @('Id','Name','State') }
} catch { $clusterAvailable = $false }
[pscustomobject]@{
    schemaVersion = '1.0'; capability = 'INVENTORY'; platform = 'HYPERV'; transport = 'LOCAL_CIM_V2'; mutationAttempted = $false
    host = [pscustomobject]@{ UUID = [string]$product.UUID; Name = [string]$system.Name; Domain = [string]$system.Domain; Manufacturer = [string]$system.Manufacturer; Model = [string]$system.Model; TotalPhysicalMemory = [uint64]$system.TotalPhysicalMemory }
    computerSystems = $systems; settings = $settings; processors = $processors; memory = $memory; clusterAvailable = $clusterAvailable; cluster = $cluster; clusterNodes = $clusterNodes
    unavailableFamilies = @('SCVMM_HOST_GROUP','SCVMM_TEMPLATE','SCVMM_STORAGE_FABRIC','SCVMM_NETWORK_INTENT')
} | ConvertTo-Json -Depth 9 -Compress
