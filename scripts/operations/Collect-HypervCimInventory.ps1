# This script runs only on the local Hyper-V host and is Authenticode-signed during release.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$system = Get-CimInstance -Namespace root/cimv2 -ClassName Win32_ComputerSystem | Select-Object -First 1 Name, Domain, Manufacturer, Model, TotalPhysicalMemory
$product = Get-CimInstance -Namespace root/cimv2 -ClassName Win32_ComputerSystemProduct | Select-Object -First 1 UUID
$systems = @(Get-CimInstance -Namespace root/virtualization/v2 -ClassName Msvm_ComputerSystem | Select-Object Name, ElementName, Caption, EnabledState, HealthState, OperationalStatus)
$settings = @(Get-CimInstance -Namespace root/virtualization/v2 -ClassName Msvm_VirtualSystemSettingData | Select-Object InstanceID, VirtualSystemIdentifier, ElementName, SettingType, VirtualSystemType, ConfigurationDataRoot, SnapshotDataRoot)
$cluster = $null
$clusterNodes = @()
$clusterAvailable = $true
try {
    $cluster = Get-CimInstance -Namespace root/MSCluster -ClassName MSCluster_Cluster -ErrorAction Stop | Select-Object -First 1 Id, Name, Description
    $clusterNodes = @(Get-CimInstance -Namespace root/MSCluster -ClassName MSCluster_Node -ErrorAction Stop | Select-Object Id, Name, State)
} catch { $clusterAvailable = $false }
[pscustomobject]@{
    schemaVersion = '1.0'; capability = 'INVENTORY'; platform = 'HYPERV'; transport = 'LOCAL_CIM_V2'; mutationAttempted = $false
    host = [pscustomobject]@{ UUID = [string]$product.UUID; Name = [string]$system.Name; Domain = [string]$system.Domain; Manufacturer = [string]$system.Manufacturer; Model = [string]$system.Model; TotalPhysicalMemory = [uint64]$system.TotalPhysicalMemory }
    computerSystems = $systems; settings = $settings; clusterAvailable = $clusterAvailable; cluster = $cluster; clusterNodes = $clusterNodes
    unavailableFamilies = @('SCVMM_HOST_GROUP','SCVMM_TEMPLATE','SCVMM_STORAGE_FABRIC','SCVMM_NETWORK_INTENT')
} | ConvertTo-Json -Depth 9 -Compress
