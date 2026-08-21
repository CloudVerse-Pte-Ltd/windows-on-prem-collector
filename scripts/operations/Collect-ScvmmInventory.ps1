# This operational script is Authenticode-signed during release. Runtime rejects unsigned or changed bytes.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateLength(1, 253)][string] $Server,
    [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int] $Port
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module -Name VirtualMachineManager -ErrorAction Stop
$vmm = Get-SCVMMServer -ComputerName $Server -TCPPort $Port -ConnectAs ReadOnlyAdmin -ErrorAction Stop
[pscustomobject]@{
    schemaVersion = '1.0'; capability = 'INVENTORY'; platform = 'HYPERV'; mutationAttempted = $false
    managementPlane = [pscustomobject]@{ name = [string]$vmm.Name; version = [string]$vmm.ProductVersion; port = $Port }
    hostGroups = @(Get-SCVMHostGroup -VMMServer $vmm | Select-Object ID, Name, Path, ParentHostGroup)
    clusters = @(Get-SCVMHostCluster -VMMServer $vmm | Select-Object ID, Name, VirtualizationPlatform, VMHostGroup)
    hosts = @(Get-SCVMHost -VMMServer $vmm | Select-Object ID, Name, ComputerName, OverallState, VirtualizationPlatform, VMHostGroup, HostCluster, LogicalProcessorCount, TotalMemory, AvailableMemory)
    virtualMachines = @(Get-SCVirtualMachine -VMMServer $vmm | Select-Object ID, Name, Status, VirtualizationPlatform, VMHost, HostGroup, HostCluster, CPUCount, Memory, DynamicMemoryEnabled, TotalSize, CreationTime)
    templates = @(Get-SCVMTemplate -VMMServer $vmm | Select-Object ID, Name, CPUCount, Memory, DynamicMemoryEnabled, TotalSize, CreationTime)
    checkpoints = @(Get-SCVMCheckpoint -VMMServer $vmm | Select-Object ID, Name, VM, CreationTime, CheckpointType)
    storageArrays = @(Get-SCStorageArray -VMMServer $vmm | Select-Object ID, Name, Model, Manufacturer, SerialNumber, TotalCapacity, AllocatedCapacity)
    storagePools = @(Get-SCStoragePool -VMMServer $vmm | Select-Object ID, Name, Classification, TotalManagedSpace, RemainingManagedSpace, StorageArray)
    logicalNetworks = @(Get-SCLogicalNetwork -VMMServer $vmm | Select-Object ID, Name, Description, NetworkVirtualizationEnabled)
    vmNetworks = @(Get-SCVMNetwork -VMMServer $vmm | Select-Object ID, Name, LogicalNetwork, IsolationType)
} | ConvertTo-Json -Depth 10 -Compress
