# This operational script is Authenticode-signed during release. Runtime rejects unsigned or changed bytes.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateLength(1, 253)][string] $Server,
    [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int] $Port,
    [Parameter(Mandatory = $true)][ValidateRange(0, 50)][int] $PageNumber,
    [Parameter(Mandatory = $true)][ValidateRange(100, 2000)][int] $PageSize
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$setup = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Microsoft System Center Virtual Machine Manager Server\Setup' -ErrorAction Stop
$modulePath = Join-Path ([string] $setup.InstallPath) 'bin\psModules\virtualmachinemanager\virtualmachinemanager.psd1'
Import-Module -Name $modulePath -ErrorAction Stop
$vmm = Get-SCVMMServer -ComputerName $Server -TCPPort $Port -ConnectAs ReadOnlyAdmin -ErrorAction Stop
$idProperty = $vmm.PSObject.Properties['ID']
$managementPlaneId = if ($null -ne $idProperty) { [string] $idProperty.Value } else { '' }
if ([string]::IsNullOrWhiteSpace($managementPlaneId)) {
    $managementPlaneId = [string] $setup.VmmID
}
$skip = $PageNumber * $PageSize
$allVirtualMachines = @(Get-SCVirtualMachine -VMMServer $vmm | ForEach-Object {
    [pscustomobject]@{
        ID = [string] $_.ID; Name = [string] $_.Name; Status = [string] $_.Status; VirtualizationPlatform = [string] $_.VirtualizationPlatform
        VMHost = if ($null -ne $_.PSObject.Properties['VMHost'] -and $null -ne $_.PSObject.Properties['VMHost'].Value) { [string] $_.PSObject.Properties['VMHost'].Value.ID } else { $null }
        HostGroup = if ($null -ne $_.PSObject.Properties['HostGroup'] -and $null -ne $_.PSObject.Properties['HostGroup'].Value) { [string] $_.PSObject.Properties['HostGroup'].Value.ID } else { $null }
        HostCluster = if ($null -ne $_.PSObject.Properties['HostCluster'] -and $null -ne $_.PSObject.Properties['HostCluster'].Value) { [string] $_.PSObject.Properties['HostCluster'].Value.ID } else { $null }
        CPUCount = $_.CPUCount; Memory = $_.Memory; DynamicMemoryEnabled = $_.DynamicMemoryEnabled; TotalSize = $_.TotalSize; CreationTime = [string] $_.CreationTime
    }
} | Sort-Object ID)
$vmPage = @()
$pageLimit = [Math]::Min($allVirtualMachines.Count, $skip + $PageSize + 1)
for ($index = $skip; $index -lt $pageLimit; $index++) { $vmPage += $allVirtualMachines[$index] }
$hasMoreVirtualMachines = $vmPage.Count -gt $PageSize
if ($hasMoreVirtualMachines) { $vmPage = @($vmPage[0..($PageSize - 1)]) }
$hostGroups = @(); $clusters = @(); $hosts = @(); $templates = @(); $checkpoints = @(); $storageArrays = @(); $storagePools = @(); $logicalNetworks = @(); $vmNetworks = @()
if ($PageNumber -eq 0) {
    $hostGroups = @(Get-SCVMHostGroup -VMMServer $vmm | ForEach-Object { [pscustomobject]@{
        ID = [string] $_.ID; Name = [string] $_.Name; Path = [string] $_.Path
        ParentHostGroup = if ($null -ne $_.PSObject.Properties['ParentHostGroup'] -and $null -ne $_.PSObject.Properties['ParentHostGroup'].Value) { [string] $_.PSObject.Properties['ParentHostGroup'].Value.ID } else { $null }
    } })
    $clusters = @(Get-SCVMHostCluster -VMMServer $vmm | ForEach-Object { [pscustomobject]@{
        ID = [string] $_.ID; Name = [string] $_.Name; VirtualizationPlatform = [string] $_.VirtualizationPlatform
        VMHostGroup = if ($null -ne $_.PSObject.Properties['VMHostGroup'] -and $null -ne $_.PSObject.Properties['VMHostGroup'].Value) { [string] $_.PSObject.Properties['VMHostGroup'].Value.ID } else { $null }
    } })
    $hosts = @(Get-SCVMHost -VMMServer $vmm | ForEach-Object { [pscustomobject]@{
        ID = [string] $_.ID; Name = [string] $_.Name; ComputerName = [string] $_.ComputerName; OverallState = [string] $_.OverallState; VirtualizationPlatform = [string] $_.VirtualizationPlatform
        VMHostGroup = if ($null -ne $_.PSObject.Properties['VMHostGroup'] -and $null -ne $_.PSObject.Properties['VMHostGroup'].Value) { [string] $_.PSObject.Properties['VMHostGroup'].Value.ID } else { $null }
        HostCluster = if ($null -ne $_.PSObject.Properties['HostCluster'] -and $null -ne $_.PSObject.Properties['HostCluster'].Value) { [string] $_.PSObject.Properties['HostCluster'].Value.ID } else { $null }
        LogicalProcessorCount = $_.LogicalProcessorCount; TotalMemory = $_.TotalMemory; AvailableMemory = $_.AvailableMemory
    } })
    $templates = @(Get-SCVMTemplate -VMMServer $vmm | ForEach-Object { [pscustomobject]@{
        ID = [string] $_.ID; Name = [string] $_.Name; CPUCount = $_.CPUCount; Memory = $_.Memory; DynamicMemoryEnabled = $_.DynamicMemoryEnabled; TotalSize = $_.TotalSize; CreationTime = [string] $_.CreationTime
    } })
    $checkpoints = @(Get-SCVMCheckpoint -VMMServer $vmm | ForEach-Object { [pscustomobject]@{
        ID = [string] $_.ID; Name = [string] $_.Name
        VM = if ($null -ne $_.PSObject.Properties['VMId'] -and -not [string]::IsNullOrWhiteSpace([string] $_.PSObject.Properties['VMId'].Value)) { [string] $_.PSObject.Properties['VMId'].Value } elseif ($null -ne $_.PSObject.Properties['VM'] -and $null -ne $_.PSObject.Properties['VM'].Value) { [string] $_.PSObject.Properties['VM'].Value.ID } else { $null }
        CreationTime = if ($null -ne $_.PSObject.Properties['CreationTime']) { [string] $_.PSObject.Properties['CreationTime'].Value } elseif ($null -ne $_.PSObject.Properties['AddedTime']) { [string] $_.PSObject.Properties['AddedTime'].Value } else { $null }
        CheckpointType = if ($null -ne $_.PSObject.Properties['CheckpointType']) { [string] $_.PSObject.Properties['CheckpointType'].Value } else { $null }
    } })
    $storageArrays = @(Get-SCStorageArray -VMMServer $vmm | ForEach-Object { [pscustomobject]@{
        ID = [string] $_.ID; Name = [string] $_.Name; Model = [string] $_.Model; Manufacturer = [string] $_.Manufacturer; SerialNumber = [string] $_.SerialNumber; TotalCapacity = $_.TotalCapacity; AllocatedCapacity = $_.AllocatedCapacity
    } })
    $storagePools = @(Get-SCStoragePool -VMMServer $vmm | ForEach-Object { [pscustomobject]@{
        ID = [string] $_.ID; Name = [string] $_.Name; Classification = [string] $_.Classification; TotalManagedSpace = $_.TotalManagedSpace; RemainingManagedSpace = $_.RemainingManagedSpace
        StorageArray = if ($null -ne $_.PSObject.Properties['StorageArray'] -and $null -ne $_.PSObject.Properties['StorageArray'].Value) { [string] $_.PSObject.Properties['StorageArray'].Value.ID } else { $null }
    } })
    $logicalNetworks = @(Get-SCLogicalNetwork -VMMServer $vmm | ForEach-Object { [pscustomobject]@{
        ID = [string] $_.ID; Name = [string] $_.Name; Description = [string] $_.Description; NetworkVirtualizationEnabled = $_.NetworkVirtualizationEnabled
    } })
    $vmNetworks = @(Get-SCVMNetwork -VMMServer $vmm | ForEach-Object { [pscustomobject]@{
        ID = [string] $_.ID; Name = [string] $_.Name; LogicalNetwork = if ($null -ne $_.PSObject.Properties['LogicalNetwork'] -and $null -ne $_.PSObject.Properties['LogicalNetwork'].Value) { [string] $_.PSObject.Properties['LogicalNetwork'].Value.ID } else { $null }; IsolationType = [string] $_.IsolationType
    } })
}
[pscustomobject]@{
    schemaVersion = '1.0'; capability = 'INVENTORY'; platform = 'HYPERV'; mutationAttempted = $false
    managementPlane = [pscustomobject]@{ id = $managementPlaneId; name = [string]$vmm.Name; version = [string]$vmm.ProductVersion; port = $Port }
    page = [pscustomobject]@{ number = $PageNumber; size = $PageSize; totalVirtualMachines = $allVirtualMachines.Count; hasMore = $hasMoreVirtualMachines }
    hostGroups = $hostGroups; clusters = $clusters; hosts = $hosts; virtualMachines = $vmPage; templates = $templates; checkpoints = $checkpoints
    storageArrays = $storageArrays; storagePools = $storagePools; logicalNetworks = $logicalNetworks; vmNetworks = $vmNetworks
} | ConvertTo-Json -Depth 10 -Compress
