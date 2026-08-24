# This operational script is Authenticode-signed during release. Runtime rejects unsigned or changed bytes.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateLength(1, 253)]
    [string] $Server,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 65535)]
    [int] $Port
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$setup = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Microsoft System Center Virtual Machine Manager Server\Setup' -ErrorAction Stop
$modulePath = Join-Path ([string] $setup.InstallPath) 'bin\psModules\virtualmachinemanager\virtualmachinemanager.psd1'
Import-Module -Name $modulePath -ErrorAction Stop
$vmmServer = Get-SCVMMServer -ComputerName $Server -TCPPort $Port -ConnectAs ReadOnlyAdmin -ErrorAction Stop
$idProperty = $vmmServer.PSObject.Properties['ID']
$managementPlaneId = if ($null -ne $idProperty) { [string] $idProperty.Value } else { '' }
if ([string]::IsNullOrWhiteSpace($managementPlaneId)) {
    $managementPlaneId = [string] $setup.VmmID
}
$roles = @(Get-SCUserRole -VMMServer $vmmServer -ErrorAction Stop | Select-Object -Property Name, Profile, Description)
$hostProbe = @(Get-SCVMHost -VMMServer $vmmServer -ErrorAction Stop | Select-Object -First 1 -Property ID, Name, ComputerName, OverallState)

[pscustomobject]@{
    schemaVersion = '1.0'
    capability = 'INVENTORY'
    platform = 'HYPERV'
    managementPlane = [pscustomobject]@{
        id = $managementPlaneId
        name = [string] $vmmServer.Name
        version = [string] $vmmServer.ProductVersion
        port = $Port
    }
    requestedRole = 'ReadOnlyAdmin'
    visibleRoles = $roles
    hostReadProbe = $hostProbe
    mutationAttempted = $false
} | ConvertTo-Json -Depth 8 -Compress
