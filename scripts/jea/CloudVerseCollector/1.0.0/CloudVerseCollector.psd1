@{
  RootModule = 'CloudVerseCollector.psm1'
  ModuleVersion = '1.0.0'
  GUID = 'e1979fe2-d5ea-4863-bc24-bb6c4dd49bfd'
  Author = 'CloudVerse Pte. Ltd.'
  CompanyName = 'CloudVerse Pte. Ltd.'
  Copyright = 'Copyright CloudVerse Pte. Ltd.'
  FunctionsToExport = @('Get-CloudVerseExecutionBoundary','Invoke-CloudVerseScvmmDiscovery','Invoke-CloudVerseScvmmInventory','Invoke-CloudVerseHypervInventory','Invoke-CloudVerseHypervPerformance')
  CmdletsToExport = @()
  VariablesToExport = @()
  AliasesToExport = @()
  PrivateData = @{ PSData = @{ Tags = @('CloudVerse','JEA','HyperV','SCVMM') } }
}
