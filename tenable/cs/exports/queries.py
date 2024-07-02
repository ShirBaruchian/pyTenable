COMPUTE_VULNS_QUERY = '''
query getComputeVulns($filter:VirtualMachinesFilterInput,
                      $limit:Int,
                      $startAt:String
                      ) {
  VirtualMachines (
    first: $limit
    filter: $filter
    after: $startAt
  ){
    pageInfo {
      hasNextPage
      startCursor
      endCursor
    }
    nodes {
      Id
      AccountId
      CloudProvider
      OperatingSystem
      OperatingSystemType
      Labels
      LastScanTime: ScanTime
            #can we convert this to Now?
      #Tags {
            #	Value
      #  Key
      #}
      Software {
        Name
        Path
        Version
                Type
        Vulnerabilities {
          Id
          AttackVector
          CvssScore
          CvssVersion
          Description
          Exploitable
          FirstScanTime
          Resolvable
          Severity
          SoftwareResolutionVersions
                    #Do we really need this???
          Refs: Sources {
            Name
            Severity
            CvssScore
            CvssVersion
            CvssVector

          }
        }
      }
    }
  }
}
'''
