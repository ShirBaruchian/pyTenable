
COMPUTE_VULNS_QUERY = '''
# @prettier
# Genereated On: 2024-07-23T19:50:56.722008+00:00
query getVirtualMachinesVulns(
  $limit: Int
  $startAt: String
  $filter: VirtualMachinesFilterInput
) {
  VirtualMachines(first: $limit, after: $startAt, filter: $filter) {
    pageInfo {
      endCursor
    }
    nodes {
      OperatingSystem
      OperatingSystemType
      FixedVulnerabilities: ResolvedSoftware {
        Name
        Type
        Paths
        Vulnerabilities {
          Id
        }
      }
      ScanStatus
      ScanStatusDescription
      LastScannedAt: ScanTime
      VulnerabilityResolutionPatches
      CloudProvider
      CustomFields
      Labels
      Name
      LastUpdatedAt: SyncTime
      Tags {
        Key
        Value
      }
      AccountId
      Id
      Software {
        Name
        Type
        Paths
        Version
        Vulnerabilities {
          AttackVector
          CvssScore
          CvssVersion
          Description
          Exploitable
          ExploitMaturity
          FirstScanTime
          Id
          Resolvable
          Severity
          SoftwareResolutionVersions
          VprScore
          VprSeverity
          Sources {
            CvssScore
            CvssVersion
            CvssVector
            Name
            Severity
          }
        }
      }
    }
  }
}
'''
CONTAINER_VULNS_QUERY = '''
# @prettier
# Genereated On: 2024-07-23T19:50:58.186059+00:00
query getContainerImagesVulns(
  $limit: Int
  $startAt: String
  $filter: ContainerImagesFilterInput
) {
  ContainerImages(first: $limit, after: $startAt, filter: $filter) {
    pageInfo {
      endCursor
    }
    nodes {
      Clusters {
        Name
        Id
        AccountId
      }
      Digest
      KubernetesWorkloads {
        Name
        Id
        AccountId
      }
      OperatingSystem
      OperatingSystemType
      Repository {
        Name
        Id
        AccountId
      }
      RepositoryUri
      LastScannedAt: ScanTime
      Used
      VirtualMachines {
        Name
        Id
        AccountId
      }
      CloudProvider
      CustomFields
      Labels
      Name
      LastUpdatedAt: SyncTime
      Tags {
        Key
        Value
      }
      AccountId
      Id
      Software {
        Name
        Type
        Paths
        Version
        Vulnerabilities {
          AttackVector
          CvssScore
          CvssVersion
          Description
          Exploitable
          ExploitMaturity
          FirstScanTime
          Id
          Resolvable
          Severity
          SoftwareResolutionVersions
          VprScore
          VprSeverity
          Sources {
            CvssScore
            CvssVersion
            CvssVector
            Name
            Severity
          }
        }
      }
    }
  }
}
'''

CONTAINER_ASSETS_QUERY = '''
# @prettier
# Genereated On: 2024-07-23T19:50:59.612140+00:00
query getContainerAssets($limit: Int, $startAt: String) {
  Entities(
    first: $limit
    after: $startAt
    filter: {
      Types: [
        AwsContainerImage
        AzureContainerImage
        CiContainerImage
        GcpContainerImage
        OpContainerImage
      ]
    }
  ) {
    pageInfo {
      endCursor
    }
    nodes {
      ...AwsContainerImageSegment
      ...AzureContainerImageSegment
      ...CiContainerImageSegment
      ...GcpContainerImageSegment
      ...OpContainerImageSegment
    }
  }
}

fragment AwsContainerImageSegment on AwsContainerImage {
  Id
  AccountId
  CloudProvider
  CustomFields
  Labels
  Name
  LastUpdatedAt: SyncTime
  Tags {
    Key
    Value
  }
  Arn
  CreatedAt: CreationTime
  CreatorIdentity {
    Id
    Name
    AccountId
  }
  CreatorOriginator {
    Id
    Name
    AccountId
  }
  Region
  #Stack
  Clusters {
    Name
    AccountId
    Id
  }
  Digest
  KubernetesWorkloads {
    Name
    AccountId
    Id
  }
  OperatingSystem
  OperatingSystemType
  Repository {
    Name
    AccountId
    Id
  }
  RepositoryUri
  ScanTime
  #Software
  Used
  VirtualMachines {
    Name
    AccountId
    Id
  }
  #Vulnerabilities
}

fragment AzureContainerImageSegment on AzureContainerImage {
  Id
  AccountId
  CloudProvider
  CustomFields
  Labels
  Name
  LastUpdatedAt: SyncTime
  Tags {
    Key
    Value
  }
  CreatedAt: CreationTime
  CreatorIdentity {
    Id
    Name
    AccountId
  }
  Location
  Clusters {
    Name
    AccountId
    Id
  }
  Digest
  KubernetesWorkloads {
    Name
    AccountId
    Id
  }
  OperatingSystem
  OperatingSystemType
  Repository {
    Name
    AccountId
    Id
  }
  RepositoryUri
  ScanTime
  #Software
  Used
  VirtualMachines {
    Name
    AccountId
    Id
  }
  #Vulnerabilities
}

fragment CiContainerImageSegment on CiContainerImage {
  Id
  AccountId
  CloudProvider
  CustomFields
  Labels
  Name
  LastUpdatedAt: SyncTime
  Tags {
    Key
    Value
  }
  Clusters {
    Name
    AccountId
    Id
  }
  Digest
  KubernetesWorkloads {
    Name
    AccountId
    Id
  }
  OperatingSystem
  OperatingSystemType
  Repository {
    Name
    AccountId
    Id
  }
  RepositoryUri
  ScanTime
  #Software
  Used
  VirtualMachines {
    Name
    AccountId
    Id
  }
  #Vulnerabilities
}

fragment GcpContainerImageSegment on GcpContainerImage {
  Id
  AccountId
  CloudProvider
  CustomFields
  Labels
  Name
  LastUpdatedAt: SyncTime
  Tags {
    Key
    Value
  }
  CreatedAt: CreationTime
  CreatorIdentity {
    Id
    Name
    AccountId
  }
  CreatorOriginator {
    Id
    Name
    AccountId
  }
  Location
  Clusters {
    Name
    AccountId
    Id
  }
  Digest
  KubernetesWorkloads {
    Name
    AccountId
    Id
  }
  OperatingSystem
  OperatingSystemType
  Repository {
    Name
    AccountId
    Id
  }
  RepositoryUri
  ScanTime
  #Software
  Used
  VirtualMachines {
    Name
    AccountId
    Id
  }
  #Vulnerabilities
}

fragment OpContainerImageSegment on OpContainerImage {
  Id
  AccountId
  CloudProvider
  CustomFields
  Labels
  Name
  LastUpdatedAt: SyncTime
  Tags {
    Key
    Value
  }
  Clusters {
    Name
    AccountId
    Id
  }
  Digest
  KubernetesWorkloads {
    Name
    AccountId
    Id
  }
  OperatingSystem
  OperatingSystemType
  Repository {
    Name
    AccountId
    Id
  }
  RepositoryUri
  ScanTime
  #Software
  Used
  VirtualMachines {
    Name
    AccountId
    Id
  }
  #Vulnerabilities
}
'''

COMPUTE_ASSETS_QUERY = '''
# @prettier
# Genereated On: 2024-07-23T19:50:58.464291+00:00
query getComputeAssets($limit: Int, $startAt: String) {
  Entities(
    first: $limit
    after: $startAt
    filter: {
      Types: [
        AwsEc2Instance
        AzureComputeVirtualMachine
        AzureComputeVirtualMachineScaleSetVirtualMachine
        GcpComputeInstance
      ]
    }
  ) {
    pageInfo {
      endCursor
    }
    nodes {
      ...AwsEc2InstanceSegment
      ...AzureComputeVirtualMachineSegment
      ...AzureComputeVirtualMachineScaleSetVirtualMachineSegment
      ...GcpComputeInstanceSegment
    }
  }
}

fragment AwsEc2InstanceSegment on AwsEc2Instance {
  Id
  AccountId
  CloudProvider
  CustomFields
  Labels
  Name
  LastUpdatedAt: SyncTime
  Tags {
    Key
    Value
  }
  Arn
  CreatedAt: CreationTime
  CreatorIdentity {
    Id
    Name
    AccountId
  }
  CreatorOriginator {
    Id
    Name
    AccountId
  }
  Region
  #Stack
  #SecurityGroups
  Subnets {
    Id
    Name
    AccountId
    Arn
    Region
  }
  Vpcs {
    Id
    AccountId
    Region
    Arn
    Name
  }
  #NetworkAccess
  OperatingSystem
  OperatingSystemType
  #ResolvedSoftware
  ScanStatus
  ScanStatusDescription
  ScanTime
  #Software
  #Vulnerabilities
  #VulnerabilityResolutionPatches
  AutoScalingGroup {
    Id
    Name
    Region
    Arn
    AccountId
  }
  Architecture
  CpuCores
  InstanceType
  Image {
    Id
    AccountId
    Name
    Arn
    Region
    AwsManaged
  }
  Isolated
  #LaunchConfiguration
  #LaunchTemplate
  LaunchTime
  MetadataServiceAccessible
  MetadataServiceVersion
  MetadataServiceV1UsageTime
  NetworkInterfaces {
    Id
    AccountId
    Name
    Arn
    Region
    PrivateIpAddresses
    MacAddress
  }
  Platform
  PrivateDnsNames
  PrivateIpAddresses
  #ProductCode
  PublicIpAddressDnsNames
  #PublicIpAddresses
  #Role
  RootVolume {
    Id
    AccountId
    Name
    Arn
    Region
    DeleteOnTermination
    RootDevice
    Size
    VolumeType
  }
  State
}

fragment AzureComputeVirtualMachineSegment on AzureComputeVirtualMachine {
  Id
  AccountId
  CloudProvider
  CustomFields
  Labels
  Name
  LastUpdatedAt: SyncTime
  Tags {
    Key
    Value
  }
  CreatedAt: CreationTime
  CreatorIdentity {
    Id
    Name
    AccountId
  }
  Location
  #RoleAssignments
  ResourceGroupId
  OperatingSystem
  OperatingSystemType
  #ResolvedSoftware
  ScanStatus
  ScanStatusDescription
  ScanTime
  #Software
  #Vulnerabilities
  #VulnerabilityResolutionPatches
  PrivateIpAddresses
  PublicIpAddressResources {
    Id
    AccountId
    Name
    IpAddress
  }
}

fragment AzureComputeVirtualMachineScaleSetVirtualMachineSegment on AzureComputeVirtualMachineScaleSetVirtualMachine {
  Id
  AccountId
  CloudProvider
  CustomFields
  Labels
  Name
  LastUpdatedAt: SyncTime
  Tags {
    Key
    Value
  }
  CreatedAt: CreationTime
  CreatorIdentity {
    Id
    Name
    AccountId
  }
  Location
  #RoleAssignments
  ResourceGroupId
  OperatingSystem
  OperatingSystemType
  #ResolvedSoftware
  ScanStatus
  ScanStatusDescription
  ScanTime
  #Software
  #Vulnerabilities
  #VulnerabilityResolutionPatches
  PrivateIpAddresses
  #PublicIpAddresses
  PublicIpAddressResources {
    Id
    AccountId
    Name
    IpAddress
  }
}

fragment GcpComputeInstanceSegment on GcpComputeInstance {
  Id
  AccountId
  CloudProvider
  CustomFields
  Labels
  Name
  LastUpdatedAt: SyncTime
  Tags {
    Key
    Value
  }
  CreatedAt: CreationTime
  CreatorIdentity {
    Id
    Name
    AccountId
  }
  CreatorOriginator {
    Id
    Name
    AccountId
  }
  Location
  AccessLevel
  #RoleBindings
  #NetworkAccess
  OperatingSystem
  OperatingSystemType
  #ResolvedSoftware
  ScanStatus
  ScanStatusDescription
  ScanTime
  #Software
  #Vulnerabilities
  #VulnerabilityResolutionPatches
  PrivateIpAddresses
  #PublicIpAddresses
}
'''