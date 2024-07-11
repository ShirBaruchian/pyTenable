GET_ALL_ENTITY_TYPES = '''
{
  __type(name:"EntityType"){
    enumValues{
      name
    }
  }
}
'''
GET_FIELDS_FOR_ENTITY_QUERY = '''
query getFieldsforEntity($name: String!) {
  __type(name: $name) {
    fields {
      name
    }
  }
}
'''


COMPUTE_VULNS_QUERY = '''
query getComputeVulns($filter: VirtualMachinesFilterInput, $limit: Int, $startAt: String) {
  VirtualMachines(first: $limit, filter: $filter, after: $startAt) {
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
      LastScanTime: ScanTime
      #CustomFields
      #Labels
      #Tags {
      #  Value
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
CONTAINER_VULNS_QUERY = '''
query getContainerVulns($filter:ContainerImagesFilterInput,
                      $limit:Int,
                      $startAt:String
                      ) {
  ContainerImages (
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
      SyncTime
      Name
      CloudProvider
      LastScanTime: ScanTime
      Used
      RepositoryUri
      Repository {
        CloudProvider
        Name
        AccountId
        Id
      }
      OperatingSystem
      OperatingSystemType
      # Do we really need this?
      #KubernetesWorkloads {
      #  CloudProvider
      #  CustomFields
      #}
      Digest
      Software{
        Name
        Type
        Path
        Version
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
          Refs: Sources{
            CvssScore
            CvssVersion
            CvssVector
            Name
            Severity
          }
        }
      }
      #Tags {
      #  Key
      #  Value
      #}
      #Labels
      #CustomFields
    }
  }
}
'''
COMPUTE_ASSETS_QUERY = '''
query getComputeAssets($limit: Int, $startAt: String){
      Entities(first: $limit, after: $startAt, filter: {
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
AccountId
Region
Arn
Name
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
  #NetworkInterface
  Platform
  PrivateDnsNames
  PrivateIpAddresses
  #ProductCode
  PublicIpAddressDnsNames
  PublicIpAddresses
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
  PublicIpAddresses
}

'''

CONTAINER_ASSETS_QUERY = '''
query getContainerAssets($limit: Int, $startAt: String){
        Entities(first: $limit, after: $startAt, filter: {
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