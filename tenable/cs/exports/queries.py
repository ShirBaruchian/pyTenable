GET_FIELDS_FOR_OBJECT_TYPE_QUERY = '''
query getFieldsforObjectType($object_type: String!) {
  __type(name: $object_type) {
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
query getComputeAssets($limit: Int, $startAt: String, $filter: EntitiesFilterInput) {
  Entities(first: $limit, after: $startAt, filter: $filter) {
    pageInfo {
      startCursor
      hasNextPage
      endCursor
    }
    nodes {
      ... on AwsEc2Instance {
        CloudProvider
        Id
        AccountId
        CustomFields
        Labels
        Tags {
          Key
          Value
        }
        LastUpdatedAt: SyncTime
        Arn
        CreatedAt: CreationTime
        CreatorIdentity {
          Id
          AccountId
          Name
        }
        CreatorOriginator {
          Id
          AccountId
          Name
        }
        Region
        Stack {
          Name
          Id
          AccountId
        }
        SecurityGroups {
          Id
          AccountId
          Name
          Arn
          Region
          Stack {
            Id
            Name
            AccountId
          }
        }
        Subnets {
          Id
          Name
          AccountId
          Arn
          Region
          Stack {
            Id
            Name
            AccountId
          }
        }
        Vpcs {
          Id
          AccountId
          Name
          Arn
          Region
          Stack {
            Id
            AccountId
            Name
          }
        }
        OperatingSystem
        OperatingSystemType
        ScanStatus
        ScanStatusDescription
        LastScannedAt: ScanTime
        Architecture
        CpuCores
        InstanceType
        Image {
          Id
          AccountId
          Name
          Arn
        }
        Isolated
        LaunchTime
        NetworkInterface {
          Id
          AccountId
          Arn
          Name
          Region
          SecurityGroups {
            Id
            Name
            AccountId
            Arn
          }
          Subnets {
            Id
            Name
            AccountId
            Arn
            Region
          }
          Vpcs {
            Id
            Name
            AccountId
            Arn
            Region
          }
          PrivateIpAddresses
          PublicIpAddresses
        }
        Platform
        PrivateDnsNames
        ProductCode {
          Id
          Type
        }
        PublicIpAddressDnsNames
        Role {
          Id
          Name
          Arn
          AccountId
          Region
          AccessLevel
        }
        RootVolume {
          Id
          Name
          AccountId
          Arn
          EncryptionKeys {
            Id
            Name
            AccountId
          }
          DeleteOnTermination
          ProductCode {
            Id
            Type
          }
          RootDevice
          Size
          VolumeType
        }
        State
      }
      ... on AzureDbForMariaDbServer {
        Id
        Name
      }
    }
  }
}
'''

CONTAINER_ASSETS_QUERY = '''
query getContainerAssets($limit: Int, $startAt: String, $filter: EntitiesFilterInput) {
  Entities(first: $limit, after: $startAt, filter: $filter) {
    pageInfo {
      startCursor
      hasNextPage
      endCursor
    }
    nodes {
      ... on AwsContainerImage {
        LastScanTime: ScanTime
        Id
        AccountId
        CloudProvider
        Region
        Arn
        CreatedAt: CreationTime
        CreatorIdentity {
          Name
          Id
          AccountId
        }
        CreatorOriginator {
          Name
          Id
          AccountId
        }
        Stack {
          Name
          AccountId
          Id
        }
        CustomFields
        Labels
        Tags {
          Key
          Value
        }
        Name
        LastUpdatedAt: SyncTime
        Clusters {
          Name
          AccountId
          Id
          CloudProvider
        }
        Digest
        KubernetesWorkloads {
          CloudProvider
          Name
          AccountId
          Id
        }
        OperatingSystem
        OperatingSystemType
        Repository {
          CloudProvider
          Name
          AccountId
          Id
        }
        RepositoryUri
        Used
      }
      ... on CiContainerImage {
        LastScanTime: ScanTime
        Id
        AccountId
        CloudProvider
        CustomFields
        Labels
        Tags {
          Key
          Value
        }
        Name
        Clusters {
          Name
          AccountId
          Id
          CloudProvider
        }
        Digest
        KubernetesWorkloads {
          CloudProvider
          Name
          AccountId
          Id
        }
        OperatingSystem
        OperatingSystemType
        Repository {
          CloudProvider
          Name
          AccountId
          Id
        }
        RepositoryUri
        LastUpdatedAt: SyncTime
        Used
      }
      ... on AzureContainerImage {
        LastScanTime: ScanTime
        Id
        AccountId
        CloudProvider
        CreationTime
        CreatorIdentity {
          Name
          AccountId
          Id
        }
        Location
        CustomFields
        Labels
        Tags {
          Key
          Value
        }
        Name
        CreatedAt: CreationTime
        Clusters {
          Name
          AccountId
          Id
          CloudProvider
        }
        Digest
        KubernetesWorkloads {
          CloudProvider
          Name
          AccountId
          Id
        }
        OperatingSystem
        OperatingSystemType
        Repository {
          CloudProvider
          Name
          AccountId
          Id
        }
        RepositoryUri
        LastUpdatedAt: SyncTime
        Used
      }
      ... on GcpContainerImage {
        LastScanTime: ScanTime
        Id
        AccountId
        CloudProvider
        CreatedAt: CreationTime
        CreatorIdentity {
          Id
          AccountId
          Name
        }
        CreatorOriginator {
          Id
          Name
          AccountId
        }
        Location
        CustomFields
        Labels
        Tags {
          Key
          Value
        }
        Name
        Clusters {
          Name
          AccountId
          Id
          CloudProvider
        }
        Digest
        KubernetesWorkloads {
          CloudProvider
          Name
          AccountId
          Id
        }
        OperatingSystem
        OperatingSystemType
        Repository {
          CloudProvider
          Name
          AccountId
          Id
        }
        RepositoryUri
        LastUpdatedAt: SyncTime
        Used
      }
      ... on OpContainerImage {
        LastScanTime: ScanTime
        Id
        AccountId
        CloudProvider
        CustomFields
        Labels
        Tags {
          Key
          Value
        }
        Name
        Clusters {
          Name
          AccountId
          Id
          CloudProvider
        }
        Digest
        KubernetesWorkloads {
          CloudProvider
          Name
          AccountId
          Id
        }
        OperatingSystem
        OperatingSystemType
        Repository {
          CloudProvider
          Name
          AccountId
          Id
        }
        RepositoryUri
        LastUpdatedAt: SyncTime
        Used
      }
    }
  }
}
'''