"""
Nuke an AWS account within some parameters
"""

import boto3
import botocore.exceptions as exceptions
import sys

class Nuke():
    """ Nuke an AWS account within some parameters """

    def __init__(self):
        """ Nuke an AWS account within some parameters """

        self.tag_client = boto3.client('resourcegroupstaggingapi')
        self.config_client = boto3.client('config')

        try:
            self.tag_client.get_tag_keys()
        except exceptions.NoCredentialsError as e:
            print(f"Error making request due to credentials. Are you authed?\n{e}")
            sys.exit(1)


    def get_tagged_resources(self) -> list:
        """
        Return all resources in AWS that currently have a tag, or have ever
        had one
        """

        paginator = self.tag_client.get_paginator('get_resources')
        page_iterator = paginator.paginate(PaginationConfig={'PageSize': 100 })

        resources = []
        for page in page_iterator:
            for item in page['ResourceTagMappingList']:
                resources.append(item)

        return resources


    def filter_resources_by_tags(self, exclude_tags_dict: dict, include_tags_dict: dict) -> dict:
        """
        Return list of resource ARNs filtered by <exclude_tags> and <include_tags>.
        """

        all_resources = self.get_tagged_resources()

        results = {}
        for this_resource in all_resources:
            these_tag_keys = []

            # If no tagging options have been supplied, be safe and return nothing
            if include_tags_dict == {} and exclude_tags_dict == {}:
                continue

            resource_tags = {}
            for this_tag in this_resource['Tags']:
                resource_tags[this_tag['Key']] = this_tag['Value']

            contains_inclusion_tag = has_matching_item(resource_tags, include_tags_dict)
            contains_exclusion_tag = has_matching_item(resource_tags, exclude_tags_dict)

            # If tagged with something in the inclusion list and not tagged with
            # anything in the exclusion list, include the resource in the listing
            if contains_inclusion_tag and not contains_exclusion_tag:
                results[this_resource['ResourceARN']] = resource_tags

            # If not tagged with antyhing in the exclusion list, and inclusion
            # tags have not been set, then include the resource in the listing
            if not contains_exclusion_tag and include_tags_dict == {}:
                results[this_resource['ResourceARN']] = resource_tags

        return results

    def filter_resources(
            self,
            exclude_tags_dict: dict,
            include_tags_dict: dict,
            exclude_services: list,
            include_services: list,
            exclude_arns: list,
            include_arns: list) -> dict:
        """
        Return list of resource ARNs filtered by <exclude_tags>, <include_tags>,
        <exclude_services>, and <include_services>
        """

        resources_by_tags = self.filter_resources_by_tags(exclude_tags_dict, include_tags_dict)
        include_services = [service.upper() for service in include_services]
        exclude_services = [service.upper() for service in exclude_services]

        returned_resources = {}
        # If the ARN is to be explicitly included, add it to the listing
        for arn in include_arns:
            returned_resources[arn] = []

        for resource_arn, tags in resources_by_tags.items():
            resource_type = get_resource_type_from_arn(resource_arn).upper()

            # If an inclusion service is present, and no exclusion services are
            # present, and the ARN is not to be explicitly excluded, include the
            # resource in the listing
            if resource_type in include_services and resource_type not in exclude_services and resource_arn not in exclude_arns:
                returned_resources[resource_arn] = tags

            # If there are no exclusion services present, and inclusion service
            # has not been set, and the ARN is not to be excplicitly excluded,
            # then include the resource in the listing
            if resource_type not in exclude_services and include_services == [] and resource_arn not in exclude_arns:
                returned_resources[resource_arn] = tags

        return returned_resources


    def get_resources_by_services(
            self,
            exclude_services: list,
            include_services: list,
            exclude_arns: list,
            include_arns: list) -> list:
        """
        WIP: Return a list of ARNs for tagged or untagged services
        """

        if include_services == ():
            confirm_all_resources = input("No services given to include, defaulting to all eu-central-1 services which is an expensive operation. Is that okay? Only 'yes' will be accepted for confirmation\n").upper()
            while confirm_all_resources != 'YES' and confirm_all_resources != 'N':
                confirm_all_resources = input("Only 'yes' or 'N' are valid responses \n").upper()
            if confirm_all_resources == 'N':
                print("Aborting")
                sys.exit(0)
            include_services = eu_central_1_services

        resource_list = []
        for resource in include_services:
            response = self.config_client.list_discovered_resources(resourceType=resource)
            resource_list.append(response['resourceIdentifiers'])

        resource_arns = resource_arns_from_resource_identifiers(resource_list)

        return resource_arns


    def prospective_resources(
            self,
            exclude_tags_dict: dict,
            include_tags_dict: dict,
            exclude_services: list,
            include_services: list,
            exclude_arns: list,
            include_arns: list) -> dict:
        """
        Return list of prospective resources to be deleted
        """

        filtered_resources = self.filter_resources(exclude_tags_dict,
                                                   include_tags_dict,
                                                   exclude_services,
                                                   include_services,
                                                   exclude_arns,
                                                   include_arns)

        return filtered_resources

    def nuke(self, resource_arns: list):
        """
        Nuke <resources>
        """

        print(f"Nuking {resource_arns} resources")

        for arn in resource_arns:
            try:
                resource_type = get_resource_type_from_arn(arn).upper()
                if resource_type == 'AWS::LAMBDA::FUNCTION':
                    lambda_client = boto3.client('lambda')
                    lambda_client.delete_function(FunctionName=arn)
                elif resource_type == 'AWS::EC2::INSTANCE':
                    ec2_client = boto3.client('ec2')
                    instance_id = arn.split('/')[-1]
                    ec2_client.terminate_instances(InstanceIds=[instance_id])
                elif resource_type == 'AWS::S3::BUCKET':
                    s3_client = boto3.client('s3')
                    bucket_name = arn.split(':')[-1]
                    s3_client.delete_bucket(Bucket=bucket_name)
                elif resource_type == 'AWS::IAM::ROLE':
                    iam_client = boto3.client('iam')
                    role_name = arn.split('/')[-1]
                    iam_client.delete_role(RoleName=role_name)
                elif resource_type == 'AWS::DYNAMODB::TABLE':
                    dynamodb_client = boto3.client('dynamodb')
                    table_name = arn.split('/')[-1]
                    dynamodb_client.delete_table(TableName=table_name)
                elif resource_type == 'AWS::SQS::QUEUE':
                    sqs_client = boto3.client('sqs')
                    sqs_client.delete_queue(QueueUrl=arn)
                elif resource_type == 'AWS::SNS::TOPIC':
                    sns_client = boto3.client('sns')
                    sns_client.delete_topic(TopicArn=arn)
                elif resource_type == 'AWS::CLOUDFORMATION::STACK':
                    cfn_client = boto3.client('cloudformation')
                    stack_name = arn.split('/')[-1]
                    cfn_client.delete_stack(StackName=stack_name)
                elif resource_type == 'AWS::APIGATEWAY::RESTAPI':
                    apigw_client = boto3.client('apigateway')
                    api_id = arn.split('/')[-1]
                    apigw_client.delete_rest_api(restApiId=api_id)
                elif resource_type == 'AWS::CLOUDWATCH::ALARM':
                    cw_client = boto3.client('cloudwatch')
                    alarm_name = arn.split(':')[-1]
                    cw_client.delete_alarms(AlarmNames=[alarm_name])
                elif resource_type == 'AWS::LOGS::LOGGROUP':
                    logs_client = boto3.client('logs')
                    log_group_name = arn.split(':')[-1]
                    logs_client.delete_log_group(logGroupName=log_group_name)
                elif resource_type == 'AWS::KMS::KEY':
                    kms_client = boto3.client('kms')
                    key_id = arn.split('/')[-1]
                    kms_client.schedule_key_deletion(KeyId=key_id)
                elif resource_type == 'AWS::ECS::CLUSTER':
                    ecs_client = boto3.client('ecs')
                    cluster_name = arn.split('/')[-1]
                    ecs_client.delete_cluster(cluster=cluster_name)
                elif resource_type == 'AWS::ECR::REPOSITORY':
                    ecr_client = boto3.client('ecr')
                    repo_name = arn.split('/')[-1]
                    ecr_client.delete_repository(repositoryName=repo_name, force=True)
                elif resource_type == 'AWS::ELASTICLOADBALANCING::LOADBALANCER':
                    elb_client = boto3.client('elb')
                    lb_name = arn.split('/')[-1]
                    elb_client.delete_load_balancer(LoadBalancerName=lb_name)
                elif resource_type == 'AWS::ELASTICLOADBALANCINGV2::LOADBALANCER':
                    elbv2_client = boto3.client('elbv2')
                    lb_arn = arn
                    elbv2_client.delete_load_balancer(LoadBalancerArn=lb_arn)
                elif resource_type == 'AWS::RDS::DBINSTANCE':
                    rds_client = boto3.client('rds')
                    db_instance_id = arn.split(':')[-1]
                    rds_client.delete_db_instance(DBInstanceIdentifier=db_instance_id, SkipFinalSnapshot=True)
                elif resource_type == 'AWS::REDSHIFT::CLUSTER':
                    redshift_client = boto3.client('redshift')
                    cluster_id = arn.split(':')[-1]
                    redshift_client.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
                elif resource_type == 'AWS::ELASTICACHE::CACHECLUSTER':
                    elasticache_client = boto3.client('elasticache')
                    cache_cluster_id = arn.split(':')[-1]
                    elasticache_client.delete_cache_cluster(CacheClusterId=cache_cluster_id)
                elif resource_type == 'AWS::VPC::VPC':
                    ec2_client = boto3.client('ec2')
                    vpc_id = arn.split('/')[-1]
                    ec2_client.delete_vpc(VpcId=vpc_id)
                elif resource_type == 'AWS::APPSYNC::GRAPHQLAPI':
                    appsync_client = boto3.client('appsync')
                    api_id = arn.split('/')[-1]
                    appsync_client.delete_graphql_api(apiId=api_id)
                elif resource_type == 'AWS::ROUTE53::HOSTEDZONE':
                    route53_client = boto3.client('route53')
                    hosted_zone_id = arn.split('/')[-1]
                    route53_client.delete_hosted_zone(Id=hosted_zone_id)
                elif resource_type == 'AWS::SECRETSMANAGER::SECRET':
                    secretsmanager_client = boto3.client('secretsmanager')
                    secret_id = arn.split(':')[-1]
                    secretsmanager_client.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
                elif resource_type == 'AWS::SQS::QUEUE':
                    sqs_client = boto3.client('sqs')
                    queue_url = sqs_client.get_queue_url(QueueName=arn.split(':')[-1])['QueueUrl']
                    sqs_client.delete_queue(QueueUrl=queue_url)
                elif resource_type == 'AWS::DYNAMODB::TABLE':
                    dynamodb_client = boto3.client('dynamodb')
                    table_name = arn.split('/')[-1]
                    dynamodb_client.delete_table(TableName=table_name)
                else:
                    print(f"Deletion not implemented for resource type: {resource_type}")
                    sys.exit(0)
                print(f"Successfully sent deletion API call for: {arn}")
            except Exception as e:
                print(f"Failed to send deletion API call for resource {arn}: {str(e)}")



### Functions

def resource_arns_from_resource_identifiers(resource_list: list) -> list:
    """
    Generate resource ARNs from a list of resource identifiers
    """

    sts_client = boto3.client('sts')
    resource_names = []
    for this_resource_list in resource_list:
        for this_resource in this_resource_list:
            resource_type = this_resource.get('resourceType')
            resource_id = this_resource.get('resourceId')
            resource_name = this_resource.get('resourceName')
            account_id = sts_client.get_caller_identity()['Account']
            region = sts_client.meta.region_name

            if resource_type == 'AWS::Lambda::Function':
                arn = f"arn:aws:lambda:{region}:{account_id}:function:{resource_name}"
            elif resource_type == 'AWS::EC2::Instance':
                arn = f"arn:aws:ec2:{region}:{account_id}:instance/{resource_id}"
            elif resource_type == 'AWS::S3::Bucket':
                arn = f"arn:aws:s3:::{resource_name}"
            else:
                # Generic ARN format for other resource types
                service = resource_type.split('::')[1].lower()
                arn = f"arn:aws:{service}:{region}:{account_id}:{resource_type.split('::')[-1].lower()}/{resource_name}"

            resource_names.append(arn)

    return resource_names

def get_resource_type_from_arn(arn: str) -> str:
    """ Return the resourceType of a resource by its ARN """
    try:
        arn_parts = arn.split(':')
        service_part = arn_parts[2]
        resource_part = arn_parts[5].split('/')[0] if '/' in arn_parts[5] else arn_parts[5]
        resource_type = f"AWS::{service_part}::{resource_part}"
        return resource_type
    except IndexError:
        raise ValueError(f"Invalid ARN format: {arn}")

def has_matching_item(map_a: dict, map_b: dict) -> bool:
    """
    Return True if map_a has a key-value pair that is present in map_b

    Also returns True if the value for an item in map_b is None (presumes you
    only want to check for the presence of the key in both maps in that case)
    """

    for key, value in map_a.items():
        if key in map_b and (map_b[key] == value or map_b[key] == None):
            return True
    return False

# All AWS services that have resource identifiers
eu_central_1_services = [
    'AWS::Lambda::Function',
    'AWS::EC2::CustomerGateway',
    'AWS::EC2::EIP',
    'AWS::EC2::Host',
    'AWS::EC2::Instance',
    'AWS::EC2::InternetGateway',
    'AWS::EC2::NetworkAcl',
    'AWS::EC2::NetworkInterface',
    'AWS::EC2::RouteTable',
    'AWS::EC2::SecurityGroup',
    'AWS::EC2::Subnet',
    'AWS::CloudTrail::Trail',
    'AWS::EC2::Volume',
    'AWS::EC2::VPC',
    'AWS::EC2::VPNConnection',
    'AWS::EC2::VPNGateway',
    'AWS::EC2::RegisteredHAInstance',
    'AWS::EC2::NatGateway',
    'AWS::EC2::EgressOnlyInternetGateway',
    'AWS::EC2::VPCEndpoint',
    'AWS::EC2::VPCEndpointService',
    'AWS::EC2::FlowLog',
    'AWS::EC2::VPCPeeringConnection',
    'AWS::Elasticsearch::Domain',
    'AWS::IAM::Group',
    'AWS::IAM::Policy',
    'AWS::IAM::Role',
    'AWS::IAM::User',
    'AWS::ElasticLoadBalancingV2::LoadBalancer',
    'AWS::ACM::Certificate',
    'AWS::RDS::DBInstance',
    'AWS::RDS::DBSubnetGroup',
    'AWS::RDS::DBSecurityGroup',
    'AWS::RDS::DBSnapshot',
    'AWS::RDS::DBCluster',
    'AWS::RDS::DBClusterSnapshot',
    'AWS::RDS::EventSubscription',
    'AWS::S3::Bucket',
    'AWS::S3::AccountPublicAccessBlock',
    'AWS::Redshift::Cluster',
    'AWS::Redshift::ClusterSnapshot',
    'AWS::Redshift::ClusterParameterGroup',
    'AWS::Redshift::ClusterSecurityGroup',
    'AWS::Redshift::ClusterSubnetGroup',
    'AWS::Redshift::EventSubscription',
    'AWS::SSM::ManagedInstanceInventory',
    'AWS::CloudWatch::Alarm',
    'AWS::CloudFormation::Stack',
    'AWS::ElasticLoadBalancing::LoadBalancer',
    'AWS::AutoScaling::AutoScalingGroup',
    'AWS::AutoScaling::LaunchConfiguration',
    'AWS::AutoScaling::ScalingPolicy',
    'AWS::AutoScaling::ScheduledAction',
    'AWS::DynamoDB::Table',
    'AWS::CodeBuild::Project',
    'AWS::WAF::RateBasedRule',
    'AWS::WAF::Rule',
    'AWS::WAF::RuleGroup',
    'AWS::WAF::WebACL',
    'AWS::WAFRegional::RateBasedRule',
    'AWS::WAFRegional::Rule',
    'AWS::WAFRegional::RuleGroup',
    'AWS::WAFRegional::WebACL',
    'AWS::CloudFront::Distribution',
    'AWS::CloudFront::StreamingDistribution',
    'AWS::NetworkFirewall::Firewall',
    'AWS::NetworkFirewall::FirewallPolicy',
    'AWS::NetworkFirewall::RuleGroup',
    'AWS::ElasticBeanstalk::Application',
    'AWS::ElasticBeanstalk::ApplicationVersion',
    'AWS::ElasticBeanstalk::Environment',
    'AWS::WAFv2::WebACL',
    'AWS::WAFv2::RuleGroup',
    'AWS::WAFv2::IPSet',
    'AWS::WAFv2::RegexPatternSet',
    'AWS::WAFv2::ManagedRuleSet',
    'AWS::XRay::EncryptionConfig',
    'AWS::SSM::AssociationCompliance',
    'AWS::SSM::PatchCompliance',
    'AWS::Shield::Protection',
    'AWS::ShieldRegional::Protection',
    'AWS::Config::ConformancePackCompliance',
    'AWS::Config::ResourceCompliance',
    'AWS::ApiGateway::Stage',
    'AWS::ApiGateway::RestApi',
    'AWS::ApiGatewayV2::Stage',
    'AWS::ApiGatewayV2::Api',
    'AWS::CodePipeline::Pipeline',
    'AWS::ServiceCatalog::CloudFormationProvisionedProduct',
    'AWS::ServiceCatalog::CloudFormationProduct',
    'AWS::ServiceCatalog::Portfolio',
    'AWS::SQS::Queue',
    'AWS::KMS::Key',
    'AWS::QLDB::Ledger',
    'AWS::SecretsManager::Secret',
    'AWS::SNS::Topic',
    'AWS::SSM::FileData',
    'AWS::Backup::BackupPlan',
    'AWS::Backup::BackupSelection',
    'AWS::Backup::BackupVault',
    'AWS::Backup::RecoveryPoint',
    'AWS::ECR::Repository',
    'AWS::ECS::Cluster',
    'AWS::ECS::Service',
    'AWS::ECS::TaskDefinition',
    'AWS::EFS::AccessPoint',
    'AWS::EFS::FileSystem',
    'AWS::EKS::Cluster',
    'AWS::OpenSearch::Domain',
    'AWS::EC2::TransitGateway',
    'AWS::Kinesis::Stream',
    'AWS::Kinesis::StreamConsumer',
    'AWS::CodeDeploy::Application',
    'AWS::CodeDeploy::DeploymentConfig',
    'AWS::CodeDeploy::DeploymentGroup',
    'AWS::EC2::LaunchTemplate',
    'AWS::ECR::PublicRepository',
    'AWS::GuardDuty::Detector',
    'AWS::EMR::SecurityConfiguration',
    'AWS::SageMaker::CodeRepository',
    'AWS::Route53Resolver::ResolverEndpoint',
    'AWS::Route53Resolver::ResolverRule',
    'AWS::Route53Resolver::ResolverRuleAssociation',
    'AWS::DMS::ReplicationSubnetGroup',
    'AWS::DMS::EventSubscription',
    'AWS::MSK::Cluster',
    'AWS::StepFunctions::Activity',
    'AWS::WorkSpaces::Workspace',
    'AWS::WorkSpaces::ConnectionAlias',
    'AWS::SageMaker::Model',
    'AWS::ElasticLoadBalancingV2::Listener',
    'AWS::StepFunctions::StateMachine',
    'AWS::Batch::JobQueue',
    'AWS::Batch::ComputeEnvironment',
    'AWS::AccessAnalyzer::Analyzer',
    'AWS::Athena::WorkGroup',
    'AWS::Athena::DataCatalog',
    'AWS::Detective::Graph',
    'AWS::GlobalAccelerator::Accelerator',
    'AWS::GlobalAccelerator::EndpointGroup',
    'AWS::GlobalAccelerator::Listener',
    'AWS::EC2::TransitGatewayAttachment',
    'AWS::EC2::TransitGatewayRouteTable',
    'AWS::DMS::Certificate',
    'AWS::AppConfig::Application',
    'AWS::AppSync::GraphQLApi',
    'AWS::DataSync::LocationSMB',
    'AWS::DataSync::LocationFSxLustre',
    'AWS::DataSync::LocationS3',
    'AWS::DataSync::LocationEFS',
    'AWS::DataSync::Task',
    'AWS::DataSync::LocationNFS',
    'AWS::EC2::NetworkInsightsAccessScopeAnalysis',
    'AWS::EKS::FargateProfile',
    'AWS::Glue::Job',
    'AWS::GuardDuty::ThreatIntelSet',
    'AWS::GuardDuty::IPSet',
    'AWS::SageMaker::Workteam',
    'AWS::SageMaker::NotebookInstanceLifecycleConfig',
    'AWS::ServiceDiscovery::Service',
    'AWS::ServiceDiscovery::PublicDnsNamespace',
    'AWS::SES::ContactList',
    'AWS::SES::ConfigurationSet',
    'AWS::Route53::HostedZone',
    'AWS::IoTEvents::Input',
    'AWS::IoTEvents::DetectorModel',
    'AWS::IoTEvents::AlarmModel',
    'AWS::ServiceDiscovery::HttpNamespace',
    'AWS::Events::EventBus',
    'AWS::ImageBuilder::ContainerRecipe',
    'AWS::ImageBuilder::DistributionConfiguration',
    'AWS::ImageBuilder::InfrastructureConfiguration',
    'AWS::DataSync::LocationObjectStorage',
    'AWS::DataSync::LocationHDFS',
    'AWS::Glue::Classifier',
    'AWS::Route53RecoveryReadiness::Cell',
    'AWS::Route53RecoveryReadiness::ReadinessCheck',
    'AWS::ECR::RegistryPolicy',
    'AWS::Backup::ReportPlan',
    'AWS::Lightsail::Certificate',
    'AWS::RUM::AppMonitor',
    'AWS::Events::Endpoint',
    'AWS::SES::ReceiptRuleSet',
    'AWS::Events::Archive',
    'AWS::Events::ApiDestination',
    'AWS::Lightsail::Disk',
    'AWS::FIS::ExperimentTemplate',
    'AWS::DataSync::LocationFSxWindows',
    'AWS::SES::ReceiptFilter',
    'AWS::GuardDuty::Filter',
    'AWS::SES::Template',
    'AWS::AmazonMQ::Broker',
    'AWS::AppConfig::Environment',
    'AWS::AppConfig::ConfigurationProfile',
    'AWS::Cloud9::EnvironmentEC2',
    'AWS::EventSchemas::Registry',
    'AWS::EventSchemas::RegistryPolicy',
    'AWS::EventSchemas::Discoverer',
    'AWS::FraudDetector::Label',
    'AWS::FraudDetector::EntityType',
    'AWS::FraudDetector::Variable',
    'AWS::FraudDetector::Outcome',
    'AWS::IoT::Authorizer',
    'AWS::IoT::SecurityProfile',
    'AWS::IoT::RoleAlias',
    'AWS::IoT::Dimension',
    'AWS::IoTAnalytics::Datastore',
    'AWS::Lightsail::Bucket',
    'AWS::Lightsail::StaticIp',
    'AWS::MediaPackage::PackagingGroup',
    'AWS::Route53RecoveryReadiness::RecoveryGroup',
    'AWS::ResilienceHub::ResiliencyPolicy',
    'AWS::Transfer::Workflow',
    'AWS::EKS::IdentityProviderConfig',
    'AWS::EKS::Addon',
    'AWS::Glue::MLTransform',
    'AWS::IoT::Policy',
    'AWS::IoT::MitigationAction',
    'AWS::IoTTwinMaker::Workspace',
    'AWS::IoTTwinMaker::Entity',
    'AWS::IoTAnalytics::Dataset',
    'AWS::IoTAnalytics::Pipeline',
    'AWS::IoTAnalytics::Channel',
    'AWS::IoTSiteWise::Dashboard',
    'AWS::IoTSiteWise::Project',
    'AWS::IoTSiteWise::Portal',
    'AWS::IoTSiteWise::AssetModel',
    'AWS::IVS::Channel',
    'AWS::IVS::RecordingConfiguration',
    'AWS::IVS::PlaybackKeyPair',
    'AWS::KinesisAnalyticsV2::Application',
    'AWS::RDS::GlobalCluster',
    'AWS::S3::MultiRegionAccessPoint',
    'AWS::DeviceFarm::TestGridProject',
    'AWS::Budgets::BudgetsAction',
    'AWS::Lex::Bot',
    'AWS::CodeGuruReviewer::RepositoryAssociation',
    'AWS::IoT::CustomMetric',
    'AWS::Route53Resolver::FirewallDomainList',
    'AWS::RoboMaker::RobotApplicationVersion',
    'AWS::EC2::TrafficMirrorSession',
    'AWS::IoTSiteWise::Gateway',
    'AWS::Lex::BotAlias',
    'AWS::LookoutMetrics::Alert',
    'AWS::IoT::AccountAuditConfiguration',
    'AWS::EC2::TrafficMirrorTarget',
    'AWS::S3::StorageLens',
    'AWS::IoT::ScheduledAudit',
    'AWS::Events::Connection',
    'AWS::EventSchemas::Schema',
    'AWS::MediaPackage::PackagingConfiguration',
    'AWS::KinesisVideo::SignalingChannel',
    'AWS::AppStream::DirectoryConfig',
    'AWS::LookoutVision::Project',
    'AWS::Route53RecoveryControl::Cluster',
    'AWS::Route53RecoveryControl::SafetyRule',
    'AWS::Route53RecoveryControl::ControlPanel',
    'AWS::Route53RecoveryControl::RoutingControl',
    'AWS::Route53RecoveryReadiness::ResourceSet',
    'AWS::RoboMaker::SimulationApplication',
    'AWS::RoboMaker::RobotApplication',
    'AWS::HealthLake::FHIRDatastore',
    'AWS::Pinpoint::Segment',
    'AWS::Pinpoint::ApplicationSettings',
    'AWS::Events::Rule',
    'AWS::EC2::DHCPOptions',
    'AWS::EC2::NetworkInsightsPath',
    'AWS::EC2::TrafficMirrorFilter',
    'AWS::EC2::IPAM',
    'AWS::IoTTwinMaker::Scene',
    'AWS::NetworkManager::TransitGatewayRegistration',
    'AWS::CustomerProfiles::Domain',
    'AWS::AutoScaling::WarmPool',
    'AWS::Connect::PhoneNumber',
    'AWS::AppConfig::DeploymentStrategy',
    'AWS::AppFlow::Flow',
    'AWS::AuditManager::Assessment',
    'AWS::CloudWatch::MetricStream',
    'AWS::DeviceFarm::InstanceProfile',
    'AWS::DeviceFarm::Project',
    'AWS::EC2::EC2Fleet',
    'AWS::EC2::SubnetRouteTableAssociation',
    'AWS::ECR::PullThroughCacheRule',
    'AWS::GroundStation::Config',
    'AWS::ImageBuilder::ImagePipeline',
    'AWS::IoT::FleetMetric',
    'AWS::IoTWireless::ServiceProfile',
    'AWS::NetworkManager::Device',
    'AWS::NetworkManager::GlobalNetwork',
    'AWS::NetworkManager::Link',
    'AWS::NetworkManager::Site',
    'AWS::Panorama::Package',
    'AWS::Pinpoint::App',
    'AWS::Redshift::ScheduledAction',
    'AWS::Route53Resolver::FirewallRuleGroupAssociation',
    'AWS::SageMaker::AppImageConfig',
    'AWS::SageMaker::Image',
    'AWS::ECS::TaskSet',
    'AWS::Cassandra::Keyspace',
    'AWS::Signer::SigningProfile',
    'AWS::Amplify::App',
    'AWS::AppMesh::VirtualNode',
    'AWS::AppMesh::VirtualService',
    'AWS::AppRunner::VpcConnector',
    'AWS::AppStream::Application',
    'AWS::CodeArtifact::Repository',
    'AWS::EC2::PrefixList',
    'AWS::EC2::SpotFleet',
    'AWS::Evidently::Project',
    'AWS::Forecast::Dataset',
    'AWS::IAM::SAMLProvider',
    'AWS::IAM::ServerCertificate',
    'AWS::Pinpoint::Campaign',
    'AWS::Pinpoint::InAppTemplate',
    'AWS::SageMaker::Domain',
    'AWS::Transfer::Agreement',
    'AWS::Transfer::Connector',
    'AWS::KinesisFirehose::DeliveryStream',
    'AWS::Amplify::Branch',
    'AWS::AppIntegrations::EventIntegration',
    'AWS::AppMesh::Route',
    'AWS::Athena::PreparedStatement',
    'AWS::EC2::IPAMScope',
    'AWS::Evidently::Launch',
    'AWS::Forecast::DatasetGroup',
    'AWS::GreengrassV2::ComponentVersion',
    'AWS::GroundStation::MissionProfile',
    'AWS::MediaConnect::FlowEntitlement',
    'AWS::MediaConnect::FlowVpcInterface',
    'AWS::MediaTailor::PlaybackConfiguration',
    'AWS::MSK::Configuration',
    'AWS::Personalize::Dataset',
    'AWS::Personalize::Schema',
    'AWS::Personalize::Solution',
    'AWS::Pinpoint::EmailTemplate',
    'AWS::Pinpoint::EventStream',
    'AWS::ResilienceHub::App',
    'AWS::ACMPCA::CertificateAuthority',
    'AWS::AppConfig::HostedConfigurationVersion',
    'AWS::AppMesh::VirtualGateway',
    'AWS::AppMesh::VirtualRouter',
    'AWS::AppRunner::Service',
    'AWS::CustomerProfiles::ObjectType',
    'AWS::DMS::Endpoint',
    'AWS::EC2::CapacityReservation',
    'AWS::EC2::ClientVpnEndpoint',
    'AWS::Kendra::Index',
    'AWS::KinesisVideo::Stream',
    'AWS::Logs::Destination',
    'AWS::Pinpoint::EmailChannel',
    'AWS::S3::AccessPoint',
    'AWS::NetworkManager::CustomerGatewayAssociation',
    'AWS::NetworkManager::LinkAssociation',
    'AWS::IoTWireless::MulticastGroup',
    'AWS::Personalize::DatasetGroup',
    'AWS::IoTTwinMaker::ComponentType',
    'AWS::CodeBuild::ReportGroup',
    'AWS::SageMaker::FeatureGroup',
    'AWS::MSK::BatchScramSecret',
    'AWS::AppStream::Stack',
    'AWS::IoT::JobTemplate',
    'AWS::IoTWireless::FuotaTask',
    'AWS::IoT::ProvisioningTemplate',
    'AWS::InspectorV2::Filter',
    'AWS::Route53Resolver::ResolverQueryLoggingConfigAssociation',
    'AWS::ServiceDiscovery::Instance',
    'AWS::Transfer::Certificate',
    'AWS::MediaConnect::FlowSource',
    'AWS::APS::RuleGroupsNamespace',
    'AWS::CodeGuruProfiler::ProfilingGroup',
    'AWS::Route53Resolver::ResolverQueryLoggingConfig',
    'AWS::Batch::SchedulingPolicy',
    'AWS::ACMPCA::CertificateAuthorityActivation',
    'AWS::AppMesh::GatewayRoute',
    'AWS::AppMesh::Mesh',
    'AWS::Connect::Instance',
    'AWS::Connect::QuickConnect',
    'AWS::EC2::CarrierGateway',
    'AWS::EC2::IPAMPool',
    'AWS::EC2::TransitGatewayConnect',
    'AWS::EC2::TransitGatewayMulticastDomain',
    'AWS::ECS::CapacityProvider',
    'AWS::IAM::InstanceProfile',
    'AWS::IoT::CACertificate',
    'AWS::IoTTwinMaker::SyncJob',
    'AWS::KafkaConnect::Connector',
    'AWS::Lambda::CodeSigningConfig',
    'AWS::NetworkManager::ConnectPeer',
    'AWS::ResourceExplorer2::Index',
    'AWS::AppStream::Fleet',
    'AWS::Cognito::UserPool',
    'AWS::Cognito::UserPoolClient',
    'AWS::Cognito::UserPoolGroup',
    'AWS::EC2::NetworkInsightsAccessScope',
    'AWS::EC2::NetworkInsightsAnalysis',
    'AWS::Grafana::Workspace',
    'AWS::GroundStation::DataflowEndpointGroup',
    'AWS::ImageBuilder::ImageRecipe',
    'AWS::KMS::Alias',
    'AWS::M2::Environment',
    'AWS::QuickSight::DataSource',
    'AWS::QuickSight::Template',
    'AWS::QuickSight::Theme',
    'AWS::RDS::OptionGroup',
    'AWS::Redshift::EndpointAccess',
    'AWS::Route53Resolver::FirewallRuleGroup',
    'AWS::SSM::Document'
]
