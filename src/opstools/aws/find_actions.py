import boto3
import json
from datetime import datetime, timedelta

def extract_resource_info(event):
    """Extract meaningful resource information from CloudTrail event"""
    try:
        # Parse the CloudTrail event JSON
        ct_event = json.loads(event['CloudTrailEvent'])

        resources = []

        # Try to get resource info from responseElements first (for CREATE events)
        response_elements = ct_event.get('responseElements') or {}
        request_parameters = ct_event.get('requestParameters') or {}
        event_name = event['EventName']

        # Handle different event types
        if event_name == 'CreateApiKey':
            if 'id' in response_elements:
                resources.append({
                    'type': 'API Gateway API Key',
                    'id': response_elements['id'],
                    'name': response_elements.get('name', 'Unknown'),
                    'arn': f"arn:aws:apigateway:{ct_event.get('awsRegion', 'unknown')}::/apikeys/{response_elements['id']}"
                })

        elif event_name == 'RunInstances':
            instances = response_elements.get('instancesSet', {}).get('items', [])
            for instance in instances:
                resources.append({
                    'type': 'EC2 Instance',
                    'id': instance.get('instanceId', 'Unknown'),
                    'name': instance.get('instanceId', 'Unknown'),
                    'arn': f"arn:aws:ec2:{ct_event.get('awsRegion', 'unknown')}::instance/{instance.get('instanceId', 'unknown')}"
                })

        elif event_name == 'CreateBucket':
            bucket_name = request_parameters.get('bucketName') or response_elements.get('bucketName')
            if bucket_name:
                resources.append({
                    'type': 'S3 Bucket',
                    'id': bucket_name,
                    'name': bucket_name,
                    'arn': f"arn:aws:s3:::{bucket_name}"
                })

        elif event_name == 'CreateFunction':
            function_name = response_elements.get('functionName') or request_parameters.get('functionName')
            if function_name:
                resources.append({
                    'type': 'Lambda Function',
                    'id': function_name,
                    'name': function_name,
                    'arn': response_elements.get('functionArn', f"arn:aws:lambda:{ct_event.get('awsRegion', 'unknown')}::function:{function_name}")
                })

        elif event_name == 'CreateTable':
            table_name = request_parameters.get('tableName') or response_elements.get('tableDescription', {}).get('tableName')
            if table_name:
                resources.append({
                    'type': 'DynamoDB Table',
                    'id': table_name,
                    'name': table_name,
                    'arn': f"arn:aws:dynamodb:{ct_event.get('awsRegion', 'unknown')}::table/{table_name}"
                })

        elif event_name == 'CreateRole':
            role_name = request_parameters.get('roleName') or response_elements.get('role', {}).get('roleName')
            if role_name:
                resources.append({
                    'type': 'IAM Role',
                    'id': role_name,
                    'name': role_name,
                    'arn': response_elements.get('role', {}).get('arn', f"arn:aws:iam::{ct_event.get('recipientAccountId', 'unknown')}:role/{role_name}")
                })

        # Generic fallback - try to find common patterns
        if not resources and response_elements:
            # Look for common ID patterns in responseElements
            for key, value in response_elements.items():
                if any(id_key in key.lower() for id_key in ['id', 'arn', 'name']) and isinstance(value, str):
                    resources.append({
                        'type': f"Unknown ({event_name})",
                        'id': value,
                        'name': value,
                        'arn': value if value.startswith('arn:') else 'Unknown'
                    })
                    break

        # Fallback to original Resources field if we didn't extract anything
        if not resources and event.get('Resources'):
            for resource in event['Resources']:
                resources.append({
                    'type': resource.get('ResourceType', 'Unknown'),
                    'id': resource.get('ResourceName', 'Unknown'),
                    'name': resource.get('ResourceName', 'Unknown'),
                    'arn': resource.get('ResourceName', 'Unknown')
                })

        return resources

    except (json.JSONDecodeError, KeyError, TypeError) as e:
        print(f"Warning: Could not parse CloudTrail event: {e}")
        # Fallback to original Resources field
        return [{
            'type': resource.get('ResourceType', 'Unknown'),
            'id': resource.get('ResourceName', 'Unknown'),
            'name': resource.get('ResourceName', 'Unknown'),
            'arn': resource.get('ResourceName', 'Unknown')
        } for resource in event.get('Resources', [])]


def get_resources_created_by_user(username, days_back, event_types):
    cloudtrail = boto3.client('cloudtrail')
    start_time = datetime.now() - timedelta(days=days_back)

    if username != None:
        LookupAttributes = [
            {
                'AttributeKey': 'Username',
                'AttributeValue': username
            }
        ]
    else:
        LookupAttributes = []

    paginator = cloudtrail.get_paginator('lookup_events')
    page_iterator = paginator.paginate(
        LookupAttributes=LookupAttributes,
        StartTime=start_time,
        EndTime=datetime.now(),
        PaginationConfig={
            'PageSize': 50,
            'MaxItems': 1000
        }
    )

    creation_events = []
    for page in page_iterator:
        for event in page['Events']:
            event_name = event['EventName']

            if any(event_name.startswith(action) for action in event_types):
                resources = extract_resource_info(event)

                creation_events.append({
                    'EventName': event_name,
                    'EventTime': event['EventTime'],
                    'Username': event['Username'],
                    'Resources': resources,
                    'EventSource': event.get('EventSource', 'Unknown'),
                    'EventId': event.get('EventId', 'Unknown')
                })

    return creation_events
