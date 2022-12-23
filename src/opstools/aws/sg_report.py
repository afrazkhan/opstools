"""
Print a report of what is using a security group
"""

import boto3
import botocore
import sys

def main(security_group_id):
    """ TODO """

    ec2_client = boto3.client('ec2')
    listing = []

    try:
        full_network_interfaces = ec2_client.describe_network_interfaces(
            Filters=[
                {
                    'Name': 'group-id','Values': [security_group_id]
                }
            ]
        )
    except botocore.exceptions.ClientError as e:
        print(e)
        sys.exit(1)

    for interface in full_network_interfaces['NetworkInterfaces']:
        listing.append( {
            "interface": interface['NetworkInterfaceId'],
            "attachment_status": interface['Attachment']['Status'],
            "instance_id": interface['Attachment']['InstanceId'],
            "interface_type": interface['InterfaceType'],
            "subnet": interface['SubnetId'],
        })

    return listing
