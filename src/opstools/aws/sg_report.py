"""
Print a report of what is using a security group
"""

import boto3
import botocore
import sys
from opstools.helpers.helper_functions import print_table

def main(security_group_id):
    """ Main function for this module """

    if not security_group_id:
        print("Please pick a security group to report:\n")
        report = get_security_groups()
    else:
        report = get_report(security_group_id)

    print_table(report)

def get_report(security_group_id):
    """ Print a report on what is using [security_group] """

    ec2_client = boto3.client('ec2')

    try:
        full_network_interfaces = ec2_client.describe_network_interfaces(
            Filters=[{'Name': 'group-id','Values': [security_group_id]}]
        )
    except botocore.exceptions.ClientError as e:
        print(e)
        sys.exit(1)

    simplified_listing = []
    for interface in full_network_interfaces['NetworkInterfaces']:
        simplified_listing.append({
            "interface_id": interface['NetworkInterfaceId'],
            "status": interface['Attachment']['Status'],
            "instance_id": interface['Attachment']['InstanceId'],
            "interface_type": interface['InterfaceType'],
            "subnet_id": interface['SubnetId']
        })

    return simplified_listing

def get_security_groups():
    """ Print security groups """

    ec2_client = boto3.client('ec2')

    try:
        full_listing = ec2_client.describe_security_groups()
        simplified_listing = []

        for group in full_listing['SecurityGroups']:
            simplified_listing.append({
                "group_id": group['GroupId'],
                "group_name": group['GroupName'],
                "description": group['Description']
            })
    except Exception as e:
        print(e)
        sys.exit(1)

    return simplified_listing
