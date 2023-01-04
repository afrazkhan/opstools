"""
Print a report of what is using a security group
"""

import boto3
import botocore
import sys
from opstools.helpers.helper_functions import print_table

def main(security_group_id, all_sgs):
    """ Main function for this module """

    # When user wants a report for all security groups, or when they don't
    # specify one, then fetch a listing first
    if all_sgs or security_group_id is None:
        security_groups = get_security_groups()
    # Otherewise, put the specified group in a list
    else:
        security_groups = [{"group_id": security_group_id}]

    # User doesn't want a report for all security groups, or a single one
    if not all_sgs and not security_group_id:
        print("Please pick a security group to report:\n")
        print_table(security_groups)
    # Print reports for groups in 'security_groups'
    else:
        consolidated_report = []
        print("Report for all security groups. Missing values means it's not in use\n")
        for this_group in security_groups:
            consolidated_report.append(get_report(this_group['group_id']))

        print_table(consolidated_report)

def get_report(security_group_id):
    """ Return a dict with information on interfaces using [security_group_id] """

    ec2_client = boto3.client('ec2')

    try:
        full_network_interfaces = ec2_client.describe_network_interfaces(
            Filters=[{'Name': 'group-id','Values': [security_group_id]}]
        )
    except botocore.exceptions.ClientError as e:
        print(e)
        sys.exit(1)

    simplified_listing = {}
    for interface in full_network_interfaces['NetworkInterfaces']:
        simplified_listing["security_group_id"] = security_group_id
        simplified_listing["interface_id"] = interface['NetworkInterfaceId']
        simplified_listing["status"] = interface['Attachment']['Status']
        simplified_listing["instance_id"] = interface['Attachment'].get('InstanceId')
        simplified_listing["interface_type"] = interface['InterfaceType']
        simplified_listing["subnet_id"] = interface['SubnetId']

    return simplified_listing or {"security_group_id": security_group_id}

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
