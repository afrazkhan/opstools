"""
Given a hostname on AWS, add your IP to be allowed for the ports you specify,
to the first security group found for that resource. Currently ALBs, ELBs, and
EC2 instances are supported.
"""

import boto3
from botocore.exceptions import ClientError # pylint: disable=unused-import
import socket
import requests
import sys
import os

def main(hostname, ports):
    """ Main method for this command. Uses [subc_args] from parent command as a subset of options """

    my_info = get_my_info()
    security_group = get_security_group(hostname)
    update_security_group(my_info, security_group, ports)

def get_security_group(hostname):
    """ Return the security group we need to edit """

    addresses = get_aws_addresses(hostname)

    elbv2_client = boto3.client('elbv2')
    elb_client = boto3.client('elb')
    ec2_client = boto3.client('ec2')

    security_group = search_albs(elbv2_client, addresses)
    if security_group is not None:
        return security_group
    security_group = search_ec2(ec2_client, addresses)
    if security_group is not None:
        return security_group
    security_group = search_elbs(elb_client, addresses)
    if security_group is not None:
        return security_group

    print("Didn't find that host in ELBs, ALBs, or EC2 instances for the account you're authed to, sorry :/")
    sys.exit(1)

def get_aws_addresses(hostname):
    """Return a list of IP addresses from the hostname"""

    try:
        return socket.gethostbyname_ex(hostname)[2]
    except socket.gaierror as e:
        print("Couldn't resolve the hostname: {}".format(e))
        sys.exit(1)

def get_my_info():
    """Return dict of {'ip', 'hostname'} for the IP this machine has at the time of calling"""

    return requests.get("https://ipinfo.io").json()

def update_security_group(my_info, security_group, ports):
    """Add this machine's IP to the security group provided"""

    print("Attempting to updated security group {}".format(security_group))

    ec2_client = boto3.client('ec2')

    for port in ports:
        print("Now inserting rule for port " + str(port))
        port = int(port)

        try:
            ec2_client.authorize_security_group_ingress(
                GroupId=security_group,
                IpPermissions=[
                    {
                        'FromPort': port,
                        'IpProtocol': 'TCP',
                        'IpRanges': [
                            {
                                'CidrIp': my_info['ip'] + "/32",
                                'Description': "{} ".format(os.getlogin()) + my_info['loc']
                            },
                        ],
                        'ToPort': port,
                    }
                ]
            )

        except ec2_client.exceptions.ClientError as e:
            print("Didn't add port {} because {}".format(str(port), e))

    print("Your IP is in the security group")
    sys.exit(0)

def search_albs(elbv2_client, addresses):
    """
    Search through all ALBs for the AWS public IP, and if found return the first
    security group attached
    """

    albs = elbv2_client.describe_load_balancers()['LoadBalancers']
    for alb in albs:
        elbv2_host = socket.gethostbyaddr(alb['DNSName'])

        for address in addresses:
            if [address] in elbv2_host:
                print("Found the IP in the ALBs listing")
                return alb['SecurityGroups'][0]

def search_elbs(elb_client, addresses):
    """
    Search through all ELBs for the public IP for the AWS public IP, and if found return the first
    security group attached
    """

    elbs = elb_client.describe_load_balancers()['LoadBalancerDescriptions']
    for elb in elbs:
        elb_host = socket.gethostbyaddr(elb['DNSName'])

        for address in addresses:
            if [address] in elb_host:
                print("Found the IP in the ELBs listing")
                return elb['SecurityGroups'][0]

def search_ec2(ec2_client, addresses):
    """
    Search through all EC2 instances for the public IP for the AWS public IP, and
    if found return the first security group attached
    """

    reservations = ec2_client.describe_instances()['Reservations']

    instances_array = [ reservation['Instances'] for reservation in reservations ]
    for instances in instances_array:
        for instance in instances:
            try:
                for address in addresses:
                    if address == instance['PublicIpAddress']:
                        print("Found the IP in EC2 listings")
                        return instance['SecurityGroups'][0]['GroupId']
            except KeyError:
                pass
