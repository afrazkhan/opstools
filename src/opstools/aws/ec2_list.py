#!/usr/bin/env python

import boto3
import sys
from opstools.helpers.helper_functions import print_table

def main():
    """ Main function for this command """

    simplified_listing = extract_interesting_keys(get_listing())
    print_table(simplified_listing)

def get_listing():
    """ Return a listing for EC2 instances """

    ec2 = boto3.client('ec2')
    listing = []

    try:
        full_listing = ec2.describe_instances(
            Filters=[
                {
                    'Name': 'instance-state-name',
                    'Values': [ 'running' ]
                }
            ],
            MaxResults=1000)
    except Exception as e:
        print(e)
        sys.exit(1)

    for reservation in full_listing['Reservations']:
        for instance in reservation['Instances']:
            listing.append(instance)

    return listing

def extract_interesting_keys(listing):
    """
    Parse [listing] and extract the keys we're interested in. Create a new dict from those,
    and return it
    """

    simplified_listing = []

    for instance in listing:
        try:
            name = next(n for n in instance['Tags'] if n['Key'] == 'Name')['Value']
        except (KeyError, StopIteration):
            name = instance['InstanceId']

        instance_id = instance['InstanceId']
        private_ip = instance['NetworkInterfaces'][0]['PrivateIpAddress']

        try:
            public_ip = instance['NetworkInterfaces'][0]['Association']['PublicIp']
        except KeyError:
            public_ip = "None"

        simplified_listing.append({'name': name, 'instance_id': instance_id, 'private_ip': private_ip, 'public_ip': public_ip})

    return simplified_listing

if __name__ == "__main__":
    main()
