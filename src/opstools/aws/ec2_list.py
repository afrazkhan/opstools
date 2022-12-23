#!/usr/bin/env python

import boto3
import botocore
import sys

def main():
    """ Main function for this command """

    simplified_listing = extract_interesting_keys(get_listing())
    print_and_format(simplified_listing)

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

def print_and_format(simplified_listing):
    """ Print out a pretty report of our EC2 listing """

    for instance in simplified_listing:
        print(
            "\033[34mID: \033[0m{0:11}"
            "\033[34m Name: \033[0m{1:30}"
            "\033[34mIP: \033[0m{2:20}"
            "\033[34mPublic IP: \033[0m{3:30}".format(
                instance['instance_id'],
                instance['name'][0:29],
                instance['private_ip'],
                instance['public_ip']
            )
        )

if __name__ == "__main__":
    main()
