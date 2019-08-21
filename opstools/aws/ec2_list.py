#!/usr/bin/env python

import boto3
from termcolor import colored

def main():
    simplified_listing = extract_interesting_keys(get_listing())
    print_and_format(simplified_listing)

def get_listing():
    ec2 = boto3.client('ec2')
    listing = ec2.describe_instances(Filters=[
        {
            'Name': 'instance-state-name',
            'Values': [ 'running' ]
        }
    ])

    return listing

def extract_interesting_keys(listing):
    simplified_listing = []

    for instance in listing['Reservations']:
        try:
            name = next(n for n in instance['Instances'][0]['Tags'] if n['Key'] == 'Name')['Value']
        except:
            name = instance['Instances'][0]['InstanceId']

        instance_id = instance['Instances'][0]['InstanceId']
        private_ip = instance['Instances'][0]['NetworkInterfaces'][0]['PrivateIpAddress']

        try:
            public_ip = instance['Instances'][0]['NetworkInterfaces'][0]['Association']['PublicIp']
        except KeyError:
            public_ip = "None"

        simplified_listing.append({'name': name, 'instance_id': instance_id, 'private_ip': private_ip, 'public_ip': public_ip})

    return simplified_listing

def print_and_format(simplified_listing):
    for instance in simplified_listing:
        print(
            "\033[1mID: \033[0m{0:11}"
            "\033[1m Name: \033[0m{1:30}"
            "\033[1mIP: \033[0m{2:30}"
            "\033[1mPublic IP: \033[0m{3:30}".format(
                instance['instance_id'],
                instance['name'],
                instance['private_ip'],
                instance['public_ip']
            )
        )


if __name__ == "__main__":
    main()
