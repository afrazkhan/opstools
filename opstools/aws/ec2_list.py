#!/usr/bin/env python

import boto3
import botocore
import argparse
import sys
import asyncio
from websockets import connect

def main(subc_args=None):
    """ Main function for this command """

    class MyParser(argparse.ArgumentParser):
        """ Custom ArgumentParser so we can print the help by default """

        def error(self, message):
            sys.stderr.write('error: %s\n' % message)
            self.print_help()
            sys.exit(2)

    allowme_parser = MyParser(description=
        """
        Get a listing of AWS instances. Optionally, select one to connect to via SSM
        """
    )

    allowme_parser.add_argument("--select", "-s", action="store_true", help="Whether present the option to connect to an instance via SSM")
    args = allowme_parser.parse_known_args(subc_args)[0]

    simplified_listing = extract_interesting_keys(get_listing())
    print_and_format(simplified_listing)

    if args.select:
        instance_chosen = -1
        while int(instance_chosen) not in range(0, len(simplified_listing)):
            instance_chosen = input("\nWhich instance number would you like to connect to? ")
            ssm_to_instance(simplified_listing[int(instance_chosen)])

def ssm_to_instance(this_instance):
    """ TODO """

    print(f"Connecting to {this_instance}")
    ssm_client = boto3.client('ssm')

    response = ssm_client.start_session(
        Target=this_instance['instance_id'],
        DocumentName='AWS-StartInteractiveCommand',
        Parameters={
            'command': [
                'sudo su -',
            ]
        }
    )

    async def send_this():
        async with connect(response['StreamUrl']) as websocket:
            await websocket.send("ls")
            await websocket.recv()

    asyncio.run(send_this())

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
    except botocore.exceptions.ClientError as e:
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

    instance_number = 0

    for instance in simplified_listing:
        print(
            "{0:2} "
            "\033[34mID: \033[0m{1:2}"
            "\033[34m Name: \033[0m{2:30}"
            "\033[34mIP: \033[0m{3:20}"
            "\033[34mPublic IP: \033[0m{4:30}".format(
                instance_number,
                instance['instance_id'],
                instance['name'][0:29],
                instance['private_ip'],
                instance['public_ip']
            )
        )

        instance_number += 1

if __name__ == "__main__":
    main()
