#!/usr/bin/env python3

"""
Given a bucket location for load balancer logs, read and parse the latest logs. Currently only supports application loadbalancers
"""

import boto3
from botocore.exceptions import ClientError # pylint: disable=unused-import
import argparse
import re
import sys
import json
import datetime
import gzip

def main(subc_args=None):
    """ Main method for this command. Uses [subc_args] from parent command as a subset of options """

    class MyParser(argparse.ArgumentParser):
        """ Custom ArgumentParser so we can print the help by default """

        def error(self, message):
            sys.stderr.write(f"error: {message}\n")
            self.print_help()
            sys.exit(2)

    lb_logs_parser = MyParser(description=
        """
        Given a bucket location for load balancer logs, read and parse the latest logs.
        Currently only supports application loadbalancers
        """
    )

    lb_logs_parser.add_argument("--lb", help="Name of the load balancer")
    lb_logs_parser.add_argument("--last", "-l", default=2, help="Use last n logfiles. Defaults to 2")
    lb_logs_parser.add_argument("--search", "-s", default='', help="Space separated greedy search fields. E.g. 'client_port=89.205.139.161'")
    args = lb_logs_parser.parse_known_args(subc_args)[0]

    if args.search != '' and not re.match(r"^((\w)+\=([\w.:\/])+\s?)+", args.search):
        print("The search items must match the format 'field=string'")
        sys.exit(0)
    search_items = args.search.split(' ')

    parse_logs(args.lb, int(args.last), search_items)

def get_lb_arns(lb):
    """
    If lb != None, return the loadbalancer ARN, else print a listing of the load balancers and exit
    """

    lb_client = boto3.client('elbv2')
    lb_list = lb_client.describe_load_balancers()

    if lb is None:
        print("No loadbalancer name given, here are some to choose from:\n")
        lb_names = [ this_lb['LoadBalancerName'] for this_lb in lb_list['LoadBalancers'] ]
        for this_lb in lb_names:
            print(this_lb)
        sys.exit(0)

    lb_arn = [ this_lb['LoadBalancerArn'] for this_lb in lb_list['LoadBalancers'] if this_lb['LoadBalancerName'] == lb ]

    return lb_arn

def get_bucket(lb):
    """
    Return the S3 bucket in which the logs are stored if logs are enabled, or tell the user
    that logs are not available for this loadbalancer and exit
    """

    lb_client = boto3.client('elbv2')

    lb_arns = get_lb_arns(lb)
    these_attributes = lb_client.describe_load_balancer_attributes(LoadBalancerArn=lb_arns[0])['Attributes']

    for this_attribute in these_attributes:
        if this_attribute['Key'] == 'access_logs.s3.bucket':
            s3_bucket = this_attribute['Value']
            break

    if s3_bucket is '':
        print("Logging is either not enabled for this loadbalancer, or the S3 bucket has not been set")
        sys.exit(0)

    return s3_bucket

def get_latest_logfiles(bucket):
    """ Return {sorted_objects, bucket} from a loadbalancers logging bucket """

    s3_client = boto3.client('s3')

    account = boto3.client('sts').get_caller_identity().get('Account')
    region = s3_client.meta.region_name
    date = datetime.datetime.now().strftime("%Y/%m/%d")
    bucket_path = f"AWSLogs/{account}/elasticloadbalancing/{region}/{date}/"

    get_last_modified = lambda obj: int(obj['LastModified'].strftime('%s'))
    paginator = s3_client.get_paginator( "list_objects" )
    page_iterator = paginator.paginate( Bucket = bucket, Prefix = bucket_path)
    sorted_objects = []
    for page in page_iterator:
        if "Contents" in page:
            sorted_objects = [obj['Key'] for obj in sorted( page["Contents"], key=get_last_modified)]

    return sorted_objects

def parse_line(this_line):
    """ Parse [this_line] in the known AWS loadbalancer format """

    these_values = [ e.strip('"') for e in this_line.split(" ") ]

    formatted_line = dict(zip([
        "type",
        "time",
        "elb",
        "client_port",
        "target_port",
        "request_processing_time",
        "target_processing_time",
        "response_processing_time",
        "elb_status_code",
        "target_status_code",
        "received_bytes",
        "sent_bytes",
        "request_verb",
        "request_url",
        "request_protocol",
        "user_agent",
        "ssl_cipher",
        "ssl_protocol",
        "target_group_arn",
        "trace_id",
        "domain_name",
        "chosen_cert_arn",
        "matched_rule_priority",
        "request_creation_time",
        "actions_executed",
        "redirect_url",
        "lambda_error_reason",
        "target_port_list",
        "target_status_code_list",
        "classification",
        "classification_reason"
    ], these_values))

    return formatted_line

def find_in_dict(search_items, this_dict):
    """
    Return True if [this_dict] matches all of the [search_items]
    """

    try:
        for search_string in search_items:
            k,v = search_string.split("=")
            if v not in this_dict[k]:
                return False

        return True
    except KeyError:
        return False

def parse_logs(lb, last, search_items):
    """
    Put all the methods in this module together:

    1. Given the loadbalancer name, get the S3 bucket which stores the logs
    2. Stream the logs through g(un)zip
    3. Format each line to JSON and print it
    """

    s3_client = boto3.client('s3')
    bucket = get_bucket(lb)
    latest_logfiles = get_latest_logfiles(bucket)

    for this_object in latest_logfiles[-last:]:
        s3_obj = s3_client.get_object(Bucket=bucket, Key=this_object)
        body = s3_obj['Body']
        with gzip.open(body, 'rt') as gzipped_file:
            for this_line in gzipped_file:
                these_values = parse_line(this_line)

                if search_items == ['']:
                    print(json.dumps(these_values))
                else:
                    if find_in_dict(search_items, these_values):
                        print(json.dumps(these_values))

if __name__ == "__main__":
    main()
