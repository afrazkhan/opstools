#!/usr/bin/env python3

"""
Given a bucket location for load balancer logs, read and parse the latest logs. Currently only supports application loadbalancers
"""

import boto3
from botocore.exceptions import ClientError # pylint: disable=unused-import
import argparse
import sys
import json
import datetime
import gzip

def main(subc_args=None):
    """ Main method for this command. Uses [subc_args] from parent command as a subset of options """

    class MyParser(argparse.ArgumentParser):
        """ Custom ArgumentParser so we can print the help by default """

        def error(self, message):
            sys.stderr.write('error: %s\n' % message)
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
    args = lb_logs_parser.parse_known_args(subc_args)[0]

    parse_logs(args.lb, int(args.last))

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

    split_line = this_line.split(" ")

    formatted_line = {
        "type": split_line[0].strip('"'),
        "time": split_line[1].strip('"'),
        "elb": split_line[2].strip('"'),
        "client_port": split_line[3].strip('"'),
        "target_port": split_line[4].strip('"'),
        "request_processing_time": split_line[5].strip('"'),
        "target_processing_time": split_line[6].strip('"'),
        "response_processing_time": split_line[7].strip('"'),
        "elb_status_code": split_line[8].strip('"'),
        "target_status_code": split_line[9].strip('"'),
        "received_bytes": split_line[10].strip('"'),
        "sent_bytes": split_line[11].strip('"'),
        "request_verb": split_line[12].strip('"'),
        "request_url": split_line[13].strip('"'),
        "request_protocol": split_line[14].strip('"'),
        "user_agent": split_line[15].strip('"'),
        "ssl_cipher": split_line[16].strip('"'),
        "ssl_protocol": split_line[17].strip('"'),
        "target_group_arn": split_line[18].strip('"'),
        "trace_id": split_line[19].strip('"'),
        "domain_name": split_line[20].strip('"'),
        "chosen_cert_arn": split_line[21].strip('"'),
        "matched_rule_priority": split_line[22].strip('"'),
        "request_creation_time": split_line[23].strip('"'),
        "actions_executed": split_line[24].strip('"'),
        "redirect_url": split_line[25].strip('"'),
        "lambda_error_reason": split_line[26].strip('"'),
        "target_port_list": split_line[27].strip('"'),
        "target_status_code_list": split_line[28].strip('"'),
        "classification": split_line[29].strip('"'),
        "classification_reason": split_line[30].strip('"'),
    }

    return formatted_line

def parse_logs(lb, last):
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
                print(json.dumps(parse_line(this_line)))

if __name__ == "__main__":
    main()
