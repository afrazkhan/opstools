"""
Given a bucket location for load balancer logs, read and parse the latest logs.
Currently only supports application loadbalancers
"""

import boto3
from botocore.exceptions import ClientError # pylint: disable=unused-import
import json
import datetime
import gzip
import sys

def main(lb, last, search_items):
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
        try:
            s3_obj = s3_client.get_object(Bucket=bucket, Key=this_object)
        except Exception as e:
            print(e)
            sys.exit(1)

        body = s3_obj['Body']
        with gzip.open(body, 'rt') as gzipped_file:
            for this_line in gzipped_file:
                these_values = create_entry([
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
                    "classification_reason",
                ], this_line)

                if search_items == ['']:
                    print(json.dumps(these_values))
                else:
                    if find_in_dict(search_items, these_values):
                        print(json.dumps(these_values))

def get_lb_arns(lb):
    """
    If lb != None, return the loadbalancer ARN, else print a listing of the load balancers and exit
    """

    lb_client = boto3.client('elbv2')
    try:
        lb_list = lb_client.describe_load_balancers()
    except Exception as e:
        print(e)
        sys.exit(1)

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
    try:
        these_attributes = lb_client.describe_load_balancer_attributes(LoadBalancerArn=lb_arns[0])['Attributes']
    except Exception as e:
        print(e)
        sys.exit(1)

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

    try:
        account = boto3.client('sts').get_caller_identity().get('Account')
    except Exception as e:
        print(e)
        sys.exit(1)

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

def create_entry(these_keys, spaced_values):
    """
    Make a list of values from the space separated string [spaced_values], and return
    a dict by combining it with [these_keys]. [these_keys] must align to [spaced_values]
    as there is no way to programatically gain knowledge of their relationships. Superfluous
    keys will be discarded
    """

    these_values = [ e.strip('"') for e in spaced_values.split(" ") ]
    return dict(zip(these_keys, these_values))

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
