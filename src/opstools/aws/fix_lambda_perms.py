"""
Temporarily switch Lambda functions to the AWSLambdaBasicExecutionRole role and
back to their original role, to force AWS to re-evaluate the function's
permissions. Can also just report (read-only) on whether the KMSAccessDeniedException
stale-role-reference issue (https://repost.aws/knowledge-center/lambda-kmsaccessdeniedexception-errors)
looks to be in effect for a function's KMS key
"""

import json
import re
import sys
import time

import boto3
from botocore.exceptions import ClientError

ROLE_NAME = "AWSLambdaBasicExecutionRole"
MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }
    ]
}

# IAM unresolved unique IDs are shown in place of an ARN once the entity they
# refer to no longer exists, e.g. a role that was deleted and recreated
STALE_PRINCIPAL_RE = re.compile(r"^(AROA|AIDA|AGPA|APKA|ANPA|ANVA|ASIA)[A-Z0-9]{17}$")

# Alias for the AWS managed key Lambda uses to encrypt environment variables
# when no customer managed key is configured
DEFAULT_LAMBDA_KEY_ALIAS = "alias/aws/lambda"

def main(lambdas, report=False):
    """ Main function for this module """

    lambda_client = boto3.client('lambda')

    if report:
        kms_client = boto3.client('kms')
        for this_lambda in lambdas:
            print_report(lambda_client, kms_client, this_lambda)
        return

    iam_client = boto3.client('iam')
    role_arn = create_role(iam_client)

    for this_lambda in lambdas:
        print(f"Current Lambda: {this_lambda}")

        original_role_arn = get_function_configuration(lambda_client, this_lambda)['Role']
        print(f"Role: {original_role_arn}")

        update_function_role(lambda_client, this_lambda, role_arn)
        print(f"Role switched away to {role_arn}")

        update_function_role(lambda_client, this_lambda, original_role_arn)
        print(f"Role switched back to {original_role_arn}")

def print_report(lambda_client, kms_client, function_name):
    """ Print a read-only report on whether [function_name] has a stale KMS grant behind its execution role """

    print(f"Current Lambda: {function_name}")

    config = get_function_configuration(lambda_client, function_name)
    role_arn = config['Role']
    kms_key_arn = config.get('KMSKeyArn')

    print(f"Role: {role_arn}")
    print(f"KMS key: {kms_key_arn or f'default ({DEFAULT_LAMBDA_KEY_ALIAS})'}")

    if not config.get('Environment', {}).get('Variables'):
        print("No environment variables are configured, so no KMS decrypt calls happen for this function - issue does not apply\n")
        return

    resolved_key_arn = resolve_key_arn(kms_client, kms_key_arn)
    if resolved_key_arn is None:
        return

    grantee_principals = get_grantee_principals(kms_client, resolved_key_arn)
    if grantee_principals is None:
        return

    stale_principals = sorted(p for p in grantee_principals if STALE_PRINCIPAL_RE.match(p))
    role_recognized = role_arn in grantee_principals

    if stale_principals:
        print(f"Stale, unresolved principal ID(s) found among the key's grants: {', '.join(stale_principals)}")
        print("This means a role was granted decrypt access and was later deleted and recreated, leaving a dangling grant behind - the KMSAccessDeniedException issue is likely in effect\n")
    elif not role_recognized:
        print("No grant found for the current role on this key - inconclusive (can happen if the function hasn't run since its role last changed)\n")
    else:
        print("No stale grants found, and the current role has a valid grant on this key - issue does not look to be in effect\n")

def resolve_key_arn(kms_client, kms_key_arn):
    """ Resolve [kms_key_arn] (or the default Lambda key alias, if None) to a key ARN suitable for list_grants """

    try:
        return kms_client.describe_key(KeyId=kms_key_arn or DEFAULT_LAMBDA_KEY_ALIAS)['KeyMetadata']['Arn']
    except ClientError as e:
        print(f"Could not resolve the KMS key: {e}\n")
        return None

def get_grantee_principals(kms_client, key_arn):
    """ Return the set of grantee principals across every grant on [key_arn] """

    try:
        grantee_principals = set()
        for page in kms_client.get_paginator('list_grants').paginate(KeyId=key_arn):
            grantee_principals.update(grant['GranteePrincipal'] for grant in page['Grants'] if 'GranteePrincipal' in grant)
        return grantee_principals
    except ClientError as e:
        print(f"Could not list grants on the key: {e}\n")
        return None

def create_role(iam_client):
    """ Create the AWSLambdaBasicExecutionRole role (if it doesn't already exist), attach the managed policy of the same name, and return its ARN """

    try:
        response = iam_client.create_role(
            RoleName=ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(TRUST_POLICY)
        )
        role_arn = response['Role']['Arn']
    except ClientError as e:
        if e.response['Error']['Code'] != 'EntityAlreadyExists':
            print(e)
            sys.exit(1)
        role_arn = iam_client.get_role(RoleName=ROLE_NAME)['Role']['Arn']

    try:
        iam_client.attach_role_policy(RoleName=ROLE_NAME, PolicyArn=MANAGED_POLICY_ARN)
    except ClientError as e:
        print(e)
        sys.exit(1)

    return role_arn

def get_function_configuration(lambda_client, function_name):
    """ Return the full function configuration for [function_name] """

    try:
        return lambda_client.get_function_configuration(FunctionName=function_name)
    except ClientError as e:
        print(e)
        sys.exit(1)

def update_function_role(lambda_client, function_name, role_arn, max_attempts=10, initial_delay=3):
    """
    Update [function_name]'s role to [role_arn], retrying while IAM propagates
    a newly created role (which isn't immediately assumable by Lambda), then
    wait for the update to complete before returning
    """

    delay = initial_delay
    for attempt in range(1, max_attempts + 1):
        try:
            lambda_client.update_function_configuration(FunctionName=function_name, Role=role_arn)
            break
        except ClientError as e:
            role_not_yet_assumable = e.response['Error']['Code'] == 'InvalidParameterValueException' and 'cannot be assumed' in e.response['Error']['Message']
            if not role_not_yet_assumable or attempt == max_attempts:
                print(e)
                sys.exit(1)
            print(f"Role not yet assumable by Lambda, retrying in {delay}s ({attempt}/{max_attempts})...")
            time.sleep(delay)
            delay = min(delay * 2, 30)

    try:
        lambda_client.get_waiter('function_updated_v2').wait(FunctionName=function_name)
    except ClientError as e:
        print(e)
        sys.exit(1)
