"""
TODO
"""

import click
import sys
import re
from pprint import pprint

@click.group
@click.pass_context
def aws(ctx): # pylint: disable=unused-argument
    """ Commands for making your life in AWS easier """

    pass


@aws.command()
@click.argument("hostname")
@click.option("--ssh", "-s", is_flag=True, help="Add port 22 to the first security group found")
@click.option("--https", is_flag=True, help="Add ports 443 and 80 to the first security group found")
@click.option("--port", "-p", help="Add a custom port to the first security group found")
@click.pass_context
def allow_me(ctx, hostname, ssh, https, port):
    """
    Look up security groups associated with [hostname], and add port allowances
    for this machine's IP
    """

    ports = make_port_list(ssh, https, port)
    from opstools.aws import allow_me as this_allow_me
    this_allow_me.main(hostname, ports)

@aws.command()
@click.pass_context
def ec2_list(ctx):
    """ Return a listing for EC2 instances """

    from opstools.aws import ec2_list as this_ec2_list
    this_ec2_list.main()

@aws.command()
@click.option("--lb", help="Name of the load balancer")
@click.option("--last", "-l", default=2, help="Use last n logfiles. Defaults to 2")
@click.option("--search", "-s", default='', help="Space separated greedy search fields. E.g. 'client_port=89.205.139.161'")
@click.pass_context
def lb_logs(ctx, lb, last, search):
    """
    Given a bucket location for load balancer logs, read and parse the latest logs.
    Currently only supports application loadbalancers
    """

    search_items = check_search_argument(search)

    from opstools.aws import lb_logs as this_ec2_list
    this_ec2_list.main(lb, last, search_items)

@aws.command()
@click.argument("security_group_id", required=False)
@click.option("--all", "-a", "all_sgs", is_flag=True, help="Print report for all security groups found")
@click.pass_context
def sg_report(ctx, security_group_id, all_sgs):
    """ Print a report of what is using a security group """

    from opstools.aws import sg_report as this_sg_report
    this_sg_report.main(security_group_id, all_sgs)

@aws.command()
@click.option("--auto-confirm", "-a", is_flag=True, default=False, help="Nuke all found resources without asking for confirmation")
@click.option("--dry-run", "-d", is_flag=True, default=False, help="Explicitly state that this is a dry run, and don't ask for confirmation. Overrules --auto-confirm")
@click.option("--exclude-tag", "--et", multiple=True, help="Tags to exclude from the listing. Multiple occurences accepted. All resources not matching will be returned")
@click.option("--include-tag", "--it", multiple=True, help="Tag to include in the listing. Multiple occurences accepted. Only matching resources will be returned")
@click.option("--logical-and", "-n", is_flag=True, default=False, help="Logical AND for tag inclusions. Default is OR")
@click.option("--exclude-service", "--es", multiple=True, help="Service to exclude from the tagged listing. Multiple occurences accepted. All resources not matching will be returned")
@click.option("--include-service", "--is", multiple=True, help="Service to include in the listing. Multiple occurences accepted. By default all services with tags will be included. Only matching will be returned")
@click.option("--exclude-arn", "--ea", multiple=True, help="Specific resource ARNs to exlcude from nuking. Multiple occurences accepted. Remove from returned results")
@click.option("--include-arn", "--ia", multiple=True, help="Specific resource ARNs to include. Multiple occurences accepted. Add to returned results")
@click.option("--explore", "-x", is_flag=True, help="WIP: Used to list untagged resources. Can not be used for deletions directly")
@click.option("--arns-only", "-o", is_flag=True, help="Only output the ARN list")
@click.pass_context
def nuke(
    ctx,
    auto_confirm: bool,
    dry_run: bool,
    exclude_tag,
    include_tag: list,
    logical_and: bool,
    exclude_service: list,
    include_service: list,
    exclude_arn: list,
    include_arn: list,
    explore: bool,
    arns_only: bool):
    """
    Nuke tagged resources in AWS.

    Inclusiona and exclusion options can be supplied multiple times to specify
    multiple things to include or exclude.

    Inclusions mean "only matching", exclusions mean "all except matching", and
    supplying both means "only matching inclusions, except matching exclusions".

    With the exception of --include-arn, only resources that have been tagged
    will turn up in the result
    """

    from opstools.aws import nuke as nuke
    nuker = nuke.Nuke()

    if explore:
        resources = nuker.get_resources_by_services(
            exclude_services=exclude_service,
            include_services=include_service,
            exclude_arns=exclude_arn,
            include_arns=include_arn)
        pprint(resources)
        sys.exit(0)

    exclude_tags = list(exclude_tag)
    include_tags = list(include_tag)
    include_services = [this_service for this_service in list(include_service)]
    exclude_services = [this_service for this_service in list(exclude_service)]
    exclude_arns = list(exclude_arn)
    include_arns = list(include_arn)

    include_tags_dict = split_tags(include_tags)
    exclude_tags_dict = split_tags(exclude_tags)

    prospective_resources = nuker.prospective_resources(
        exclude_tags_dict=exclude_tags_dict,
        include_tags_dict=include_tags_dict,
        exclude_services=exclude_services,
        include_services=include_services,
        exclude_arns=exclude_arns,
        include_arns=include_arns,
        logical_and=logical_and)

    if prospective_resources == {}:
        print("No resources found to delete.\n\nℹ️ Note that for reasons of safety, if no options are provided you will always get an empty list")
        sys.exit(0)

    print("Resources found to delete:")
    if not arns_only:
        for resource_arn, tags in prospective_resources.items():
            print(f"\nARN: {resource_arn}\nTags:")
            for tag, value in tags.items():
                print(f"  - {tag}: {value}")
    else:
        pprint([*prospective_resources])

    if dry_run:
        print("\nℹ️ --dry-run was passed, so we won't go further")
    elif not auto_confirm:
        confirmation = input("\n⚠️ Shall I delete the above resources? Only 'yes' or 'N' will be accepted ").upper()
        while confirmation != 'YES' and confirmation != 'N':
            confirmation = input("Only 'yes' or 'n' will be accepted ").upper()

        if confirmation == 'YES':
            nuker.nuke(list(prospective_resources.keys()))
        else:
            print("Coward")
    else:
        print("\nProceeding to deletions since --auto-confirm was supplied")
        nuker.nuke(list(prospective_resources.keys()))

@aws.command()
@click.option("--bucket", "-b", type=str, required=True)
@click.option("--prefix", "-p", type=str, required=False, default='')
@click.option("--metadata-key", "-m", type=str, required=True)
@click.option("--metadata-value", "-a", type=str, required=False)
@click.option("--max-threads", "-t", type=int, required=False, default=10)
@click.option("--max-retries-per-thread", "-r", type=int, required=False, default=10)
@click.option("--retry-mode", "-e", type=str, required=False, default='standard')
@click.option("--unimplemented-retry-delay", "-d", help="NOT IMPLEMENTED YET", type=int, required=False, default=1)
@click.pass_context
def s3_md_search(ctx, max_threads: int, max_retries_per_thread: int, retry_mode: str, unimplemented_retry_delay: int, bucket: str, prefix: str, metadata_key: str, metadata_value: str):
    """
    Search through custom metadata in S3 objects. If no value is given to search
    for, then only the existence of <metadata-key> will be searched for
    """

    from opstools.aws import s3_metadata_search as s3_md_search
    s3_md_search = s3_md_search.S3MetadataSearch(max_threads=max_threads, max_retries_per_thread=max_retries_per_thread, retry_mode=retry_mode, retry_delay=unimplemented_retry_delay, bucket_name=bucket, prefix=prefix, metadata_key=metadata_key, metadata_value= metadata_value)
    matching_files = s3_md_search.iterate_pages()

    pprint(f"Results:\n{matching_files}")

### Functions
#
def check_search_argument(search):
    """ Checks [search] against a regex for the correct format """

    if search != '' and not re.match(r"^(([\w.:\/\-)+\=([\w.:\/\-])+\s?)+", search):
        print("The search items must match the format 'field=string'")
        sys.exit(0)
    search_items = search.split(' ')

    return search_items


def make_port_list(ssh, https, port):
    """Return a list of the ports asked for by flags to the script"""

    ports = []

    if ssh:
        ports.append(22)
    if https:
        ports.append(443)
        ports.append(80)
    if port is not None:
        ports.append(port)

    return ports

def split_tags(tags: list) -> dict:
    """
    Split '=' separated key-value tags into key-value pairs and return them
    """

    tag_dict = {}
    for this_tag in tags:
        if '=' in this_tag:
            key, value = this_tag.split("=")
            tag_dict[key] = value
        else:
            tag_dict[this_tag] = None

    return tag_dict
