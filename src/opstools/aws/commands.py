"""
TODO
"""

import click
import sys
import re

@click.group
@click.pass_context
def aws(ctx): # pylint: disable=unused-argument
    """ Commands for making your life in AWS easier """
    pass # pylint: disable=unnecessary-pass

@aws.command()
@click.argument("hostname")
@click.option("--ssh", "-s", is_flag=True, help="Add port 22 to the first security group found")
@click.option("--https", is_flag=True, help="Add ports 443 and 80 to the first security group found")
@click.option("--port", "-p", help="Add a custom port to the first security group found")
@click.pass_context
def allow_me(ctx, hostname, ssh, https, port):
    """ Look up security groups associated with [hostname], and add port allowances for this machine's IP """

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
@click.pass_context
def sg_report(ctx, security_group_id):
    """ Print a report of what is using a security group """

    from opstools.aws import sg_report as this_sg_report
    this_sg_report.main(security_group_id)


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
