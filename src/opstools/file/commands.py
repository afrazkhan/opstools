"""
Parse arbitrarily headered log files for searching
"""

import click

@click.group
@click.pass_context
def file(ctx): # pylint: disable=unused-argument
    """ Scripts which act on files """
    pass # pylint: disable=unnecessary-pass

@file.command()
@click.option("--fields", "-f", help="Which fields to search", multiple=True)
@click.argument("search_string")
@click.argument("files", nargs=-1)
@click.pass_context
def log_search(ctx, fields, search_string, files):
    """ Parse arbitrarily headered log files for searching """

    from opstools.file import log_search as this_log_search
    this_log_search.main(files, search_string, fields)

@file.command()
@click.argument("ip", required=True)
@click.argument("names", required=True, nargs=-1)
@click.option("--rm", "-r", is_flag=True, help="Remove the entry instead of adding it")
@click.option("--reminder-interval", "-i", default="10", help="How often to reminded you about the entry in minutes. Default is 10, and 0 disables reminders")
@click.option("--hosts-file", "-f", default="/etc/hosts", help="Location of hosts file. Only useful for testing")
@click.pass_context
def hosts(ctx, ip, names, rm, reminder_interval, hosts_file):
    """ Add / remove entries to /etc/hosts, with reminders for removal """

    from opstools.file import hosts as this_hosts
    this_hosts.main(ip, names, rm, reminder_interval, hosts_file)
