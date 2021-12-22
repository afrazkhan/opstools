#!/usr/bin/env python3

"""
Sets an entry in /etc/hosts, and a crontab to remind you that it exists every 10 minutes
"""

import argparse
from python_hosts import Hosts, HostsEntry
from crontab import CronTab
import sys
import os

def create_crontab_entry(names, reminder_interval):
    """
    Creates a crontab entry to notify you via MacOS notifications every 10 minutes
    about the /etc/hosts entry you just added for [names]
    """

    crontab_command = f"osascript -e 'display notification \"You have an /etc/hosts entry for {names} you might want to delete\" with title \"/etc/hosts\"'"

    if reminder_interval != 0:
        cron = CronTab(user=os.getlogin())
        job = cron.new(command=crontab_command, comment=names)
        job.minute.every(reminder_interval)
        cron.write()
        print(f"\nas well as a reminder to go off every {reminder_interval} minutes")

def add_entry(ip, names, reminder_interval, etc_hosts):
    """ Add the [entry] to /etc/hosts. Returns True on success and False on failure """

    new_entry = HostsEntry(entry_type='ipv4', address=ip, names=names)
    etc_hosts.add([new_entry], force=False, allow_address_duplication=True, merge_names=False)
    etc_hosts.write()
    print(f"Added hosts entry for:\n\n{ip} {' '.join(names)}")

    create_crontab_entry(' '.join(names), reminder_interval)

def remove_entry(names, etc_hosts):
    """
    Find entries with [names] in /etc/hosts and delete them. Only the first value from [names]
    is used.

    Find crontab entries for comments matching [names] and delete them
    """

    names = ' '.join(names)
    etc_hosts.remove_all_matching(name=names.split(' ', maxsplit=1)[0])
    etc_hosts.write()
    cron = CronTab(user=os.getlogin())
    cron.remove_all(comment=names)
    cron.write()

    print(f"Removed any reminders and hosts entries matching:\n\n{names}")

def main(subc_args=None):
    """ Create the entry """

    class MyParser(argparse.ArgumentParser): # pylint: disable=missing-docstring
        def error(self, message):
            sys.stderr.write(f"error: {message}\n")
            self.print_help()
            sys.exit(2)

    hosts_parser = MyParser(description="Sets an entry in /etc/hosts, and reminds you about it every n minutes")

    hosts_parser.add_argument("ip", help="IP to use for entry, followed by names to assign to it")
    hosts_parser.add_argument("names", help="Names to assign to the IP", nargs="+")
    hosts_parser.add_argument("--rm", "-r", action='store_true', help="Remove the entry instead of adding it")
    hosts_parser.add_argument("--reminder-interval", "-i", default="10", help="How often to reminded you about the entry in minutes. Default is 10, and 0 disables reminders")
    hosts_parser.add_argument("--hosts-file", "-f", default="/etc/hosts", help="Location of hosts file. Only useful for testing")
    args = hosts_parser.parse_known_args(subc_args)[0]

    if not os.access(args.hosts_file, os.W_OK):
        print("Can not write to hosts file. Please use sudo")
        sys.exit(1)

    etc_hosts = Hosts(args.hosts_file)

    if args.rm:
        remove_entry(args.names, etc_hosts)
    else:
        add_entry(args.ip, args.names, int(args.reminder_interval), etc_hosts)

if __name__ == "__main__":
    main()
