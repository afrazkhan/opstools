"""
Sets an entry in /etc/hosts, and a crontab to remind you that it exists every 10 minutes
"""

from python_hosts import Hosts, HostsEntry
from crontab import CronTab
import sys
import os

def main(ip, names, rm, reminder_interval, hosts_file):
    """ Create the entry """

    if not os.access(hosts_file, os.W_OK):
        print("Can not write to hosts file. Please use sudo")
        sys.exit(1)

    etc_hosts = Hosts(hosts_file)

    if rm:
        remove_entry(names, etc_hosts)
    else:
        add_entry(ip, names, int(reminder_interval), etc_hosts)

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

    try:
        new_entry = HostsEntry(entry_type='ipv4', address=ip, names=names)
        etc_hosts.add([new_entry], force=False, allow_address_duplication=True, merge_names=False)
        etc_hosts.write()
    except Exception as e:
        print(e)
        sys.exit(1)

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
