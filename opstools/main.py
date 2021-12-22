#!/usr/bin/env python
# -*- coding: utf-8 -*-

__version__ = "0.3.0"

import argparse
import sys

def main():
    """ Top level method to be called for all commands """

    class MyParser(argparse.ArgumentParser):
        """ Custom ArgumentParser so we can print a top level help message by default """

        def error(self, message):
            sys.stderr.write('error: %s\n' % message)
            self.print_help()
            sys.exit(2)

    main_search = MyParser(description=
        """
        Swiss army knife of silly ops stuff you couldn't be bothered to script yourself
        """,
        add_help=False
    )

    main_search.add_argument("command", help="The subcommand to run", choices=["allowme", "ec2ls", "st", "lblogs", "hosts"])

    args, subc_args = main_search.parse_known_args()

    if args.command == "allowme":
        from opstools.aws import allow_me
        allow_me.main(subc_args)

    if args.command == "ec2ls":
        from opstools.aws import ec2_list
        ec2_list.main()

    if args.command == "lblogs":
        from opstools.aws import lb_logs
        lb_logs.main(subc_args)

    if args.command == "st":
        from opstools.url import stresstest
        stresstest.main(subc_args)

    if args.command == "hosts":
        from opstools.localhost import hosts
        hosts.main(subc_args)

    # WIP
    # if args.command == "log-search":
    #     import opstools.file.log_search as log_search
    #     log_search.main(subc_args)

if __name__ == "__main__":
    main()
