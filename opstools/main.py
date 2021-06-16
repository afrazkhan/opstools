#!/usr/bin/env python
# -*- coding: utf-8 -*-

__version__ = "0.0.5"

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

    main_parser = MyParser(description=
        """
        Swiss army knife of silly ops stuff you couldn't be bothered to script yourself
        """,
        add_help=False
    )

    main_parser.add_argument("command", help="The subcommand to run", choices=["allowme", "ec2ls", "timeout-tester"])

    args, subc_args = main_parser.parse_known_args()

    if args.command == "allowme":
        import opstools.aws.allow_me as allow_me
        allow_me.main(subc_args)

    if args.command == "ec2ls":
        import opstools.aws.ec2_list as ec2_list
        ec2_list.main()

    if args.command == "timeout-tester":
        import opstools.url.timeout_tester as timeout_tester
        timeout_tester.main(subc_args)

if __name__ == "__main__":
    main()
