#!/usr/bin/env python
# -*- coding: utf-8 -*-

__version__ = "0.0.1"

import argparse
import sys

def main():
    class MyParser(argparse.ArgumentParser):
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
    main_parser.add_argument("command", help="The subcommand to run", choices=["allowme", "ec2ls"])

    args, subc_args = main_parser.parse_known_args()

    if args.command == "allowme":
        import opstools.aws.allow_me as allow_me
        allow_me.main(subc_args)

    if args.command == "ec2ls":
        import opstools.aws.ec2_list as ec2_list
        ec2_list.main()

if __name__ == "__main__":
    main()
