#!/usr/bin/env python3

"""
Parse arbitrarily headered log files for searching
"""

import sys
import argparse
import shlex

def find_in_line(these_field_values, search_string, fields_to_search):
    """ Grep [this_string] for [search_string] in [these_fields] (all if None) """

    for search_field in fields_to_search:
        if search_string in these_field_values[int(search_field)]:
            return these_field_values

    import pdb; pdb.set_trace() # pylint: disable=multiple-statements

    return None

def return_fields(this_file):
    """ Return a list of fields and example values from [this_file], based on the second line """

    with open(this_file, "r") as opened_file:
        these_field_values = shlex.split(opened_file.readline())

    return these_field_values

def search(this_file, search_string, fields_to_search):
    """ Return all the fields in [this_file] """

    report = { this_file: [] }

    with open(this_file, "r") as opened_file:
        for this_line in opened_file:
            these_field_values = shlex.split(this_line)

            search_result = find_in_line(these_field_values, search_string, fields_to_search)

            if search_result:
                report[this_file].append(search_result)

    return report

def main(subc_args=None):
    """ TODO """

    class MyParser(argparse.ArgumentParser): # pylint: disable=missing-class-docstring
        def error(self, message):
            sys.stderr.write('error: %s\n' % message)
            self.print_help()
            sys.exit(2)

    log_argparser = MyParser(description=
        """
        Parse fields in log files and perform operations on them, such as count, or search
        """
    )

    log_argparser.add_argument("files", help="Files to look at")
    log_argparser.add_argument("search_string", help="What to search for")
    log_argparser.add_argument("-f", "--fields", help="Which fields to search", default=None)
    args = log_argparser.parse_known_args(subc_args)[0]

    for this_file in args.files.split(' '):
        results = search(this_file, args.search_string, args.fields.split(' '))
        print(results)

if __name__ == "__main__":
    main()
