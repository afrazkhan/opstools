"""
Parse arbitrarily headered log files for searching
"""

import shlex

def main(files, search_string, fields):
    """ Main function for this script """

    for this_file in files:
        results = search(this_file, search_string, fields)
        print(results)

def find_in_line(these_field_values, search_string, fields_to_search):
    """ Grep [this_string] for [search_string] in [these_fields] (all if None) """

    for search_field in fields_to_search:
        if search_string in these_field_values[int(search_field)]:
            return these_field_values

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
