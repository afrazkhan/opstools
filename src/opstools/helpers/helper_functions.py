import tabulate

def print_table(list_of_dicts):
    """ Make and print a pretty table out of [list_of_dicts] """

    # FIXME: This is horrible, but sets can't preserve order, and we want to get
    #       all possible headers. There must be a better way though?
    headers = []
    for this_dict in list_of_dicts:
        these_headers = this_dict.keys()
        for this_header in these_headers:
            if this_header not in headers:
                headers.append(this_header)

    rows = [this_dict.values() for this_dict in list_of_dicts]
    print(tabulate.tabulate(rows, headers))
