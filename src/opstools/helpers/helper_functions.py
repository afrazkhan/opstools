import tabulate

def print_table(list_of_dicts):
    """ Make and print a pretty table out of [list_of_dicts] """

    header = list_of_dicts[0].keys()
    rows = [this_dict.values() for this_dict in list_of_dicts]
    print(tabulate.tabulate(rows, header))
