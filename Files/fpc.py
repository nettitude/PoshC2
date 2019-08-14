#!/usr/bin/env python3

import sys, argparse, sqlite3, os, pandas

class Colours:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    END = '\033[0m'
    YELLOW = '\033[93m'

def create_arg_parser():
    parser = argparse.ArgumentParser(description='Find Posh COmmand - Search for a PoshC2 Command Output')
    parser.add_argument("-p", "--project", help='The PoshC2 project dir', default = '/opt/PoshC2_Project')
    parser.add_argument("-c", "--command", help='The command to search for', default = '%')
    parser.add_argument("-u", "--user", help='The user to filter on', default = '%')
    parser.add_argument("-o", "--output", help='The output to search for', default = '%')
    return parser

def main():
    args = create_arg_parser().parse_args()
    if args.command == '%' and args.output == '%':
        print("%s[-] A minimum of a --command or --output search term must be specified%s" % (Colours.RED, Colours.END))
        sys.exit(1)
    conn = sqlite3.connect(os.path.join(args.project, 'PowershellC2.SQLite'))
    with pandas.option_context('display.max_rows', None, 'display.max_columns', None, 'display.max_colwidth', -1):
        output = pandas.read_sql_query("SELECT Command,Output from Tasks where User like '%s' and Command like '%%%s%%' and Output like '%%%s%%'" % (args.user, args.command, args.output), conn)
        for entry in output.values:
            print("\n%s[*][*][*] Command:\n%s" % (Colours.GREEN, Colours.END))
            print(entry[0])
            print("\n%s[*][*][*] Output:\n%s" % (Colours.BLUE, Colours.END))
            print(entry[1])

if __name__ == '__main__':
    main()
