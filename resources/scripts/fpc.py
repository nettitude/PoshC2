#!/usr/bin/env python3

import sys, argparse, os, pandas


class Colours:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    END = '\033[0m'
    YELLOW = '\033[93m'


def create_arg_parser():
    parser = argparse.ArgumentParser(description='Find Posh Command - Search for a PoshC2 Command Output')
    parser.add_argument("-p", "--project", help='The PoshC2 project dir', default = '/opt/PoshC2_Project')
    parser.add_argument("-d", "--database_type", help="The database type (SQLite/Postgres)", default = 'SQLite')
    parser.add_argument("-pg", "--postgres_string", help="The postgres connection string (if using postgres)", default = '')
    parser.add_argument("-c", "--command", help='The command to search for', default = '%')
    parser.add_argument("-u", "--user", help='The user to filter on', default = '%')
    parser.add_argument("-o", "--output", help='The output to search for', default = '%')
    parser.add_argument("-t", "--taskid", help='The taskid to search for', default = '%')
    return parser


def get_db_connection(args):
    conn = None
    if args.database_type.lower() == "postgres":
        import psycopg2
        conn = psycopg2.connect(args.postgres_string)
    else:
        db_path = os.path.join(args.project, 'PowershellC2.SQLite')
        if not os.path.exists(db_path):
            print(f"[-] Database does not exist: {db_path}")
            sys.exit(1)
        import sqlite3
        conn = sqlite3.connect(db_path)
        conn.text_factory = str
        conn.row_factory = sqlite3.Row
    return conn


def main():
    args = create_arg_parser().parse_args()
    conn = get_db_connection(args)
    if args.command == '%' and args.output == '%' and args.taskid == '%':
        print("%s[-] A minimum of a --command, --taskid or --output search term must be specified%s" % (Colours.RED, Colours.END))
        sys.exit(1)
    with pandas.option_context('display.max_rows', None, 'display.max_columns', None, 'display.max_colwidth', -1):
        output = pandas.read_sql_query("SELECT SentTime,CompletedTime,User,Command,Output,TaskId from Tasks where Command like '%%%s%%' or taskid = '%s'" % (args.command, args.taskid), conn)
        for entry in output.values:
            print("\n%s[*][*][*] Task %05d Command (Issued: %s by %s):\n%s" % (Colours.GREEN, entry[5], entry[0], entry[2], Colours.END))
            print(entry[3])
            print("\n%s[*][*][*] Task %05d Output (Completed: %s):\n%s" % (Colours.BLUE, entry[5], entry[1], Colours.END))
            print(entry[4])
            print()


if __name__ == '__main__':
    main()
