#!/usr/bin/env python3

import argparse
import os
import sys
import pandas

from sqlalchemy import create_engine, text


class Colours:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    END = '\033[0m'
    YELLOW = '\033[93m'


def create_arg_parser():
    parser = argparse.ArgumentParser(description='Find Posh Command - Search for a PoshC2 Command Output')
    parser.add_argument("-p", "--project", help='The PoshC2 project dir', default='/opt/PoshC2_Project')
    parser.add_argument("-d", "--database_type", help="The database type (SQLite/Postgres)", default='SQLite')
    parser.add_argument("-pg", "--postgres_string", help="The postgres connection string (if using postgres)", default='')
    parser.add_argument("-c", "--command", help='The command to search for', default='%')
    parser.add_argument("-u", "--user", help='The user to filter on', default='%')
    parser.add_argument("-o", "--output", help='The output to search for', default='%')
    parser.add_argument("-t", "--taskid", help='The taskid to search for', default='%')
    return parser


def get_database_engine(args):
    if args.database_type.lower() == "postgresql":
        database = args.postgres_string
    else:
        database = f"sqlite:///{args.project}/PoshC2.SQLite"

    return create_engine(database, connect_args={"check_same_thread": False}, echo=False)


def main():
    args = create_arg_parser().parse_args()

    if args.command == '%' and args.output == '%' and args.taskid == '%':
        print("%s[-] A minimum of a --command, --taskid or --output search term must be specified%s" % (Colours.RED, Colours.END))
        sys.exit(1)

    engine = get_database_engine(args)

    with pandas.option_context('display.max_rows', None, 'display.max_columns', None, 'display.max_colwidth', -1):
        statement = text(f"SELECT sent_time, completed_time, user, command, output, id FROM tasks WHERE user LIKE '{args.user}' AND command LIKE '%{args.command}%' AND output LIKE '%{args.output}%' AND CAST(id as text) LIKE '%{args.taskid}%';")
        output = pandas.read_sql(statement, engine)

        for entry in output.values:
            print("\n%s[*][*][*] Task %05d Command (Issued: %s by %s):\n%s" % (Colours.GREEN, entry[5], entry[0], entry[2], Colours.END))
            print(entry[3])
            print("\n%s[*][*][*] Task %05d Output (Completed: %s):\n%s" % (Colours.BLUE, entry[5], entry[1], Colours.END))
            print(entry[4])
            print()


if __name__ == '__main__':
    main()
