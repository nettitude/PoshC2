#!/usr/bin/env python3

import argparse
import sqlite3  # For SQLite raw connection
import sys
from sqlalchemy import create_engine, text
import pandas as pd


class Colours:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    END = '\033[0m'
    YELLOW = '\033[93m'


def create_arg_parser():
    parser = argparse.ArgumentParser(description='Find Posh Command - Search for a PoshC2 Command Output')
    parser.add_argument("-p", "--project", help="The PoshC2 project directory", default="/opt/PoshC2_Project")
    parser.add_argument("-d", "--database_type", help="The database type (SQLite/PostgreSQL)", default="SQLite")
    parser.add_argument("-pg", "--postgres_string", help="The PostgreSQL connection string (if using PostgreSQL)", default="")
    parser.add_argument("-c", "--command", help="The command to search for", default="%")
    parser.add_argument("-u", "--user", help="The user to filter on", default="%")
    parser.add_argument("-o", "--output", help="The output to search for", default="%")
    parser.add_argument("-t", "--taskid", help="The task ID to search for", default="%")
    return parser


def get_database_connection(args):
    """
    Returns a raw DBAPI connection depending on the database type.
    """
    if args.database_type.lower() == "postgresql":
        try:
            import psycopg2
            connection = psycopg2.connect(args.postgres_string)
            return connection
        except Exception as e:
            print(f"{Colours.RED}[-] Failed to connect to PostgreSQL: {e}{Colours.END}")
            sys.exit(1)
    else:
        try:
            db_path = f"{args.project}/PoshC2.SQLite"
            connection = sqlite3.connect(db_path)
            return connection
        except Exception as e:
            print(f"{Colours.RED}[-] Failed to connect to SQLite: {e}{Colours.END}")
            sys.exit(1)


def main():
    args = create_arg_parser().parse_args()

    # Check for minimum search criteria
    if args.command == '%' and args.output == '%' and args.taskid == '%':
        print(f"{Colours.RED}[-] A minimum of a --command, --taskid, or --output search term must be specified.{Colours.END}")
        sys.exit(1)

    # Get a raw database connection
    connection = get_database_connection(args)

    # Define the SQL query with parameterization
    sql_query = """
        SELECT sent_time, completed_time, user, command, output, id
        FROM tasks
        WHERE user LIKE ?
          AND command LIKE ?
          AND output LIKE ?
          AND CAST(id as text) LIKE ?;
    """

    # Define query parameters
    params = (
        f"%{args.user}%",
        f"%{args.command}%",
        f"%{args.output}%",
        f"%{args.taskid}%"
    )

    # Execute the query
    try:
        with pd.option_context('display.max_rows', None, 'display.max_columns', None, 'display.max_colwidth', None):
            output = pd.read_sql_query(sql_query, con=connection, params=params)
    except Exception as e:
        print(f"{Colours.RED}[-] Failed to execute query: {e}{Colours.END}")
        sys.exit(1)
    finally:
        connection.close()

    # Display the results
    if output.empty:
        print(f"{Colours.YELLOW}[!] No results found for the given criteria.{Colours.END}")
    else:
        for entry in output.itertuples(index=False):
            print(f"\n{Colours.GREEN}[*][*][*] Task {entry.id:05d} Command (Issued: {entry.sent_time} by {entry.user}):{Colours.END}")
            print(entry.command)
            print(f"\n{Colours.BLUE}[*][*][*] Task {entry.id:05d} Output (Completed: {entry.completed_time}):{Colours.END}")
            print(entry.output)
            print()


if __name__ == '__main__':
    main()
