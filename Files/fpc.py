#!/usr/bin/env python

import sys, argparse, sqlite3, os, pandas


def create_arg_parser():
	parser = argparse.ArgumentParser(description='Search for a PoshC2 Command Output')
	parser.add_argument("-p", "--project", help='The PoshC2 project dir', default = '/opt/PoshC2_Project')
	parser.add_argument("-c", "--command", help='The command to search for', default = '%')
	parser.add_argument("-u", "--user", help='The user to filter on', default = '%')
	parser.add_argument("-o", "--output", help='The output to search for', default = '%')
	return parser

def main():
	args = create_arg_parser().parse_args()
	if args.command == '%' and args.output == '%':
		print("[-] A minimum of a --command or --output search term must be specified")
		sys.exit(1)
	conn = sqlite3.connect(os.path.join(args.project, 'PowershellC2.SQLite'))
	with pandas.option_context('display.max_rows', None, 'display.max_columns', None, 'display.max_colwidth', -1):
		print (str(pandas.read_sql_query("SELECT Command,Output from Tasks where User like '%s' and Command like '%%%s%%' and Output like '%%%s%%'" % (args.user, args.command, args.output), conn)).replace('\\r', '\r').replace('\\n', '\n'))

if __name__ == '__main__':
	main()
