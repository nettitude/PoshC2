#!/usr/bin/env python3

from poshc2.Colours import Colours
from poshc2.server.Core import decrypt
from poshc2.server.database.DB import get_keys, database_connect

import sys, re

file = open(sys.argv[1], "r")
database_connect()
result = get_keys()

if result:
    for line in file:
        if re.search("SessionID", line):
            for i in result:
                try:
                    value = decrypt(i[0], line.split('=')[1])
                    print(Colours.GREEN + "Success with Key %s - %s" % (i[0], value))
                except Exception:
                    print(Colours.RED + "Failed with Key %s" % i[0])
