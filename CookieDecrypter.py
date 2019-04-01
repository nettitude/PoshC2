#!/usr/bin/python

from Colours import Colours
from Core import decrypt 
from DB import get_keys
import os, sys, re

file = open(sys.argv[1], "r")
result = get_keys()

if result:
     for line in file:
          if re.search("SessionID", line):
          	for i in result:
                    try:
                         value = decrypt(i[0], line.split('=')[1]) 
                         print (Colours.GREEN + "Success with Key %s - %s" % (i[0],value))
                    except: 
                         print (Colours.RED + "Failed with Key %s" % i[0])

