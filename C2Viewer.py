#!/usr/bin/env python

from Colours import *
from Config import *
from DB import *
from Help import *
import time, os

rows = 10
taskid = 0

try:
  if os.name == 'nt':
    os.system('cls')
  else:
    os.system('clear')
except Exception as e:
  print "cls"
  print chr(27) + "[2J"

print (Colours.GREEN + "")
print (logopic)
print (Colours.END + "")

try:
  taskid = get_seqcount("CompletedTasks") + 1
except Exception as e:
  user = "None"
  taskid = 1

try:
  newtaskid = get_seqcount("NewTasks") + 1
except Exception as e:
  user = "None"
  newtaskid = 1

try:
  implantid = get_seqcount("Implants") + 1
except Exception as e:
  user = "None"
  implantid = 1

print newtaskid
while(1):
  try:
    newtask = get_newtasksbyid(newtaskid)
    hostinfo = get_hostinfo(newtask[1])
    now = datetime.datetime.now()
    command = newtask[2]
    print Colours.YELLOW
    print "Command issued against implant %s on host %s %s (%s)" % (hostinfo[0],hostinfo[3],hostinfo[11],now.strftime("%m/%d/%Y %H:%M:%S"))

    if (command.lower().startswith("$shellcode64")) or (command.lower().startswith("$shellcode64")) :
      print "Loading Shellcode",Colours.END
    elif (command.lower().startswith("$shellcode86")) or (command.lower().startswith("$shellcode86")) :
      print "Loading Shellcode",Colours.END
    elif "upload-file" in command.lower():
      print "Uploading File",Colours.END
    else:
      print command,Colours.END

    newtaskid = newtaskid + 1
  except Exception as e:
    user = "None"

  try:
    completedtask = get_completedtasksbyid(taskid)
    hostinfo = get_hostinfo(completedtask[2])
    now = datetime.datetime.now()
    if hostinfo:
      print Colours.GREEN
      print "Command returned against implant %s on host %s %s (%s)" % (hostinfo[0],hostinfo[3],hostinfo[11],now.strftime("%m/%d/%Y %H:%M:%S"))
      print completedtask[4],Colours.END
      taskid = taskid + 1
  except Exception as e:
    user = "None"

  try:
    implant = get_implantbyid(implantid)
    if implant:
      print Colours.GREEN
      print "New %s implant connected: (uri=%s key=%s) (%s)" % (implant[15], implant[1], implant[5], now.strftime("%m/%d/%Y %H:%M:%S"))
      print "%s | URL:%s | Time:%s | PID:%s | Sleep:%s | %s (%s) " % (implant[4], implant[9], implant[6],
        implant[8], implant[13], implant[11], implant[10])
      print Colours.END
      implantid = implantid + 1
  except Exception as e:
    user = "None"

  time.sleep(1)
      
