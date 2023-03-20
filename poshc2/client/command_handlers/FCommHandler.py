from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style

from poshc2.Utils import get_command_word
from poshc2.client.Alias import cs_alias, cs_replace
from poshc2.client.cli.AutosuggestionAggregator import AutosuggestionAggregator
from poshc2.client.cli.CommandPromptCompleter import FirstWordCompleter
from poshc2.client.cli.PoshExamplesAutosuggestions import AutoSuggestFromPoshExamples
from poshc2.client.command_handlers.CommonCommands import common_implant_commands, common_implant_commands_help, common_implant_examples, common_block_help
from poshc2.client.command_handlers.SharpHandler import commands as sharp_commands, examples as sharp_examples
from poshc2.server.AutoLoads import run_sharp_autoloads
from poshc2.server.Config import PoshProjectDirectory
from poshc2.server.Core import get_parent_implant
from poshc2.server.ImplantType import ImplantType
from poshc2.server.database.Helpers import insert_object, get_implant_by_numeric_id
from poshc2.server.database.Model import NewTask

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
    '': '#772953',
})

autosuggester = AutoSuggestFromPoshExamples(examples)


def fc_prompt(prefix):
    session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/{ImplantType.SharpFComm.get_history_file()}'),
                            auto_suggest=AutosuggestionAggregator([AutoSuggestFromHistory(), autosuggester]), style=style)
    completions = list(commands.keys())
    completions.extend(examples)
    return session.prompt(f'{prefix}> ', completer=FirstWordCompleter(completions, WORD=True))


def handle_fcomm_command(command, user, parent_implant_id, handler_numeric_id):
    parent_implant = get_parent_implant(parent_implant_id)
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

    run_sharp_autoloads(command, parent_implant.id, user, load_module_command=f"fcomm-load-module {handler_numeric_id}")
    command_word = get_command_word(command)

    if command_word.startswith("load-module"):
        if " " in command:
            module_name = command.split()[1]
            new_task = NewTask(
                implant_id=parent_implant.id,
                command=f"fcomm-load-module {handler_numeric_id} {module_name}",
                user=user,
                child_implant_id=None
            )

            insert_object(new_task)
        else:
            print_bad("Please provide a module to load")
        return

    if command_word in commands:
        if command_word in common_implant_commands:
            implant = get_implant_by_numeric_id(handler_numeric_id)
            commands[command_word](user, command, implant.id, f"fcomm-command {handler_numeric_id}")
        else:
            commands[command_word](user, command, parent_implant.id, f"fcomm-command {handler_numeric_id}")
        return

    if command:
        new_task = NewTask(
            implant_id=parent_implant.id,
            command=f"fcomm-command {handler_numeric_id} {command}",
            user=user,
            child_implant_id=None
        )

        insert_object(new_task)


def get_commands():
    return commands.keys()
