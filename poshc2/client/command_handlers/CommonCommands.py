import os
import re

from poshc2 import Colours
from poshc2.Utils import command, validate_sleep_time
from poshc2.server.AutoLoads import check_module_loaded
from poshc2.server.Config import PoshProjectDirectory, ModulesDirectory
from poshc2.server.Core import print_bad, clear
from poshc2.server.ImplantType import ImplantType
from poshc2.server.Pipelines import initiate_pipeline
from poshc2.server.database.Helpers import insert_object, update_object, get_implant
from poshc2.server.database.Model import NewTask, Implant

common_implant_commands = {}
common_implant_commands_help = {}
common_implant_examples = []
common_block_help = {}


@command(common_implant_commands, common_implant_commands_help, common_implant_examples, common_block_help)
def do_label_implant(user, command, implant_id, command_prefix=""):
    """
    Label the implant with a user defined label.

    The label is visible in blue on the far right of the implant details in the ImplantHandler.

    Examples:
        label-implant backup
    """
    label = command.replace('label-implant', '').strip()
    implant = get_implant(implant_id)
    implant_type = ImplantType.get(implant.type)

    if implant_type.is_pbind_implant():
        print("Cannot re-label a PBind implant at this time")
    else:
        update_object(Implant, {Implant.label: label}, {Implant.id: implant_id})


@command(common_implant_commands, common_implant_commands_help, common_implant_examples, common_block_help)
def do_remove_label(user, command, implant_id, command_prefix=""):
    """
    Remove the label from this implant.

    Examples:
        remove-label
    """
    implant = get_implant(implant_id)
    implant_type = ImplantType.get(implant.type)

    if implant_type.is_pbind_implant():
        print("Cannot re-label a PBind implant at this time")
    else:
        update_object(Implant, {Implant.label: ""}, {Implant.id: implant_id})


@command(common_implant_commands, common_implant_commands_help, common_implant_examples, common_block_help)
def do_beacon(user, command, implant_id, command_prefix=""):
    """
    Set the beacon time for this implant.

    Examples:
        beacon 60s
        beacon 10m
        beacon 2h
    """
    new_sleep = command.replace('beacon ', '').strip()

    if not validate_sleep_time(new_sleep):
        print_bad("Invalid sleep command, please specify a time such as 50s, 10m or 1h")
    else:
        new_task = NewTask(
            implant_id=implant_id,
            command=f"{command_prefix} {command}" if command_prefix else command,
            user=user,
            child_implant_id=None
        )

        insert_object(new_task)


@command(common_implant_commands, common_implant_commands_help, common_implant_examples, common_block_help)
def do_unhide_implant(user, command, implant_id, command_prefix=""):
    """
    Un-hides the implant from the ImplantHandler list.

    Examples:
        unhide-implant
    """
    update_object(Implant, {Implant.alive: "Yes"}, {Implant.id: implant_id})


@command(common_implant_commands, common_implant_commands_help, common_implant_examples, common_block_help)
def do_hide_implant(user, command, implant_id, command_prefix=""):
    """
    Hides the implant from the ImplantHandler list.

    Examples:
        hide-implant
    """
    update_object(Implant, {Implant.alive: "No"}, {Implant.id: implant_id})


@command(common_implant_commands, common_implant_commands_help, common_implant_examples, common_block_help)
def do_search_history(user, command, implant_id, command_prefix=""):
    """
    Search through comand history for commands containing a search term.

    The search is case insensitive.

    Examples:
        search-history mimikatz
    """
    search_term = command.replace("search-history ", "")
    implant = get_implant(implant_id)
    implant_type = ImplantType.get(implant.type)

    with open(f'{PoshProjectDirectory}/{implant_type.get_history_file()}') as history_file:
        for line in history_file:
            if search_term in line.lower():
                print(Colours.GREEN + line.replace("+", ""))


@command(common_implant_commands, common_implant_commands_help, common_implant_examples, common_block_help)
def do_back(user, command, implant_id, command_prefix=""):
    """
    Go back to the ImplantHandler.

    Examples:
        back
    """
    clear()
    pass


@command(common_implant_commands, common_implant_commands_help, common_implant_examples, common_block_help)
def do_run_pipeline(user, command, implant_id, command_prefix=""):
    """
    Starts a Jenkins pipeline job and caches the result in the local modules directory.

    Will overwrite any existing file with the same name locally. The job name parameter must match the job name in Jenkins.

    Examples:
        run-pipeline Seatbelt
    """
    params = re.compile("run-pipeline ", re.IGNORECASE)
    params = params.sub("", command)
    res = params.split()
    module = res[0]

    try:
        initiate_pipeline(module, False)
    except Exception as e:
        print(f"Error: {command}: {e}")


@command(common_implant_commands, common_implant_commands_help, common_implant_examples, common_block_help)
def do_list_modules(user, command, implant_id, command_prefix=""):
    """
    List available modules supported by this implant type.

    Examples:
        list-modules
    """
    modules = os.listdir(ModulesDirectory)
    modules = sorted(modules, key=lambda s: s.lower())
    implant = get_implant(implant_id)
    implant_type = ImplantType.get(implant.type)
    print("")
    print("[+] Available modules:")
    print("")

    for mod in modules:
        if implant_type.supports_module(mod):
            print(mod)


@command(common_implant_commands, common_implant_commands_help, common_implant_examples, common_block_help)
def do_list_loaded_modules(user, command, implant_id, command_prefix=""):
    """
    List modules loaded into memory for this implant.

    Examples:
        list-loaded-modules
    """
    new_task = NewTask(
        implant_id=implant_id,
        command=f"{command_prefix} listmodules" if command_prefix else "listmodules",
        user=user,
        child_implant_id=None
    )

    insert_object(new_task)
    print("")
    print("[+] Loaded modules:")
    print(get_loaded_modules(implant_id))


@command(common_implant_commands, common_implant_commands_help, common_implant_examples, common_block_help)
def do_load_module(user, command, implant_id, command_prefix=""):
    """
    Loads a module into memory for execution.

    Ths module itself does not touch disk at any point, however if its execution
    involves writing to disk that will occur as expected.

    Note most in-built commands will automatically load relevant modules.

    Examples:
        load-module MyModule.exe
    """
    if command_prefix:
        command_prefix = command_prefix.replace("command", "load-module")

    params = re.compile("load-module ", re.IGNORECASE)
    params = params.sub("", command)
    check_module_loaded(params, implant_id, user, load_module_command=command_prefix)


@command(common_implant_commands, common_implant_commands_help, common_implant_examples, common_block_help)
def do_run_temp_appdomain(user, command, implant_id, command_prefix=""):
    """
    Loads a module into a temporary appdomain for execution.

    Ths module itself does not touch disk at any point, however if its execution
    involves writing to disk that will occur as expected.

    Examples:
        run-temp-appdomain Seatbelt.exe -group=user
    """
    if command_prefix:
        command_prefix = command_prefix.replace("command", "run-temp-appdomain")

    params = re.compile("run-temp-appdomain ", re.IGNORECASE)
    params = params.sub("", command)

    load_appdomain_command = "run-temp-appdomain"

    try:
        new_task = NewTask(
            implant_id=implant_id,
            command=f"{load_appdomain_command} {params}",
            user=user,
            child_implant_id=None
        )

        insert_object(new_task)
    except Exception as e:
        print(f"Error: {command}: {e}")


@command(common_implant_commands, common_implant_commands_help, common_implant_examples, common_block_help)
def do_force_load_module(user, command, implant_id, command_prefix=""):
    """
    Loads a module into memory forcibly overwriting an already loaded module of the same name.

    Examples:
        force-load-module MyModule.exe
    """
    if command_prefix:
        command_prefix = command_prefix.replace("command", "load-module")

    params = re.compile("force-load-module ", re.IGNORECASE)
    params = params.sub("", command)
    check_module_loaded(params, implant_id, user, force=True, load_module_command=command_prefix)
