import argparse
import base64
import datetime
import functools
import os
import random
import re
import shlex
import string

validate_sleep_regex = re.compile(r"^\d+[smh]$")


def gen_key():
    key = os.urandom(256 // 8)
    return base64.b64encode(key)


def format_macro(varstr, instr):
    holder = []
    str2 = ''
    str1 = varstr + ' = "' + instr[:54] + '"'
    for i in range(54, len(instr), 48):
        holder.append(varstr + ' = ' + varstr + ' + "' + instr[i:i + 48])
        str2 = '"\r\n'.join(holder)

    str2 = str2 + "\""
    str1 = str1 + "\r\n" + str2
    return str1


def build_shellcode_array(prefix, hex_string):
    holder = []
    str2 = ''
    str1 = prefix + ' = "' + hex_string[:56] + '"'
    for i in range(56, len(hex_string), 48):
        holder.append('"' + hex_string[i:i + 48])
        str2 = '"\r\n'.join(holder)

    str2 = str2 + "\""
    return str1 + "\r\n" + str2


# Can pass a list of words to use and it will randomly concatenate those until
# the length is above the size value. If whole_words is set to True it will
# return the full sentence, if False it will strip the sentence to length 'size'
def new_implant_id(size=15, chars=string.ascii_letters + string.digits, words=None, whole_words=False):
    if words is not None:
        result = ""
        while len(result) < size:
            result = result + random.choice(words)
        if whole_words:
            return result
        return result[:size]
    else:
        return random.choice(string.ascii_letters) + "".join(random.choice(chars) for _ in range(size - 1))


def validate_sleep_time(sleep_time):
    if sleep_time is None:
        return None
    sleep_time = sleep_time.strip()
    return validate_sleep_regex.match(sleep_time)


def validate_kill_date(kill_date):
    return validate_timestamp_string(kill_date, '%Y-%m-%d')


def argp(cmd):
    args = ""
    try:
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument('-Help', '-help', '-h', action='store', dest='help', required=False)
        parser.add_argument('-Source', '-source', action='store', dest='source', required=True)
        parser.add_argument('-Destination', '-destination', action='store', dest='destination', required=True)
        parser.add_argument('-NotHidden', '-nothidden', action='store', dest='nothidden', required=False)
        args, unknown = parser.parse_known_args(shlex.split(cmd))
    except Exception:
        pass
    return args


def load_file(location):
    fr = None
    try:
        file = open(location, "rb")
        fr = file.read()
    except Exception as e:
        print("Error loading file %s" % e)

    if fr:
        return fr
    else:
        return None


def parse_creds(all_creds):
    creds = ""
    hashes = ""

    if all_creds is None:
        return creds, hashes

    for cred in all_creds:
        if cred is not None:
            if cred.password is not None and cred.password != "":
                creds += str(cred.id) + ": " + str(cred.domain) + "\\" + str(cred.username) + " : " + str(
                    cred.password) + "\n"

            if cred.hash is not None and cred.hash != "":
                hashes += str(cred.id) + ": " + str(cred.domain) + "\\" + str(cred.username) + " : " + str(
                    cred.hash) + "\n"

    return creds, hashes


def string_to_array(string_arg):
    y = ""
    p = string_arg.replace(" ", "")
    x = p.split(",")
    c = 0

    for i in x:
        if c > 0:
            y += f",\"{i}\""
        else:
            y += f"\"{i}\""
        c += 1

    return y, c


def get_first_domainfront_header(domain_front_header):
    domain_front_header = domain_front_header.replace('"', '')

    if domain_front_header:
        if "," in domain_front_header:
            return domain_front_header.split(',')[0]
        return domain_front_header
    return None


def get_first_url(payload_comms_host, domain_front_header):
    payload_comms_host = payload_comms_host.replace('"', '')
    if not domain_front_header:
        domain_front_header = ""
    else:
        domain_front_header = domain_front_header.replace('"', '')

    if domain_front_header:
        if "," in domain_front_header:
            domain = domain_front_header.split(',')[0]
        else:
            domain = domain_front_header

        if payload_comms_host.startswith("http://"):
            return f"http://{domain}"
        return f"https://{domain}"
    else:
        if "," in payload_comms_host:
            return payload_comms_host.split(',')[0]
        return payload_comms_host


def offset_finder(filepath):
    with open(filepath, "rb") as input_file:
        file = input_file.read()
        file = base64.b64decode(file)

    try:
        offset = file.index(b'\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41')

        iterator = offset
        patch_placeholder_length = 0

        while file[iterator] == 0x41:
            patch_placeholder_length += 1
            iterator += 1

        return offset, patch_placeholder_length
    except ValueError:
        offset = file.index(b'\x41\x00\x41\x00\x41\x00\x41\x00\x41\x00\x41\x00\x41\x00\x41\x00')

        iterator = offset
        patch_placeholder_length = 0

        while file[iterator] == 0x41 and file[iterator + 1] == 0x00:
            patch_placeholder_length += 2
            iterator += 2

        return offset, patch_placeholder_length


def yes_no_prompt(message):
    ri = input(f"{message} (Y/n) ")
    if ri.lower() == "n":
        return False
    if ri == "" or ri.lower() == "y":
        return True


def no_yes_prompt(message):
    ri = input(f"{message} (N/y) ")
    if ri == "" or ri.lower() == "n":
        return False
    if ri.lower() == "y":
        return True


def validate_timestamp_string(timestamp_string, format_string):
    if not timestamp_string:
        return False
    timestamp_string = timestamp_string.strip()
    try:
        datetime.datetime.strptime(timestamp_string, format_string)
        return True
    except ValueError:
        return False


def command(commands, commands_help, examples, block_help, tags=None, name=None):
    """
    Decorator that adds a function as an implant command. Here in the implant handler that means it is a common command to all PoshC2 implant types, such as set-beacon.

    The command is added as the function name, but _s in the function name are replaced with -s for the command.
    If the function name starts with 'do_', this is stripped.

    An additional command name can also be specified.

    Once the command is prepared it is added to the 'commands' dictionary that is passed into the enclosing function.
    """

    def decorator(func):

        if name:
            commands[name] = func
            commands_help[name] = func.__doc__

        command_name = func.__name__
        if command_name.startswith("do_"):
            command_name = command_name[3:]
        command_name = command_name.replace("_", "-")
        commands[command_name] = func
        commands_help[command_name] = func.__doc__

        in_examples = False
        for line in func.__doc__.split("\n"):
            line = line.strip()
            if not line:
                continue
            if "Examples:" in line:
                in_examples = True
                continue
            if not in_examples:
                continue
            examples.append(line)

        if tags:
            for tag in tags:
                tag = tag.get_friendly_name()
                if tag not in block_help:
                    block_help[tag] = ""
                block_help[tag] += f"{command_name}\n"
        else:
            if "Uncategorised" not in block_help:
                block_help["Uncategorised"] = ""
            block_help["Uncategorised"] += f"{command_name}\n"

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(args, kwargs)

        return wrapper

    return decorator


def get_command_word(command):
    if len(command.split()) > 0:
        return command.split()[0].strip()
    else:
        return command.strip()
