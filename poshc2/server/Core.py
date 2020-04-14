import os, base64, random, codecs, glob, readline, re, gzip, io
from poshc2.server.Config import POST_200_Responses, PayloadsDirectory, BeaconDataDirectory, ModulesDirectory, DatabaseType
from poshc2.Utils import randomuri
from poshc2.client.cli.TabComplete import tabCompleter
from poshc2.client.Help import COMMANDS
from poshc2.Colours import Colours

if DatabaseType.lower() == "postgres":
    from poshc2.server.database.DBPostgres import get_cred_by_id, insert_cred
else:
    from poshc2.server.database.DBSQLite import get_cred_by_id, insert_cred


def number_of_days(date1, date2):
    return (date2 - date1).days


def default_response():
    return bytes((random.choice(POST_200_Responses)).replace("#RANDOMDATA#", randomuri()), "utf-8")


def load_module(module_name):
    if module_name.startswith("/"):
        module_source = codecs.open(module_name, 'r', encoding='utf-8-sig')
    else:
        module_source = codecs.open(("%s%s" % (ModulesDirectory, module_name)), 'r', encoding='utf-8-sig')
    return module_source.read()


def load_module_sharp(module_name):
    if module_name.startswith("/"):
        module_source = open(module_name, 'r+b')
    else:
        module_source = open(("%s%s" % (ModulesDirectory, module_name)), 'r+b')
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
                        images += "\"%s\"" % (base64.b64encode(image).decode("utf-8"))
            if count < 5:
                with open(BeaconDataDirectory + f, "rb") as image_file:
                    image = image_file.read()
                    if len(image) < 1500:
                        images += "\"%s\"," % (base64.b64encode(image).decode("utf-8"))
            count += 1
    return images


# Decrypt a string from base64 encoding
def get_encryption(key, iv='0123456789ABCDEF'):
    from Crypto.Cipher import AES
    iv = os.urandom(AES.block_size)
    bkey = base64.b64decode(key)
    aes = AES.new(bkey, AES.MODE_CBC, iv)
    return aes

# Decrypt a string from base64 encoding


def decrypt(key, data):
    iv = data[0:16]
    aes = get_encryption(key, iv)
    data = aes.decrypt(base64.b64decode(data))
    return data[16:].decode("utf-8")

# Decrypt a string from base64 encoding


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

# Encrypt a string and base64 encode it


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
    if mod != 0:
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


def shellcodefilecomplete(text, state):
    os.chdir(PayloadsDirectory)
    return (glob.glob(text + '*' + ".bin") + [None])[state]


def shellcodereadfile_with_completion(message):
    readline.set_completer(shellcodefilecomplete)
    path = input(message)
    t = tabCompleter()
    t.createListCompleter(COMMANDS)
    readline.set_completer(t.listCompleter)
    return path


def readfile_with_completion(message):
    readline.set_completer(filecomplete)
    path = input(message)
    t = tabCompleter()
    t.createListCompleter(COMMANDS)
    readline.set_completer(t.listCompleter)
    return path


def get_creds_from_params(params, user):
    if "-credid" in params:
        p = re.compile(r"-credid (\w*)")
        credId = re.search(p, params)
        params = p.sub("", params)
        if credId:
            credId = credId.group(1)
        else:
            print(Colours.RED, "Please specify a credid", Colours.GREEN)
        creds = get_cred_by_id(credId)
        if creds is None:
            print(Colours.RED, "Unrecognised CredID: %s" % credId, Colours.GREEN)
        return (creds, params)
    else:
        print(Colours.RED, "Command does not contain -credid", Colours.GREEN)


def creds(accept_hashes=True):
    '''
    Decorator around commands that allows credentials to be passed as '-credid <id>' parameters with an appropriate ID.

    Wraps the function replacing '-credid <id>' with '-domain <domain> -user <user> -pass <password>' (or '-hash <hash>' if the credid is a hash type).

    The wrapped function must take the arguments 'user, command, randomuri'.

    The decorator can take an 'accept_hashes' argument, e.g. '@creds(accept_hashes = False)' to disable the use of hash credential IDs.
    '''

    def decorator(func):

        def wrapper(*args, **kwargs):

            user = args[0]
            command = args[1]
            randomuri = args[2]

            if "-credid" in command:
                creds, command = get_creds_from_params(command, user)
                if creds is None:
                    return
                if creds['Password']:
                    command = command + " -domain %s -user %s -pass %s" % (creds['Domain'], creds['Username'], creds['Password'])
                elif not accept_hashes:
                    print_bad("This command does not support hash authentication")
                    return
                else:
                    command = command + " -domain %s -user %s -hash %s" % (creds['Domain'], creds['Username'], creds['Hash'])
            output = func(user, command, randomuri)
            return output

        return wrapper

    return decorator


def print_good(message):
    print(Colours.GREEN)
    print(message)


def print_bad(message):
    print(Colours.RED)
    print(message)
    print(Colours.GREEN)


def process_mimikatz(lines):
    # code source https://github.com/stufus/parse-mimikatz-log/blob/master/pml.py
    main_count = 0
    current = {}
    for line in lines.split('\n'):
        main_count += 1
        val = re.match(r'^\s*\*\s+Username\s+:\s+(.+)\s*$', line.strip())
        if val is not None:
            current = {}
            current['Username'] = val.group(1).strip()
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
                    insert_cred(current['Domain'], current['Username'], current['Password'], None)
                elif val.group(1) == "NTLM":
                    if val.group(2) == '(null)':
                        continue
                    insert_cred(current['Domain'], current['Username'], None, current['NTLM'])
