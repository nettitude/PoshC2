import os, base64, random, codecs, glob, readline, re
from poshc2.server.Config import HTTPResponses, PoshInstallDirectory, PayloadsDirectory, BeaconDataDirectory, ModulesDirectory
from poshc2.Utils import randomuri
from poshc2.client.cli.TabComplete import tabCompleter
from poshc2.client.Help import COMMANDS
from poshc2.server.DB import get_cred_by_id
from poshc2.Colours import Colours


def number_of_days(date1, date2): 
    return (date2-date1).days 

def default_response():
    return bytes((random.choice(HTTPResponses)).replace("#RANDOMDATA#", randomuri()), "utf-8")


def load_module(module_name):
    file = codecs.open(("%s%s" % (ModulesDirectory, module_name)), 'r', encoding='utf-8-sig')
    return file.read()


def load_module_sharp(module_name):
    file = open(("%s%s" % (ModulesDirectory, module_name)), 'r+b')
    return base64.b64encode(file.read()).decode("utf-8")


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


def encrypt(key, data, gzip=False):
    if gzip:
        print("Gzipping data - pre-zipped len, " + str(len(data)))
        import StringIO
        import gzip
        out = StringIO.StringIO()
        with gzip.GzipFile(fileobj=out, mode="w") as f:
            f.write(data)
        data = out.getvalue()

    # Pad with zeros
    mod = len(data) % 16
    if mod != 0:
        newlen = len(data) + (16 - mod)
        data = data.ljust(newlen, '\0')
    aes = get_encryption(key, os.urandom(16))
    data = aes.IV + aes.encrypt(data)
    if not gzip:
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


def creds(accept_hashes = True):
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