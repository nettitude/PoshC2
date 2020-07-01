import os, base64, string, random, re, argparse, shlex, datetime

validate_sleep_regex = re.compile("^[0-9]+[smh]$")


def gen_key():
    key = os.urandom(256 // 8)
    return base64.b64encode(key)


def formStrMacro(varstr, instr):
    holder = []
    str1 = ''
    str2 = ''
    str1 = varstr + ' = "' + instr[:54] + '"'
    for i in range(54, len(instr), 48):
        holder.append(varstr + ' = ' + varstr + ' + "' + instr[i:i + 48])
        str2 = '"\r\n'.join(holder)

    str2 = str2 + "\""
    str1 = str1 + "\r\n" + str2
    return str1


def formStr(varstr, instr):
    holder = []
    str1 = ''
    str2 = ''
    str1 = varstr + ' = "' + instr[:56] + '"'
    for i in range(56, len(instr), 48):
        holder.append('"' + instr[i:i + 48])
        str2 = '"\r\n'.join(holder)

    str2 = str2 + "\""
    str1 = str1 + "\r\n" + str2
    return "%s;" % str1


def randomuri(size=15, chars=string.ascii_letters + string.digits):
    return random.choice(string.ascii_letters) + "".join(random.choice(chars) for _ in range(size - 1))


def validate_sleep_time(sleeptime):
    if sleeptime is None:
        return None
    sleeptime = sleeptime.strip()
    return validate_sleep_regex.match(sleeptime)


def validate_killdate(killdate):
    if not killdate:
        return False
    killdate = killdate.strip()
    try :
        datetime.datetime.strptime(killdate, '%Y-%m-%d')
        return True
    except ValueError :
        pass
    return False


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
        file = open((location), "rb")
        fr = file.read()
    except Exception as e:
        print("Error loading file %s" % e)

    if fr:
        return fr
    else:
        return None


def parse_creds(allcreds):
    creds = ""
    hashes = ""
    if allcreds is None:
        return (creds, hashes)
    for cred in allcreds:
        if cred is not None:
            if cred[3] is not None and cred[3] != "":
                creds += str(cred[0]) + ": " + str(cred[1]) + "\\" + str(cred[2]) + " : " + str(cred[3]) + "\n"
            if cred[4] is not None and cred[4] != "":
                hashes += str(cred[0]) + ": " + str(cred[1]) + "\\" + str(cred[2]) + " : " + str(cred[4]) + "\n"
    return (creds, hashes)

def string_to_array(stringarg):
    y = ""
    x = []

    try:
        p = stringarg.replace(" ", "")
        x = p.split(",")
        x = x.replace(" ", "")
    except:
        pass
    c = 0
    for i in x:
        if c > 0:
            y += f",\"{i}\""
        else:
            y += f"\"{i}\""
        c += 1

    return(y, c)


def get_first_url(PayloadCommsHost, DomainFrontHeader):
    try:
        domains = PayloadCommsHost.split(",")
        domains = domains[0]
    except:
        domains = PayloadCommsHost

    domain_name = domains.replace("\"", "")

    try:
        headers = DomainFrontHeader.split(",")
        headers = headers[0]
    except:
        headers = DomainFrontHeader

    hostheader_name = headers.replace("\"", "")

    if hostheader_name != "":
        try:
            ma = re.match(r'(^\S*:\S*:).*', domain_name).group(1)
            if ma:
                hostheader_name += ":" + domain_name.replace(ma, "")
        except:
            pass

        if "https://" in domain_name:
            hostheader_name = f"https://{hostheader_name}"
        else:
            hostheader_name = f"http://{hostheader_name}"

    else:
        hostheader_name = domain_name

    return hostheader_name


def offsetFinder(filepath):
    with open(filepath, "rb") as input_file:
        file = input_file.read()
        file = base64.b64decode(file)
    try:
        offset = hex(file.index(b'\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41'))
        return(int(offset, 0))
    except ValueError:        
        offset = hex(file.index(b'\x41\x00\x41\x00\x41\x00\x41\x00\x41\x00\x41\x00\x41\x00\x41\x00'))
        return(int(offset, 0))