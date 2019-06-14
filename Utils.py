import os, base64, string, random, re, argparse, shlex

validate_sleep_regex = re.compile("^[0-9]*[smh]$")

def gen_key():
  key = os.urandom(256//8)
  return base64.b64encode(key)

def formStrMacro(varstr, instr):
  holder = []
  str1 = ''
  str2 = ''
  str1 = varstr + ' = "' + instr[:54] + '"'
  for i in range(54, len(instr), 48):
    holder.append(varstr + ' = '+ varstr +' + "'+instr[i:i+48])
    str2 = '"\r\n'.join(holder)

  str2 = str2 + "\""
  str1 = str1 + "\r\n"+str2
  return str1

def formStr(varstr, instr):
  holder = []
  str1 = ''
  str2 = ''
  str1 = varstr + ' = "' + instr[:56] + '"'
  for i in range(56, len(instr), 48):
    holder.append('"'+instr[i:i+48])
    str2 = '"\r\n'.join(holder)

  str2 = str2 + "\""
  str1 = str1 + "\r\n"+str2
  return "%s;" % str1

def randomuri(size = 15, chars=string.ascii_letters + string.digits):
  return random.choice(string.ascii_letters) + "".join(random.choice(chars) for _ in range(size - 1))

def validate_sleep_time(sleeptime):
  sleeptime = sleeptime.strip()
  return validate_sleep_regex.match(sleeptime)

def argp(cmd):
  args = ""
  try:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-Help', '-help', '-h', action='store', dest='help', required=False)
    parser.add_argument('-Source', '-source', action='store', dest='source', required=True)
    parser.add_argument('-Destination', '-destination', action='store', dest='destination', required=True)
    parser.add_argument('-NotHidden', '-nothidden', action='store', dest='nothidden', required=False)
    args, unknown = parser.parse_known_args(shlex.split(cmd))
  except:
    pass
  return args

def load_file(location):
  fr = None
  try:
    file = open((location), "rb")
    fr = file.read()
  except Exception as e:
    print ("Error loading file %s" % e)
  
  if fr:
    return fr
  else:
    return None