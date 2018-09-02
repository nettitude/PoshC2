#!/usr/bin/python

import zlib, argparse, os, re, datetime, time, base64, string, random, codecs
from C2Server import *
from Config import *

def default_response():
  return (random.choice(HTTPResponses)).replace("#RANDOMDATA#",randomuri())

def formStr(varstr, instr):
  holder = []
  str1 = ''
  str2 = ''
  str1 = varstr + ' = "' + instr[:56] + '"' 
  for i in xrange(56, len(instr), 48):
    holder.append('"'+instr[i:i+48])
    str2 = '"\r\n'.join(holder)

  str2 = str2 + "\""
  str1 = str1 + "\r\n"+str2
  return "%s;" % str1

def formStrMacro(varstr, instr):
  holder = []
  str1 = ''
  str2 = ''
  str1 = varstr + ' = "' + instr[:54] + '"' 
  for i in xrange(54, len(instr), 48):
    holder.append(varstr + ' = '+ varstr +' + "'+instr[i:i+48])
    str2 = '"\r\n'.join(holder)

  str2 = str2 + "\""
  str1 = str1 + "\r\n"+str2
  return str1


def load_module(module_name):
  file = codecs.open(("%sModules/%s" % (POSHDIR,module_name)), 'r', encoding='utf-8-sig')
  return file.read()

def get_images():
  dir_path = os.path.dirname(os.path.realpath(__file__))
  rootimagedir = "%s/Images/" % dir_path
  images = ""
  for root, dirs, filenames in os.walk(rootimagedir):
    count = 1
    for f in filenames: 
        if count == 5:
          with open(rootimagedir+f, "rb") as image_file:
            image = image_file.read()
            if len(image) < 1500:
              images += "\"%s\"" % (base64.b64encode(image))
        if count < 5:
          with open(rootimagedir+f, "rb") as image_file:
            image = image_file.read()
            if len(image) < 1500:
              images += "\"%s\"," % (base64.b64encode(image))
        count += 1
  return images

def gen_key():
  key = os.urandom(256/8)
  return base64.b64encode(key)

def randomuri(size = 15, chars=string.ascii_letters + string.digits):
  return ''.join(random.choice(chars) for _ in range(size))

# Decrypt a string from base64 encoding 
def get_encryption( key, iv='0123456789ABCDEF' ):
  from Crypto.Cipher import AES
  print AES.block_size
  iv = os.urandom(AES.block_size)
  print iv
  aes = AES.new( base64.b64decode(key), AES.MODE_CBC, iv )
  return aes

# Decrypt a string from base64 encoding 
def decrypt( key, data ):
  iv = data[0:16]
  aes = get_encryption(key, iv)
  data =  aes.decrypt( base64.b64decode(data) )
  return data[16:]

# Decrypt a string from base64 encoding 
def decrypt_bytes_gzip( key, data):
  iv = data[0:16]
  aes = get_encryption(key, iv)
  data =  aes.decrypt( data )
  import StringIO
  import gzip
  infile = StringIO.StringIO(data[16:])
  with gzip.GzipFile(fileobj=infile, mode="r") as f:
    data = f.read()
  return data

# Encrypt a string and base64 encode it
def encrypt( key, data, gzip=False ):
  if gzip:
    print 'Gzipping data - pre-zipped len, ' + str(len(data))
    import StringIO
    import gzip
    out = StringIO.StringIO()
    with gzip.GzipFile(fileobj=out, mode="w") as f:
      f.write(data)
    data = out.getvalue() 

  # Pad with zeros
  mod = len(data) % 16
  if mod != 0:
    newlen = len(data) + (16-mod)
    data = data.ljust( newlen, '\0' )
  aes = get_encryption(key, os.urandom(16))
  # print 'Data len: ' + str(len(data))
  print aes.IV
  data = aes.IV + aes.encrypt( data )
  if not gzip:
    data = base64.b64encode( data )
  return data