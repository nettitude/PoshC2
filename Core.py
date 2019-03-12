#!/usr/bin/python

import zlib, argparse, os, re, datetime, time, base64, string, random, codecs, glob
from Config import HTTPResponses, POSHDIR, PayloadsDirectory
from Utils import randomuri 
from TabComplete import readline, tabCompleter
from Help import COMMANDS

def default_response():
  return (random.choice(HTTPResponses)).replace("#RANDOMDATA#",randomuri())

def load_module(module_name):
  file = codecs.open(("%sModules/%s" % (POSHDIR,module_name)), 'r', encoding='utf-8-sig')
  return file.read()

def load_module_sharp(module_name):
  file = open(("%sModules/%s" % (POSHDIR,module_name)), 'r+b')
  return base64.b64encode(file.read())

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

# Decrypt a string from base64 encoding
def get_encryption(key, iv='0123456789ABCDEF'):
  from Crypto.Cipher import AES
  iv = os.urandom(AES.block_size)
  aes = AES.new(base64.b64decode(key), AES.MODE_CBC, iv)
  return aes

# Decrypt a string from base64 encoding
def decrypt(key, data):
  iv = data[0:16]
  aes = get_encryption(key, iv)
  data =  aes.decrypt(base64.b64decode(data))
  return data[16:]

# Decrypt a string from base64 encoding
def decrypt_bytes_gzip(key, data):
  iv = data[0:16]
  aes = get_encryption(key, iv)
  data =  aes.decrypt(data)
  import StringIO
  import gzip
  infile = StringIO.StringIO(data[16:])
  with gzip.GzipFile(fileobj=infile, mode="r") as f:
    data = f.read()
  return data

# Encrypt a string and base64 encode it
def encrypt(key, data, gzip=False):
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
    data = data.ljust(newlen, '\0')
  aes = get_encryption(key, os.urandom(16))
  data = aes.IV + aes.encrypt(data)
  if not gzip:
    data = base64.b64encode(data)
  return data

def filecomplete(text, state):
  os.chdir(PayloadsDirectory)
  return (glob.glob(text+'*')+[None])[state]

def readfile_with_completion(message):
  readline.set_completer(filecomplete)
  path = raw_input(message)
  t = tabCompleter()
  t.createListCompleter(COMMANDS)
  readline.set_completer(t.listCompleter)
  return path