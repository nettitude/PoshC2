import os

from poshc2.server.Config import ModulesDirectory, PipelineEnabled
from poshc2.server.Pipelines import check_pipeline_status
from poshc2.server.database.Helpers import insert_object, update_object, get_loaded_modules
from poshc2.server.database.Model import NewTask, Implant


def check_module_loaded(module_name, implant_id, user, force=False, load_module_command=""):
    if not load_module_command:
        load_module_command = "load-module"
    else:
        load_module_command = load_module_command.replace("command", "load-module")
    try:
        if PipelineEnabled:
            if ".exe" in module_name.lower() or ".dll" in module_name.lower():
                check_pipeline_status(module_name)

        if force:
            for modname in os.listdir(ModulesDirectory):
                if modname.lower() == module_name.lower():
                    module_name = modname

            new_task = NewTask(
                implant_id=implant_id,
                command=f"{load_module_command} {module_name}",
                user=user,
                child_implant_id=None
            )

            insert_object(new_task)
            update_object(Implant, {Implant.loaded_modules: module_name}, {Implant.id: implant_id})

        modules_loaded = get_loaded_modules(implant_id)

        if modules_loaded:
            new_modules_loaded = f"{modules_loaded} {module_name}"

            if module_name not in modules_loaded:
                for modname in os.listdir(ModulesDirectory):
                    if modname.lower() == module_name.lower():
                        module_name = modname

                new_task = NewTask(
                    implant_id=implant_id,
                    command=f"{load_module_command} {module_name}",
                    user=user,
                    child_implant_id=None
                )

                insert_object(new_task)
                update_object(Implant, {Implant.loaded_modules: new_modules_loaded}, {Implant.id: implant_id})
        else:
            new_modules_loaded = module_name

            new_task = NewTask(
                implant_id=implant_id,
                command=f"{load_module_command} {module_name}",
                user=user,
                child_implant_id=None
            )

            insert_object(new_task)
            update_object(Implant, {Implant.loaded_modules: new_modules_loaded}, {Implant.id: implant_id})
    except Exception as e:
        print(f"Error: {load_module_command} {module_name}: {e}")


def run_powershell_autoloads(command, implant_id, user, load_module_command="load-module"):
    command = command.lower().strip()
    if command.startswith("invoke-eternalblue"):
        check_module_loaded("Exploit-EternalBlue.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-screenshotallwindows"):
        check_module_loaded("Get-ScreenshotAllWindows.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-psuacme"):
        check_module_loaded("Invoke-PsUACme.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-bloodhound"):
        check_module_loaded("SharpHound.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("brute-ad"):
        check_module_loaded("Brute-AD.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("brute-locadmin"):
        check_module_loaded("Brute-LocAdmin.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("bypass-uac"):
        check_module_loaded("Bypass-UAC.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("cred-popper"):
        check_module_loaded("Cred-Popper.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("cve-2016-9192"):
        check_module_loaded("CVE-2016-9192.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("convertto-shellcode"):
        check_module_loaded("ConvertTo-Shellcode.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("decrypt-rdcman"):
        check_module_loaded("Decrypt-RDCMan.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("dump-ntds"):
        check_module_loaded("Dump-NTDS.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-computerinfo"):
        check_module_loaded("Get-ComputerInfo.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-creditcarddata"):
        check_module_loaded("Get-CreditCardData.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-gppautologon"):
        check_module_loaded("Get-GPPAutologon.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-gpppassword"):
        check_module_loaded("Get-GPPPassword.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-idletime"):
        check_module_loaded("Get-IdleTime.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-ipconfig"):
        check_module_loaded("Get-IPConfig.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-keystrokes"):
        check_module_loaded("Get-Keystrokes.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-hash"):
        check_module_loaded("Get-Hash.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-locadm"):
        check_module_loaded("Get-LocAdm.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-mshotfixes"):
        check_module_loaded("Get-MSHotFixes.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-netstat"):
        check_module_loaded("Get-Netstat.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-passnotexp"):
        check_module_loaded("Get-PassNotExp.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-passpol"):
        check_module_loaded("Get-PassPol.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-recentfiles"):
        check_module_loaded("Get-RecentFiles.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-serviceperms"):
        check_module_loaded("Get-ServicePerms.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-userinfo"):
        check_module_loaded("Get-UserInfo.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-wlanpass"):
        check_module_loaded("Get-WLANPass.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-domaingroupmember"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-kerberoast"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("resolve-ipaddress"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-userhunter"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-netlocalgroupmember"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-daisychain"):
        check_module_loaded("invoke-daisychain.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-hostenum"):
        check_module_loaded("HostEnum.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("inject-shellcode"):
        check_module_loaded("Inject-Shellcode.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("inveigh-relay"):
        check_module_loaded("Inveigh-Relay.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("inveigh"):
        check_module_loaded("Inveigh.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-inveigh"):
        check_module_loaded("Inveigh.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-arpscan"):
        check_module_loaded("Invoke-Arpscan.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("arpscan"):
        check_module_loaded("Invoke-Arpscan.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-dcsync"):
        check_module_loaded("Invoke-DCSync.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-eventvwrbypass"):
        check_module_loaded("Invoke-EventVwrBypass.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-hostscan"):
        check_module_loaded("Invoke-Hostscan.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-ms16-032-proxy"):
        check_module_loaded("Invoke-MS16-032-Proxy.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-ms16-032"):
        check_module_loaded("Invoke-MS16-032.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-mimikatz"):
        check_module_loaded("Invoke-Mimikatz.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-psinject"):
        check_module_loaded("Invoke-PSInject.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-pipekat"):
        check_module_loaded("Invoke-Pipekat.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-portscan"):
        check_module_loaded("Invoke-Portscan.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-powerdump"):
        check_module_loaded("Invoke-PowerDump.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-psexec"):
        check_module_loaded("Invoke-SMBExec.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-reflectivepeinjection"):
        check_module_loaded("Invoke-ReflectivePEInjection.ps1", implant_id, user,
                            load_module_command=load_module_command)
    elif command.startswith("invoke-reversednslookup"):
        check_module_loaded("Invoke-ReverseDnsLookup.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-runas"):
        check_module_loaded("Invoke-RunAs.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("runas-netonly"):
        check_module_loaded("RunAs-NetOnly.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-smblogin"):
        check_module_loaded("Invoke-SMBExec.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-smbclient"):
        check_module_loaded("Invoke-SMBClient.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-smbexec"):
        check_module_loaded("Invoke-SMBExec.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-psexec"):
        check_module_loaded("Invoke-SMBExec.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-shellcode"):
        check_module_loaded("Invoke-Shellcode.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-sniffer"):
        check_module_loaded("Invoke-Sniffer.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-sqlquery"):
        check_module_loaded("Invoke-SqlQuery.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-tater"):
        check_module_loaded("Invoke-Tater.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-thehash"):
        check_module_loaded("Invoke-TheHash.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-tokenmanipulation"):
        check_module_loaded("Invoke-TokenManipulation.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-wmichecker"):
        check_module_loaded("Invoke-WMIChecker.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-wmicommand"):
        check_module_loaded("Invoke-WMICommand.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-wscriptbypassuac"):
        check_module_loaded("Invoke-WScriptBypassUAC.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-winrmsession"):
        check_module_loaded("Invoke-WinRMSession.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("out-minidump"):
        check_module_loaded("Out-Minidump.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("portscan"):
        check_module_loaded("PortScanner.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("powercat"):
        check_module_loaded("powercat.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-allchecks"):
        check_module_loaded("PowerUp.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("set-lhstokenprivilege"):
        check_module_loaded("Set-LHSTokenPrivilege.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("sharpsocks"):
        check_module_loaded("SharpSocks.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("find-allvulns"):
        check_module_loaded("Sherlock.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("test-adcredential"):
        check_module_loaded("Test-ADCredential.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("new-zipfile"):
        check_module_loaded("Zippy.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-netuser"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-aclscanner"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-dfsshare"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-objectacl"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("add-objectacl"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-netuser"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-domainuser"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-netcomputer"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-domaincomputer"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-netuser"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-netgroup"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-netgroupmember"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-netshare"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-sharefinder"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-netdomain"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-netdomaincontroller"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-netforest"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("find-domainshare"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-netforestdomain"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-mapdomaintrust"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-wmireglastloggedon"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-wmiregcachedrdpconnection"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-wmiregmounteddrive"):
        check_module_loaded("powerview.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-wmievent"):
        check_module_loaded("Invoke-WMIEvent.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("remove-wmievent"):
        check_module_loaded("Invoke-WMIEvent.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-wmi"):
        check_module_loaded("Invoke-WMIExec.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-lapspasswords"):
        check_module_loaded("Get-LAPSPasswords.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("new-jscriptshell"):
        check_module_loaded("New-JScriptShell.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-edrchecker"):
        check_module_loaded("Invoke-EDRChecker.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-urlcheck"):
        check_module_loaded("Invoke-URLCheck.ps1", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-injectedthread"):
        check_module_loaded("Get-InjectedThread.ps1", implant_id, user, load_module_command=load_module_command)


def run_sharp_autoloads(command, implant_id, user, load_module_command="load-module"):
    command = command.lower().strip()
    if command.startswith("run-exe seatbelt"):
        check_module_loaded("Seatbelt.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe smbexec.program"):
        check_module_loaded("SExec.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe sharpup"):
        check_module_loaded("SharpUp.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe safetydump"):
        check_module_loaded("SafetyDump.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe rubeus"):
        check_module_loaded("Rubeus.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe standin"):
        check_module_loaded("StandIn.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe sharpview"):
        check_module_loaded("SharpView.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe watson"):
        check_module_loaded("Watson.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe sharphound"):
        check_module_loaded("SharpHound.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe internalmonologue"):
        check_module_loaded("InternalMonologue.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe sharpsocks"):
        check_module_loaded("SharpSocksImplant.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe sharpweb"):
        check_module_loaded("SharpWeb.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe sharpwmi"):
        check_module_loaded("SharpWMI.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe wmiexec.program"):
        check_module_loaded("WExec.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe smbexec.program"):
        check_module_loaded("SExec.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe invoke_dcom.program"):
        check_module_loaded("DCOM.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe sharpsc.program"):
        check_module_loaded("SharpSC.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("get-screenshotallwindows"):
        check_module_loaded("Screenshot.dll", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("sharpsocks"):
        check_module_loaded("SharpSocksImplant.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("safetykatz"):
        check_module_loaded("SafetyKatz.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("sharpwmi"):
        check_module_loaded("SharpWMI.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("sharpsc"):
        check_module_loaded("SharpSC.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe program ps"):
        check_module_loaded("PS.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("pslo"):
        check_module_loaded("PS.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-dll sharpsploit"):
        check_module_loaded("SharpSploit.dll", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe mainclass runascs"):
        check_module_loaded("RunasCs.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("invoke-daisychain"):
        check_module_loaded("Daisy.dll", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe runas.program runas"):
        check_module_loaded("RunAs.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("portscan"):
        check_module_loaded("PortScanner.dll", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe sweetpotato.program "):
        check_module_loaded("SweetPotato.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe sharpdpapi.program "):
        check_module_loaded("SharpDPAPI.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe sharpchome.program "):
        check_module_loaded("SharpChrome.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-dll pbind"):
        check_module_loaded("PBind.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("pbind-connect"):
        check_module_loaded("PBind.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-dll fcomm"):
        check_module_loaded("FComm.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("fcomm-connect"):
        check_module_loaded("FComm.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe-background inveigh"):
        check_module_loaded("Inveigh.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-dll pwrstatustracker"):
        check_module_loaded("PwrStatusTracker.dll", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("getpowerstatus"):
        check_module_loaded("PwrStatusTracker.dll", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("loadpowerstatus"):
        check_module_loaded("PwrStatusTracker.dll", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe lockless.program lockless "):
        check_module_loaded("LockLess.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe sharpapplocker.program sharpapplocker"):
        check_module_loaded("SharpApplocker.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe sharpedrchecker.program sharpedrchecker"):
        check_module_loaded("SharpEDRChecker.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe csharp_oracleclient.program"):
        check_module_loaded("CSharp-OracleClient.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-dll db pgrabber"):
        check_module_loaded("PGrabber.dll", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe runpe.program runpe-debug"):
        check_module_loaded("RunPE-Debug.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe runpe.program"):
        check_module_loaded("RunPE.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe runof.program runof-debug"):
        check_module_loaded("RunOF-Debug.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe runof.program"):
        check_module_loaded("RunOF.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe pingcs.program pingcs"):
        check_module_loaded("PingCS.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe ipconfigcs.program ipconfigcs"):
        check_module_loaded("IPConfigCS.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe eventlogsearcher.program eventlogsearcher"):
        check_module_loaded("EventLogSearcher.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe sqlquery.program sqlquery"):
        check_module_loaded("SQLQuery.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe dnsresolve.program dnsresolve"):
        check_module_loaded("DNSResolve.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe getinstallerinfo.program getinstallerinfo"):
        check_module_loaded("GetInstallerInfo.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-dll net_gpppassword"):
        check_module_loaded("Net-GPPPassword.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe net_gpppassword"):
        check_module_loaded("Net-GPPPassword.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe sharpchrome.program"):
        check_module_loaded("SharpChrome.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe sharpchromium.program"):
        check_module_loaded("SharpChromium.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe filegrep.program"):
        check_module_loaded("FileGrep.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe sharpshadowcopy.program"):
        check_module_loaded("SharpShadowCopy.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe filegrep.program"):
        check_module_loaded("FileGrep.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe stickynotesextract"):
        check_module_loaded("StickyNotesExtract.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe-background sharpshares"):
        check_module_loaded("SharpShares.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe sharpprintnightmare"):
        check_module_loaded("SharpPrintNightmare.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe sharpwsus"):
        check_module_loaded("SharpWSUS.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe sharpreg"):
        check_module_loaded("SharpReg.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe sharptelnet"):
        check_module_loaded("SharpTelnet.exe", implant_id, user, load_module_command=load_module_command)
    elif command.startswith("run-exe clipboard"):
        check_module_loaded("clipboard.exe", implant_id, user, load_module_command=load_module_command)


def run_linux_autoloads(command, implant_id, user, load_module_command="load-module"):
    pass


def run_jxa_autoloads(command, implant_id, user, load_module_command="load-module"):
    pass


def run_go_autoloads(command, implant_id, user, load_module_command="load-module"):
    pass


def run_python_autoloads(command, implant_id, user, load_module_command="load-module"):
    pass
