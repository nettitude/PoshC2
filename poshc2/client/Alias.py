# Powershell Implant
ps_alias = [
    ["s", "get-screenshot"],
    ["whoami", "([Security.Principal.WindowsIdentity]::GetCurrent()).name"]
]

# Python Implant
py_alias = [
    ["s", "get-screenshot"]
]

# C# Implant
cs_alias = [
    ["s", "get-screenshot"],
    ["ps", "get-processlist"]
]

# Parts of commands to replace if command starts with the key
cs_replace = [
    ["safetydump", "run-exe SafetyDump.Program SafetyDump"],
    ["sharpup", "run-exe SharpUp.Program SharpUp"],
    ["seatbelt", "run-exe Seatbelt.Program Seatbelt"],
    ["rubeus", "run-exe Rubeus.Program Rubeus"],
    ["sharpview", "run-exe SharpView.Program SharpView"],
    ["sharphound", "run-exe SharpHound3.SharpHound SharpHound"],
    ["sharpweb", "run-exe SharpWeb.Program SharpWeb"],
    ["watson", "run-exe Watson.Program Watson"],
    ["sharpwmi", "run-exe SharpWMI.Program SharpWMI"],
    ["wmiexec", "run-exe WMIExec.Program WExec"],
    ["smbexec", "run-exe SMBExec.Program SExec"],
    ["dcomexec", "run-exe Invoke_DCOM.Program DCOM"],
    ["sharpsc", "run-exe SharpSC.Program SharpSC"],
    ["sharpcookiemonster", "run-exe SharpCookieMonster.Program SharpCookieMonster"],
    ["mimikatz", "run-dll SharpSploit.Credentials.Mimikatz SharpSploit"],
    ["runasps", "run-exe RunAs.Program RunAs"],
    ["runas", "run-exe MainClass RunasCs"],
    ["sharpps", "run-exe Program PS"],
    ["sweetpotato", "run-exe SweetPotato.Program SweetPotato"],
    ["sharpdpapi", "run-exe SharpDPAPI.Program SharpDPAPI"],
    ["sharpchrome", "run-exe SharpChrome.Program SharpChrome"],
    ["sharpchromium", "run-exe SharpChromium.Program SharpChromium"],
    ["inveigh", "run-exe-background Inveigh.Program Inveigh"],
    ["stopinveigh", "run-dll Inveigh.Program Inveigh StopAll"],
    ["lockless", "run-exe LockLess.Program LockLess"],
    ["sharpapplocker", "run-exe SharpApplocker.Program SharpApplocker"],
    ["sharpedrchecker", "run-exe SharpEDRChecker.Program SharpEDRChecker"],
    ["standin", "run-exe StandIn.Program StandIn"],
    ["certify", "run-exe Certify.Program Certify"],
    ["stopsocks", "run-dll SharpSocksImplant.Program SharpSocks StopSocks"],
    ["runpe-debug", "run-exe RunPE.Program RunPE"],
    ["runpe", "run-exe RunPE.Program RunPE"],
    ["runof-debug", "run-exe RunOF.Program RunOF"],
    ["runof", "run-exe RunOF.Program RunOF"],
    ["ping", "run-exe PingCS.Program PingCS"],
    ["eventlogsearcher", "run-exe EventLogSearcher.Program EventLogSearcher"],
    ["ipconfig", "run-exe IPConfigCS.Program IPConfigCS"],
    ["nslookup", "run-exe DNSResolve.Program DNSResolve"],
    ["getinstallerinfo", "run-exe GetInstallerInfo.Program GetInstallerInfo"],
    ["getgpppassword", "run-exe Net_GPPPassword.Program Net-GPPPassword"],
    ["getgppgroups", "run-dll Net_GPPPassword.Program Net-GPPPassword Groups"],
    ["sqlquery", "run-exe SQLQuery.Program SQLQuery"],
    ["shadowcopy", "run-exe SharpShadowCopy.Program SharpShadowCopy"],
    ["filegrep", "run-exe FileGrep.Program FileGrep"],
    ["stickynotesextract", "run-exe StickyNotesExtract.Program StickyNotesExtract"],
    ["sharpshares", "run-exe-background SharpShares.Program SharpShares"],
    ["sharpprintnightmare", "run-exe SharpPrintNightmare.Program SharpPrintNightmare"],
    ["sharpreg", "run-exe SharpReg.Program SharpReg"],
    ["sharptelnet", "run-exe SharpTelnet.Program SharpTelnet"],
    ["syscallsextractor", "run-exe SyscallsExtractor.Program SyscallsExtractor"]
]
