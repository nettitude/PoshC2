ps_alias = [
    ["s", "get-screenshot"],
    ["whoami", "([Security.Principal.WindowsIdentity]::GetCurrent()).name"]
]

ps_replace = [
]

py_alias = [
    ["s", "get-screenshot"],
    ["sai", "startanotherimplant"]
]

py_replace = [
]

cs_alias = [
    ["s", "get-screenshot"],
    ["ps", "get-processlist"]
]

cs_replace = [
    ["safetydump", "run-exe SafetyDump.Program SafetyDump"],
    ["sharpup", "run-exe SharpUp.Program SharpUp"],
    ["seatbelt", "run-exe Seatbelt.Program Seatbelt"],
    ["rubeus", "run-exe Rubeus.Program Rubeus"],
    ["sharpview", "run-exe SharpView.Program SharpView"],
    ["sharphound", "run-exe SharpHound3.SharpHound SharpHound"],
    ["sharpweb", "run-exe SharpWeb.Program SharpWeb"],
    ["watson", "run-exe Watson.Program Watson"],
    ["wmiexec", "run-exe WMIExec.Program WExec"],
    ["smbexec", "run-exe SMBExec.Program SExec"],
    ["dcomexec", "run-exe Invoke_DCOM.Program DCOM"],
    ["sharpsc", "run-exe SharpSC.Program SharpSC"],
    ["mimikatz", "run-dll SharpSploit.Credentials.Mimikatz SharpSploit"],
    ["runasps", "run-exe RunAs.Program RunAs"],
    ["runas", "run-exe MainClass RunasCs"],
    ["sharpps", "run-exe Program PS"],
    ["sweetpotato", "run-exe SweetPotato.Program SweetPotato"],
    ["sharpdpapi", "run-exe SharpDPAPI.Program SharpDPAPI"],
    ["sharpchrome", "run-exe SharpChrome.Program SharpChrome"],
    ["sharpchromium", "run-exe SharpChromium.Program SharpChromium"],
    ["inveigh", "run-exe-background Inveigh.Program Inveigh"],
    ["stop-inveigh", "run-dll Inveigh.Program Inveigh StopAll"],
    ["lockless", "run-exe LockLess.Program LockLess"],
    ["sharpapplocker", "run-exe SharpApplocker.Program SharpApplocker"],
    ["sharpedrchecker", "run-exe SharpEDRChecker.Program SharpEDRChecker"],
    ["standin", "run-exe StandIn.Program StandIn"],
    ["inveigh", "run-exe-background Inveigh.Program Inveigh"],
    ["oraclecli", "run-exe CSharp_OracleClient.Program CSharp-OracleClient"],
    ["stop-socks", "run-dll SharpSocksImplant.Program SharpSocks StopSocks"],
    ["standin", "run-exe StandIn.Program StandIn"],
    ["runpe-debug", "run-exe RunPE.Program RunPE"],
    ["runpe", "run-exe RunPE.Program RunPE"],
    ["runof-debug", "run-exe RunOF.Program RunOF"],
    ["runof", "run-exe RunOF.Program RunOF"],
    ["ping", "run-exe PingCS.Program PingCS"],
    ["eventlogsearcher", "run-exe EventLogSearcher.Program EventLogSearcher"],
    ["ipconfig", "run-exe IPConfigCS.Program IPConfigCS"],
    ["nslookup", "run-exe DNSResolve.Program DNSResolve"],
    ["get-installer-info", "run-exe GetInstallerInfo.Program GetInstallerInfo"],
    ["get-gpp-password", "run-exe Net_GPPPassword.Program Net-GPPPassword"],
    ["get-gpp-groups", "run-dll Net_GPPPassword.Program Net-GPPPassword Groups"],
    ["sqlquery", "run-exe SQLQuery.Program SQLQuery"],
    ["shadowcopy", "run-exe SharpShadowCopy.Program SharpShadowCopy"],
    ["filegrep", "run-exe FileGrep.Program FileGrep"],
    ["stickynotes-extract", "run-exe StickyNotesExtract.Program StickyNotesExtract"],
    ["sharpshares", "run-exe-background SharpShares.Program SharpShares"],
    ["sharpprintnightmare", "run-exe SharpPrintNightmare.Program SharpPrintNightmare"],
    ["sharpwsus", "run-exe SharpWSUS.Program SharpWSUS"],
    ["sharpreg", "run-exe SharpReg.Program SharpReg"],
    ["sharptelnet", "run-exe SharpTelnet.Program SharpTelnet"],
    ["get-clipboard", "run-exe clipboard.Program clipboard get"],
    ["set-clipboard", "run-exe clipboard.Program clipboard set"],
    ["show-clipboard-history", "run-exe clipboard.Program clipboard show-history"],
    ["set-clipboard-history", "run-exe clipboard.Program clipboard set-history"],
    ["clear-clipboard", "run-exe clipboard.Program clipboard clear"],
]

jxa_alias = [
]

jxa_replace = [
]

go_alias = [
]

go_replace = [
]

linux_alias = [
]

linux_replace = [
]

um_alias = [
]

um_replace = [
]
