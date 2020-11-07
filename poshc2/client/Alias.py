# Powershell Implant
ps_alias = [
    ["s", "get-screenshot"],
    ["whoami", "([Security.Principal.WindowsIdentity]::GetCurrent()).name"],
]

# Python Implant
py_alias = [
    ["s", "get-screenshot"]
]

# C# Implant
cs_alias = [
    ["s", "get-screenshot"],
]

# Parts of commands to replace if command starts with the key
cs_replace = [
    ["safetydump", "run-exe SafetyDump.Program SafetyDump"],
    ["sharpup", "run-exe SharpUp.Program SharpUp"],
    ["seatbelt", "run-exe Seatbelt.Program Seatbelt"],
    ["rubeus", "run-exe Rubeus.Program Rubeus"],
    ["sharpview", "run-exe SharpView.Program SharpView"],
    ["sharphound", "run-exe Sharphound2.Sharphound Sharphound"],
    ["sharpweb", "run-exe SharpWeb.Program SharpWeb"],
    ["watson", "run-exe Watson.Program Watson"],
    ["sharpwmi", "run-exe SharpWMI.Program SharpWMI"],
    ["wmiexec", "run-exe WMIExec.Program WExec"],
    ["smbexec", "run-exe SMBExec.Program SExec"],
    ["dcomexec", "run-exe Invoke_DCOM.Program DCOM"],
    ["sharpsc","run-exe SharpSC.Program SharpSC"]  
]
