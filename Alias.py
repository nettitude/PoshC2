#!/usr/bin/python

# Powershell Implant
ps_alias = [
    ["s","get-screenshot"],
    ["whoami","([Security.Principal.WindowsIdentity]::GetCurrent()).name"],
]

# Python Implant
py_alias = [
    ["s","get-screenshot"]
]

# C# Implant
cs_alias = [
    ["s","get-screenshot"],
]

# Parts of commands to replace if command starts with the key
cs_replace = [
    ["safetydump", "run-exe SafetyDump.Program SafetyDump"],
    ["sharpup", "run-exe SharpUp.Program SharpUp"],
    ["seatbelt", "run-exe Seatbelt.Program Seatbelt"],
    ["rubeus", "run-exe Rubeus.Program Rubeus"],
    ["sharpview", "run-exe SharpView.Program SharpView"],
    ["sharphound", "run-exe Sharphound2.Sharphound Sharphound"],
    ["watson", "run-exe Watson.Program Watson"]
]
