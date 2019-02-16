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
    [ "safetydump", "run-exe SafetyDump.Program SafetyDump"]
]
