# Testing

The following checklist gives decent testing coverage across PoshC2.

## Checklist

### PowerShell

- [ ] Get Implant
- [ ] `ls`
- [ ] `beacon`
- [ ] `download-file`
- [ ] `download-file` (same file)
- [ ] `download-file` (file > 50MB)
- [ ] `upload-file`
- [ ] `migrate`
- [ ] `inject-shellcode`
- [ ] `loadmodule powerview.ps1` & `Get-NetLocalGroup Administrators`
- [ ] `kill-implant`

### C#

- [ ] Get Implant
- [ ] `ls`
- [ ] `beacon`
- [ ] `download-file`
- [ ] `download-file` (same file)
- [ ] `download-file` (file > 50MB)
- [ ] `upload-file`
- [ ] `inject-shellcode`
- [ ] `loadmodule Seatbelt.exe` & `run-exe Seatbelt.Program Seatbelt BasicOSInfo`
- [ ] `kill-implant`

### Python

- [ ] Get Implant
- [ ] `ls`
- [ ] `beacon`
- [ ] `download-file`
- [ ] `download-file` (same file)
- [ ] `download-file` (file > 50MB)
- [ ] `upload-file`
- [ ] `sai`
- [ ] `get-screenshot`
- [ ] `kill-implant`

### General

- [ ] `label-implant`
- [ ] `output-to-html` & check report
- [ ] `opsec`
