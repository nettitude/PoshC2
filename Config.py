#!/usr/bin/env python

HOST_NAME = '0.0.0.0' 
PORT_NUMBER = 443

POSHDIR = "/opt/PoshC2_Python/" 
ROOTDIR = "/opt/PoshC2_Project/" 
HostnameIP = "https://172.19.131.109" 
ServerPort = "443"
DomainFrontHeader = "" # example df.azureedge.net
DefaultSleep = "5"
KillDate = "08/06/2019"
QuickCommand = "adsense/troubleshooter/1631343?id=Ndks8dmsPld"
DownloadURI = "adsense/troubleshooter/1631343?id=Ndks8dmsPld"
Sounds = "No"
EnableNotifications = "No"
# ClockworkSMS - https://www.clockworksms.com
APIKEY = ""  
MobileNumber = '"07777777777","07777777777"' 
# Pushover - https://pushover.net/
APIToken = ""  
APIUser = ""  
URLS = '"adsense/troubleshooter/1631343/","adServingData/PROD/TMClient/6/8736/","advanced_search?hl=en-GB&fg=","async/newtab?ei=","babel-polyfill/6.3.14/polyfill.min.js=","bh/sync/aol?rurl=/ups/55972/sync?origin=","bootstrap/3.1.1/bootstrap.min.js?p=","branch-locator/search.asp?WT.ac&api=","business/home.asp&ved=","business/retail-business/insurance.asp?WT.mc_id=","cdb?ptv=48&profileId=125&av=1&cb=","cis/marketq?bartype=AREA&showheader=FALSE&showvaluemarkers=","classroom/sharewidget/widget_stable.html?usegapi=","client_204?&atyp=i&biw=1920&bih=921&ei=","load/pages/index.php?t=","putil/2018/0/11/po.html?ved=","q/2018/load.php?lang=en&modules=","status/995598521343541248/query=","TOS?loc=GB&hl=en&privacy=","trader-update/history&pd=","types/translation/v1/articles/","uasclient/0.1.34/modules/","usersync/tradedesk/","utag/lbg/main/prod/utag.15.js?utv=","vs/1/vsopts.js?","vs/site/bgroup/visitor/","w/load.php?debug=false&lang=en&modules=","web/20110920084728/","webhp?hl=en&sa=X&ved=","work/embedded/search?oid="'
SocksURLS = '"GoPro5/black/2018/","Philips/v902/"'
UserAgent = "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko"
Referer = "" # optional
HTTPResponse = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache (Debian) Server</address>
</body></html>
"""
HTTPResponses = [
"STATUS 200",
"OK",
"<html><head></head><body>#RANDOMDATA#</body></html>",
"<html><body>#RANDOMDATA#</body></html>",
"""<?xml version="1.0" encoding="UTF-8"?>
<heading>#RANDOMDATA#</heading>
<body>#RANDOMDATA#</body>""",
"<html><head>#RANDOMDATA#</head><body><div>#RANDOMDATA#</div></body></html>"
]
ServerHeader = "Apache"
Insecure = "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}"



# DO NOT CHANGE #
FilesDirectory = "%sFiles/" % POSHDIR
PayloadsDirectory = "%spayloads/" % ROOTDIR
DownloadsDirectory = "%sdownloads/" % ROOTDIR
ReportsDirectory = "%sreports/" % ROOTDIR
DB = "%s/PowershellC2.SQLite" % ROOTDIR 

logo = """__________            .__.     _________  ________  
 \_______  \____  _____|  |__   \_   ___ \ \_____  \ 
  |     ___/  _ \/  ___/  |  \  /    \  \/  /  ____/ 
  |    |  (  <_> )___ \|   Y  \ \     \____/       \ 
  |____|   \____/____  >___|  /  \______  /\_______ \  
                     \/     \/          \/         \/
  =============== v4.3 www.PoshC2.co.uk ============="""
  
# DO NOT CHANGE #

'''
RewriteEngine On
SSLProxyEngine On
SSLProxyCheckPeerCN Off
SSLProxyVerify none
SSLProxyCheckPeerName off
SSLProxyCheckPeerExpire off

Define PoshC2 <ADD_IPADDRESS_HERE>
Define SharpSocks <ADD_IPADDRESS_HERE>

RewriteRule ^/adsense/troub(.*) https://${PoshC2}/adsense/troub$1 [NC,L,P]
RewriteRule ^/adServingData(.*) https://${PoshC2}/adServingData$1 [NC,L,P]
RewriteRule ^/advanced_sear(.*) https://${PoshC2}/advanced_sear$1 [NC,L,P]
RewriteRule ^/async/newtab(.*) https://${PoshC2}/async/newtab$1 [NC,L,P]
RewriteRule ^/babel-polyfil(.*) https://${PoshC2}/babel-polyfil$1 [NC,L,P]
RewriteRule ^/bh/sync/aol(.*) https://${PoshC2}/bh/sync/aol$1 [NC,L,P]
RewriteRule ^/bootstrap/3.1(.*) https://${PoshC2}/bootstrap/3.1$1 [NC,L,P]
RewriteRule ^/branch-locato(.*) https://${PoshC2}/branch-locato$1 [NC,L,P]
RewriteRule ^/business/home(.*) https://${PoshC2}/business/home$1 [NC,L,P]
RewriteRule ^/business/reta(.*) https://${PoshC2}/business/reta$1 [NC,L,P]
RewriteRule ^/cdb(.*) https://${PoshC2}/cdb$1 [NC,L,P]
RewriteRule ^/cis/marketq(.*) https://${PoshC2}/cis/marketq$1 [NC,L,P]
RewriteRule ^/classroom/sha(.*) https://${PoshC2}/classroom/sha$1 [NC,L,P]
RewriteRule ^/client_204(.*) https://${PoshC2}/client_204$1 [NC,L,P]
RewriteRule ^/load/pages/in(.*) https://${PoshC2}/load/pages/in$1 [NC,L,P]
RewriteRule ^/putil/2018/0/(.*) https://${PoshC2}/putil/2018/0/$1 [NC,L,P]
RewriteRule ^/q/2018/load.p(.*) https://${PoshC2}/q/2018/load.p$1 [NC,L,P]
RewriteRule ^/status/995598(.*) https://${PoshC2}/status/995598$1 [NC,L,P]
RewriteRule ^/TOS(.*) https://${PoshC2}/TOS$1 [NC,L,P]
RewriteRule ^/trader-update(.*) https://${PoshC2}/trader-update$1 [NC,L,P]
RewriteRule ^/types/transla(.*) https://${PoshC2}/types/transla$1 [NC,L,P]
RewriteRule ^/uasclient/0.1(.*) https://${PoshC2}/uasclient/0.1$1 [NC,L,P]
RewriteRule ^/usersync/trad(.*) https://${PoshC2}/usersync/trad$1 [NC,L,P]
RewriteRule ^/utag/lbg/main(.*) https://${PoshC2}/utag/lbg/main$1 [NC,L,P]
RewriteRule ^/vs/1/vsopts.j(.*) https://${PoshC2}/vs/1/vsopts.j$1 [NC,L,P]
RewriteRule ^/vs/site/bgrou(.*) https://${PoshC2}/vs/site/bgrou$1 [NC,L,P]
RewriteRule ^/w/load.php(.*) https://${PoshC2}/w/load.php$1 [NC,L,P]
RewriteRule ^/web/201109200(.*) https://${PoshC2}/web/201109200$1 [NC,L,P]
RewriteRule ^/webhp(.*) https://${PoshC2}/webhp$1 [NC,L,P]
RewriteRule ^/work/embedded(.*) https://${PoshC2}/work/embedded$1 [NC,L,P]

RewriteRule ^/GoPro5/black/2018/(.*) http://${SharpSocks}/GoPro5/black/2018/$1 [NC,L,P]
RewriteRule ^/Philips/v902/(.*) http://${SharpSocks}/Philips/v902/$1 [NC,L,P]

'''
