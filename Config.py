#!/usr/bin/env python
from UrlConfig import UrlConfig

urlConfig = UrlConfig("./oldurls.txt") # Instantiate UrlConfig object.

HOST_NAME = '0.0.0.0' 
PORT_NUMBER = 443

POSHDIR = "/opt/PoshC2_Python/" 
ROOTDIR = "/opt/PoshC2_Project/" 
HostnameIP = "https://127.0.0.1" # Point to location of the Server/Proxy/Client Facing
poshIP = "127.0.0.1" # Needed for URL Rewrite Rules.
sharpIP = "127.0.0.1" # Needed for URL Rewrite Rules.
ServerPort = "443"
DomainFrontHeader = "" # example df.azureedge.net
DefaultSleep = "5"
KillDate = "08/06/2019"
QuickCommand = urlConfig.fetchQCUrl()
DownloadURI = urlConfig.fetchConnUrl()
Sounds = "No"
EnableNotifications = "No"
# ClockworkSMS - https://www.clockworksms.com
APIKEY = ""  
MobileNumber = '"07777777777","07777777777"' 
# Pushover - https://pushover.net/
APIToken = ""  
APIUser = ""  
URLS = urlConfig.fetchUrls()
SocksURLS = urlConfig.fetchSocks()
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
  
# DO NOT CHANGE #
#These rules aren't needed as you'll find them auto-generated within the project folder now.
# checkout <project-name>/rewrite-rules.txt but left them here just in case.

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
