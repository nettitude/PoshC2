#!/usr/bin/env python
from UrlConfig import UrlConfig

HOST_NAME = '0.0.0.0'
PORT_NUMBER = 443

POSHDIR = "/opt/PoshC2_Python/"
ROOTDIR = "/opt/PoshC2_Project/"
HostnameIP = "https://172.16.0.124"
DomainFrontHeader = "" # example df.azureedge.net
DefaultSleep = "5"
KillDate = "08/06/2019"
UserAgent = "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko"
urlConfig = UrlConfig("%soldurls.txt" % POSHDIR) # Instantiate UrlConfig object - old urls using a list from a text file
#urlConfig = UrlConfig(wordList="%swordlist.txt" % POSHDIR) # Instantiate UrlConfig object - wordlist random url generator
QuickCommand = urlConfig.fetchQCUrl()
DownloadURI = urlConfig.fetchConnUrl()
Sounds = "No"
ServerPort = "443"
EnableNotifications = "No"

# ClockworkSMS - https://www.clockworksms.com
APIKEY = ""
MobileNumber = '"07777777777","07777777777"'

# Pushover - https://pushover.net/
APIToken = ""
APIUser = ""
URLS = urlConfig.fetchUrls()
SocksURLS = urlConfig.fetchSocks()
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
ModulesDirectory = "%sModules/" % ROOTDIR
DownloadsDirectory = "%sdownloads/" % ROOTDIR
ReportsDirectory = "%sreports/" % ROOTDIR
DB = "%s/PowershellC2.SQLite" % ROOTDIR
  
# DO NOT CHANGE #
# These rules aren't needed as you'll find them auto-generated within the project folder now.
# checkout <project-name>/rewrite-rules.txt but left them here just in case.
