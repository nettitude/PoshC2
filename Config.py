import os
from UrlConfig import UrlConfig

HOST_NAME = '0.0.0.0'
PORT_NUMBER = 443  # This is the bind port

# These options are loaded into the database on first run, changing them after
# that must be done through commands (such as set-defaultbeacon), or by
# creating a new project
POSHDIR = "/opt/PoshC2/"
ROOTDIR = "/opt/PoshC2_Project/"
HostnameIP = "https://192.168.213.134"
DomainFrontHeader = ""  # example df.azureedge.net
UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36"  # This should be updated to match the environment, this is Chrome on 2019-09-04
DefaultSleep = "5s"
Jitter = 0.20
KillDate = "12/12/2019"  # dd/MM/yyyy
urlConfig = UrlConfig("%soldurls.txt" % POSHDIR)  # Instantiate UrlConfig object - old urls using a list from a text file
# urlConfig = UrlConfig(wordList="%swordlist.txt" % POSHDIR) # Instantiate UrlConfig object - wordlist random url generator
QuickCommand = urlConfig.fetchQCUrl()
DownloadURI = urlConfig.fetchConnUrl()
Sounds = "No"
ServerPort = "443"  # This the port the payload communicates with
NotificationsProjectName = "PoshC2"
EnableNotifications = "No"
DefaultMigrationProcess = "C:\\Windows\\system32\\netsh.exe"  # Used in the PoshXX_migrate.exe payloads

# ClockworkSMS - https://www.clockworksms.com
APIKEY = ""
MobileNumber = '"07777777777","07777777777"'

# Pushover - https://pushover.net/
APIToken = ""
APIUser = ""
URLS = urlConfig.fetchUrls()
SocksURLS = urlConfig.fetchSocks()
SocksHost = "http://127.0.0.1:49031"
Referrer = ""  # optional
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
FilesDirectory = "%sFiles%s" % (POSHDIR, os.sep)
PayloadsDirectory = "%spayloads%s" % (ROOTDIR, os.sep)
ModulesDirectory = "%sModules%s" % (POSHDIR, os.sep)
DownloadsDirectory = "%sdownloads%s" % (ROOTDIR, os.sep)
ReportsDirectory = "%sreports%s" % (ROOTDIR, os.sep)
Database = "%s%sPowershellC2.SQLite" % (ROOTDIR, os.sep)
