import os, yaml
from poshc2.server.UrlConfig import UrlConfig

with open('./config.yml', 'r') as fileio:
    try:
        config = yaml.safe_load(fileio)
    except yaml.YAMLError as e:
        print("Error parsing config.yml: ", e)

# Directory & file locations
PoshInstallDirectory = config["PoshInstallDirectory"]
PoshProjectDirectory = config["PoshProjectDirectory"]
ResourcesDirectory = "%sresources%s" % (PoshInstallDirectory, os.sep)
PayloadTemplatesDirectory = "%spayload-templates%s" % (ResourcesDirectory, os.sep)
BeaconDataDirectory = "%sbeacon-data%s" % (ResourcesDirectory, os.sep)
ModulesDirectory = "%smodules%s" % (ResourcesDirectory, os.sep)
DownloadsDirectory = "%sdownloads%s" % (PoshProjectDirectory, os.sep)
ReportsDirectory = "%sreports%s" % (PoshProjectDirectory, os.sep)
PayloadsDirectory = "%spayloads%s" % (PoshProjectDirectory, os.sep)
Database = "%sPowershellC2.SQLite" % (PoshProjectDirectory)

# Server Config
BindIP = config["BindIP"]
BindPort = config["BindPort"]

# Payload Comms
PayloadCommsHost = config["PayloadCommsHost"]
PayloadCommsPort = config["PayloadCommsPort"]
DomainFrontHeader = config["DomainFrontHeader"]
Referrer = config["Referrer"]
ServerHeader = config["ServerHeader"]
UserAgent = config["UserAgent"]
DefaultSleep = config["DefaultSleep"]
Jitter = config["Jitter"]
KillDate = config["KillDate"]

if PayloadCommsHost.strip().startswith("https://"):
    UseHttp = False
elif PayloadCommsHost.strip().startswith("http://"):
    UseHttp = True
else:
    raise Exception(f"Invalid configuration: PayloadCommsHost must start with http:// or https:// : {config['PayloadCommsHost']}")

if config["UrlConfig"] == "urls":
    urlConfig = UrlConfig("%surls.txt" % ResourcesDirectory, use_http=UseHttp)
elif config["UrlConfig"] == "wordlist":
    urlConfig = UrlConfig(wordList="%swordlist.txt" % ResourcesDirectory, use_http=UseHttp)
else:
    raise Exception(f"Invalid configuration: urlConfig must be urls/wordlist but was: {config['urlConfig']}")

QuickCommand = urlConfig.fetchQCUrl()
DownloadURI = urlConfig.fetchConnUrl()
URLS = urlConfig.fetchUrls()

# Payload Options
DefaultMigrationProcess = config["DefaultMigrationProcess"]
Insecure = "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}"

# Notifications Options
Sounds = config["Sounds"]
NotificationsProjectName = config["NotificationsProjectName"]
EnableNotifications = config["EnableNotifications"]
ClockworkSMS_APIKEY = config["ClockworkSMS_APIKEY"]
ClockworkSMS_MobileNumbers = config["ClockworkSMS_MobileNumbers"]
Pushover_APIToken = config["Pushover_APIToken"]
Pushover_APIUser = config["Pushover_APIUser"]

# SOCKS Proxying Options
SocksHost = config["SocksHost"]
SocksURLS = urlConfig.fetchSocks()

# HTTP Response Options
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

# Certificate Options
Cert_C = "US"
Cert_ST = "Minnesota"
Cert_L = "Minnetonka"
Cert_O = "Pajfds"
Cert_OU = "Jethpro"
Cert_CN = "P18055077"
Cert_SerialNumber = 1000
Cert_NotBefore = 0
Cert_NotAfter = (10 * 365 * 24 * 60 * 60)
