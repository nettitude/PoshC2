import os, yaml, glob
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
ImagesDirectory = "%simages%s" % (ResourcesDirectory, os.sep)


# Database Config
DatabaseType = config["DatabaseType"]
if DatabaseType.lower() == "sqlite":
    Database = "%sPowershellC2.SQLite" % (PoshProjectDirectory)
elif DatabaseType.lower() == 'postgres':
    Database = config["PostgresConnectionString"]
else:
    raise Exception(f"Invalid configuration: DatabaseType must be Postgres or SQLite: {DatabaseType}")


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

if "https://" in PayloadCommsHost.strip():
    UseHttp = False
elif "http://" in PayloadCommsHost.strip():
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
Pushover_APIToken = config["Pushover_APIToken"]
Pushover_APIUser = config["Pushover_APIUser"]

# SOCKS Proxying Options
SocksHost = config["SocksHost"]
SocksURLS = urlConfig.fetchSocks()

# HTTP Response Options
GET_404_Response = open('%sresponses/404_response.html' % ResourcesDirectory, 'r').read()

post_response_files = [x for x in glob.glob(ResourcesDirectory + "responses/200*.html")]
POST_200_Responses = []
for f in post_response_files:
    with(open(f, 'r')) as g:
        POST_200_Responses.append(g.read())

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
