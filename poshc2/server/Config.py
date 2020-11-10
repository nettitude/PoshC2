import os, yaml, glob, sys
from poshc2.server.UrlConfig import UrlConfig
from poshc2.Utils import string_to_array
from poshc2.server.database.DBType import DBType

POSH_PROJECTS_DIR = "/var/poshc2/"

if not os.path.exists(f"{POSH_PROJECTS_DIR}CURRENT_PROJECT"):
    print("PoshC2 current project file does not exist, please run posh-project")
    sys.exit(1)

# Directory & file locations
PoshInstallDirectory = os.path.realpath(os.path.dirname(os.path.realpath(__file__)) + "../../../")

if not PoshInstallDirectory.endswith("/"):
    PoshInstallDirectory = PoshInstallDirectory + "/"

with open(f"{POSH_PROJECTS_DIR}CURRENT_PROJECT", 'r') as current_project_file:
    current_project = current_project_file.read().strip()

PoshProjectDirectory = f"{POSH_PROJECTS_DIR}{current_project}"
if not PoshProjectDirectory.endswith("/"):
    PoshProjectDirectory = PoshProjectDirectory + "/"

if not os.path.exists(f"{PoshProjectDirectory}config.yml"):
    print("Current project configuration does not exist, please create it using posh-project")
    sys.exit(1)

with open(f'{PoshProjectDirectory}config.yml', 'r') as config_file:
    try:
        config = yaml.safe_load(config_file)
    except yaml.YAMLError as e:
        print("Error parsing config.yml: ", e)
        sys.exit(1)

ResourcesDirectory = f"{PoshInstallDirectory}resources/"
PayloadTemplatesDirectory = f"{ResourcesDirectory}payload-templates/"
BeaconDataDirectory = f"{ResourcesDirectory}beacon-data/"
ModulesDirectory = f"{ResourcesDirectory}modules/"
DownloadsDirectory = f"{PoshProjectDirectory}downloads/"
ReportsDirectory = f"{PoshProjectDirectory}reports/"
PayloadsDirectory = f"{PoshProjectDirectory}payloads/"
ImagesDirectory = f"{ResourcesDirectory}images/"
ReportingDirectory = f"{ResourcesDirectory}reporting/"
PayloadModulesDirectory = f"{PoshInstallDirectory}/poshc2/server/payloads/"

# Database Config
if config["DatabaseType"].lower() == "sqlite":
    DatabaseType = DBType.SQLite
    Database = f"{PoshProjectDirectory}PowershellC2.SQLite"
elif config["DatabaseType"].lower() == 'postgres':
    DatabaseType = DBType.Postgres
    Database = config["PostgresConnectionString"]
else:
    raise Exception(f"Invalid configuration: DatabaseType must be Postgres or SQLite: {DatabaseType}")

PayloadCommsHostString, PayloadCommsHostCount = string_to_array(config["PayloadCommsHost"])
DomainFrontHeaderString, DomainFrontHeaderCount = string_to_array(config["DomainFrontHeader"])
if PayloadCommsHostCount != DomainFrontHeaderCount:
    raise Exception("[-] Error - different number of host headers and URLs in config.yml")
# Server Config
BindIP = config["BindIP"]
BindPort = config["BindPort"]

# Payload Comms
PayloadCommsHost = PayloadCommsHostString
DomainFrontHeader = DomainFrontHeaderString
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
PayloadDomainCheck = config["PayloadDomainCheck"]

# Notifications Options
NotificationsProjectName = config["NotificationsProjectName"]
EnableNotifications = config["EnableNotifications"]
Pushover_APIToken = config["Pushover_APIToken"]
Pushover_APIUser = config["Pushover_APIUser"]
Slack_UserID = config["Slack_UserID"]
Slack_Channel = config["Slack_Channel"]
Slack_BotToken = config["Slack_BotToken"]

# SOCKS Proxying Options
SocksHost = config["SocksHost"]
SocksURLS = urlConfig.fetchSocks()

# PBind Options
PBindPipeName = config["PBindPipeName"]
PBindSecret = config["PBindSecret"]

# HTTP Response Options
GET_404_Response = open('%sresponses/404_response.html' % ResourcesDirectory, 'r').read()

post_response_files = [x for x in glob.glob(ResourcesDirectory + "responses/200*.html")]
POST_200_Responses = []
for f in post_response_files:
    with(open(f, 'r')) as g:
        POST_200_Responses.append(g.read())

StageRetries = config["PayloadStageRetries"]
StageRetriesInitialWait = config["PayloadStageRetriesInitialWait"]
StageRetriesLimit = config["PayloadStageRetriesLimit"]

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
