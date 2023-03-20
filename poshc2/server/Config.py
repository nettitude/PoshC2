import glob
import os
import sys

import yaml

from poshc2.server.UrlConfig import UrlConfig

# TODO replace directory and get from environmental variable source

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
DatabaseType = config["DatabaseType"]
if DatabaseType == "SQLite":
    Database = f"sqlite:///{PoshProjectDirectory}PoshC2.SQLite"
elif DatabaseType == 'PostgreSQL':
    Database = config["PostgresConnectionString"]
else:
    raise Exception(f"Invalid configuration: DatabaseType must be PostgreSQL or SQLite: {config['DatabaseType']}")

PayloadComms = config["PayloadComms"]
# Server Config
BindIP = config["BindIP"]
BindPort = config["BindPort"]

# Payload Comms
Referer = config["Referer"]
ServerHeader = config["ServerHeader"]
UserAgent = config["UserAgent"]

if UserAgent.lower() == "default":
    raise Exception(f"Please set the user agent")

DefaultSleep = config["DefaultSleep"]
Jitter = config["Jitter"]
KillDate = config["KillDate"]

protocol = ""
for comms_channel in PayloadComms:
    comms_url = list(comms_channel.keys())[0]
    if not protocol:
        protocol = comms_url[:comms_url.index("/")]
        if protocol != "http:" and protocol != "https:":
            raise Exception(f"Invalid configuration: PayloadComms Comms URLs must start with http:// or https://")
    else:
        if protocol != comms_url[:comms_url.index("/")]:
            raise Exception(
                f"Invalid configuration: PayloadComms Comms URLS must all use the same protocol (http/https)")

PayloadCommsHost = ",".join([f'"{list(x.keys())[0]}"' for x in PayloadComms])
DomainFrontHeader = ",".join([f'"{list(x.values())[0]}"' for x in PayloadComms])
if not DomainFrontHeader:
    DomainFrontHeader = ""

if "https:" in protocol:
    UseHttp = False
else:
    UseHttp = True

if config["UrlConfig"] == "urls":
    urlConfig = UrlConfig(f"{ResourcesDirectory}urls.txt", use_http=UseHttp)
elif config["UrlConfig"] == "wordlist":
    urlConfig = UrlConfig(wordlist=f"{ResourcesDirectory}wordlist.txt", use_http=UseHttp)
else:
    raise Exception(f"Invalid configuration: urlConfig must be urls/wordlist but was: {config['urlConfig']}")

HostedFileURL = urlConfig.get_hosted_file_url()
DownloadURL = urlConfig.get_connect_url()
URLS = urlConfig.get_urls()

# Payload Options
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
SocksURLS = urlConfig.get_socks()

# PBind Options
PBindPipeName = config["PBindPipeName"]
PBindSecret = config["PBindSecret"]

# FComm Options
FCommFilePath = config["FCommFilePath"]

# Pipline Options
PipelineEnabled = config["PipelineEnabled"]
ProjectName = config["ProjectName"]
if ProjectName == "Project-XX":
    print("\nPlease set the project name in the config\n")
    sys.exit(-1)
JenkinsServer = config["JenkinsServer"]
NexusServer = config["NexusServer"]
JenkinsKey = config["JenkinsKey"]
NexusKey = config["NexusKey"]

# HTTP Response Options
GET_404_Response = open(f'{ResourcesDirectory}responses/404_response.html', 'r').read()

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

# XOR encryption key
XOR_KEY = bytes(config["XOR_KEY"], "utf-8")

# MITRE Mapping
with open(f'{ResourcesDirectory}mitre-mapping.yml', 'r') as mitre_mapping_file:
    try:
        mitre_mapping = yaml.safe_load(mitre_mapping_file)
    except yaml.YAMLError as e:
        print("Error parsing mitre-mapping.yml: ", e)
        sys.exit(1)
