from enum import Enum

class ReportKeys(Enum):
    Tasks = ['TaskID', 'Context', 'Command', 'Output', 'User', 'SentTime', 'CompletedTime', 'ImplantID']
    C2Server = ['ID', 'PayloadCommsHost', 'EncKey', 'DomainFrontHeader', 'DefaultSleep', 'KillDate', 'GET_404_Response', 'PoshProjectDirectory', 'QuickCommand', 'DownloadURI', 'ProxyURL', 'ProxyUser', 'ProxyPass', 'URLS', 'SocksURLS','Insecure', 'UserAgent', 'Referrer', 'Pushover_APIToken', 'Pushover_APIUser', 'EnableNotifications']
    Creds = ['CredID', 'Domain', 'Username', 'Password', 'Hash']
    Implants = ['ImplantID', 'Context', 'URLID', 'User', 'Hostname', 'IpAddress', 'Key', 'FirstSeen', 'LastSeen', 'PID', 'Arch', 'Domain', 'Alive', 'Sleep', 'ModsLoaded', 'Pivot', 'Label']
    URLs = ['URLID', 'Name', 'URL', 'HostHeader', 'ProxyURL', 'ProxyUsername', 'ProxyPassword', 'CredentialExpiry']
    OpSec_Entry = ['OpsecID', 'Date', 'Owner', 'Event', 'Note']
