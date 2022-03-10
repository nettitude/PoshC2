from enum import Enum

class ReportColumns(Enum):
    Tasks = """{rowHandle:true, formatter:"handle", headerSort:false, frozen:true, width:42, minWidth:30},
        {title:"Task ID", field:"TaskID", frozen:true},
        {title:"Context", field:"Context", headerFilter:"input", contextMenu: rightClickContextMenu, formatter:contextBackgroundColor},
        {title:"Command", field:"Command", headerFilter:"input", width: '33vw', contextMenu: rightClickContextMenu},
        {title:"Output", field:"Output", width:'50vw', headerFilter:"input", contextMenu: rightClickContextMenu, formatter:largeTextAreaFormatter},
        {title:"User", field:"User", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Sent Time", field:"SentTime", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Completed Time", field:"CompletedTime", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Implant ID", field:"ImplantID", headerFilter:"input", contextMenu: rightClickContextMenu}
        """
    C2Server = """{rowHandle:true, formatter:"handle", headerSort:false, frozen:true, width:42, minWidth:30},
        {title:"ID", field:"ID", frozen:true},
        {title:"Payload Comms Host", field:"PayloadCommsHost", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Enc Key", field:"EncKey", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Domain Front Header", field:"DomainFrontHeader", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Default Sleep", field:"DefaultSleep", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Kill Date", field:"KillDate", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"404 Response", field:"GET_404_Response", headerFilter:"input", contextMenu: rightClickContextMenu, width: '33vw', formatter:largeTextAreaFormatter},
        {title:"Posh Project Directory", field:"PoshProjectDirectory", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Quick Command", field:"QuickCommand", headerFilter:"input", contextMenu: rightClickContextMenu, width: '33vw'},
        {title:"Download URI", field:"DownloadURI", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Proxy URL", field:"ProxyURL", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Proxy User", field:"ProxyUser", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Proxy Pass", field:"ProxyPass", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"URLs", field:"URLS", headerFilter:"input", contextMenu: rightClickContextMenu, width: '33vw', formatter:largeTextAreaFormatter},
        {title:"Socks URLs", field:"SocksURLS", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Insecure", field:"Insecure", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"User Agent", field:"UserAgent", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Referrer", field:"Referrer", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Pushover API Token", field:"Pushover_APIToken", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Pushover API User", field:"Pushover_APIUser", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Enable Notifications", field:"EnableNotifications", headerFilter:"input", contextMenu: rightClickContextMenu}
        """
    Creds = """{rowHandle:true, formatter:"handle", headerSort:false, frozen:true, width:42, minWidth:30},
        {title:"Cred ID", field:"CredID", frozen:true},
        {title:"Domain", field:"Domain", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Username", field:"Username", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Password", field:"Password", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Hash", field:"Hash", headerFilter:"input", contextMenu: rightClickContextMenu}
        """
    Implants = """{rowHandle:true, formatter:"handle", headerSort:false, frozen:true, width:42, minWidth:30},
        {title:"Implant ID", field:"ImplantID", frozen:true},
        {title:"Context", field:"Context", headerFilter:"input", contextMenu: rightClickContextMenu, formatter:contextBackgroundColor},
        {title:"URL ID", field:"URLID", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"User", field:"User", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Hostname", field:"Hostname", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"IP Address", field:"IpAddress", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Key", field:"Key", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"First Seen", field:"FirstSeen", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Last Seen", field:"LastSeen", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"PID", field:"PID", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Arch", field:"Arch", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Domain", field:"Domain", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Alive", field:"Alive", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Sleep", field:"Sleep", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Mods Loaded", field:"ModsLoaded", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Pivot", field:"Pivot", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Label", field:"Label", headerFilter:"input", contextMenu: rightClickContextMenu}
        """
    URLs = """{rowHandle:true, formatter:"handle", headerSort:false, frozen:true, width:42, minWidth:30},
        {title:"URL ID", field:"URLID", frozen:true},
        {title:"Name", field:"Name", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"URL", field:"URL", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Host Header", field:"HostHeader", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Proxy URL", field:"ProxyURL", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Proxy Username", field:"ProxyUsername", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Proxy Password", field:"ProxyPassword", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Credential Expiry", field:"CredentialExpiry", headerFilter:"input", contextMenu: rightClickContextMenu}
        """
    OpSec_Entry = """{rowHandle:true, formatter:"handle", headerSort:false, frozen:true, width:42, minWidth:30},
        {title:"Opsec ID", field:"OpsecID", frozen:true},
        {title:"Date", field:"Date", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Owner", field:"Owner", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Event", field:"Event", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Note", field:"Note", headerFilter:"input", contextMenu: rightClickContextMenu, formatter:largeTextAreaFormatter}
        """
