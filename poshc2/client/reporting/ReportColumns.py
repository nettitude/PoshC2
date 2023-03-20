from enum import Enum


class ReportColumns(Enum):
    tasks = """{rowHandle:true, formatter:"handle", headerSort:false, frozen:true, width:42, minWidth:30},
        {title:"ID", field:"id", frozen:true},
        {title:"Context", field:"context", headerFilter:"input", contextMenu: rightClickContextMenu, formatter:contextBackgroundColor},
        {title:"Command", field:"command", headerFilter:"input", width: '33vw', contextMenu: rightClickContextMenu},
        {title:"Output", field:"output", width:'50vw', headerFilter:"input", contextMenu: rightClickContextMenu, formatter:largeTextAreaFormatter},
        {title:"User", field:"user", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Sent Time", field:"sent_time", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Completed Time", field:"completed_time", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Implant ID", field:"implant_id", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Implant Numeric ID", field:"numeric_id", headerFilter:"input", contextMenu: rightClickContextMenu}
        """

    c2_server = """{rowHandle:true, formatter:"handle", headerSort:false, frozen:true, width:42, minWidth:30},
        {title:"ID", field:"id", frozen:true},
        {title:"Payload Comms Host", field:"payload_comms_host", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Encryption Key", field:"encryption_key", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Domain Front Header", field:"domain_front_header", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Default Sleep", field:"default_sleep", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Kill Date", field:"kill_date", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"404 Response", field:"get_404_response", headerFilter:"input", contextMenu: rightClickContextMenu, width: '33vw', formatter:largeTextAreaFormatter},
        {title:"Posh Project Directory", field:"posh_project_directory", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Hosted File URL", field:"hosted_file_url", headerFilter:"input", contextMenu: rightClickContextMenu, width: '33vw'},
        {title:"Download URL", field:"download_url", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Proxy URL", field:"proxy_url", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Proxy Username", field:"proxy_username", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Proxy Password", field:"proxy_password", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"URLs", field:"urls", headerFilter:"input", contextMenu: rightClickContextMenu, width: '33vw', formatter:largeTextAreaFormatter},
        {title:"Socks URLs", field:"socks_urls", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Insecure", field:"insecure", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"User Agent", field:"user_agent", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Referer", field:"referer", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Pushover API Token", field:"pushover_api_token", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Pushover API User", field:"pushover_api_user", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Slack User ID", field:"slack_user_id", headerFilter:"input", contextMenu: rightClickContextMenu}
        {title:"Slack Channel", field:"slack_channel", headerFilter:"input", contextMenu: rightClickContextMenu}
        {title:"Slack Bot Token", field:"slack_bot_token", headerFilter:"input", contextMenu: rightClickContextMenu}
        {title:"Notifications Enabled", field:"notifications_enabled", headerFilter:"input", contextMenu: rightClickContextMenu}
        """

    creds = """{rowHandle:true, formatter:"handle", headerSort:false, frozen:true, width:42, minWidth:30},
        {title:"ID", field:"id", frozen:true},
        {title:"Domain", field:"domain", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Username", field:"username", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Password", field:"password", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Hash", field:"hash", headerFilter:"input", contextMenu: rightClickContextMenu}
        """

    implants = """{rowHandle:true, formatter:"handle", headerSort:false, frozen:true, width:42, minWidth:30},
        {title:"Numeric ID", field:"numeric_id", frozen:true},
        {title:"ID", field:"id", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"URL ID", field:"url_id", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Context", field:"context", headerFilter:"input", contextMenu: rightClickContextMenu, formatter:contextBackgroundColor},,
        {title:"IP Address", field:"ip_address", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Encryption Key", field:"encryption_key", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"First Seen", field:"first_seen", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Last Seen", field:"last_seen", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Process ID", field:"process_id", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Process Name", field:"process_name", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Architecture", field:"architecture", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Alive", field:"alive", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Sleep", field:"sleep", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Loaded Modules", field:"loaded_modules", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Type", field:"type", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Label", field:"label", headerFilter:"input", contextMenu: rightClickContextMenu}
        """

    urls = """{rowHandle:true, formatter:"handle", headerSort:false, frozen:true, width:42, minWidth:30},
        {title:"ID", field:"id", frozen:true},
        {title:"Name", field:"name", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"URL", field:"url", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Host Header", field:"host_header", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Proxy URL", field:"proxy_url", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Proxy Username", field:"proxy_username", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Proxy Password", field:"proxy_password", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Credential Expiry", field:"credential_expiry", headerFilter:"input", contextMenu: rightClickContextMenu}
        """

    opsec_entries = """{rowHandle:true, formatter:"handle", headerSort:false, frozen:true, width:42, minWidth:30},
        {title:"ID", field:"id", frozen:true},
        {title:"Date", field:"date", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Owner", field:"owner", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Event", field:"event", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Note", field:"note", headerFilter:"input", contextMenu: rightClickContextMenu, formatter:largeTextAreaFormatter}
        """

    mitre_ttps = """{rowHandle:true, formatter:"handle", headerSort:false, frozen:true, width:42, minWidth:30},
        {title:"ID", field:"id", frozen:true},
        {title:"Technique ID", field:"technique_id", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Technique Name", field:"technique_name", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Tactics", field:"tactics", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Context", field:"context", headerFilter:"input", contextMenu: rightClickContextMenu, formatter:contextBackgroundColor},
        {title:"Timestamp", field:"timestamp", headerFilter:"input", contextMenu: rightClickContextMenu},
        {title:"Command", field:"command", headerFilter:"input", contextMenu: rightClickContextMenu}
        """
