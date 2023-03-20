from enum import Enum


class ReportKeys(Enum):
    tasks = ['id', 'context', 'command', 'output', 'user', 'sent_time', 'completed_time', 'implant_id']

    c2_server = ['id', 'payload_comms_host', 'encryption_key', 'domain_front_header', 'default_sleep', 'kill_date', 'get_404_response',
                'posh_project_directory', 'hosted_file_url', 'download_url', 'proxy_url', 'proxy_username', 'proxy_password', 'urls',
                'socks_urls', 'insecure', 'user_agent', 'referer', 'pushover_api_token', 'pushover_api_user', 'slack_user_id',
                'slack_channel', 'slack_bot_token', 'notifications_enabled']

    creds = ['id', 'domain', 'username', 'password', 'hash']

    implants = ['numeric_id', 'implant_id', 'url_id', 'context', 'ip_address', 'encryption_key', 'first_seen', 'last_seen',
                'process_id', 'process_name', 'architecture', 'alive', 'sleep', 'loaded_modules', 'type', 'label']

    urls = ['id', 'name', 'url', 'host_header', 'proxy_url', 'proxy_username', 'proxy_password', 'credential_expiry']

    opsec_entries = ['id', 'date', 'owner', 'event', 'note']

    mitre_ttps = ['id', 'technique_id', 'technique_name', 'tactics', 'context', 'timestamp', 'command']
