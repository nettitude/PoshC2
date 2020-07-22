class C2:
    def __init__(self, PayloadCommsHost, EncKey, DomainFrontHeader, DefaultSleep, KillDate, GET_404_Response,
        PoshProjectDirectory, QuickCommand, DownloadURI, ProxyURL, ProxyUser, ProxyPass,
        URLS, SocksURLS, Insecure, UserAgent, Referrer, Pushover_APIToken, Pushover_APIUser, EnableNotifications):
        self.PayloadCommsHost = PayloadCommsHost
        self.EncKey = EncKey
        self.DomainFrontHeader = DomainFrontHeader
        self.DefaultSleep = DefaultSleep
        self.KillDate = KillDate
        self.GET_404_Response = GET_404_Response
        self.PoshProjectDirectory = PoshProjectDirectory
        self.QuickCommand = QuickCommand
        self.DownloadURI = DownloadURI
        self.ProxyURL = ProxyURL
        self.ProxyUser = ProxyUser
        self.ProxyPass = ProxyPass
        self.URLS = URLS
        self.SocksURLS = SocksURLS
        self.Insecure = Insecure
        self.UserAgent = UserAgent
        self.Referrer = Referrer
        self.Pushover_APIToken = Pushover_APIToken
        self.Pushover_APIUser = Pushover_APIUser
        self.EnableNotifications = EnableNotifications

class Implant:
        def __init__(self, ImplantID, RandomURI, URLID, User, Hostname, IpAddress, Key, FirstSeen, LastSeen, PID, Arch, Domain, Alive, Sleep, ModsLoaded, Pivot, Label):
            self.ImplantID = ImplantID
            self.RandomURI = RandomURI
            self.URLID = URLID
            self.User = User
            self.Hostname = Hostname
            self.IpAddress = IpAddress
            self.Key = Key
            self.FirstSeen = FirstSeen
            self.LastSeen = LastSeen
            self.PID = PID
            self.Arch = Arch
            self.Domain = Domain
            self.Alive = Alive
            self.Sleep = Sleep
            self.ModsLoaded = ModsLoaded
            self.Pivot = Pivot
            self.Label = Label

class CachedUrls:
        def __init__(self, ID, URI, FilePath, ContentType, Base64, Active):
            self.ID = ID
            self.URI = URI
            self.FilePath = FilePath
            self.ContentType = ContentType
            self.Base64 = Base64
            self.Active = Active

class NewTask:
        def __init__(self, TaskID, RandomURI, Command, User):
            self.TaskID = TaskID
            self.RandomURI = RandomURI
            self.Command = Command
            self.User = User
