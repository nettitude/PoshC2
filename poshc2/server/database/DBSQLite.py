import sqlite3, os
from poshc2.server.Config import Database, PoshProjectDirectory
from poshc2.server.database.Model import C2, Implant, NewTask


def connect():
    conn = sqlite3.connect(Database, check_same_thread=False)
    conn.text_factory = str
    conn.row_factory = sqlite3.Row
    return conn


def initialise(create_database):
    create_implants = """CREATE TABLE IF NOT EXISTS Implants (
        ImplantID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        RandomURI VARCHAR(20),
        URLID INTEGER,
        User TEXT,
        Hostname TEXT,
        IpAddress TEXT,
        Key TEXT,
        FirstSeen TEXT,
        LastSeen TEXT,
        PID TEXT,
        ProcName TEXT,
        Arch TEXT,
        Domain TEXT,
        Alive TEXT,
        Sleep TEXT,
        ModsLoaded TEXT,
        Pivot TEXT,
        Label TEXT,
        FOREIGN KEY(URLID) REFERENCES URLs(URLID));"""

    create_autoruns = """CREATE TABLE AutoRuns (
        TaskID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        Task TEXT);"""

    create_tasks = """CREATE TABLE Tasks (
        TaskID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        RandomURI TEXT,
        Command TEXT,
        Output TEXT,
        User TEXT,
        SentTime TEXT,
        CompletedTime TEXT,
        ImplantID INTEGER,
        FOREIGN KEY(ImplantID) REFERENCES Implants(ImplantID))"""

    create_newtasks = """CREATE TABLE NewTasks (
        TaskID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        RandomURI TEXT,
        Command TEXT,
        User TEXT);"""

    create_urls = """CREATE TABLE URLs (
        URLID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        Name TEXT UNIQUE,
        URL TEXT,
        HostHeader TEXT,
        ProxyURL TEXT,
        ProxyUsername TEXT,
        ProxyPassword TEXT,
        CredentialExpiry TEXT);"""

    create_creds = """CREATE TABLE Creds (
        CredID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        Domain TEXT,
        Username TEXT,
        Password TEXT,
        Hash TEXT);"""

    create_opsec_entry = """CREATE TABLE OpSec_Entry (
        OpsecID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        Date TEXT,
        Owner TEXT,
        Event TEXT,
        Note TEXT);"""

    create_c2server = """CREATE TABLE C2Server (
        ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        PayloadCommsHost TEXT,
        EncKey TEXT,
        DomainFrontHeader TEXT,
        DefaultSleep TEXT,
        KillDate TEXT,
        GET_404_Response TEXT,
        PoshProjectDirectory TEXT,
        QuickCommand TEXT,
        DownloadURI TEXT,
        ProxyURL TEXT,
        ProxyUser TEXT,
        ProxyPass TEXT,
        URLS TEXT,
        SocksURLS TEXT,
        Insecure TEXT,
        UserAgent TEXT,
        Referrer TEXT,
        Pushover_APIToken TEXT,
        Pushover_APIUser TEXT,
        Slack_UserID TEXT,
        Slack_Channel TEXT,
        Slack_BotToken TEXT,
        EnableNotifications TEXT);"""

    create_c2_messages = """CREATE TABLE C2_Messages (
        ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        Message TEXT,
        Read TEXT);"""

    create_power_status = """CREATE TABLE IF NOT EXISTS PowerStatus (
        PowerStatusId INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        RandomURI TEXT,
        APMStatus TEXT,
        OnACPower INTEGER,
        Charging INTEGER,
        BatteryStatus TEXT,
        BatteryPercentLeft TEXT,
        ScreenLocked INTEGER,
        MonitorOn INTEGER,
        LastUpdate TEXT);"""

    create_hosted_files = """CREATE TABLE Hosted_Files (
        ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        URI TEXT,
        FilePath TEXT,
        ContentType TEXT,
        Base64 TEXT,
        Active TEXT);"""

    create_database(create_urls, create_implants, create_autoruns, create_tasks, create_newtasks,
                    create_creds, create_opsec_entry, create_c2server, create_c2_messages, create_hosted_files,
                    create_power_status)


def db_exists(conn):
    if not os.path.isfile(Database):
        return False
    c = conn.cursor()
    c.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='PowerStatus';")
    result = c.fetchone()
    if result:
        return True
    else:
        return False