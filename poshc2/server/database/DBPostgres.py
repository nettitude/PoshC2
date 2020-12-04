import psycopg2
from psycopg2.extensions import AsIs
from poshc2.server.Config import Database, PoshProjectDirectory
from poshc2.server.database.Model import C2, Implant, NewTask


def connect():
    conn = psycopg2.connect(Database)
    return conn


def initialise(create_database):
    create_implants = """CREATE TABLE IF NOT EXISTS Implants (
        ImplantID SERIAL NOT NULL PRIMARY KEY,
        RandomURI VARCHAR(20),
        URLID INTEGER,
        "User" TEXT,
        Hostname TEXT,
        IpAddress TEXT,
        Key TEXT,
        FirstSeen TEXT,
        LastSeen TEXT,
        PID TEXT,
        Arch TEXT,
        Domain TEXT,
        Alive TEXT,
        Sleep TEXT,
        ModsLoaded TEXT,
        Pivot TEXT,
        Label TEXT,
        FOREIGN KEY(URLID) REFERENCES URLs(URLID));"""

    create_autoruns = """CREATE TABLE AutoRuns (
        TaskID SERIAL NOT NULL PRIMARY KEY,
        Task TEXT);"""

    create_tasks = """CREATE TABLE Tasks (
        TaskID SERIAL NOT NULL PRIMARY KEY,
        RandomURI TEXT,
        Command TEXT,
        Output TEXT,
        "User" TEXT,
        SentTime TEXT,
        CompletedTime TEXT,
        ImplantID INTEGER,
        FOREIGN KEY(ImplantID) REFERENCES Implants(ImplantID))"""

    create_newtasks = """CREATE TABLE NewTasks (
        TaskID SERIAL NOT NULL PRIMARY KEY,
        RandomURI TEXT,
        Command TEXT,
        "User" TEXT);"""

    create_urls = """CREATE TABLE URLs (
        URLID SERIAL NOT NULL PRIMARY KEY,
        Name TEXT UNIQUE,
        URL TEXT,
        HostHeader TEXT,
        ProxyURL TEXT,
        ProxyUsername TEXT,
        ProxyPassword TEXT,
        CredentialExpiry TEXT);"""

    create_creds = """CREATE TABLE Creds (
        CredID SERIAL NOT NULL PRIMARY KEY,
        Domain TEXT,
        Username TEXT,
        Password TEXT,
        Hash TEXT);"""

    create_opsec_entry = """CREATE TABLE OpSec_Entry (
        OpsecID SERIAL NOT NULL PRIMARY KEY,
        Date TEXT,
        Owner TEXT,
        Event TEXT,
        Note TEXT);"""

    create_c2server = """CREATE TABLE C2Server (
        ID SERIAL NOT NULL PRIMARY KEY,
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
        ID SERIAL NOT NULL PRIMARY KEY,
        Message TEXT,
        Read TEXT);"""

    create_hosted_files = """CREATE TABLE Hosted_Files (
        ID SERIAL NOT NULL PRIMARY KEY,
        URI TEXT,
        FilePath TEXT,
        ContentType TEXT,
        Base64 TEXT,
        Active TEXT);"""

    create_power_status = """CREATE TABLE IF NOT EXISTS PowerStatus (
        PowerStatusId SERIAL NOT NULL PRIMARY KEY,
        RandomURI TEXT,
        APMStatus TEXT,
        OnACPower INTEGER,
        Charging TEXT,
        BatteryStatus TEXT,
        BatteryPercentLeft TEXT,
        ScreenLocked INTEGER,
        MonitorOn INTEGER,
        LastUpdate TEXT);"""

    create_database(create_urls, create_implants, create_autoruns, create_tasks, create_newtasks,
                    create_creds, create_opsec_entry, create_c2server, create_c2_messages, create_hosted_files,
                    create_power_status)


def db_exists(conn):
    c = conn.cursor()
    c.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';")
    return c.rowcount > 0