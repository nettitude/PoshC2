import sqlite3
from datetime import datetime
from poshc2.Colours import Colours
from poshc2.server.Config import Database


conn = None

def database_connect():
    global conn
    conn = sqlite3.connect(Database, check_same_thread=False)
    conn.text_factory = str
    conn.row_factory = sqlite3.Row


def initializedb():
    database_connect()
    create_implants = """CREATE TABLE IF NOT EXISTS Implants (
        ImplantID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        RandomURI VARCHAR(20),
        User TEXT,
        Hostname TEXT,
        IpAddress TEXT,
        Key TEXT,
        FirstSeen TEXT,
        LastSeen TEXT,
        PID TEXT,
        Proxy TEXT,
        Arch TEXT,
        Domain TEXT,
        Alive TEXT,
        Sleep TEXT,
        ModsLoaded TEXT,
        Pivot TEXT,
        Label TEXT);"""

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
        RandomID TEXT,
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

    create_c2server = """CREATE TABLE C2Server (
        ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        PayloadCommsHost TEXT,
        EncKey TEXT,
        DomainFrontHeader TEXT,
        DefaultSleep TEXT,
        KillDate TEXT,
        HTTPResponse TEXT,
        FolderPath TEXT,
        PayloadCommsPort TEXT,
        QuickCommand TEXT,
        DownloadURI TEXT,
        ProxyURL TEXT,
        ProxyUser TEXT,
        ProxyPass TEXT,
        Sounds TEXT,
        ClockworkSMS_APIKEY TEXT,
        ClockworkSMS_MobileNumbers TEXT,
        URLS TEXT,
        SocksURLS TEXT,
        Insecure TEXT,
        UserAgent TEXT,
        Referrer TEXT,
        Pushover_APIToken TEXT,
        Pushover_APIUser TEXT,
        EnableNotifications TEXT);"""

    create_history = """CREATE TABLE History (
        ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        Command TEXT);"""

    create_c2_messages = """CREATE TABLE C2_Messages (
    ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
    Message TEXT);"""

    c = conn.cursor()

    if conn is not None:
        c.execute(create_implants)
        c.execute(create_autoruns)
        c.execute(create_tasks)
        c.execute(create_newtasks)
        c.execute(create_creds)
        c.execute(create_urls)
        c.execute(create_c2server)
        c.execute(create_history)
        c.execute(create_c2_messages)
        conn.commit()
    else:
        print("Error! cannot create the database connection.")


def setupserver(PayloadCommsHost, EncKey, DomainFrontHeader, DefaultSleep, KillDate, HTTPResponse, FolderPath, PayloadCommsPort, QuickCommand, DownloadURI, ProxyURL, ProxyUser, ProxyPass, Sounds, ClockworkSMS_APIKEY, ClockworkSMS_MobileNumbers, URLS, SocksURLS, Insecure, UserAgent, Referrer, Pushover_APIToken, Pushover_APIUser, EnableNotifications):
    c = conn.cursor()
    c.execute("INSERT INTO C2Server (PayloadCommsHost,EncKey,DomainFrontHeader,DefaultSleep,KillDate,HTTPResponse,FolderPath,PayloadCommsPort,QuickCommand,DownloadURI,ProxyURL,ProxyUser,ProxyPass,Sounds,ClockworkSMS_APIKEY,ClockworkSMS_MobileNumbers,URLS,SocksURLS,Insecure,UserAgent,Referrer,Pushover_APIToken,Pushover_APIUser,EnableNotifications) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (PayloadCommsHost, EncKey, DomainFrontHeader, DefaultSleep, KillDate, HTTPResponse, FolderPath, PayloadCommsPort, QuickCommand, DownloadURI, ProxyURL, ProxyUser, ProxyPass, Sounds, ClockworkSMS_APIKEY, ClockworkSMS_MobileNumbers, URLS, SocksURLS, Insecure, UserAgent, Referrer, Pushover_APIToken, Pushover_APIUser, EnableNotifications))
    conn.commit()


def get_c2server_all():
    c = conn.cursor()
    c.execute("SELECT * FROM C2Server")
    result = c.fetchone()
    if result:
        return result
    else:
        return None


def get_implants_all():
    c = conn.cursor()
    c.execute("SELECT * FROM Implants")
    result = c.fetchall()
    if result:
        return result
    else:
        return None


def get_newtasks_all():
    c = conn.cursor()
    c.execute("SELECT * FROM NewTasks")
    result = c.fetchall()
    if result:
        return result
    else:
        return None


def new_urldetails(RandomID, URL, HostHeader, ProxyURL, ProxyUsername, ProxyPassword, CredentialExpiry):
    c = conn.cursor()
    c.execute("INSERT INTO URLs (RandomID, URL, HostHeader, ProxyURL, ProxyUsername, ProxyPassword, CredentialExpiry) VALUES (?, ?, ?, ?, ?, ?, ?)", (RandomID, URL, HostHeader, ProxyURL, ProxyUsername, ProxyPassword, CredentialExpiry))
    conn.commit()


def drop_newtasks():
    c = conn.cursor()
    c.execute("DELETE FROM NewTasks ")
    conn.commit()


def new_task(task, user, randomuri):
    c = conn.cursor()
    c.execute("INSERT INTO NewTasks (RandomURI, Command, User) VALUES (?, ?, ?)", (randomuri, task, user))
    conn.commit()


def get_lastcommand():
    c = conn.cursor()
    c.execute("SELECT * FROM History ORDER BY ID DESC LIMIT 1")
    try:
        result = c.fetchone()[1]
    except Exception:
        result = None
    if result:
        return result
    else:
        return None


def new_commandhistory(command):
    c = conn.cursor()
    c.execute("INSERT INTO History (Command) VALUES (?)", (command,))
    conn.commit()


def get_history_dict():
    c = conn.cursor()
    c.execute("SELECT * FROM History")
    result = c.fetchall()
    if result:
        return result
    else:
        return None


def get_history():
    c = conn.cursor()
    c.execute("SELECT * FROM History")
    result = c.fetchall()
    history = ""
    for command in result:
        history = "%s \r\n %s" % (history, command[1])
    history = "%s \r\n" % (history)
    if history:
        return history
    else:
        return None


def get_implants():
    c = conn.cursor()
    c.execute("SELECT * FROM Implants WHERE Alive='Yes'")
    result = c.fetchall()
    if result:
        return result
    else:
        return None


def get_implanttype(randomuri):
    c = conn.cursor()
    c.execute("SELECT Pivot FROM Implants WHERE RandomURI=?", (randomuri,))
    result = str(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def get_implantdetails(randomuri):
    c = conn.cursor()
    c.execute("SELECT * FROM Implants WHERE RandomURI=?", (randomuri,))
    result = c.fetchone()
    if result:
        return result
    else:
        return None


def get_hostdetails(implant_id):
    c = conn.cursor()
    c.execute("SELECT * FROM Implants WHERE ImplantID=?", (implant_id,))
    result = c.fetchone()
    if result:
        return result
    else:
        return None


def get_randomuri(implant_id):
    c = conn.cursor()
    c.execute("SELECT RandomURI FROM Implants WHERE ImplantID=?", (implant_id,))
    result = str(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def add_autorun(Task):
    c = conn.cursor()
    c.execute("INSERT INTO AutoRuns (Task) VALUES (?)", (Task,))
    conn.commit()


def update_sleep(sleep, randomuri):
    c = conn.cursor()
    c.execute("UPDATE Implants SET Sleep=? WHERE RandomURI=?", (sleep, randomuri))
    conn.commit()


def update_label(label, randomuri):
    c = conn.cursor()
    c.execute("UPDATE Implants SET Label=? WHERE RandomURI=?", (label, randomuri))
    conn.commit()


def update_mods(modules, randomuri):
    c = conn.cursor()
    c.execute("UPDATE Implants SET ModsLoaded=? WHERE RandomURI=?", (modules, randomuri))
    conn.commit()


def kill_implant(randomuri):
    c = conn.cursor()
    c.execute("UPDATE Implants SET Alive='No' WHERE RandomURI=?", (randomuri,))
    conn.commit()


def unhide_implant(randomuri):
    c = conn.cursor()
    c.execute("UPDATE Implants SET Alive='Yes' WHERE RandomURI=?", (randomuri,))
    conn.commit()


def hide_implant(randomuri):
    c = conn.cursor()
    c.execute("UPDATE Implants SET Alive='No' WHERE RandomURI=?", (randomuri,))
    conn.commit()


def select_mods(randomuri):
    c = conn.cursor()
    c.execute("SELECT ModsLoaded FROM Implants WHERE RandomURI=?", (randomuri,))
    result = str(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def select_item(column, table):
    c = conn.cursor()
    c.execute("SELECT %s FROM %s" % (column, table))
    result = str(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def del_newtasks(TaskID):
    c = conn.cursor()
    c.execute("DELETE FROM NewTasks WHERE TaskID=?", (TaskID,))
    conn.commit()


def del_autorun(TaskID):
    c = conn.cursor()
    c.execute("DELETE FROM AutoRuns WHERE TaskID=?", (TaskID,))
    conn.commit()


def del_autoruns():
    c = conn.cursor()
    c.execute("DELETE FROM AutoRuns ")
    conn.commit()


def update_implant_lastseen(time, randomuri):
    c = conn.cursor()
    c.execute("UPDATE Implants SET LastSeen=? WHERE RandomURI=?", (time, randomuri))
    conn.commit()


def new_implant(RandomURI, User, Hostname, IpAddress, Key, FirstSeen, LastSeen, PID, Proxy, Arch, Domain, Alive, Sleep, ModsLoaded, Pivot, Label):
    c = conn.cursor()
    c.execute("INSERT INTO Implants (RandomURI, User, Hostname, IpAddress, Key, FirstSeen, LastSeen, PID, Proxy, Arch, Domain, Alive, Sleep, ModsLoaded, Pivot, Label) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (RandomURI, User, Hostname, IpAddress, Key, FirstSeen, LastSeen, PID, Proxy, Arch, Domain, Alive, Sleep, ModsLoaded, Pivot, Label))
    conn.commit()
    return c.lastrowid


def insert_task(randomuri, command, user):
    now = datetime.now()
    sent_time = now.strftime("%d/%m/%Y %H:%M:%S")
    implantId = get_implantbyrandomuri(randomuri)[0]
    c = conn.cursor()
    if user is None:
        user = ""
    c.execute("INSERT INTO Tasks (RandomURI, Command, Output, User, SentTime, CompletedTime, ImplantID) VALUES (?, ?, ?, ?, ?, ?, ?)", (randomuri, command, "", user, sent_time, "", implantId))
    conn.commit()
    return c.lastrowid


def update_task(taskId, output):
    now = datetime.now()
    completedTime = now.strftime("%d/%m/%Y %H:%M:%S")
    c = conn.cursor()
    c.execute("UPDATE Tasks SET Output=?, CompletedTime=? WHERE TaskID=?", (output, completedTime, taskId))
    conn.commit()
    return c.lastrowid


def get_task_owner(taskId):
    c = conn.cursor()
    c.execute("SELECT User FROM Tasks WHERE TaskID=?", (taskId,))
    result = c.fetchone()
    if result and result[0] != "":
        return result[0]
    else:
        return None


def update_item(column, table, value, wherecolumn=None, where=None):
    c = conn.cursor()
    if wherecolumn is None:
        c.execute("UPDATE %s SET %s=?" % (table, column), (value,))
    else:
        c.execute("UPDATE %s SET %s=? WHERE %s=?" % (table, column, wherecolumn), (value, where))
    conn.commit()


def get_implantbyid(implantId):
    c = conn.cursor()
    c.execute("SELECT * FROM Implants WHERE ImplantID=?", (implantId,))
    result = c.fetchone()
    if result:
        return result
    else:
        return None


def get_implantbyrandomuri(RandomURI):
    c = conn.cursor()
    c.execute("SELECT * FROM Implants WHERE RandomURI=?", (RandomURI,))
    result = c.fetchone()
    if result:
        return result
    else:
        return None


def get_tasks():
    c = conn.cursor()
    c.execute("SELECT * FROM Tasks")
    result = c.fetchall()
    if result:
        return result
    else:
        return None


def get_tasksbyid(implantId):
    c = conn.cursor()
    c.execute("SELECT * FROM Tasks WHERE CompletedTaskID=?", (implantId,))
    result = c.fetchone()
    if result:
        return result
    else:
        return None


def get_newtasksbyid(taskid):
    c = conn.cursor()
    c.execute("SELECT * FROM NewTasks WHERE TaskID=?", (taskid,))
    result = c.fetchone()
    if result:
        return result
    else:
        return None


def get_seqcount(table):
    c = conn.cursor()
    c.execute("SELECT seq FROM sqlite_sequence WHERE name=\"?\"", (table,))
    result = int(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def get_baseenckey():
    c = conn.cursor()
    c.execute("SELECT EncKey FROM C2Server")
    result = str(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def get_dfheader():
    c = conn.cursor()
    c.execute("SELECT DomainFrontHeader FROM C2Server")
    result = str(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def get_cmd_from_task_id(taskId):
    c = conn.cursor()
    c.execute("SELECT Command FROM Tasks WHERE TaskId=?", (taskId,))
    result = str(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def get_notificationstatus():
    c = conn.cursor()
    c.execute("SELECT EnableNotifications FROM C2Server")
    result = str(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def get_defaultuseragent():
    c = conn.cursor()
    c.execute("SELECT UserAgent FROM C2Server")
    result = str(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def get_defaultbeacon():
    c = conn.cursor()
    c.execute("SELECT DefaultSleep FROM C2Server")
    result = str(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def get_killdate():
    c = conn.cursor()
    c.execute("SELECT KillDate FROM C2Server")
    result = str(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def get_sharpurls():
    c = conn.cursor()
    c.execute("SELECT SocksURLS FROM C2Server")
    result = str(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def get_allurls():
    c = conn.cursor()
    c.execute("SELECT URLS FROM C2Server")
    result1 = str(c.fetchone()[0])
    c.execute("SELECT SocksURLS FROM C2Server")
    result2 = str(c.fetchone()[0])
    result = result1 + "," + result2
    if result:
        return result
    else:
        return None


def get_beaconurl():
    c = conn.cursor()
    c.execute("SELECT URLS FROM C2Server")
    result = str(c.fetchone()[0])
    if result:
        url = result.split(",")
        return url[0]
    else:
        return None


def get_otherbeaconurls():
    c = conn.cursor()
    c.execute("SELECT URLS FROM C2Server")
    result = str(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def get_newimplanturl():
    c = conn.cursor()
    c.execute("SELECT URLS FROM C2Server")
    result = str(c.fetchone()[0])
    if result:
        url = result.split(",")
        return "/" + url[0].replace('"', '')
    else:
        return None


def get_hostinfo(randomuri):
    c = conn.cursor()
    c.execute("SELECT * FROM Implants WHERE RandomURI=?", (randomuri,))
    result = c.fetchall()
    if result:
        return result[0]
    else:
        return None


def get_c2urls():
    c = conn.cursor()
    c.execute("SELECT * FROM URLs")
    result = c.fetchall()
    if result:
        return result
    else:
        return None


def get_autoruns():
    c = conn.cursor()
    c.execute("SELECT * FROM AutoRuns")
    result = c.fetchall()
    if result:
        return result
    else:
        return None


def get_autorun():
    c = conn.cursor()
    c.execute("SELECT * FROM AutoRuns")
    result = c.fetchall()
    autoruns = ""
    for autorun in result:
        autoruns += "%s:%s\r\n" % (autorun[0], autorun[1])
    if autoruns:
        return autoruns
    else:
        return None


def get_pid(randomuri):
    c = conn.cursor()
    c.execute("SELECT PID FROM Implants WHERE RandomURI=?", (randomuri,))
    result = c.fetchone()[0]
    if result:
        return result
    else:
        return None


def get_newtasks(randomuri):
    c = conn.cursor()
    c.execute("SELECT * FROM NewTasks WHERE RandomURI=?", (randomuri,))
    result = c.fetchall()
    if result:
        return result
    else:
        return None


def get_keys():
    c = conn.cursor()
    result = c.execute("SELECT EncKey FROM C2Server")
    result = c.fetchall()
    if result:
        return result
    else:
        return None


def insert_cred(domain, username, password, hash):
    if check_if_cred_exists(domain, username, password, hash):
        return None
    c = conn.cursor()
    c.execute("INSERT INTO Creds (Domain, Username, Password, Hash) VALUES (?, ?, ?, ?)", (domain, username, password, hash))
    conn.commit()
    return c.lastrowid


def check_if_cred_exists(domain, username, password, hash):
    c = conn.cursor()
    c.execute("SELECT * FROM Creds WHERE Domain is ? AND Username is ? AND Password is ? AND Hash is ?", (domain, username, password, hash))
    result = c.fetchall()
    if result:
        return True
    else:
        return False


def get_creds():
    c = conn.cursor()
    c.execute("SELECT * FROM Creds")
    result = c.fetchall()
    if result:
        return result
    else:
        return None


def get_creds_for_user(username):
    c = conn.cursor()
    c.execute("SELECT * FROM Creds WHERE Username=?", (username,))
    result = c.fetchall()
    if result:
        return result
    else:
        return None


def get_cred_by_id(credId):
    c = conn.cursor()
    c.execute("SELECT * FROM Creds WHERE CredID=?", (credId,))
    result = c.fetchone()
    if result:
        return result
    else:
        return None


def new_c2_message(message):
    now = datetime.now()
    message = "\n%s%s: %s%s\n" % (Colours.BLUE, now.strftime("%d/%m/%Y %H:%M:%S"), message, Colours.END)
    c = conn.cursor()
    c.execute("INSERT INTO C2_Messages (Message) VALUES (?)", (message,))
    conn.commit()
    return c.lastrowid


def get_c2_messages():
    c = conn.cursor()
    c.execute("SELECT * FROM C2_Messages")
    result = c.fetchall()
    if result:
        messages = []
        for item in result:
            c.execute("DELETE FROM C2_Messages WHERE ID=?", (item[0],))
            conn.commit()
            messages.append(item[1])
        return messages
    else:
        return None
