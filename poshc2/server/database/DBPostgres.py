import psycopg2, re
import pandas as pd
from psycopg2.extensions import AsIs
from datetime import datetime
from poshc2.Colours import Colours
from poshc2.server.Config import Database, PoshProjectDirectory
from poshc2.server.database.Model import C2, Implant


conn = None


def database_connect():
    global conn
    conn = psycopg2.connect(Database)


def initializedb():
    database_connect()
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
        Sounds TEXT,
        URLS TEXT,
        SocksURLS TEXT,
        Insecure TEXT,
        UserAgent TEXT,
        Referrer TEXT,
        Pushover_APIToken TEXT,
        Pushover_APIUser TEXT,
        EnableNotifications TEXT);"""

    create_c2_messages = """CREATE TABLE C2_Messages (
        ID SERIAL NOT NULL PRIMARY KEY,
        Message TEXT);"""


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

    try:
        c = conn.cursor()
    except Exception as e:
        print("[-] Error occurred using %s" % Database)
        print("[-] Exception: %s" % e)

    if conn is not None:
        try:
            c.execute(create_urls)
            c.execute(create_implants)
            c.execute(create_autoruns)
            c.execute(create_tasks)
            c.execute(create_newtasks)
            c.execute(create_creds)
            c.execute(create_c2server)
            c.execute(create_c2_messages)
            c.execute(create_power_status)            
            conn.commit()
        except Exception as e:
            print("Error creating database: " + e)


def get_db():
    if conn is None:
        database_connect()
    c = conn.cursor()
    c.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';")
    return c.rowcount


def setupserver(PayloadCommsHost, EncKey, DomainFrontHeader, DefaultSleep, KillDate, GET_404_Response, PoshProjectDirectory, QuickCommand, DownloadURI, ProxyURL, ProxyUser, ProxyPass, Sounds, URLS, SocksURLS, Insecure, UserAgent, Referrer, Pushover_APIToken, Pushover_APIUser, EnableNotifications):
    c = conn.cursor()
    c.execute("INSERT INTO C2Server (PayloadCommsHost,EncKey,DomainFrontHeader,DefaultSleep,KillDate,GET_404_Response,PoshProjectDirectory,QuickCommand,DownloadURI,ProxyURL,ProxyUser,ProxyPass,Sounds,URLS,SocksURLS,Insecure,UserAgent,Referrer,Pushover_APIToken,Pushover_APIUser,EnableNotifications) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (PayloadCommsHost, EncKey, DomainFrontHeader, DefaultSleep, KillDate, GET_404_Response, PoshProjectDirectory, QuickCommand, DownloadURI, ProxyURL, ProxyUser, ProxyPass, Sounds, URLS, SocksURLS, Insecure, UserAgent, Referrer, Pushover_APIToken, Pushover_APIUser, EnableNotifications))
    conn.commit()


def get_c2server_all():
    c = conn.cursor()
    c.execute("SELECT * FROM C2Server")
    result = c.fetchone()
    return C2(result[1], result[2], result[3], result[4], result[5], result[6], result[7], result[8], result[9],
    result[10], result[11], result[12], result[13], result[14], result[15], result[16], result[17],
    result[18], result[19], result[20], result[21])


def get_implants_all():
    c = conn.cursor()
    c.execute("SELECT * FROM Implants")
    results = c.fetchall()
    implants = []
    for result in results:
        implants.append(Implant(result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7], result[8], 
        result[9], result[10], result[11], result[12], result[13], result[14], result[15], result[16]))
    return implants


def get_newtasks_all():
    c = conn.cursor()
    c.execute("SELECT * FROM NewTasks")
    result = c.fetchall()
    if result:
        return result
    else:
        return None


def new_urldetails(Name, URL, HostHeader, ProxyURL, ProxyUsername, ProxyPassword, CredentialExpiry):
    c = conn.cursor()
    c.execute("INSERT INTO URLs (Name, URL, HostHeader, ProxyURL, ProxyUsername, ProxyPassword, CredentialExpiry) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING URLID", (Name, URL, HostHeader, ProxyURL, ProxyUsername, ProxyPassword, CredentialExpiry))
    conn.commit()
    return c.fetchone()[0]


def drop_newtasks():
    c = conn.cursor()
    c.execute("DELETE FROM NewTasks ")
    conn.commit()


def new_task(task, user, randomuri):
    c = conn.cursor()
    c.execute("INSERT INTO NewTasks (RandomURI, Command, \"User\") VALUES (%s, %s, %s)", (randomuri, task, user))
    conn.commit()


def get_implants():
    c = conn.cursor()
    c.execute("SELECT * FROM Implants WHERE Alive='Yes' ORDER BY implantid")
    results = c.fetchall()
    implants = []
    for result in results:
        implants.append(Implant(result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7], result[8], 
        result[9], result[10], result[11], result[12], result[13], result[14], result[15], result[16]))
    return implants


def get_implanttype(randomuri):
    c = conn.cursor()
    c.execute("SELECT Pivot FROM Implants WHERE RandomURI=%s", (randomuri,))
    result = c.fetchone()[0]
    if result:
        return result
    else:
        return None


def get_implantdetails(randomuri):
    c = conn.cursor()
    c.execute("SELECT * FROM Implants WHERE RandomURI=%s", (randomuri,))
    result = c.fetchone()
    if result:
        return Implant(result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7], result[8], 
        result[9], result[10], result[11], result[12], result[13], result[14], result[15], result[16])
    else:
        return None


def get_randomuri(implant_id):
    c = conn.cursor()
    c.execute("SELECT RandomURI FROM Implants WHERE ImplantID=%s", (implant_id,))
    result = c.fetchone()[0]
    if result:
        return result
    else:
        return None


def add_autorun(Task):
    c = conn.cursor()
    c.execute("INSERT INTO AutoRuns (Task) VALUES (%s)", (Task,))
    conn.commit()


def update_sleep(sleep, randomuri):
    c = conn.cursor()
    c.execute("UPDATE Implants SET Sleep=%s WHERE RandomURI=%s", (sleep, randomuri))
    conn.commit()


def update_label(label, randomuri):
    c = conn.cursor()
    c.execute("UPDATE Implants SET Label=%s WHERE RandomURI=%s", (label, randomuri))
    conn.commit()


def update_mods(modules, randomuri):
    c = conn.cursor()
    c.execute("UPDATE Implants SET ModsLoaded=%s WHERE RandomURI=%s", (modules, randomuri))
    conn.commit()


def kill_implant(randomuri):
    c = conn.cursor()
    c.execute("UPDATE Implants SET Alive='No' WHERE RandomURI=%s", (randomuri,))
    conn.commit()


def unhide_implant(randomuri):
    c = conn.cursor()
    c.execute("UPDATE Implants SET Alive='Yes' WHERE RandomURI=%s", (randomuri,))
    conn.commit()


def hide_implant(randomuri):
    c = conn.cursor()
    c.execute("UPDATE Implants SET Alive='No' WHERE RandomURI=%s", (randomuri,))
    conn.commit()


def select_mods(randomuri):
    c = conn.cursor()
    c.execute("SELECT ModsLoaded FROM Implants WHERE RandomURI=%s", (randomuri,))
    result = c.fetchone()[0]
    if result:
        return result
    else:
        return None


def select_item(column, table):
    c = conn.cursor()
    c.execute("SELECT %s FROM %s" % (column, table))
    result = c.fetchone()[0]
    if result:
        return result
    else:
        return None


def del_newtasks(TaskID):
    c = conn.cursor()
    c.execute("DELETE FROM NewTasks WHERE TaskID=%s", (TaskID,))
    conn.commit()


def del_autorun(TaskID):
    c = conn.cursor()
    c.execute("DELETE FROM AutoRuns WHERE TaskID=%s", (TaskID,))
    conn.commit()


def del_autoruns():
    c = conn.cursor()
    c.execute("DELETE FROM AutoRuns ")
    conn.commit()


def update_implant_lastseen(time, randomuri):
    try:
        c = conn.cursor()
        c.execute("UPDATE Implants SET LastSeen=%s WHERE RandomURI=%s", (time, randomuri))
        conn.commit()
    except:
        pass


def new_implant(RandomURI, URLID, User, Hostname, IpAddress, Key, FirstSeen, LastSeen, PID, Arch, Domain, Alive, Sleep, ModsLoaded, Pivot, Label):
    c = conn.cursor()
    c.execute("INSERT INTO Implants (RandomURI, URLID, \"User\", Hostname, IpAddress, Key, FirstSeen, LastSeen, PID, Arch, Domain, Alive, Sleep, ModsLoaded, Pivot, Label) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING ImplantID", (RandomURI, URLID, User, Hostname, IpAddress, Key, FirstSeen, LastSeen, PID, Arch, Domain, Alive, Sleep, ModsLoaded, Pivot, Label))
    conn.commit()
    return c.fetchone()[0]


def insert_task(randomuri, command, user):
    now = datetime.now()
    sent_time = now.strftime("%d/%m/%Y %H:%M:%S")
    implantId = get_implantbyrandomuri(randomuri).ImplantID
    c = conn.cursor()
    if user is None:
        user = ""
    c.execute("INSERT INTO Tasks (RandomURI, Command, Output, \"User\", SentTime, CompletedTime, ImplantID) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING TaskID", (randomuri, command, "", user, sent_time, "", implantId))
    conn.commit()
    return c.fetchone()[0]


def update_task(taskId, output):
    now = datetime.now()
    completedTime = now.strftime("%d/%m/%Y %H:%M:%S")
    output = re.sub(u'\x00', '', output)  # TODO can just be replaced using string.replace?
    c = conn.cursor()
    c.execute("""UPDATE Tasks SET Output=%(output)s, CompletedTime=%(completedTime)s WHERE TaskID=%(taskId)s RETURNING TaskID;""",
              {'output': output, 'completedTime': completedTime, 'taskId': taskId})
    conn.commit()
    return c.fetchone()[0]


def get_task_owner(taskId):
    c = conn.cursor()
    c.execute("SELECT \"User\" FROM Tasks WHERE TaskID=%(taskId)s", {'taskId': taskId})
    result = c.fetchone()[0]
    if result and result != "":
        return result
    else:
        return None


def update_item(column, table, value, wherecolumn=None, where=None):
    c = conn.cursor()
    if wherecolumn is None:
        c.execute("UPDATE %s SET %s=%s", (AsIs(table), AsIs(column), value,))
    else:
        c.execute("UPDATE %s SET %s=%s WHERE %s = %s" % (AsIs(table), AsIs(column), wherecolumn, value, where))
    conn.commit()


def get_implantbyid(implantId):
    c = conn.cursor()
    c.execute("SELECT * FROM Implants WHERE ImplantID=%s", (implantId,))
    result = c.fetchone()
    if result:
        return Implant(result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7], result[8], 
        result[9], result[10], result[11], result[12], result[13], result[14], result[15], result[16])
    else:
        return None


def get_implantbyrandomuri(RandomURI):
    c = conn.cursor()
    c.execute("SELECT * FROM Implants WHERE RandomURI=%s", (RandomURI,))
    result = c.fetchone()
    if result:
        return Implant(result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7], result[8], 
        result[9], result[10], result[11], result[12], result[13], result[14], result[15], result[16])
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
    c.execute("SELECT * FROM Tasks WHERE CompletedTaskID=%s", (implantId,))
    result = c.fetchone()
    if result:
        return result
    else:
        return None


def get_newtasksbyid(taskid):
    c = conn.cursor()
    c.execute("SELECT * FROM NewTasks WHERE TaskID=%s", (taskid,))
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
    result = c.fetchone()[0]
    if result:
        return result
    else:
        return None


def get_dfheader():
    c = conn.cursor()
    c.execute("SELECT DomainFrontHeader FROM C2Server")
    result = c.fetchone()[0]
    if result:
        return result
    else:
        return None


def get_cmd_from_task_id(taskId):
    c = conn.cursor()
    c.execute("SELECT Command FROM Tasks WHERE TaskId=%s", (taskId,))
    result = c.fetchone()[0]
    if result:
        return result
    else:
        return None


def get_notificationstatus():
    c = conn.cursor()
    c.execute("SELECT EnableNotifications FROM C2Server")
    result = c.fetchone()[0]
    if result:
        return result
    else:
        return None


def get_defaultuseragent():
    c = conn.cursor()
    c.execute("SELECT UserAgent FROM C2Server")
    result = c.fetchone()[0]
    if result:
        return result
    else:
        return None


def get_defaultbeacon():
    c = conn.cursor()
    c.execute("SELECT DefaultSleep FROM C2Server")
    result = c.fetchone()[0]
    if result:
        return result
    else:
        return None


def get_killdate():
    c = conn.cursor()
    c.execute("SELECT KillDate FROM C2Server")
    result = c.fetchone()[0]
    if result:
        return result
    else:
        return None


def get_sharpurls():
    c = conn.cursor()
    c.execute("SELECT SocksURLS FROM C2Server")
    result = c.fetchone()[0]
    if result:
        return result
    else:
        return None


def get_allurls():
    c = conn.cursor()
    c.execute("SELECT URLS FROM C2Server")
    result1 = c.fetchone()[0]
    c.execute("SELECT SocksURLS FROM C2Server")
    result2 = c.fetchone()[0]
    result = result1 + "," + result2
    if result:
        return result
    else:
        return None


def get_url_by_id(urlid):
    c = conn.cursor()
    c.execute("SELECT * FROM URLs where URLID=%s", (urlid,))
    result = c.fetchone()
    return result


def get_default_url_id():
    c = conn.cursor()
    c.execute("SELECT * FROM URLs where Name='updated_host' ORDER BY URLID DESC LIMIT 1")
    result = c.fetchone()
    if result:
        return result
    else:
        c.execute("SELECT * FROM URLs where Name='default' ORDER BY URLID DESC LIMIT 1")
        return c.fetchone()


def get_beaconurl():
    c = conn.cursor()
    c.execute("SELECT URLS FROM C2Server")
    result = c.fetchone()[0]
    if result:
        url = result.split(",")
        return url[0]
    else:
        return None


def get_otherbeaconurls():
    c = conn.cursor()
    c.execute("SELECT URLS FROM C2Server")
    result = c.fetchone()[0]
    if result:
        return result
    else:
        return None


def get_newimplanturl():
    c = conn.cursor()
    c.execute("SELECT URLS FROM C2Server")
    result = c.fetchone()[0]
    if result:
        url = result.split(",")
        return "/" + url[0].replace('"', '')
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
    c.execute("SELECT PID FROM Implants WHERE RandomURI=%s", (randomuri,))
    result = c.fetchone()[0]
    if result:
        return result
    else:
        return None


def get_newtasks(randomuri):
    c = conn.cursor()
    c.execute("SELECT * FROM NewTasks WHERE RandomURI=%s", (randomuri,))
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
    c.execute("INSERT INTO Creds (Domain, Username, Password, Hash) VALUES (%s, %s, %s, %s) RETURNING CredID", (domain, username, password, hash))
    conn.commit()
    return c.fetchone()[0]


def check_if_cred_exists(domain, username, password, hash):
    c = conn.cursor()
    c.execute("SELECT * FROM Creds WHERE Domain=%(domain)s AND Username=%(username)s AND Password=%(password)s AND Hash=%(hash)s",
              {'domain': domain, 'username': username, 'password': password, 'hash': hash})
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
    c.execute("SELECT * FROM Creds WHERE Username=%s", (username,))
    result = c.fetchall()
    if result:
        return result
    else:
        return None


def get_cred_by_id(credId):
    c = conn.cursor()
    c.execute("SELECT * FROM Creds WHERE CredID=%s", (credId,))
    result = c.fetchone()[0]
    if result:
        return result
    else:
        return None


def new_c2_message(message):
    now = datetime.now()
    message = "\n%s%s: %s%s\n" % (Colours.BLUE, now.strftime("%d/%m/%Y %H:%M:%S"), message, Colours.END)
    c = conn.cursor()
    c.execute("INSERT INTO C2_Messages (Message) VALUES (%s) RETURNING ID;", (message,))
    conn.commit()
    return c.fetchone()[0]


def get_c2_messages():
    c = conn.cursor()
    c.execute("SELECT * FROM C2_Messages")
    result = c.fetchall()
    if result:
        messages = []
        for item in result:
            c.execute("DELETE FROM C2_Messages WHERE ID=%s", (item[0],))
            conn.commit()
            messages.append(item[1])
        return messages
    else:
        return None


def get_alldata(table):
    pd.set_option('display.max_colwidth', None)
    pd.options.mode.chained_assignment = None
    return pd.read_sql_query("SELECT * FROM %s" % table, conn)


def generate_csv(tableName):
    print(f"{PoshProjectDirectory}reports/{tableName}.csv")
    query = f"COPY {tableName} TO '{PoshProjectDirectory}reports/{tableName}.csv' DELIMITER ',' CSV HEADER;"
    c = conn.cursor()
    c.execute(query)


def get_powerstatusbyrandomuri(randomuri):
    c = conn.cursor()
    c.execute("SELECT * FROM PowerStatus WHERE RandomURI=%s", (randomuri,))
    result = c.fetchone()
    if result:
        return result
    else:
        return None


def insert_powerstatus(randomuri, apmstatus, onacpower, charging, batterystatus, batterypercentleft, screenlocked, monitoron):
    now = datetime.now()
    c = conn.cursor()
    now = datetime.now()
    c.execute("INSERT INTO PowerStatus (RandomURI,APMStatus,OnACPower,Charging,BatteryStatus,BatteryPercentLeft,ScreenLocked,MonitorOn,LastUpdate) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)" %
              (randomuri, apmstatus, onacpower, charging, batterystatus, batterypercentleft, screenlocked, monitoron, now.strftime("%m/%d/%Y %H:%M:%S")))
    conn.commit()


def insert_blankpowerstatus(randomuri):
    now = datetime.now()
    c = conn.cursor()
    now = datetime.now()
    c.execute("INSERT INTO PowerStatus (RandomURI,APMStatus,OnACPower,Charging,BatteryStatus,BatteryPercentLeft,ScreenLocked,MonitorOn,LastUpdate) VALUES (%(RandomURI)s, %(APMStatus)s, %(OnACPower)s, %(Charging)s, %(BatteryStatus)s, %(BatteryPercentLeft)s, %(ScreenLocked)s, %(MonitorOn)s, %(LastUpdate)s)",
    {'RandomURI':randomuri, 'APMStatus':'', 'OnACPower':'255', 'Charging':'255', 'BatteryStatus':'', 'BatteryPercentLeft':'', 'ScreenLocked': '0', 'MonitorOn':'1', 'LastUpdate':now.strftime("%m/%d/%Y %H:%M:%S") })
    conn.commit()


def update_powerstatus(randomuri, onacpower, charging, batterystatus, batterypercentleft):
    now = datetime.now()
    c = conn.cursor()
    now = datetime.now()
    c.execute("UPDATE PowerStatus SET OnACPower=%(onacpower)s, Charging=%(charging)s, BatteryStatus=%(batterystatus)s, BatteryPercentLeft=%(batterypercentleft)s, LastUpdate=%(now)s WHERE RandomURI=%(randomuri)s", 
    {'onacpower': onacpower, 'charging': charging, 'batterystatus': batterystatus, 'batterypercentleft': batterypercentleft, 'now': now.strftime("%m/%d/%Y %H:%M:%S"), 'randomuri': randomuri })
    conn.commit()


def update_apmstatus(randomuri, apmstatus):
    now = datetime.now()
    c = conn.cursor()
    now = datetime.now()
    c.execute("UPDATE PowerStatus SET APMStatus=%(apmstatus)s, LastUpdate=%(LastUpdate)s WHERE RandomURI=%(randomuri)s",
        {'apmstatus': apmstatus, 'LastUpdate': now.strftime("%m/%d/%Y %H:%M:%S"), 'randomuri': randomuri })
    conn.commit()


def update_acstatus(randomuri, onacpower):
    now = datetime.now()
    c = conn.cursor()
    now = datetime.now()
    c.execute("UPDATE PowerStatus SET OnACPower=%(OnACPower)s, LastUpdate=%(LastUpdate)s WHERE RandomURI=%(randomuri)s",
        {'OnACPower': onacpower, 'LastUpdate': now.strftime("%m/%d/%Y %H:%M:%S"), 'randomuri': randomuri })
    conn.commit()


def update_screenlocked(randomuri, locked):
    now = datetime.now()
    conn = psycopg2.connect(Database)

    c = conn.cursor()
    now = datetime.now()
    c.execute("UPDATE PowerStatus SET ScreenLocked=%(ScreenLocked)s, LastUpdate=%(LastUpdate)s WHERE RandomURI=%(randomuri)s",
        {'ScreenLocked': locked, 'LastUpdate': now.strftime("%m/%d/%Y %H:%M:%S"), 'randomuri': randomuri })
    conn.commit()


def update_monitoron(randomuri, monitoron):
    now = datetime.now()
    conn = psycopg2.connect(Database)

    c = conn.cursor()
    now = datetime.now()
    c.execute("UPDATE PowerStatus SET MonitorOn=%(MonitorOn)s, LastUpdate=%(LastUpdate)s WHERE RandomURI=%(randomuri)s",
        {'MonitorOn': monitoron, 'LastUpdate': now.strftime("%m/%d/%Y %H:%M:%S"), 'randomuri': randomuri })
    conn.commit()
