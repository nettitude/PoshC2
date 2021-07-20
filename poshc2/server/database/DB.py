import pandas as pd
from datetime import datetime

from poshc2.Colours import Colours
from poshc2.server.database.Model import C2, Implant, NewTask, HostedFile
from poshc2.server.database.DBType import DBType
from poshc2.server.Config import Database, DatabaseType, PoshProjectDirectory


if DatabaseType == DBType.Postgres:
    import poshc2.server.database.DBPostgres as DBImplementation
else:
    import poshc2.server.database.DBSQLite as DBImplementation


conn = None


def get_conn():
    global conn
    return conn


def set_conn(new_conn):
    global conn
    conn = new_conn


def database_connect():
    if conn is None:
        set_conn(DBImplementation.connect())


def initializedb():
    database_connect()
    DBImplementation.initialise(create_database)


def db_exists():
    if get_conn() is None:
        database_connect()
    return DBImplementation.db_exists(conn)


def create_database(create_urls, create_implants, create_autoruns, create_tasks, create_newtasks,
                    create_creds, create_opsec_entry, create_c2server, create_c2_messages, create_hosted_files,
                    create_power_status):
    try:
        c = get_conn().cursor()
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
            c.execute(create_opsec_entry)
            c.execute(create_c2server)
            c.execute(create_c2_messages)
            c.execute(create_hosted_files)
            c.execute(create_power_status)
            conn.commit()
        except Exception as e:
            print("Error creating database: " + str(e))


def convert_query(query, postgres_suffix=None):
    if DatabaseType == DBType.Postgres:
        query = query.replace("?", "%s")
        if postgres_suffix:
            query += postgres_suffix
    return query


def get_last_insert_row_id(cursor):
    if DatabaseType == DBType.Postgres:
        return cursor.fetchone()[0]
    return cursor.lastrowid


def setupserver(PayloadCommsHost, EncKey, DomainFrontHeader, DefaultSleep, KillDate, GET_404_Response, PoshProjectDirectory, QuickCommand, DownloadURI, ProxyURL, ProxyUser, ProxyPass, URLS, SocksURLS, Insecure, UserAgent, Referrer, Pushover_APIToken, Pushover_APIUser, Slack_UserID, Slack_Channel, Slack_BotToken, EnableNotifications):
    c = conn.cursor()
    command = convert_query("INSERT INTO C2Server (PayloadCommsHost,EncKey,DomainFrontHeader,DefaultSleep,KillDate,GET_404_Response,PoshProjectDirectory,QuickCommand,DownloadURI,ProxyURL,ProxyUser,ProxyPass,URLS,SocksURLS,Insecure,UserAgent,Referrer,Pushover_APIToken,Pushover_APIUser,Slack_UserID,Slack_Channel,Slack_BotToken,EnableNotifications) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    c.execute(command, (PayloadCommsHost, EncKey, DomainFrontHeader, DefaultSleep, KillDate, GET_404_Response, PoshProjectDirectory, QuickCommand, DownloadURI, ProxyURL, ProxyUser, ProxyPass, URLS, SocksURLS, Insecure, UserAgent, Referrer, Pushover_APIToken, Pushover_APIUser, Slack_UserID, Slack_Channel, Slack_BotToken, EnableNotifications))
    conn.commit()


def get_c2server_all():
    c = get_conn().cursor()
    c.execute("SELECT * FROM C2Server")
    result = c.fetchone()
    return C2(result[1], result[2], result[3], result[4], result[5], result[6], result[7], result[8], result[9],
              result[10], result[11], result[12], result[13], result[14], result[15], result[16], result[17],
              result[18], result[19], result[20], result[21], result[22], result[23])


def get_implants_all():
    c = get_conn().cursor()
    c.execute("SELECT * FROM Implants")
    results = c.fetchall()
    implants = []
    for result in results:
        implants.append(Implant(result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7], result[8],
                                result[9], result[10], result[11], result[12], result[13], result[14], result[15], result[16]))
    return implants


def get_newtasks_all():
    c = get_conn().cursor()
    c.execute("SELECT * FROM NewTasks")
    results = c.fetchall()
    tasks = []
    for result in results:
        tasks.append(NewTask(result[0], result[1], result[2], result[3]))
    return tasks


def new_urldetails(Name, URL, HostHeader, ProxyURL, ProxyUsername, ProxyPassword, CredentialExpiry):
    c = get_conn().cursor()
    command = convert_query("INSERT INTO URLs (Name, URL, HostHeader, ProxyURL, ProxyUsername, ProxyPassword, CredentialExpiry) VALUES (?, ?, ?, ?, ?, ?, ?)", " RETURNING URLID")
    c.execute(command, (Name, URL, HostHeader, ProxyURL, ProxyUsername, ProxyPassword, CredentialExpiry))
    get_conn().commit()
    return get_last_insert_row_id(c)


def drop_newtasks():
    c = get_conn().cursor()
    c.execute("DELETE FROM NewTasks ")
    get_conn().commit()


def new_task(task, user, randomuri):
    c = get_conn().cursor()
    command = convert_query("INSERT INTO NewTasks (RandomURI, Command, \"User\") VALUES (?, ?, ?)")
    c.execute(command, (randomuri, task, user))
    get_conn().commit()


def get_implants():
    c = get_conn().cursor()
    c.execute("SELECT * FROM Implants WHERE Alive='Yes' ORDER BY implantid")
    results = c.fetchall()
    implants = []
    for result in results:
        implants.append(Implant(result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7], result[8],
                                result[9], result[10], result[11], result[12], result[13], result[14], result[15], result[16]))
    return implants


def get_implanttype(randomuri):
    c = get_conn().cursor()
    query = convert_query("SELECT Pivot FROM Implants WHERE RandomURI=?")
    c.execute(query, (randomuri,))
    result = str(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def get_implantdetails(randomuri):
    c = get_conn().cursor()
    query = convert_query("SELECT * FROM Implants WHERE RandomURI=?")
    c.execute(query, (randomuri,))
    result = c.fetchone()
    if result:
        return Implant(result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7], result[8],
                       result[9], result[10], result[11], result[12], result[13], result[14], result[15], result[16])
    else:
        return None


def get_randomuri(implant_id):
    c = get_conn().cursor()
    try:
        implant_id = int(implant_id)
        query = convert_query("SELECT RandomURI FROM Implants WHERE ImplantID=?")
        c.execute(query, (implant_id,))
        result = str(c.fetchone()[0])
    except ValueError:
        return None
    if result:
        return result
    else:
        return None


def add_autorun(Task):
    c = get_conn().cursor()
    command = convert_query("INSERT INTO AutoRuns (Task) VALUES (?)")
    c.execute(command, (Task,))
    get_conn().commit()


def update_sleep(sleep, randomuri):
    c = get_conn().cursor()
    command = convert_query("UPDATE Implants SET Sleep=? WHERE RandomURI=?")
    c.execute(command, (sleep, randomuri))
    get_conn().commit()


def update_label(label, randomuri):
    c = get_conn().cursor()
    command = convert_query("UPDATE Implants SET Label=? WHERE RandomURI=?")
    c.execute(command, (label, randomuri))
    get_conn().commit()


def update_mods(modules, randomuri):
    c = get_conn().cursor()
    command = convert_query("UPDATE Implants SET ModsLoaded=? WHERE RandomURI=?")
    c.execute(command, (modules, randomuri))
    get_conn().commit()


def kill_implant(randomuri):
    c = get_conn().cursor()
    command = convert_query("UPDATE Implants SET Alive='No' WHERE RandomURI=?")
    c.execute(command, (randomuri,))
    get_conn().commit()


def unhide_implant(randomuri):
    c = get_conn().cursor()
    command = convert_query("UPDATE Implants SET Alive='Yes' WHERE RandomURI=?")
    c.execute(command, (randomuri,))
    get_conn().commit()


def hide_implant(randomuri):
    c = get_conn().cursor()
    command = convert_query("UPDATE Implants SET Alive='No' WHERE RandomURI=?")
    c.execute(command, (randomuri,))
    get_conn().commit()


def select_mods(randomuri):
    c = get_conn().cursor()
    query = convert_query("SELECT ModsLoaded FROM Implants WHERE RandomURI=?")
    c.execute(query, (randomuri,))
    result = str(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def select_item(column, table):
    c = get_conn().cursor()
    c.execute(f"SELECT {column} FROM {table}")
    result = str(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def del_newtasks(TaskID):
    c = get_conn().cursor()
    command = convert_query("DELETE FROM NewTasks WHERE TaskID=?")
    c.execute(command, (TaskID,))
    get_conn().commit()


def del_autorun(TaskID):
    c = get_conn().cursor()
    command = convert_query("DELETE FROM AutoRuns WHERE TaskID=?")
    c.execute(command, (TaskID,))
    get_conn().commit()


def del_autoruns():
    c = get_conn().cursor()
    c.execute("DELETE FROM AutoRuns ")
    get_conn().commit()


def update_implant_lastseen(time, randomuri):
    c = get_conn().cursor()
    command = convert_query("UPDATE Implants SET LastSeen=? WHERE RandomURI=?")
    c.execute(command, (time, randomuri))
    get_conn().commit()


def new_implant(RandomURI, URLID, User, Hostname, IpAddress, Key, FirstSeen, LastSeen, PID, Arch, Domain, Alive, Sleep, ModsLoaded, Pivot, Label):
    c = get_conn().cursor()
    command = convert_query("INSERT INTO Implants (RandomURI, URLID, \"User\", Hostname, IpAddress, Key, FirstSeen, LastSeen, PID, Arch, Domain, Alive, Sleep, ModsLoaded, Pivot, Label) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", " RETURNING ImplantID")
    c.execute(command, (RandomURI, URLID, User, Hostname, IpAddress, Key, FirstSeen, LastSeen, PID, Arch, Domain, Alive, Sleep, ModsLoaded, Pivot, Label))
    get_conn().commit()
    return get_last_insert_row_id(c)


def insert_task(randomuri, command, user):
    now = datetime.now()
    sent_time = now.strftime("%Y-%m-%d %H:%M:%S")
    implantId = get_implantbyrandomuri(randomuri).ImplantID
    c = get_conn().cursor()
    if user is None:
        user = ""
    query = convert_query("INSERT INTO Tasks (RandomURI, Command, Output, \"User\", SentTime, CompletedTime, ImplantID) VALUES (?, ?, ?, ?, ?, ?, ?)", " RETURNING TaskID")
    c.execute(query, (randomuri, command, "", user, sent_time, "", implantId))
    get_conn().commit()
    return get_last_insert_row_id(c)


def update_task(taskId, output):
    now = datetime.now()
    completedTime = now.strftime("%Y-%m-%d %H:%M:%S")
    c = get_conn().cursor()
    command = convert_query("UPDATE Tasks SET Output=?, CompletedTime=? WHERE TaskID=?")
    c.execute(command, (output, completedTime, taskId))
    get_conn().commit()
    return taskId


def get_task_owner(taskId):
    c = get_conn().cursor()
    query = convert_query("SELECT \"User\" FROM Tasks WHERE TaskID=?")
    c.execute(query, (taskId,))
    result = c.fetchone()
    if result and result[0] != "":
        return result[0]
    else:
        return None


def update_item(column, table, value, wherecolumn=None, where=None):
    c = get_conn().cursor()
    if wherecolumn is None:
        query = convert_query(f"UPDATE {table} SET {column}=?")
        c.execute(query, (value,))
    else:
        query = convert_query(f"UPDATE {table} SET {column}=? WHERE {wherecolumn}=?")
        c.execute(query, (value, where))
    get_conn().commit()


def get_implantbyid(implantId):
    try:
        implantId = int(implantId)
    except ValueError:
        return None
    c = get_conn().cursor()
    query = convert_query("SELECT * FROM Implants WHERE ImplantID=?")
    c.execute(query, (implantId,))
    result = c.fetchone()
    if result:
        return Implant(result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7], result[8],
                       result[9], result[10], result[11], result[12], result[13], result[14], result[15], result[16])
    else:
        return None


def get_implantbyrandomuri(RandomURI):
    c = get_conn().cursor()
    query = convert_query("SELECT * FROM Implants WHERE RandomURI=?")
    c.execute(query, (RandomURI,))
    result = c.fetchone()
    if result:
        return Implant(result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7], result[8],
                       result[9], result[10], result[11], result[12], result[13], result[14], result[15], result[16])
    else:
        return None


def get_alldata(table):
    pd.set_option('display.max_colwidth', None)
    pd.options.mode.chained_assignment = None
    return pd.read_sql_query(f"SELECT * FROM {table}", get_conn())


def get_html_report_data(table_name):
    query_string = ""
    if (table_name == "Tasks"):
        query_string = "SELECT t.TaskID, i.Domain || '\\' || i.\"User\" || ' @ ' || i.Hostname AS Context, t.Command, t.Output, t.\"User\", t.SentTime, t.CompletedTime, t.ImplantID FROM Tasks t INNER JOIN Implants i USING(ImplantID)"
    elif (table_name == "C2Server"):
        query_string = "SELECT * FROM C2Server"
    elif (table_name == "Creds"):
        query_string = "SELECT * FROM Creds"
    elif (table_name == "Implants"):
        query_string = "SELECT ImplantID, Domain || '\\' || \"User\" || ' @ ' || Hostname AS Context, URLID, \"User\", Hostname, IpAddress, Key, FirstSeen, LastSeen, PID, Arch, Domain, Alive, Sleep, ModsLoaded, Pivot, Label FROM Implants"
    elif (table_name == "URLs"):
        query_string = "SELECT * FROM URLs"
    elif (table_name == "OpSec_Entry"):
        query_string = "SELECT * FROM OpSec_Entry"

    if (query_string == ""):
        return None

    c = get_conn().cursor()
    c.execute(query_string)
    result = c.fetchall()

    if result:
        return result
    else:
        return None

def get_tasks():
    c = get_conn().cursor()
    c.execute("SELECT * FROM Tasks")
    result = c.fetchall()
    if result:
        return result
    else:
        return None


def get_tasksbyid(implantId):
    c = get_conn().cursor()
    query = convert_query("SELECT * FROM Tasks WHERE CompletedTaskID=?")
    c.execute(query, (implantId,))
    result = c.fetchone()
    if result:
        return result
    else:
        return None


def get_newtasksbyid(taskid):
    c = get_conn().cursor()
    query = convert_query("SELECT * FROM NewTasks WHERE TaskID=?")
    c.execute(query, (taskid,))
    result = c.fetchone()
    if result:
        return result
    else:
        return None


def get_baseenckey():
    c = get_conn().cursor()
    c.execute("SELECT EncKey FROM C2Server")
    result = str(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def get_dfheader():
    c = get_conn().cursor()
    c.execute("SELECT DomainFrontHeader FROM C2Server")
    result = str(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def get_cmd_from_task_id(taskId):
    c = get_conn().cursor()
    query = convert_query("SELECT Command FROM Tasks WHERE TaskId=?")
    c.execute(query, (taskId,))
    result = str(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def get_notificationstatus():
    c = get_conn().cursor()
    c.execute("SELECT EnableNotifications FROM C2Server")
    result = str(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def get_defaultuseragent():
    c = get_conn().cursor()
    c.execute("SELECT UserAgent FROM C2Server")
    result = str(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def get_defaultbeacon():
    c = get_conn().cursor()
    c.execute("SELECT DefaultSleep FROM C2Server")
    result = str(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def get_killdate():
    c = get_conn().cursor()
    c.execute("SELECT KillDate FROM C2Server")
    result = str(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def get_sharpurls():
    c = get_conn().cursor()
    c.execute("SELECT SocksURLS FROM C2Server")
    result = str(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def get_allurls():
    c = get_conn().cursor()
    c.execute("SELECT URLS FROM C2Server")
    c2Urls = str(c.fetchone()[0])
    c.execute("SELECT SocksURLS FROM C2Server")
    socksURLs = str(c.fetchone()[0])
    result = c2Urls + "," + socksURLs
    if result:
        return result
    else:
        return None


def get_url_by_id(id):
    c = get_conn().cursor()
    query = convert_query("SELECT * FROM URLs where URLID=?")
    c.execute(query, (id,))
    result = c.fetchone()
    return result


def get_default_url_id():
    c = get_conn().cursor()
    c.execute("SELECT * FROM URLs where Name='updated_host' ORDER BY URLID DESC LIMIT 1")
    result = c.fetchone()
    if result:
        return result
    else:
        c.execute("SELECT * FROM URLs where Name='default' ORDER BY URLID DESC LIMIT 1")
        return c.fetchone()


def get_beaconurl():
    c = get_conn().cursor()
    c.execute("SELECT URLS FROM C2Server")
    result = str(c.fetchone()[0])
    if result:
        url = result.split(",")
        return url[0]
    else:
        return None


def get_otherbeaconurls():
    c = get_conn().cursor()
    c.execute("SELECT URLS FROM C2Server")
    result = str(c.fetchone()[0])
    if result:
        return result
    else:
        return None


def get_newimplanturl():
    c = get_conn().cursor()
    c.execute("SELECT URLS FROM C2Server")
    result = str(c.fetchone()[0])
    if result:
        url = result.split(",")
        return "/" + url[0].replace('"', '')
    else:
        return None


def get_c2urls():
    c = get_conn().cursor()
    c.execute("SELECT * FROM URLs")
    result = c.fetchall()
    if result:
        return result
    else:
        return None


def get_autoruns():
    c = get_conn().cursor()
    c.execute("SELECT * FROM AutoRuns")
    result = c.fetchall()
    if result:
        return result
    else:
        return None


def get_autorun():
    c = get_conn().cursor()
    c.execute("SELECT * FROM AutoRuns")
    result = c.fetchall()
    autoruns = ""
    for autorun in result:
        autoruns += f"{autorun[0]}:{autorun[1]}\r\n"
    if autoruns:
        return autoruns
    else:
        return None


def get_pid(randomuri):
    c = get_conn().cursor()
    query = convert_query("SELECT PID FROM Implants WHERE RandomURI=?")
    c.execute(query, (randomuri,))
    result = c.fetchone()[0]
    if result:
        return result
    else:
        return None


def get_newtasks(randomuri):
    c = get_conn().cursor()
    query = convert_query("SELECT * FROM NewTasks WHERE RandomURI=?")
    c.execute(query, (randomuri,))
    result = c.fetchall()
    if result:
        return result
    else:
        return None


def get_keys():
    c = get_conn().cursor()
    result = c.execute("SELECT EncKey FROM C2Server")
    result = c.fetchall()
    if result:
        return result
    else:
        return None


def insert_cred(domain, username, password, hash):
    if check_if_cred_exists(domain, username, password, hash):
        return None
    c = get_conn().cursor()
    command = convert_query("INSERT INTO Creds (Domain, Username, Password, Hash) VALUES (?, ?, ?, ?)", " RETURNING CredID")
    c.execute(command, (domain, username, password, hash))
    get_conn().commit()
    return get_last_insert_row_id(c)


def check_if_cred_exists(domain, username, password, hash):
    c = get_conn().cursor()
    if not password:
        query = convert_query("SELECT * FROM Creds WHERE Domain=? AND Username=? AND Password IS NULL AND Hash=?")
        c.execute(query, (domain, username, hash))
    elif not hash:
        query = convert_query("SELECT * FROM Creds WHERE Domain=? AND Username=? AND Password=? AND Hash IS NULL")
        c.execute(query, (domain, username, password))
    else:
        query = convert_query("SELECT * FROM Creds WHERE Domain=? AND Username=? AND Password=? AND Hash=?")
        c.execute(query, (domain, username, password, hash))
    result = c.fetchall()
    if result:
        return True
    else:
        return False


def get_creds():
    c = get_conn().cursor()
    c.execute("SELECT * FROM Creds")
    result = c.fetchall()
    if result:
        return result
    else:
        return None


def get_creds_for_user(username):
    c = get_conn().cursor()
    query = convert_query("SELECT * FROM Creds WHERE Username=?")
    c.execute(query, (username,))
    result = c.fetchall()
    if result:
        return result
    else:
        return None


def get_cred_by_id(credId):
    c = get_conn().cursor()
    query = convert_query("SELECT * FROM Creds WHERE CredID=?")
    c.execute(query, (credId,))
    result = c.fetchone()
    if result:
        return result
    else:
        return None


def new_c2_message(message):
    now = datetime.now()
    message = "\n%s%s: %s%s\n" % (Colours.BLUE, now.strftime("%Y-%m-%d %H:%M:%S"), message, Colours.END)
    c = get_conn().cursor()
    command = convert_query("INSERT INTO C2_Messages (Message,Read) VALUES (?,'No')", " RETURNING ID")
    c.execute(command, (message,))
    get_conn().commit()
    return get_last_insert_row_id(c)


def get_c2_messages():
    c = get_conn().cursor()
    c.execute("SELECT * FROM C2_Messages WHERE Read='No'")
    result = c.fetchall()
    if result:
        messages = []
        for item in result:
            command = convert_query("UPDATE C2_Messages Set Read='Yes' WHERE ID=?")
            c.execute(command, (item[0],))
            get_conn().commit()
            messages.append(item[1])
        return messages
    else:
        return None


def get_powerstatusbyrandomuri(randomuri):
    c = get_conn().cursor()
    query = convert_query("SELECT * FROM PowerStatus WHERE RandomURI=?")
    c.execute(query, (randomuri,))
    result = c.fetchone()
    if result:
        return result
    else:
        return None


def insert_powerstatus(randomuri, apmstatus, onacpower, charging, batterystatus, batterypercentleft, screenlocked, monitoron):
    now = datetime.now()
    c = get_conn().cursor()
    now = datetime.now()
    command = convert_query("INSERT INTO PowerStatus (RandomURI,APMStatus,OnACPower,Charging,BatteryStatus,BatteryPercentLeft,ScreenLocked,MonitorOn,LastUpdate) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
    c.execute(command, (randomuri, apmstatus, onacpower, charging, batterystatus, batterypercentleft, screenlocked, monitoron, now.strftime("%Y-%m-%d %H:%M:%S")))
    get_conn().commit()


def insert_blankpowerstatus(randomuri):
    now = datetime.now()
    c = get_conn().cursor()
    now = datetime.now()
    command = convert_query("INSERT INTO PowerStatus (RandomURI,APMStatus,OnACPower,Charging,BatteryStatus,BatteryPercentLeft,ScreenLocked,MonitorOn,LastUpdate) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
    c.execute(command, (randomuri, "", 255, 255, "", "", 0, 1, now.strftime("%Y-%m-%d %H:%M:%S")))
    get_conn().commit()


def update_powerstatus(randomuri, onacpower, charging, batterystatus, batterypercentleft):
    now = datetime.now()
    c = get_conn().cursor()
    now = datetime.now()
    command = convert_query("UPDATE PowerStatus SET OnACPower=?,Charging=?,BatteryStatus=?,BatteryPercentLeft=?,LastUpdate=? WHERE RandomURI=?")
    c.execute(command, (onacpower, charging, batterystatus, batterypercentleft, now.strftime("%Y-%m-%d %H:%M:%S"), randomuri))
    get_conn().commit()


def update_apmstatus(randomuri, apmstatus):
    now = datetime.now()
    c = get_conn().cursor()
    now = datetime.now()
    command = convert_query("UPDATE PowerStatus SET APMStatus=?, LastUpdate=? WHERE RandomURI=?")
    c.execute(command, (apmstatus, now.strftime("%Y-%m-%d %H:%M:%S"), randomuri))
    get_conn().commit()


def update_acstatus(randomuri, onacpower):
    now = datetime.now()
    c = get_conn().cursor()
    now = datetime.now()
    command = convert_query("UPDATE PowerStatus SET OnACPower=?, LastUpdate=? WHERE RandomURI=?")
    c.execute(command, (onacpower, now.strftime("%Y-%m-%d %H:%M:%S"), randomuri))
    get_conn().commit()


def update_screenlocked(randomuri, locked):
    now = datetime.now()
    c = get_conn().cursor()
    now = datetime.now()
    command = convert_query("UPDATE PowerStatus SET ScreenLocked=?, LastUpdate=? WHERE RandomURI=?")
    c.execute(command, (locked, now.strftime("%Y-%m-%d %H:%M:%S"), randomuri))
    get_conn().commit()


def update_monitoron(randomuri, monitoron):
    now = datetime.now()
    c = get_conn().cursor()
    now = datetime.now()
    command = convert_query("UPDATE PowerStatus SET MonitorOn=?, LastUpdate=? WHERE RandomURI=?")
    c.execute(command, (monitoron, now.strftime("%Y-%m-%d %H:%M:%S"), randomuri))
    get_conn().commit()


def enable_hosted_file(ID):
    c = get_conn().cursor()
    command = convert_query("UPDATE Hosted_Files SET Active='Yes' WHERE ID=?")
    c.execute(command, (ID,))
    get_conn().commit()


def del_hosted_file(ID):
    c = get_conn().cursor()
    command = convert_query("UPDATE Hosted_Files SET Active='No' WHERE ID=?")
    c.execute(command, (ID,))
    get_conn().commit()


def insert_hosted_file(URI, FilePath, ContentType, Base64, Active):
    c = get_conn().cursor()
    command = convert_query("INSERT INTO Hosted_Files (URI, FilePath, ContentType, Base64, Active) VALUES (?, ?, ?, ?, ?)")
    c.execute(command, (URI, FilePath, ContentType, Base64, Active))
    get_conn().commit()


def get_hosted_files():
    c = get_conn().cursor()
    c.execute("SELECT * FROM Hosted_Files")
    results = c.fetchall()
    hosted_files = []
    for result in results:
        hosted_files.append(HostedFile(result[0], result[1], result[2], result[3], result[4], result[5]))
    return hosted_files


def insert_opsec_event(date, owner, event, note):
    c = get_conn().cursor()
    command = convert_query("INSERT INTO OpSec_Entry (Date, Owner, Event, Note) VALUES (?, ?, ?, ?)")
    c.execute(command, (date, owner, event, note))
    get_conn().commit()


def del_opsec_event(OpsecID):
    c = get_conn().cursor()
    command = convert_query("DELETE FROM Opsec_Entry WHERE OpsecID=?")
    c.execute(command, (OpsecID,))
    get_conn().commit()


def get_opsec_events():
    c = get_conn().cursor()
    c.execute("SELECT * FROM Opsec_Entry")
    result = c.fetchall()
    if result:
        return result
    else:
        return None
