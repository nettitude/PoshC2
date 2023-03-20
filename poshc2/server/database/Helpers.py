from contextlib import contextmanager
from datetime import datetime, timezone

import pandas
from sqlalchemy.sql import select, update, delete, desc

from poshc2 import Colours
from poshc2.server.database import database_engine, Session
from poshc2.server.database.Model import *


@contextmanager
def session_scope():
    session = Session()

    try:
        yield session
        session.commit()
    except Exception as e:
        print(f"Error committing to database: {e}")
        session.rollback()
        raise


def insert_object(object):
    with session_scope() as session:
        session.add(object)


def update_object(table, values, where=None):
    with session_scope() as session:
        if where:
            statement = update(table).where(list(where.keys())[0] == list(where.values())[0]).values(values)
        else:
            statement = update(table).values(values)

        session.execute(statement)


def delete_object(table, where=None):
    with session_scope() as session:
        if where:
            statement = delete(table).where(list(where.keys())[0] == list(where.values())[0])
        else:
            statement = delete(table)

        session.execute(statement)


def select_first(table):
    with session_scope() as session:
        statement = select(table).execution_options(populate_existing=True)
        result = session.scalars(statement).first()

    return result


def select_all(table):
    with session_scope() as session:
        statement = select(table).execution_options(populate_existing=True)
        result = session.scalars(statement).all()

    return result


def update_task(task_id, output):
    with session_scope() as session:
        completed_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        statement = update(Task).where(Task.id == task_id).values(output=output, completed_time=completed_time)
        session.execute(statement)


def get_alive_implants():
    with session_scope() as session:
        statement = select(Implant).where(Implant.alive == "Yes").order_by(Implant.numeric_id).execution_options(populate_existing=True)
        result = session.scalars(statement).all()

    return result


def get_implant(implant_id):
    with session_scope() as session:
        statement = select(Implant).where(Implant.id == implant_id).execution_options(populate_existing=True)
        result = session.scalars(statement).first()

    return result


def get_implant_by_numeric_id(numeric_id):
    with session_scope() as session:
        statement = select(Implant).where(Implant.numeric_id == numeric_id).execution_options(populate_existing=True)
        result = session.scalars(statement).first()

    return result


def get_process_id(implant_id):
    with session_scope() as session:
        statement = select(Implant.process_id).where(Implant.id == implant_id).execution_options(populate_existing=True)
        result = session.scalars(statement).first()

    return result


def get_loaded_modules(implant_id):
    with session_scope() as session:
        statement = select(Implant.loaded_modules).where(Implant.id == implant_id).execution_options(populate_existing=True)
        result = session.scalars(statement).first()

    return result


def get_url(url_id):
    with session_scope() as session:
        statement = select(URL).where(URL.id == url_id).execution_options(populate_existing=True)
        result = session.scalars(statement).first()

    return result


def get_default_url():
    with session_scope() as session:
        statement = select(URL).where(URL.name.like("updated_host-%")).order_by(desc(URL.id)).limit(1).execution_options(populate_existing=True)
        result = session.scalars(statement).first()

        if not result:
            statement = select(URL).where(URL.name == "default").order_by(desc(URL.id)).limit(1).execution_options(populate_existing=True)
            result = session.scalars(statement).first()

    return result


def get_new_implant_url():
    urls = select_first(C2Server.urls)
    url = urls.split(',')[0]
    return "/" + url.replace('"', '')


def get_new_tasks_for_implant(implant_id):
    with session_scope() as session:
        statement = select(NewTask).where(NewTask.implant_id == implant_id).execution_options(populate_existing=True)
        result = session.scalars(statement).all()

    return result


def get_task(task_id):
    with session_scope() as session:
        statement = select(Task).where(Task.id == task_id).execution_options(populate_existing=True)
        result = session.scalars(statement).first()

    return result


def get_creds(username):
    with session_scope() as session:
        statement = select(Cred).where(Cred.username == username).execution_options(populate_existing=True)
        result = session.scalars(statement).all()

    return result


def get_cred(cred_id):
    with session_scope() as session:
        statement = select(Cred).where(Cred.id == cred_id).execution_options(populate_existing=True)
        result = session.scalars(statement).first()

    return result


def get_unread_messages():
    with session_scope() as session:
        statement = select(C2Message).where(C2Message.read == "No").execution_options(populate_existing=True)
        result = session.scalars(statement).all()

        for message in result:
            message.read = "Yes"

    return result


def get_power_status(implant_id):
    with session_scope() as session:
        statement = select(PowerStatus).where(PowerStatus.implant_id == implant_id).execution_options(populate_existing=True)
        result = session.scalars(statement).first()

    return result


def get_mitre_ttps():
    with session_scope() as session:
        statement = select(MitreTTP).group_by(MitreTTP.technique_id).order_by(MitreTTP.id).execution_options(populate_existing=True)
        result = session.scalars(statement).all()

    return result


def get_data_frame(table):
    pandas.set_option("display.max_colwidth", None)
    pandas.options.mode.chained_assignment = None
    return pandas.read_sql(select(table), database_engine)


def get_html_report_data(table):
    with session_scope() as session:
        if table == Task:
            statement = select(Task.id, (Implant.domain + '\\' + Implant.user + ' @ ' + Implant.hostname).label("context"), Task.command, Task.output,
                               Task.user, Task.sent_time, Task.completed_time, Task.implant_id, Implant.numeric_id).join(Implant, Task.implant_id == Implant.id).execution_options(
                populate_existing=True)
        elif table == C2Server:
            statement = select(C2Server.id, C2Server.payload_comms_host, C2Server.encryption_key, C2Server.domain_front_header,
                               C2Server.default_sleep, C2Server.kill_date, C2Server.get_404_response, C2Server.posh_project_directory,
                               C2Server.hosted_file_url, C2Server.download_url, C2Server.proxy_url, C2Server.proxy_username,
                               C2Server.proxy_password, C2Server.urls, C2Server.socks_urls, C2Server.insecure, C2Server.user_agent,
                               C2Server.referer, C2Server.pushover_api_token, C2Server.pushover_api_user, C2Server.slack_user_id,
                               C2Server.slack_channel, C2Server.slack_bot_token, C2Server.notifications_enabled).execution_options(populate_existing=True)
        elif table == Cred:
            statement = select(Cred.id, Cred.domain, Cred.username, Cred.password, Cred.hash).execution_options(populate_existing=True)
        elif table == Implant:
            statement = select(Implant.numeric_id, Implant.id, Implant.url_id, (Implant.domain + '\\' + Implant.user + ' @ ' + Implant.hostname).label("context"),
                               Implant.ip_address, Implant.encryption_key, Implant.first_seen, Implant.last_seen, Implant.process_id, Implant.process_name,
                               Implant.architecture, Implant.alive, Implant.sleep, Implant.loaded_modules, Implant.type, Implant.label).execution_options(populate_existing=True)
        elif table == URL:
            statement = select(URL.id, URL.name, URL.url, URL.host_header, URL.proxy_url, URL.proxy_username, URL.proxy_password, URL.credential_expiry).execution_options(
                populate_existing=True)
        elif table == OpsecEntry:
            statement = select(OpsecEntry.id, OpsecEntry.date, OpsecEntry.owner, OpsecEntry.event, OpsecEntry.note).execution_options(populate_existing=True)
        elif table == MitreTTP:
            statement = select(MitreTTP.id, MitreTTP.technique_id, MitreTTP.technique_name, MitreTTP.tactics,
                               (Implant.domain + '\\' + Implant.user + ' @ ' + Implant.hostname).label("context"),
                               Task.completed_time.label("timestamp"), Task.command.label("command")).join(Task, MitreTTP.task_id == Task.id).join(Implant,
                                                                                                                                                   Task.implant_id == Implant.id).execution_options(
                populate_existing=True)
        else:
            print(f"{Colours.RED}\nError: HTML report data not available for table '{table.__name__}'\n{Colours.END}")
            return []

        result = session.execute(statement).all()

    return result
