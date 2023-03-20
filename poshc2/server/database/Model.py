from poshc2.server.database import Base
from sqlalchemy import Column, Integer, String, ForeignKey, UniqueConstraint


class URL(Base):
    __tablename__ = "urls"

    id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    name = Column(String, unique=True)
    url = Column(String)
    host_header = Column(String)
    proxy_url = Column(String, default="")
    proxy_username = Column(String, default="")
    proxy_password = Column(String, default="")
    credential_expiry = Column(String)

    def __repr__(self):
        repr = "<URL(\n"
        repr += f"    id='{self.id}',\n"
        repr += f"    name='{self.name}',\n"
        repr += f"    url='{self.url}',\n"
        repr += f"    host_header='{self.host_header}',\n"
        repr += f"    proxy_url='{self.proxy_url}',\n"
        repr += f"    proxy_username='{self.proxy_username}',\n"
        repr += f"    proxy_password='{self.proxy_password}',\n"
        repr += f"    credential_expiry='{self.credential_expiry}'\n"
        repr += ")>"

        return repr


class Implant(Base):
    __tablename__ = "implants"

    numeric_id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    id = Column(Integer)
    url_id = Column(Integer, ForeignKey("urls.id"))
    user = Column(String)
    hostname = Column(String)
    ip_address = Column(String)
    encryption_key = Column(String)
    first_seen = Column(String)
    last_seen = Column(String)
    process_id = Column(Integer)
    process_name = Column(String)
    architecture = Column(String)
    domain = Column(String)
    alive = Column(String)
    sleep = Column(String)
    loaded_modules = Column(String)
    type = Column(String)
    label = Column(String)

    def __repr__(self):
        repr = "<Implant(\n"
        repr += f"    numeric_id='{self.numeric_id}',\n"
        repr += f"    id='{self.id}',\n"
        repr += f"    url_id='{self.url_id}',\n"
        repr += f"    user='{self.user}',\n"
        repr += f"    hostname='{self.hostname}',\n"
        repr += f"    ip_address='{self.ip_address}',\n"
        repr += f"    encryption_key='{self.encryption_key}',\n"
        repr += f"    first_seen='{self.first_seen}',\n"
        repr += f"    last_seen='{self.last_seen}',\n"
        repr += f"    process_id='{self.process_id}',\n"
        repr += f"    process_name='{self.process_name}',\n"
        repr += f"    architecture='{self.architecture}',\n"
        repr += f"    domain='{self.domain}',\n"
        repr += f"    alive='{self.alive}',\n"
        repr += f"    sleep='{self.sleep}',\n"
        repr += f"    loaded_modules='{self.loaded_modules}',\n"
        repr += f"    type='{self.type}',\n"
        repr += f"    label='{self.label}'\n"
        repr += ")>"

        return repr


class Task(Base):
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    implant_id = Column(Integer)
    command = Column(String)
    output = Column(String, default="")
    user = Column(String)
    sent_time = Column(String)
    completed_time = Column(String)
    implant_numeric_id = Column(Integer, ForeignKey("implants.numeric_id"))
    child_implant_id = Column(Integer)

    def __repr__(self):
        repr = "<Task(\n"
        repr += f"    id='{self.id}',\n"
        repr += f"    implant_id='{self.implant_id}',\n"
        repr += f"    command='{self.command}',\n"
        repr += f"    output='{self.output}',\n"
        repr += f"    user='{self.user}',\n"
        repr += f"    sent_time='{self.sent_time}',\n"
        repr += f"    completed_time='{self.completed_time}',\n"
        repr += f"    implant_numeric_id='{self.implant_numeric_id}',\n"
        repr += f"    child_implant_id='{self.child_implant_id}'\n"
        repr += ")>"

        return repr


# TODO ChildImplantIDs
class NewTask(Base):
    __tablename__ = "new_tasks"

    id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    implant_id = Column(Integer)
    command = Column(String)
    user = Column(String)
    child_implant_id = Column(Integer)

    def __repr__(self):
        repr = "<NewTask(\n"
        repr += f"    id='{self.id}',\n"
        repr += f"    implant_id='{self.implant_id}',\n"
        repr += f"    command='{self.command}',\n"
        repr += f"    user='{self.user}',\n"
        repr += f"    child_implant_id='{self.child_implant_id}'\n"
        repr += ")>"

        return repr


class AutoRun(Base):
    __tablename__ = "autoruns"

    id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    task = Column(String)

    def __repr__(self):
        repr = "<AutoRun(\n"
        repr += f"    id='{self.id}',\n"
        repr += f"    task='{self.task}'\n"
        repr += ")>"

        return repr


class C2Server(Base):
    __tablename__ = "c2_server"

    id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    payload_comms_host = Column(String)
    encryption_key = Column(String)
    domain_front_header = Column(String)
    default_sleep = Column(String)
    kill_date = Column(String)
    get_404_response = Column(String)
    posh_project_directory = Column(String)
    hosted_file_url = Column(String)
    download_url = Column(String)
    proxy_url = Column(String, default="")
    proxy_username = Column(String, default="")
    proxy_password = Column(String, default="")
    urls = Column(String)
    socks_urls = Column(String)
    insecure = Column(String)
    user_agent = Column(String)
    referer = Column(String)
    pushover_api_token = Column(String)
    pushover_api_user = Column(String)
    slack_user_id = Column(String)
    slack_channel = Column(String)
    slack_bot_token = Column(String)
    notifications_enabled = Column(String)

    def __repr__(self):
        repr = "<C2Server(\n"
        repr += f"    id='{self.id}',\n"
        repr += f"    payload_comms_host='{self.payload_comms_host}',\n"
        repr += f"    encryption_key='{self.encryption_key}',\n"
        repr += f"    domain_front_header='{self.domain_front_header}',\n"
        repr += f"    default_sleep='{self.default_sleep}',\n"
        repr += f"    kill_date='{self.kill_date}',\n"
        repr += f"    get_404_response='{self.get_404_response}',\n"
        repr += f"    posh_project_directory='{self.posh_project_directory}',\n"
        repr += f"    hosted_file_url='{self.hosted_file_url}',\n"
        repr += f"    download_url='{self.download_url}',\n"
        repr += f"    proxy_url='{self.proxy_url}',\n"
        repr += f"    proxy_username='{self.proxy_username}',\n"
        repr += f"    proxy_password='{self.proxy_password}',\n"
        repr += f"    urls='{self.urls}',\n"
        repr += f"    socks_urls='{self.socks_urls}',\n"
        repr += f"    insecure='{self.insecure}',\n"
        repr += f"    user_agent='{self.user_agent}',\n"
        repr += f"    referer='{self.referer}',\n"
        repr += f"    pushover_api_token='{self.pushover_api_token}',\n"
        repr += f"    pushover_api_user='{self.pushover_api_user}',\n"
        repr += f"    slack_user_id='{self.slack_user_id}',\n"
        repr += f"    slack_channel='{self.slack_channel}',\n"
        repr += f"    slack_bot_token='{self.slack_bot_token}',\n"
        repr += f"    notifications_enabled='{self.notifications_enabled}'\n"
        repr += ")>"

        return repr


class Cred(Base):
    __tablename__ = "creds"
    __table_args__ = (UniqueConstraint("domain", "username", "password", "hash", name="unique_cred"),)

    id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    domain = Column(String)
    username = Column(String)
    password = Column(String, default="")
    hash = Column(String, default="")

    def __repr__(self):
        repr = "<Cred(\n"
        repr += f"    id='{self.id}',\n"
        repr += f"    domain='{self.domain}',\n"
        repr += f"    username='{self.username}',\n"
        repr += f"    password='{self.password}',\n"
        repr += f"    hash='{self.hash}'\n"
        repr += ")>"

        return repr


class OpsecEntry(Base):
    __tablename__ = "opsec_entries"

    id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    date = Column(String)
    owner = Column(String)
    event = Column(String)
    note = Column(String)

    def __repr__(self):
        repr = "<OpsecEntry(\n"
        repr += f"    id='{self.id}',\n"
        repr += f"    date='{self.date}',\n"
        repr += f"    owner='{self.owner}',\n"
        repr += f"    event='{self.event}',\n"
        repr += f"    note='{self.note}'\n"
        repr += ")>"

        return repr


class C2Message(Base):
    __tablename__ = "c2_messages"

    id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    message = Column(String)
    read = Column(String)

    def __repr__(self):
        repr = "<C2Message(\n"
        repr += f"    id='{self.id}',\n"
        repr += f"    message='{self.message}',\n"
        repr += f"    read='{self.read}'\n"
        repr += ")>"

        return repr


class PowerStatus(Base):
    __tablename__ = "power_status"

    id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    implant_id = Column(Integer)
    apm_status = Column(String)
    on_ac_power = Column(Integer)
    charging = Column(Integer)
    battery_status = Column(String)
    battery_percent_left = Column(String)
    screen_locked = Column(Integer)
    monitor_on = Column(Integer)
    last_update = Column(String)

    def __repr__(self):
        repr = "<PowerStatus(\n"
        repr += f"    id='{self.id}',\n"
        repr += f"    implant_id='{self.implant_id}',\n"
        repr += f"    apm_status='{self.apm_status}',\n"
        repr += f"    on_ac_power='{self.on_ac_power}',\n"
        repr += f"    charging='{self.charging}',\n"
        repr += f"    battery_status='{self.battery_status}',\n"
        repr += f"    battery_percent_left='{self.battery_percent_left}',\n"
        repr += f"    screen_locked='{self.screen_locked}',\n"
        repr += f"    monitor_on='{self.monitor_on}',\n"
        repr += f"    last_update='{self.last_update}'\n"
        repr += ")>"

        return repr


class HostedFile(Base):
    __tablename__ = "hosted_files"

    id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    uri = Column(String)
    file_path = Column(String)
    content_type = Column(String)
    base64 = Column(String)
    active = Column(String)

    def __repr__(self):
        repr = "<HostedFile(\n"
        repr += f"    id='{self.id}',\n"
        repr += f"    uri='{self.uri}',\n"
        repr += f"    file_path='{self.file_path}',\n"
        repr += f"    content_type='{self.content_type}',\n"
        repr += f"    base64='{self.base64}',\n"
        repr += f"    active='{self.active}'\n"
        repr += ")>"

        return repr


class MitreTTP(Base):
    __tablename__ = "mitre_ttps"

    id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    technique_id = Column(String)
    technique_name = Column(String)
    tactics = Column(String)
    task_id = Column(Integer)

    def __repr__(self):
        repr = "<MitreTTP(\n"
        repr += f"    id='{self.id}',\n"
        repr += f"    technique_id='{self.technique_id}',\n"
        repr += f"    technique_name='{self.technique_name}',\n"
        repr += f"    tactics='{self.tactics}',\n"
        repr += f"    task_id='{self.task_id}'\n"
        repr += ")>"

        return repr
