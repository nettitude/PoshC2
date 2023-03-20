import os
import re
import time
from datetime import datetime

import jenkins
import requests
from requests.auth import HTTPBasicAuth

from poshc2 import Colours
from poshc2.server.Config import ModulesDirectory, ProjectName, JenkinsKey, NexusKey, JenkinsServer, NexusServer


def check_pipeline_status(module_name):
    module_cache_file = f'{ModulesDirectory}{module_name}.txt'
    if os.path.isfile(module_cache_file):
        return True
    else:
        if input(
                f'{Colours.GREEN}[*] This module does not appear to have been collected from the pipeline, do you want to collect a fresh copy? (y/N) {Colours.END}').lower().strip() == 'y':
            return initiate_pipeline(module_name)


def initiate_pipeline(module_name, load_after=True):
    server = jenkins.Jenkins(JenkinsServer, username='admin', password=JenkinsKey)
    module = os.path.splitext(module_name)[0]
    print(f'{Colours.GREEN}[*] Checking if Jenkins contains a job for the module {module}')
    job_exists = server.get_job_name(module)
    if job_exists != module:
        print(
            f'[!] Jenkins job does not exist with the name {module}, consider adding the module into Jenkins for future use!')
        if load_after:
            confirm = input("[*] Load existing non-pipeline module? (y/N) ")
            if confirm.lower().strip() == 'y':
                return True
            else:
                return False
        return False
    project_name = ProjectName
    branch = 'master'
    print('[*] Getting the current module build number')
    last_build_number = server.get_job_info(module)['lastCompletedBuild']['number']
    print(f'[*] Starting build of {module}')
    server.build_job(module, {'BRANCH': branch, 'projectId': project_name})
    print('[*] Checking on build status')
    new_build_number = server.get_job_info(module)['lastCompletedBuild']['number']
    while new_build_number == last_build_number:
        print('[*] Building...')
        new_build_number = server.get_job_info(module)['lastCompletedBuild']['number']
        time.sleep(5)
    else:
        print('[+] Build Complete')
    print('[*] Parsing build console output')
    build_console = server.get_build_console_output(module, new_build_number)
    print('[*] Getting nexus URL for the payload')
    searcher = re.search(f'{NexusServer}(.+?).exe', build_console)
    if searcher:
        uri = searcher.group(1)
        nexus_url = f'{NexusServer}{uri}.exe'
    else:
        print('[!] Nexus URL Not found')
        raise Exception(
            'The build succeeded however the console output shows no upload to Nexus, check job output on jenkins')
    print('[*] Downloading Compiled Binary')
    r = requests.get(nexus_url, auth=HTTPBasicAuth('admin', NexusKey))
    module_path = ModulesDirectory + module_name
    with open(module_path, 'wb') as f:
        f.write(r.content)
    print('[*] Downloaded to modules directory')
    print('[*] Creating time file to show it was built using the pipeline')
    now = datetime.now()
    timestamp = now.strftime("%m/%d/%Y, %H:%M:%S")
    module_cache_file_path = f'{ModulesDirectory}{module_name}.txt'
    with open(module_cache_file_path, 'w') as f:
        f.write(timestamp)
    print(f'[*] Cache file {module_cache_file_path} created')
    print(f'[+] Pipeline Complete{Colours.END}')
    return True
