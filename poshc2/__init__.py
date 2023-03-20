#! /usr/bin/env python3

import subprocess
import sys

try:
    VERSION = subprocess.check_output(
        ["git", "describe", "--match", "v[0-9]*", "--abbrev=0", "--tags", "HEAD"]).decode().strip()
except subprocess.CalledProcessError:
    VERSION = "Zip"


class Colours:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    END = '\033[0m'
    YELLOW = '\033[93m'
    PURPLE = '\033[1;35m'


logo = Colours.GREEN + r"""
                    _________            .__.     _________  ________
                    \_______ \____  _____|  |__   \_   ___ \ \_____  \\
                    |     ___/  _ \/  ___/  |  \  /    \  \/  /  ____/
                    |    |  (  <_> )___ \|   Y  \ \     \____/       \\
                    |____|   \____/____  >___|  /  \______  /\_______ \\
                                        \/     \/          \/         \/
"""

try:
    commit = subprocess.check_output(["git", "log", "-1", "--format='%h %ci'"]).decode().strip('\n').strip("'")[:-6]
    banner = Colours.GREEN + fr"""==== {Colours.RED}PoshC2 {VERSION} ({commit}){Colours.GREEN} ====
"""
except Exception:
    banner = Colours.GREEN + fr"""==== {Colours.RED}PoshC2 {VERSION}{Colours.GREEN} ====
"""

logo = logo + banner


def run():
    if sys.argv[1] == '--client':
        import poshc2.client as client
        client.start()
    elif sys.argv[1] == '--server':
        import poshc2.server as server
        server.start()
    else:
        print(f"Unrecognised startup arguments, expected --server/--client as first arg: {str(sys.argv)}")
