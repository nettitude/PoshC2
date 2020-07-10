#!/bin/bash

# Install PoshC2
echo ""
echo """
   __________            .__.     _________  ________
   \_______  \____  _____|  |__   \_   ___ \ \_____  \\\\
    |     ___/  _ \/  ___/  |  \  /    \  \/  /  ____/
    |    |   ( <_>)___  \|   Y  \ \     \____/       \\\\
    |____|   \____/____  >___|  /  \______  /\_______ \\\\
                       \/     \/          \/         \/
    ================= www.PoshC2.co.uk ================"""

echo ""
echo ""
echo "[+] Installing PoshC2 for Docker"
echo ""

if [[ $(id -u) -ne 0 ]]; then
    echo -e "[-] You must run this installer as root.\nQuitting!";
    exit 1;
fi

command -v curl >/dev/null 2>&1
if [ "$?" != "0" ]; then
    command -v apt >/dev/null 2>&1

    if [ "$?" == "0" ]; then
        echo "[+] Performing apt-get update"
        apt-get update
        echo ""
        echo "[+] Installing curl for downloading scripts"
        apt-get install -y curl
    else
        echo "[-] Curl not found and apt not found in order to install it, please install curl on your system and try again."
        exit 1
    fi
fi

BRANCH="master"

if [ ! -z "$1" ]; then
    BRANCH="$1"
fi

echo ""
echo "[+] Installing scripts to /usr/bin"
rm -f /usr/bin/_posh-common
rm -f /usr/bin/fpc
rm -f /usr/bin/posh
rm -f /usr/bin/posh-server
rm -f /usr/bin/posh-config
rm -f /usr/bin/posh-log
rm -f /usr/bin/posh-service
rm -f /usr/bin/posh-stop-service
rm -f /usr/bin/posh-project
rm -f /usr/bin/posh-docker-clean
rm -f /usr/bin/posh-docker-debug
rm -f /usr/bin/posh-docker-build
curl https://raw.githubusercontent.com/nettitude/PoshC2/$BRANCH/resources/scripts/_posh-common -o /usr/bin/_posh-common
curl https://raw.githubusercontent.com/nettitude/PoshC2/$BRANCH/resources/scripts/fpc -o /usr/bin/fpc
curl https://raw.githubusercontent.com/nettitude/PoshC2/$BRANCH/resources/scripts/posh-docker -o /usr/bin/posh
curl https://raw.githubusercontent.com/nettitude/PoshC2/$BRANCH/resources/scripts/posh-docker-server -o /usr/bin/posh-server
curl https://raw.githubusercontent.com/nettitude/PoshC2/$BRANCH/resources/scripts/posh-config -o /usr/bin/posh-config
curl https://raw.githubusercontent.com/nettitude/PoshC2/$BRANCH/resources/scripts/posh-log -o /usr/bin/posh-log
curl https://raw.githubusercontent.com/nettitude/PoshC2/$BRANCH/resources/scripts/posh-service -o /usr/bin/posh-service
curl https://raw.githubusercontent.com/nettitude/PoshC2/$BRANCH/resources/scripts/posh-stop-service -o /usr/bin/posh-stop-service
curl https://raw.githubusercontent.com/nettitude/PoshC2/$BRANCH/resources/scripts/posh-project -o /usr/bin/posh-project
curl https://raw.githubusercontent.com/nettitude/PoshC2/$BRANCH/resources/scripts/posh-docker-clean -o /usr/bin/posh-docker-clean
curl https://raw.githubusercontent.com/nettitude/PoshC2/$BRANCH/resources/scripts/posh-docker-debug -o /usr/bin/posh-docker-debug
curl https://raw.githubusercontent.com/nettitude/PoshC2/$BRANCH/resources/scripts/posh-docker-build -o /usr/bin/posh-docker-build
chmod +x /usr/bin/fpc
chmod +x /usr/bin/posh
chmod +x /usr/bin/posh-server
chmod +x /usr/bin/posh-config
chmod +x /usr/bin/posh-log
chmod +x /usr/bin/posh-service
chmod +x /usr/bin/posh-stop-service
chmod +x /usr/bin/posh-project
chmod +x /usr/bin/posh-docker-clean
chmod +x /usr/bin/posh-docker-debug
chmod +x /usr/bin/posh-docker-build

mkdir -p "$HOME/.poshc2"
curl https://raw.githubusercontent.com/nettitude/PoshC2/$BRANCH/resources/config-template.yml -o "$HOME/.poshc2/config-template.yml"

curl https://raw.githubusercontent.com/nettitude/PoshC2/$BRANCH/resources/scripts/poshc2.service -o /lib/systemd/system/poshc2.service

echo ""
echo "[+] Setup complete"
echo """
   __________            .__.     _________  ________
   \_______  \____  _____|  |__   \_   ___ \ \_____  \\\\
    |     ___/  _ \/  ___/  |  \  /    \  \/  /  ____/
    |    |   ( <_>)___  \|   Y  \ \     \____/       \\\\
    |____|   \____/____  >___|  /  \______  /\_______ \\\\
                       \/     \/          \/         \/
    ================= www.PoshC2.co.uk ================"""
echo ""
echo "Create a new project with: "
echo "# posh-project -n <project-name>"
echo ""
echo "Then edit the config file - run: "
echo "# posh-config"
echo ""
echo "Then run:"
echo "# posh-server <-- This will run the C2 server, which communicates with Implants and receives task output"
echo "# posh <-- This will run the ImplantHandler, used to issue commands to the server and implants"
echo ""
echo "Other options:"
echo "posh-service <-- This will run the C2 server as a service instead of in the foreground"
echo "posh-log <-- This will view the C2 log if the server is already running"