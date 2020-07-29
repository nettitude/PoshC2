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

# A POSIX variable
OPTIND=1         # Reset in case getopts has been used previously in the shell.

# Initialize our own variables:
GIT_BRANCH="master"

show_help(){
    echo "*** PoshC2 Install script for Docker ***"
    echo "Usage:"
    echo "./Install.sh -b <git branch>"
    echo ""
    echo "Default is the master branch"
}

while getopts "h?b:" opt; do
    case "$opt" in
    h|\?)
        show_help
        exit 0
        ;;
    b)  GIT_BRANCH="$OPTARG"
        ;;
    esac
done

echo "[+] Installing PoshC2 for Docker"
echo ""
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
rm -f /usr/bin/posh-stop-server
curl https://raw.githubusercontent.com/nettitude/PoshC2/$GIT_BRANCH/resources/scripts/_posh-common -o /usr/bin/_posh-common >/dev/null
curl https://raw.githubusercontent.com/nettitude/PoshC2/$GIT_BRANCH/resources/scripts/fpc -o /usr/bin/fpc >/dev/null
curl https://raw.githubusercontent.com/nettitude/PoshC2/$GIT_BRANCH/resources/scripts/posh-docker -o /usr/bin/posh >/dev/null
curl https://raw.githubusercontent.com/nettitude/PoshC2/$GIT_BRANCH/resources/scripts/posh-docker-server -o /usr/bin/posh-server >/dev/null
curl https://raw.githubusercontent.com/nettitude/PoshC2/$GIT_BRANCH/resources/scripts/posh-config -o /usr/bin/posh-config >/dev/null
curl https://raw.githubusercontent.com/nettitude/PoshC2/$GIT_BRANCH/resources/scripts/posh-log -o /usr/bin/posh-log >/dev/null
curl https://raw.githubusercontent.com/nettitude/PoshC2/$GIT_BRANCH/resources/scripts/posh-service -o /usr/bin/posh-service >/dev/null
curl https://raw.githubusercontent.com/nettitude/PoshC2/$GIT_BRANCH/resources/scripts/posh-stop-service -o /usr/bin/posh-stop-service >/dev/null
curl https://raw.githubusercontent.com/nettitude/PoshC2/$GIT_BRANCH/resources/scripts/posh-project -o /usr/bin/posh-project >/dev/null
curl https://raw.githubusercontent.com/nettitude/PoshC2/$GIT_BRANCH/resources/scripts/posh-docker-clean -o /usr/bin/posh-docker-clean >/dev/null
curl https://raw.githubusercontent.com/nettitude/PoshC2/$GIT_BRANCH/resources/scripts/posh-docker-stop-server -o /usr/bin/posh-stop-server >/dev/null
chmod +x /usr/bin/fpc
chmod +x /usr/bin/posh
chmod +x /usr/bin/posh-server
chmod +x /usr/bin/posh-config
chmod +x /usr/bin/posh-log
chmod +x /usr/bin/posh-service
chmod +x /usr/bin/posh-stop-service
chmod +x /usr/bin/posh-project
chmod +x /usr/bin/posh-docker-clean
chmod +x /usr/bin/posh-stop-server

mkdir -p "/var/poshc2"
curl https://raw.githubusercontent.com/nettitude/PoshC2/$GIT_BRANCH/resources/config-template.yml -o "/var/poshc2/config-template.yml" >/dev/null

curl https://raw.githubusercontent.com/nettitude/PoshC2/$GIT_BRANCH/resources/scripts/poshc2.service -o /lib/systemd/system/poshc2.service >/dev/null

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
echo "# posh-stop-server <-- This will stop the server container"
echo "# posh <-- This will run the ImplantHandler, used to issue commands to the server and implants"
echo ""
echo "Other options:"
echo "posh-service <-- This will run the C2 server as a service instead of in the foreground"
echo "posh-stop-service <-- This will stop the service"
echo "posh-log <-- This will view the C2 log if the server is already running"