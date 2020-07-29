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
echo "[+] Installing PoshC2"
echo ""

if [[ $(id -u) -ne 0 ]]; then
    echo -e "You must run this installer as root.\nQuitting!";
    exit 1;
fi

if [[ ! -z "$1" ]]; then
    POSH_DIR="$1"
    echo "PoshC2 is not being installed to /opt/PoshC2."
    echo "Don't forget to set the POSHC2_DIR environment variable so that the commands use the correct directory."
elif [[ ! -z "${POSHC2_DIR}" ]]; then
     POSH_DIR="${POSHC2_DIR}"
else
     POSH_DIR="/opt/PoshC2"
fi

# Update apt
echo "[+] Performing apt-get update"
apt-get update

# Check if /opt/ exists, else create folder opt
if [ ! -d /opt/ ]; then
	echo ""
	echo "[+] Creating folder in /opt/"
	mkdir /opt/
fi

if [[ ! -d "$POSH_DIR" ]]; then
    # Git cloning PoshC2
    echo ""
    echo "[+] Installing git & cloning PoshC2 into $POSH_DIR"
    apt-get install -y git
    git clone https://github.com/nettitude/PoshC2 "$POSH_DIR"
fi

echo ""
echo "[+] Symlinking useful scripts to /usr/bin"
ln -s "$POSH_DIR/resources/scripts/fpc" /usr/bin/fpc
ln -s "$POSH_DIR/resources/scripts/posh-docker" /usr/bin/posh
ln -s "$POSH_DIR/resources/scripts/posh-docker-server" /usr/bin/posh-server
ln -s "$POSH_DIR/resources/scripts/posh-config" /usr/bin/posh-config
ln -s "$POSH_DIR/resources/scripts/posh-log" /usr/bin/posh-log
ln -s "$POSH_DIR/resources/scripts/posh-docker-service" /usr/bin/posh-service
ln -s "$POSH_DIR/resources/scripts/posh-stop-service" /usr/bin/posh-stop-service
ln -s "$POSH_DIR/resources/scripts/posh-update" /usr/bin/posh-update
ln -s "$POSH_DIR/resources/scripts/posh-cookie-decrypter" /usr/bin/posh-cookie-decryptor
ln -s "$POSH_DIR/resources/scripts/posh-project" /usr/bin/posh-project
ln -s "$POSH_DIR/resources/scripts/posh-docker-build" /usr/bin/posh-docker-build
ln -s "$POSH_DIR/resources/scripts/posh-docker-clean" /usr/bin/posh-docker-clean
ln -s "$POSH_DIR/resources/scripts/posh-docker-debug" /usr/bin/posh-docker-debug
chmod +x "$POSH_DIR/resources/scripts/fpc"
chmod +x "$POSH_DIR/resources/scripts/posh-docker"
chmod +x "$POSH_DIR/resources/scripts/posh-docker-server"
chmod +x "$POSH_DIR/resources/scripts/posh-config"
chmod +x "$POSH_DIR/resources/scripts/posh-log"
chmod +x "$POSH_DIR/resources/scripts/posh-docker-service"
chmod +x "$POSH_DIR/resources/scripts/posh-stop-service"
chmod +x "$POSH_DIR/resources/scripts/posh-update"
chmod +x "$POSH_DIR/resources/scripts/posh-cookie-decrypter"
chmod +x "$POSH_DIR/resources/scripts/posh-project"
chmod +x "$POSH_DIR/resources/scripts/posh-docker-build"
chmod +x "$POSH_DIR/resources/scripts/posh-docker-clean"
chmod +x "$POSH_DIR/resources/scripts/posh-docker-debug"

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
echo "Edit the config file - run: "
echo "# posh-config"
echo ""
echo "Then build the Docker image:"
echo "# posh-docker-build"
echo ""
echo "Then run:"
echo "# posh-server <-- This will run the C2 server, which communicates with Implants and receives task output"
echo "# posh <-- This will run the ImplantHandler, used to issue commands to the server and implants"
echo ""
echo "Other options:"
echo "posh-service <-- This will run the C2 server as a service instead of in the foreground"
echo "posh-log <-- This will view the C2 log if the server is already running"