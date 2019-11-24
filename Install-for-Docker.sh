#!/bin/bash

# Install PoshC2
echo ""
echo """ 
   __________            .__.     _________  ________
   \_______  \____  _____|  |__   \_   ___ \ \_____  \\
    |     ___/  _ \/  ___/  |  \  /    \  \/  /  ____/
    |    |   ( <_>)___  \|   Y  \ \     \____/       \\
    |____|   \____/____  >___|  /  \______  /\_______ \\
                       \/     \/          \/         \/
    ================= www.PoshC2.co.uk ================"""
echo ""
echo ""
echo "[+] Installing PoshC2"
echo ""

if [[ ! -z "$1" ]]; then
    POSH_DIR="$1"
    echo "\033[93mPoshC2 is not being installed to /opt/PoshC2."
    echo "Don't forget to set the POSHC2_DIR environment variable so that the commands use the correct directory.\033[0m"
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
echo "[+] Copying useful scripts to /usr/bin"
cp "$POSH_DIR/Files/fpc" /usr/bin
cp "$POSH_DIR/Files/posh-config" /usr/bin
cp "$POSH_DIR/Files/posh-docker" /usr/bin
cp "$POSH_DIR/Files/posh-docker-server" /usr/bin
cp "$POSH_DIR/Files/posh-docker-build" /usr/bin
cp "$POSH_DIR/Files/posh-docker-clean" /usr/bin
cp "$POSH_DIR/Files/posh-docker-service" /usr/bin
chmod +x /usr/bin/fpc
chmod +x /usr/bin/posh-config
chmod +x /usr/bin/posh-docker
chmod +x /usr/bin/posh-docker-server
chmod +x /usr/bin/posh-docker-build
chmod +x /usr/bin/posh-docker-clean
chmod +x /usr/bin/posh-docker-service

echo ""
echo "[+] Setup complete"
echo """\033[92m
   __________            .__.     _________  ________
   \_______  \____  _____|  |__   \_   ___ \ \_____  \\
    |     ___/  _ \/  ___/  |  \  /    \  \/  /  ____/
    |    |   ( <_>)___  \|   Y  \ \     \____/       \\
    |____|   \____/____  >___|  /  \______  /\_______ \\
                       \/     \/          \/         \/
    ================= www.PoshC2.co.uk ================"""
echo ""
echo "EDIT the config file - run: posh-config"
echo ""
echo "Then build the Docker image:"
echo "# posh-docker-build"
echo ""
echo "Then run:"
echo "# posh-docker-server"
echo "# posh-docker"
echo ""
echo "To run as a service use posh-docker-service instead of posh-docker-server"
echo "\033[0m"
