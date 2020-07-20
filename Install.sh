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

# Install requirements for PoshC2
echo ""
echo "[+] Installing requirements using apt"
apt-get install -y screen python3 python3-dev python3-pip build-essential mingw-w64-tools mingw-w64 mingw-w64-x86-64-dev mingw-w64-i686-dev mingw-w64-common espeak graphviz mono-complete apt-transport-https vim nano python2.7 libpq-dev curl sudo sqlite3
apt-get install -y python3.8-dev python3-distutils python3-lib2to3 python3.7-dev python3.7 2>/dev/null

# Setting the minimum protocol to TLS1.0 to allow the python server to support TLSv1.0+
echo ""
echo "[+] Updating TLS protocol minimum version in /etc/ssl/openssl.cnf"
echo "[+] Backup file generated - /etc/ssl/openssl.cnf.bak"
sed -i.bak 's/MinProtocol = TLSv1.2/MinProtocol = TLSv1.0/g' /etc/ssl/openssl.cnf

# Check if PIP is installed, if not install it
command -v pip3 > /dev/null 2>&1
if [ "$?" -ne "0"  ]; then
	echo "[+] Installing pip as this was not found"
	wget https://bootstrap.pypa.io/get-pip.py -O /tmp/get-pip.py >/dev/null
	python3 /tmp/get-pip.py >/dev/null
fi

echo ""
echo "[+] Installing requirements using pip"
echo "[+] python3 -m pipenv --three install"
echo ""
python3 -m pip install --upgrade pip > /dev/null
python3 -m pip install pandas pipenv > /dev/null
cd "$POSH_DIR"
python3 -m pipenv --three install >/dev/null

echo ""
echo "[+] Symlinking useful scripts to /usr/bin"
ln -s "$POSH_DIR/resources/scripts/fpc" /usr/bin/fpc
ln -s "$POSH_DIR/resources/scripts/posh" /usr/bin/posh
ln -s "$POSH_DIR/resources/scripts/posh-server" /usr/bin/posh-server
ln -s "$POSH_DIR/resources/scripts/posh-config" /usr/bin/posh-config
ln -s "$POSH_DIR/resources/scripts/posh-log" /usr/bin/posh-log
ln -s "$POSH_DIR/resources/scripts/posh-service" /usr/bin/posh-service
ln -s "$POSH_DIR/resources/scripts/posh-stop-service" /usr/bin/posh-stop-service
ln -s "$POSH_DIR/resources/scripts/posh-update" /usr/bin/posh-update
ln -s "$POSH_DIR/resources/scripts/posh-cookie-decrypter" /usr/bin/posh-cookie-decryptor
ln -s "$POSH_DIR/resources/scripts/posh-project" /usr/bin/posh-project
chmod +x "$POSH_DIR/resources/scripts/fpc"
chmod +x "$POSH_DIR/resources/scripts/posh"
chmod +x "$POSH_DIR/resources/scripts/posh-server"
chmod +x "$POSH_DIR/resources/scripts/posh-config"
chmod +x "$POSH_DIR/resources/scripts/posh-log"
chmod +x "$POSH_DIR/resources/scripts/posh-service"
chmod +x "$POSH_DIR/resources/scripts/posh-stop-service"
chmod +x "$POSH_DIR/resources/scripts/posh-update"
chmod +x "$POSH_DIR/resources/scripts/posh-cookie-decrypter"
chmod +x "$POSH_DIR/resources/scripts/posh-project"

echo "[+] Adding service files"
cp "$POSH_DIR/resources/scripts/poshc2.service" /lib/systemd/system/poshc2.service
cp "$POSH_DIR/resources/scripts/poshc2-docker.service" /lib/systemd/system/poshc2-docker.service

# Install requirements of dotnet core for SharpSocks
echo ""
echo "[+] Adding microsoft debian repository & subsequent"
curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-stretch-prod stretch main" > /etc/apt/sources.list.d/dotnetdev.list
apt-get update
apt-get install -y dotnet-runtime-2.2 dotnet-hostfxr-2.2 dotnet-host libssl1.1
apt-get install -y libicu63

if [[ $(uname -a) == *"Ubuntu"* ]]; then
    apt-get install -y mono-reference-assemblies-4.0
    apt-get install -y mono-reference-assemblies-2.0
fi

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
echo "Then run:"
echo "# posh-server <-- This will run the C2 server, which communicates with Implants and receives task output"
echo "# posh <-- This will run the ImplantHandler, used to issue commands to the server and implants"
echo ""
echo "Other options:"
echo "posh-service <-- This will run the C2 server as a service instead of in the foreground"
echo "posh-log <-- This will view the C2 log if the server is already running"
