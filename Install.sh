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

# Install requirements for PoshC2
echo ""
echo "[+] Installing requirements using apt"
apt-get install -y screen python3 python3-dev python3-pip build-essential mingw-w64-tools mingw-w64 mingw-w64-x86-64-dev mingw-w64-i686-dev mingw-w64-common espeak graphviz mono-complete apt-transport-https vim nano python2.7

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
echo "[+] python3 -m pip install -r $POSH_DIR/requirements.txt"
echo ""
python3 -m pip install --upgrade pip > /dev/null
python3 -m pip install pandas pipenv > /dev/null
cd "$POSH_DIR"
rm Pipfile >/dev/null 2>/dev/null
python3 -m pipenv --python 3 run pip install -r "$POSH_DIR/requirements.txt" >/dev/null

echo ""
echo "[+] Copying useful scripts to /usr/bin"
cp "$POSH_DIR/Files/fpc" /usr/bin
cp "$POSH_DIR/Files/posh" /usr/bin
cp "$POSH_DIR/Files/posh-server" /usr/bin
cp "$POSH_DIR/Files/posh-config" /usr/bin
cp "$POSH_DIR/Files/posh-log" /usr/bin
cp "$POSH_DIR/Files/posh-service" /usr/bin
cp "$POSH_DIR/Files/posh-stop-service" /usr/bin
cp "$POSH_DIR/Files/posh-update" /usr/bin
cp "$POSH_DIR/Files/posh-docker" /usr/bin
cp "$POSH_DIR/Files/posh-docker-server" /usr/bin
cp "$POSH_DIR/Files/posh-docker-build" /usr/bin
cp "$POSH_DIR/Files/posh-docker-clean" /usr/bin
cp "$POSH_DIR/Files/posh-docker-service" /usr/bin
chmod +x /usr/bin/fpc
chmod +x /usr/bin/posh
chmod +x /usr/bin/posh-server
chmod +x /usr/bin/posh-config
chmod +x /usr/bin/posh-log
chmod +x /usr/bin/posh-service
chmod +x /usr/bin/posh-stop-service
chmod +x /usr/bin/posh-update
chmod +x /usr/bin/posh-docker
chmod +x /usr/bin/posh-docker-server
chmod +x /usr/bin/posh-docker-build
chmod +x /usr/bin/posh-docker-clean
chmod +x /usr/bin/posh-docker-service

echo "[+] Adding service files"
cp "$POSH_DIR/poshc2.service" /lib/systemd/system/poshc2.service
cp "$POSH_DIR/poshc2-docker.service" /lib/systemd/system/poshc2-docker.service

# Install requirements of dotnet core for SharpSocks
echo ""
echo "[+] Adding microsoft debian repository & subsequent"
apt-key adv --keyserver packages.microsoft.com --recv-keys EB3E94ADBE1229CF
apt-key adv --keyserver packages.microsoft.com --recv-keys 52E16F86FEE04B979B07E28DB02C46DF417A0893
echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-stretch-prod stretch main" > /etc/apt/sources.list.d/dotnetdev.list
apt-get update
apt-get install -y dotnet-runtime-2.2 dotnet-hostfxr-2.2 dotnet-host libicu63 libssl1.1

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
echo "Then run:"
echo "# posh-server"
echo "# posh"
echo ""
echo "To run as a service use posh-service instead of posh-server"
echo "\033[0m"
