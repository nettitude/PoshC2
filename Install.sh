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

command -v apt >/dev/null 2>&1

if [ "$?" != "0" ]; then
    echo "[-] This install script must be run on a Debian based system with apt installed."
    echo "[-] Look at PoshC2's Docker support for running PoshC2 on none-Debian based systems."
    exit 1
fi

# A POSIX variable
OPTIND=1         # Reset in case getopts has been used previously in the shell.

# Initialize our own variables:
GIT_BRANCH="master"
MANUAL_BRANCH_SET=false
POSH_DIR="/opt/PoshC2"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

if [ -f "$SCRIPT_DIR/poshc2/server/C2Server.py" ]; then
    POSH_DIR="$SCRIPT_DIR"
fi

show_help(){
    echo "*** PoshC2 Install script ***"
    echo "Usage:"
    echo "./Install.sh -b <git branch> -p <Directory to clone PoshC2 to>"
    echo ""
    echo "Defaults are master branch to /opt/PoshC2"
}

while getopts "h?b:p:" opt; do
    case "$opt" in
    h|\?)
        show_help
        exit 0
        ;;
    b)  GIT_BRANCH="$OPTARG"
        MANUAL_BRANCH_SET=true
        ;;
    p)  POSH_DIR="$OPTARG"
        ;;
    esac
done

command -v git >/dev/null 2>&1

if [ "$?" != "0" ]; then
    echo "[*] Git not found - installing via apt"
    apt-get install -y git
fi

if [[ ! -d "$POSH_DIR" ]]; then
    # Git cloning PoshC2
    echo -e "\n[+] Installing PoshC2 in \"$POSH_DIR\" for branch \"$GIT_BRANCH\"\n"
    mkdir -p `dirname $POSH_DIR`
    git clone -b "$GIT_BRANCH" https://github.com/nettitude/PoshC2 "$POSH_DIR"
else
    pushd "$POSH_DIR" >/dev/null
    git fetch >/dev/null 2>&1
    if [ "$MANUAL_BRANCH_SET" == "false" ]; then
        GIT_BRANCH=`git rev-parse --abbrev-ref HEAD`
    fi
    echo -e "[+] Updating existing PoshC2 install at \"$POSH_DIR\" to branch \"$GIT_BRANCH\"\n"
    git stash
    git reset --hard origin/"$GIT_BRANCH"
fi

# Update apt
echo -e "\n[+] Performing apt-get update\n"
apt-get update

# Install requirements for PoshC2
echo -e "\n[+] Installing requirements using apt\n"
apt-get install -y screen python3 python3-dev python3-pip build-essential mingw-w64-tools mingw-w64 mingw-w64-x86-64-dev mingw-w64-i686-dev mingw-w64-common espeak graphviz mono-complete apt-transport-https vim nano python2.7 libpq-dev curl sudo sqlite3
apt-get install -y python3.8-dev python3-distutils python3-lib2to3 python3.7-dev python3.7 2>/dev/null

# Setting the minimum protocol to TLS1.0 to allow the python server to support TLSv1.0+
echo -e "\n[+] Updating TLS protocol minimum version in /etc/ssl/openssl.cnf"
echo "[+] Backup file generated - /etc/ssl/openssl.cnf.bak"
sed -i.bak 's/MinProtocol = TLSv1.2/MinProtocol = TLSv1.0/g' /etc/ssl/openssl.cnf

# Check if PIP is installed, if not install it
command -v pip3 > /dev/null 2>&1
if [ "$?" -ne "0"  ]; then
	echo -e "[+] Installing pip as this was not found\n"
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
rm -f /usr/local/bin/_posh-common
rm -f /usr/bin/fpc
rm -f /usr/local/bin/posh
rm -f /usr/local/bin/posh-server
rm -f /usr/local/bin/posh-config
rm -f /usr/local/bin/posh-log
rm -f /usr/local/bin/posh-service
rm -f /usr/local/bin/posh-stop-service
rm -f /usr/local/bin/posh-update
rm -f /usr/local/bin/posh-cookie-decryptor
rm -f /usr/local/bin/posh-project
ln -s "$POSH_DIR/resources/scripts/_posh-common" /usr/local/bin/_posh-common
ln -s "$POSH_DIR/resources/scripts/fpc" /usr/bin/fpc
ln -s "$POSH_DIR/resources/scripts/posh" /usr/local/bin/posh
ln -s "$POSH_DIR/resources/scripts/posh-server" /usr/local/bin/posh-server
ln -s "$POSH_DIR/resources/scripts/posh-config" /usr/local/bin/posh-config
ln -s "$POSH_DIR/resources/scripts/posh-log" /usr/local/bin/posh-log
ln -s "$POSH_DIR/resources/scripts/posh-service" /usr/local/bin/posh-service
ln -s "$POSH_DIR/resources/scripts/posh-stop-service" /usr/local/bin/posh-stop-service
ln -s "$POSH_DIR/resources/scripts/posh-update" /usr/local/bin/posh-update
ln -s "$POSH_DIR/resources/scripts/posh-cookie-decrypter" /usr/local/bin/posh-cookie-decryptor
ln -s "$POSH_DIR/resources/scripts/posh-project" /usr/local/bin/posh-project
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

mkdir -p "/var/poshc2/"
cp "$POSH_DIR/resources/config-template.yml" "/var/poshc2/config-template.yml"

echo "[+] Adding service files"
cp "$POSH_DIR/resources/scripts/poshc2.service" /lib/systemd/system/poshc2.service

# Install requirements of dotnet core for SharpSocks
echo ""
echo "[+] Adding microsoft debian repository & subsequent"
curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add - >/dev/null
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
echo "posh-stop-service <-- This will stop the service"
echo "posh-log <-- This will view the C2 log if the server is already running"
