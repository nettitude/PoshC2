#!/bin/sh

# Install PoshC2
echo ""
echo """ __________            .__.     _________  ________
   \_______  \____  _____|  |__   \_   ___ \ \_____  \\
    |     ___/  _ \/  ___/  |  \  /    \  \/  /  ____/
    |    |  ( <_>)___ \|   Y  \ \     \____/       \\
    |____|   \____/____  >___|  /  \______  /\_______ \\
                       \/     \/          \/         \/
    ================= www.PoshC2.co.uk ================"""
echo ""
echo ""
echo "[+] Installing PoshC2"
echo ""

# Update apt
echo "[+] Performing apt-get update"
apt-get update

# Check if /opt/ exists, else create folder opt
if [ ! -d /opt/ ]; then
	echo ""
	echo "[+] Creating folder in /opt/"
	mkdir /opt/
fi

# Install requirements for PoshC2_Python
echo ""
echo "[+] Installing git & cloning PoshC2_Python into /opt/PoshC2_Python/"
apt-get install -y git
git clone https://github.com/nettitude/PoshC2_Python /opt/PoshC2_Python/

# Install requirements for PoshC2_Python
echo ""
echo "[+] Installing requirements using apt"
apt-get install -y screen python-setuptools python-dev build-essential python-pip mingw-w64-tools mingw-w64 mingw-w64-x86-64-dev mingw-w64-i686-dev mingw-w64-common espeak graphviz mono-complete

# Setting the minimum protocol to TLS1.0 to allow the python server to support TLSv1.0+
echo ""
echo "[+] Updating TLS protocol minimum version in /etc/ssl/openssl.cnf"
echo "[+] Backup file generated - /etc/ssl/openssl.cnf.bak"
sed -i.bak 's/MinProtocol = TLSv1.2/MinProtocol = TLSv1.0/g' /etc/ssl/openssl.cnf

# Check if PIP is installed, if not install it
command -v pip2 > /dev/null 2>&1
if [ "$?" -ne "0"  ]; then
	echo "[+] Installing pip as this was not found"
	wget https://bootstrap.pypa.io/get-pip.py -O /tmp/get-pip.py >/dev/null
	python2 /tmp/get-pip.py >/dev/null
fi

echo ""
echo "[+] Installing requirements using pip"
echo "[+] python -m pip install -r /opt/PoshC2_Python/requirements.txt"
echo ""
python2 -m pip install --upgrade pip > /dev/null
cd /opt/PoshC2_Python
python2 -m pipenv run pip install -r /opt/PoshC2_Python/requirements.txt >/dev/null

echo ""
echo "[+] Copying useful scripts to /usr/bin"
cp /opt/PoshC2_Python/Files/fpc /usr/bin
cp /opt/PoshC2_Python/Files/fpc.py /usr/bin
cp /opt/PoshC2_Python/Files/posh /usr/bin
cp /opt/PoshC2_Python/Files/posh-server /usr/bin
cp /opt/PoshC2_Python/Files/posh-config /usr/bin
cp /opt/PoshC2_Python/Files/posh-log /usr/bin
cp /opt/PoshC2_Python/Files/posh-service /usr/bin
chmod +x /usr/bin/fpc
chmod +x /usr/bin/fpc.py
chmod +x /usr/bin/posh
chmod +x /usr/bin/posh-server
chmod +x /usr/bin/posh-config
chmod +x /usr/bin/posh-log
chmod +x /usr/bin/posh-service

echo "[+] Adding service file"
cp /opt/PoshC2_Python/poshc2.service /lib/systemd/system/poshc2.service

echo ""
echo "[+] Setup complete"
echo ""
echo """ __________            .__.     _________  ________
   \_______  \____  _____|  |__   \_   ___ \ \_____  \\
    |     ___/  _ \/  ___/  |  \  /    \  \/  /  ____/
    |    |  ( <_>)___ \|   Y  \ \     \____/       \\
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
