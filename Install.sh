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

# Git cloning PoshC2_Python
echo ""
echo "[+] Installing git & cloning PoshC2_Python into /opt/PoshC2_Python/"
apt-get install -y git
git clone https://github.com/nettitude/PoshC2_Python /opt/PoshC2_Python/

# Install requirements for PoshC2_Python
echo ""
echo "[+] Installing requirements using apt"
apt-get install -y screen python-setuptools python3 python3-dev python3-pip python-dev build-essential python-pip mingw-w64-tools mingw-w64 mingw-w64-x86-64-dev mingw-w64-i686-dev mingw-w64-common espeak graphviz mono-complete apt-transport-https
  
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
echo "[+] python -m pip install -r /opt/PoshC2_Python/requirements.txt"
echo ""
python3 -m pip install --upgrade pip > /dev/null
python3 -m pip install pipenv > /dev/null
cd /opt/PoshC2_Python
rm Pipfile >/dev/null 2>/dev/null
python3 -m pipenv --python 3 run pip install -r /opt/PoshC2_Python/requirements.txt >/dev/null

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

# Install requirements of dotnet core for SharpSocks
echo ""
echo "[+] Adding microsoft debian repository & subsequent"
apt-key adv --keyserver packages.microsoft.com --recv-keys EB3E94ADBE1229CF
apt-key adv --keyserver packages.microsoft.com --recv-keys 52E16F86FEE04B979B07E28DB02C46DF417A0893
echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-stretch-prod stretch main" > /etc/apt/sources.list.d/dotnetdev.list
apt-get update

wget http://ftp.us.debian.org/debian/pool/main/i/icu/libicu57_57.1-6+deb9u2_amd64.deb -O /tmp/libicu57_57.1-6+deb9u2_amd64.deb
dpkg -i /tmp/libicu57_57.1-6+deb9u2_amd64.deb

wget http://ftp.us.debian.org/debian/pool/main/o/openssl1.0/libssl1.0.2_1.0.2r-1~deb9u1_amd64.deb -O /tmp/libssl1.0.2_1.0.2r-1~deb9u1_amd64.deb
dpkg -i /tmp/libssl1.0.2_1.0.2r-1\~deb9u1_amd64.deb

apt-get install -y dotnet-runtime-2.2 dotnet-hostfxr-2.2 dotnet-host

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
