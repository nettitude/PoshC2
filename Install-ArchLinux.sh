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
echo "[+] Performing Pacman update"
sudo pacman -Syu

# Check if /opt/ exists, else create folder opt
if [ ! -d /opt/ ]; then
	echo ""
	echo "[+] Creating folder in /opt/"
	mkdir /opt/
fi

# Git cloning PoshC2_Python
echo ""
echo "[+] Installing git & cloning PoshC2_Python into /opt/PoshC2_Python/"
sudo pacman -Sy git
sudo git clone https://github.com/nettitude/PoshC2_Python /opt/PoshC2_Python/

# Install requirements for PoshC2_Python
echo ""
echo "[+] Installing requirements using pacman"
sudo pacman -Sy screen python3 python-pip espeak graphviz mono vim nano
pamac build mingw-w64-gcc-base
pamac build mingw-w64-gcc mono-git
sudo ln -s /usr/bin/csc /usr/bin/mono-csc

# Setting the minimum protocol to TLS1.0 to allow the python server to support TLSv1.0+
echo ""
echo "[+] Updating TLS protocol minimum version in /etc/ssl/openssl.cnf"
echo "[+] Backup file generated - /etc/ssl/openssl.cnf.bak"
sudo sed -i.bak 's/MinProtocol = TLSv1.2/MinProtocol = TLSv1.0/g' /etc/ssl/openssl.cnf

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
sudo python3 -m pip install --upgrade pip > /dev/null
sudo python3 -m pip install pipenv > /dev/null
cd /opt/PoshC2_Python
sudo rm Pipfile >/dev/null 2>/dev/null
sudo python3 -m pipenv --python 3 run pip install -r /opt/PoshC2_Python/requirements.txt >/dev/null

echo ""
echo "[+] Copying useful scripts to /usr/bin"
sudo cp /opt/PoshC2_Python/Files/fpc /usr/bin
sudo cp /opt/PoshC2_Python/Files/fpc.py /usr/bin
sudo cp /opt/PoshC2_Python/Files/posh /usr/bin
sudo cp /opt/PoshC2_Python/Files/posh-server /usr/bin
sudo cp /opt/PoshC2_Python/Files/posh-config /usr/bin
sudo cp /opt/PoshC2_Python/Files/posh-log /usr/bin
sudo cp /opt/PoshC2_Python/Files/posh-service /usr/bin
sudo chmod +x /usr/bin/fpc
sudo chmod +x /usr/bin/fpc.py
sudo chmod +x /usr/bin/posh
sudo chmod +x /usr/bin/posh-server
sudo chmod +x /usr/bin/posh-config
sudo chmod +x /usr/bin/posh-log
sudo chmod +x /usr/bin/posh-service

echo "[+] Adding service file"
sudo cp /opt/PoshC2_Python/poshc2.service /lib/systemd/system/poshc2.service

# Install requirements of dotnet core for SharpSocks
echo ""
echo "[+] Adding dotnet core for Sharpsocks"
sudo pacman -S dotnet-runtime dotnet-host lib32-openssl-1.0 openssl-1.0

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
