#!/bin/sh

# Install PoshC2
echo ""

echo """__________            .__.     _________  ________
 \_______  \____  _____|  |__   \_   ___ \ \_____  \
  |     ___/  _ \/  ___/  |  \  /    \  \/  /  ____/
  |    |  (  <_> )___ \|   Y  \ \     \____/       \
  |____|   \____/____  >___|  /  \______  /\_______ \
                     \/     \/          \/         \/
  ================= www.PoshC2.co.uk ================="""

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
apt-get install -y screen python-setuptools python-dev build-essential python-pip mingw-w64-tools mingw-w64 mingw-w64-x86-64-dev mingw-w64-i686-dev mingw-w64-common espeak graphviz mono-devel

# Check if PIP is installed, if not install it
if [! which pip > /dev/null]; then
	echo "[+] Installing pip as this was not found"
	wget https://bootstrap.pypa.io/get-pip.py
	python get-pip.py
fi

# Run pip with requirements file
echo ""
echo "[+] Installing requirements using pip"
echo "[+] python -m pip install -r /opt/PoshC2_Python/requirements.txt"
echo ""
pip install --upgrade pip
python -m pip install -r /opt/PoshC2_Python/requirements.txt

echo ""
echo "[+] Setup complete"
echo ""
echo """__________            .__.     _________  ________
 \_______  \____  _____|  |__   \_   ___ \ \_____  \
  |     ___/  _ \/  ___/  |  \  /    \  \/  /  ____/
  |    |  (  <_> )___ \|   Y  \ \     \____/       \
  |____|   \____/____  >___|  /  \______  /\_______ \
                     \/     \/          \/         \/
  ================= www.PoshC2.co.uk ================="""
echo ""
echo "EDIT the config file: '/opt/PoshC2_Python/Config.py'"
echo ""
echo "sudo python /opt/PoshC2_Python/C2Server.py"
echo "sudo python /opt/PoshC2_Python/ImplantHandler.py"
echo ""
echo "To install via systemctl read poshc2.service"
