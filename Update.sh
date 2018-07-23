#!/bin/sh

# Update PoshC2
echo ""

echo """__________            .__.     _________  ________  
 \_______  \____  _____|  |__   \_   ___ \ \_____  \ 
  |     ___/  _ \/  ___/  |  \  /    \  \/  /  ____/ 
  |    |  (  <_> )___ \|   Y  \ \     \____/       \ 
  |____|   \____/____  >___|  /  \______  /\_______ \  
                     \/     \/          \/         \/
  =============== v4.0 www.PoshC2.co.uk ============="""

echo ""
echo "[+] Updating PoshC2_Python"
echo ""

# Backup config
echo "[+] Backup Config.py"
mv /opt/PoshC2_Python/Config.py /tmp/Config.py

# Install requirements for PoshC2_Python
echo ""
echo "[+] Performing git pull on /opt/PoshC2_Python/"
cd /opt/PoshC2_Python/
git pull

# Restore config
echo "[+] Restore Config.py"
mv /tmp/Config.py /opt/PoshC2_Python/Config.py
echo ""
echo "[+] Update complete"
echo ""
