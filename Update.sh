#!/bin/bash

# Update PoshC2
echo ""

echo """__________            .__.     _________  ________
 \_______  \____  _____|  |__   \_   ___ \ \_____  \
  |     ___/  _ \/  ___/  |  \  /    \  \/  /  ____/
  |    |  (  <_> )___ \|   Y  \ \     \____/       \
  |____|   \____/____  >___|  /  \______  /\_______ \
                     \/     \/          \/         \/
  ================= www.PoshC2.co.uk ================="""

echo ""
echo "[+] Updating PoshC2_Python"
echo ""

ROOTDIR=`dirname "$0"`
if [ ! -d "$ROOTDIR" ]; then
  ROOTDIR="/opt/PoshC2_Python/"
fi
pushd "$ROOTDIR" > /dev/null

# Backup config
echo "[+] Backup Config"
git stash > /dev/null

# Install requirements for PoshC2_Python
echo ""
echo "[+] Performing git pull on $ROOTDIR"
git pull

# Restore config
echo "[+] Restore Config"
git stash pop > /dev/null
echo ""
echo "[+] Update complete"
echo ""

popd > /dev/null
