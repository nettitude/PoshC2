# Install PoshC2
Write-Host ""
Write-Host @'
   __________            .__.     _________  ________
   \_______  \____  _____|  |__   \_   ___ \ \_____  \\
    |     ___/  _ \/  ___/  |  \  /    \  \/  /  ____/
    |    |  ( <_>)___ \|   Y  \ \     \____/       \\
    |____|   \____/____  >___|  /  \______  /\_______ \\
                       \/     \/          \/         \/
    ================= www.PoshC2.co.uk ================
'@
Write-Host ""
Write-Host ""
Write-Host "[+] Installing PoshC2"
Write-Host ""

# Install PoshC2_Python
Write-Host ""
Write-Host "[+] Cloning PoshC2_Python into ~/PoshC2_Python"
git clone https://github.com/nettitude/PoshC2_Python $HOME/PoshC2_Python/

# Check if PIP is installed, if not install it
get-command pip >$null 2>$null
if($?)
{
    Write-Host "[+] Installing pip as it was not found"
	wget https://bootstrap.pypa.io/get-pip.py -outfile $env:temp\get-pip.py
	python $env:temp\get-pip.py
}

# Run pip with requirements file
Write-Host ""
Write-Host "[+] Installing requirements using pip"
Write-Host "[+] python -m pip install -r ~/PoshC2_Python/requirements.txt"
Write-Host ""
pip install --upgrade pip
python -m pip install -r $HOME/PoshC2_Python/requirements.txt

Write-Host ""
Write-Host "[+] Setup complete"
Write-Host ""
Write-Host @"
   __________            .__.     _________  ________
   \_______  \____  _____|  |__   \_   ___ \ \_____  \\
    |     ___/  _ \/  ___/  |  \  /    \  \/  /  ____/
    |    |  ( <_>)___ \|   Y  \ \     \____/       \\
    |____|   \____/____  >___|  /  \______  /\_______ \\
                       \/     \/          \/         \/
    ================= www.PoshC2.co.uk ================
"@
Write-Host ""
Write-Host "EDIT the config file: '~/PoshC2_Python/Config.py'"
Write-Host ""
Write-Host "python ~/PoshC2_Python/C2Server.py"
Write-Host "python ~/PoshC2_Python/ImplantHandler.py"
