# PoshC2
PoshC2 is a proxy aware C2 framework written completely in PowerShell to aid penetration testers with red teaming, post-exploitation and lateral movement. The tools and modules were developed off the back of our successful PowerShell sessions and payload types for the Metasploit Framework. PowerShell was chosen as the base language as it provides all of the functionality and rich features required without needing to introduce multiple languages to the framework.

Windows Install (PoshC2):

```
powershell -exec bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nettitude/PoshC2/master/C2-Installer.ps1')"
```

Linux Install (PoshC2_Python):

```
curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2_Python/master/Install.sh | bash
```

# Documentation

We maintain PoshC2 documentation over at https://poshc2.readthedocs.io/en/latest/

Find us on #Slack - poshc2.slack.com

# Install

```
curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2_Python/master/Install.sh | bash
```