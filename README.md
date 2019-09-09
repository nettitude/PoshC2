# PoshC2
![PoshC2 Logo](https://raw.githubusercontent.com/nettitude/PoshC2_Python/master/Files/PoshC2Logo.png)
PoshC2 is a proxy aware C2 framework that utilises Powershell **and/or** equivalent (System.Management.Automation.dll) to aid penetration testers with red teaming, post-exploitation and lateral movement. Powershell was chosen as the base implant language as it provides all of the functionality and rich features without needing to introduce multiple third party libraries to the framework.

In addition to the Powershell implant, PoshC2 also has a basic dropper written purely in Python that can be used for command and control over Unix based systems such as Mac OS or Ubuntu.

The server-side component is written in Python for cross-platform portability and speed, a Powershell server component still exists and can be installed using the 'Windows Install' as shown below but will not be maintained with future updates and releases.

## Linux Install Python3
Automatic install for Python3 using curl & bash

```bash
curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2_Python/master/Install.sh | bash
```

Manual install Python3

```bash
wget https://raw.githubusercontent.com/nettitude/PoshC2_Python/master/Install.sh
chmod +x ./Install.sh
./Install.sh
```

## Linux Install Python2 - stable but unmaintained

Automatic install for Python2 using curl & bash

```bash
curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2_Python/python2/Install.sh | bash
```

Manual install Python2

```bash
wget https://raw.githubusercontent.com/nettitude/PoshC2_Python/python2/Install.sh
chmod +x ./Install.sh
./Install.sh
```

## Windows Install

Install Git and Python (and ensure Python is in the PATH), then run:

```bash
powershell -exec bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nettitude/PoshC2_Python/master/Install.ps1')"
```

## Using older versions

You can use an older version of PoshC2 by referencing the appropriate tag. You can list the tags for the repository by issuing:

```bash
git tag --list
```
or viewing them online.


Then you can use the install one-liner but replace the branch name with the tag:

```bash
curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2_Python/<tag name>/Install.sh | bash
```

For example:

```bash
curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2_Python/v4.8/Install.sh | bash
```

### Offline

If you have a local clone of PoshC2 you can change the version that is in use by just checking out the version you want to use:

```bash
git reset --hard <tag name>
```

For example:

```bash
git reset --hard v4.8
```

However note that this will overwrite any local changes to files, such as Config.py and you may have to re-run the install script for that version or re-setup the environment appropriately.

## Running PoshC2

1. Edit the config file by running `posh-config` to open it in $EDITOR. If this variable is not set then it defaults to vim, or you can use --nano to open it in nano.
2. Run the server using `posh-server` or `python3 -u C2Server.py | tee -a /var/log/poshc2_server.log`
3. Others can view the log using `posh-log` or `tail -n 5000 -f /var/log/poshc2_server.log`
4. Interact with the implants using the handler, run by using `posh` or `python3 ImplantHandler.py`

## Installing as a service

Installing as a service provides multiple benefits such as being able to log to service logs, viewing with journalctl and automatically starting on reboot.

1. Add the file in systemd (this is automatically done via the install script)

```bash
cp poshc2.service /lib/systemd/system/poshc2.service
```

2. Start the service

```bash
posh-service
```

3. View the log:

```
posh-log
```

4. Or alternatively us journalctl (but note this can be rate limited)

```bash
journalctl -n 20000 -u poshc2.service -f --output cat
```

Note that re-running `posh-service` will restart the posh-service.
Running `posh-service` will automatically start to display the log, but Ctrl-C will not stop the service only quit the log in this case
`posh-log` can be used to re-view the log at any point.
`posh-stop-service` can be used to stop the service.

## Issues / FAQs

If you are experiencing any issues during the installation or use of PoshC2 please check the known issues below and the open issues tracking page within GitHub. If this page doesn't have what you're looking for please open a new issue and we will try to resolve the issue asap.

If you are looking for tips and tricks on PoshC2 usage and optimisation, you are welcome to join the slack channel below.

## License / Terms of Use

This software should only be used for **authorised** testing activity and not for malicious use.

By downloading this software you are accepting the terms of use and the licensing agreement.

## Documentation

We maintain PoshC2 documentation over at https://poshc2.readthedocs.io/en/latest/

Find us on #Slack - [poshc2.slack.com](poshc2.slack.com) (to request an invite send an email to labs@nettitude.com)

## Known issues

### Error encrypting value: object type

If you get this error after installing PoshC2 it is due to dependency clashes in the pip packages on the system.

Try creating a virtualenv in python and re-install the requirements so that the exact versions specified are in use for PoshC2. Make sure you deactivate when you've finished in this virtualenv.

For example:

```bash
pip install virtualenv
virtualenv /opt/PoshC2_Python/
source /opt/PoshC2_Python/bin/activate
pip install -r requirements.txt
python C2Server.py
```

Note anytime you run PoshC2 you have to reactivate the virtual environment and run it in that.

The use of a virtual environment is abstracted if you use the `posh-` scripts on *nix.
