# PoshC2

PoshC2 is a proxy aware C2 framework that utilises Powershell **and/or** equivalent (System.Management.Automation.dll) to aid penetration testers with red teaming, post-exploitation and lateral movement. Powershell was chosen as the base implant language as it provides all of the functionality and rich features without needing to introduce multiple third party libraries to the framework.

In addition to the Powershell implant, PoshC2 also has a basic dropper written purely in Python that can be used for command and control over Unix based systems such as Mac OS or Ubuntu.

The server-side component is written in Python for cross-platform portability and speed, a Powershell server component still exists and can be installed using the 'Windows Install' as shown below but will not be maintained with future updates and releases.

## Linux Install

Install using curl & bash

```bash
curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2_Python/master/Install.sh | bash
```

Manual install

```bash
wget https://raw.githubusercontent.com/nettitude/PoshC2_Python/master/Install.sh
chmod +x ./Install.sh
./Install.sh
```

## Windows Install

Install Git and Python (and ensure Python is in the PATH), then run:

```bash
powershell -exec bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nettitude/PoshC2_Python/master/Install.ps1')"
```

## Running PoshC2

1. Edit the config file at **/opt/PoshC2_Python/Config.py** or run `posh-config` to open it in an editor.
2. Run the server using `posh-server` or `python2 -u C2Server.py | tee -a /var/log/poshc2_server.log`
3. Others can view the log using `posh-log` or `tail -n 5000 -f /var/log/poshc2_server.log`
4. Interact with the implants using the handler, run using `posh` or `python2 ImplantHandler.py`

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

### Python < 2.7.9 SSL Error

Remove this line for all python versions less that 2.7.9 when running a python implant only:

`ssl._create_default_https_context=ssl._create_unverified_context`

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