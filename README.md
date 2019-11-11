![PoshC2 Logo](https://raw.githubusercontent.com/nettitude/PoshC2/master/Files/PoshC2Logo.png)


PoshC2 is a proxy aware C2 framework used to aid penetration testers with red teaming, post-exploitation and lateral movement.

PoshC2 is primarily written in Python3 and follows a modular format to enable users to add their own modules and tools, allowing an extendible and flexible C2 framework. Out-of-the-box PoshC2 comes PowerShell/C# and Python3 implants with payloads written in PowerShell v2 and v4, C++ and C# source code, a variety of executables, DLLs and raw shellcode in addition to a Python3 payload. These enable C2 functionality on a wide range of devices and operating systems, including Windows, *nix and OSX.

Other notable features of PoshC2 include:

* Highly configurable payloads, including default beacon times, jitter, kill dates, user agents and more.
* A large number of payloads generated out-of-the-box which are frequently updated and maintained to bypass common Anti-Virus products.
* Auto-generated Apache Rewrite rules for use in a C2 proxy, protecting your C2 infrastructure and maintaining good operational security.
* A modular format allowing users to create or edit C#, PowerShell or Python3 modules which can be run in-memory by the Implants.
* Notifications on receiving a successful Implant, such as via text message or Pushover.
* A comprehensive and maintained contextual help and an intelligent prompt with contextual auto-completion, history and suggestions.
* Fully encrypted communications, protecting the confidentiality and integrity of the C2 traffic even when communicating over HTTP.
* Client/Server format allowing multiple team members to utilise a single C2 server.
* Extensive logging. Every action and response is timestamped and stored in a database with all relevant information such as user, host, implant number etc. In addition to this the C2 server output is directly logged to a separate file.

## Install
Automatic install for Python3 using curl & bash

```bash
curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2/master/Install.sh | bash
```

Manual install 

```bash
wget https://raw.githubusercontent.com/nettitude/PoshC2/master/Install.sh
chmod +x ./Install.sh
./Install.sh
```

## Using older versions

You can use an older version of PoshC2 by referencing the appropriate tag. You can list the tags for the repository by issuing:

### Linux Install Python2 - stable but unmaintained

Automatic install for Python2 using curl & bash

```bash
curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2/python2/Install.sh | bash
```
### Other tags

```bash
git tag --list
```
or viewing them online.

Then you can use the install one-liner but replace the branch name with the tag:

```bash
curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2/<tag name>/Install.sh | bash
```

For example:

```bash
curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2/v4.8/Install.sh | bash
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
