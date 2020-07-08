![PoshC2 Logo](https://raw.githubusercontent.com/nettitude/PoshC2/master/resources/images/PoshC2Logo.png)

PoshC2 is a proxy aware C2 framework used to aid penetration testers with red teaming, post-exploitation and lateral movement.

PoshC2 is primarily written in Python3 and follows a modular format to enable users to add their own modules and tools, allowing an extendible and flexible C2 framework. Out-of-the-box PoshC2 comes PowerShell/C# and Python3 implants with payloads written in PowerShell v2 and v4, C++ and C# source code, a variety of executables, DLLs and raw shellcode in addition to a Python3 payload. These enable C2 functionality on a wide range of devices and operating systems, including Windows, *nix and OSX.

Other notable features of PoshC2 include:

* Consistent and Cross-Platform support using Docker.
* Highly configurable payloads, including default beacon times, jitter, kill dates, user agents and more.
* A large number of payloads generated out-of-the-box which are frequently updated and maintained to bypass common Anti-Virus products.
* Auto-generated Apache Rewrite rules for use in a C2 proxy, protecting your C2 infrastructure and maintaining good operational security.
* A modular format allowing users to create or edit C#, PowerShell or Python3 modules which can be run in-memory by the Implants.
* Notifications on receiving a successful Implant, such as via text message or Pushover.
* A comprehensive and maintained contextual help and an intelligent prompt with contextual auto-completion, history and suggestions.
* Fully encrypted communications, protecting the confidentiality and integrity of the C2 traffic even when communicating over HTTP.
* Client/Server format allowing multiple team members to utilise a single C2 server.
* Extensive logging. Every action and response is timestamped and stored in a database with all relevant information such as user, host, implant number etc. In addition to this the C2 server output is directly logged to a separate file.
* PowerShell-less implants that do not use System.Management.Automation.dll using C# or Python.
* A free and open-source SOCKS Proxy by integrating with SharpSocks

## Documentation

We maintain PoshC2 documentation over at https://poshc2.readthedocs.io/en/latest/

Find us on #Slack - [poshc2.slack.com](poshc2.slack.com) (to request an invite send an email to labs@nettitude.com)

## Install

You can install PoshC2 directly or use the Docker images, instructions for both are below.

### Direct install on Kali hosts

Python3 install script:

Elevated privileges are required as the install script performs `apt` updates and installations.

```bash
curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2/master/Install.sh | bash
```
You can manually set the PoshC2 installation directory by passing it as an argument to the Install.sh script, or by setting the `POSHC2_DIR` environment variable. The default is **/opt/PoshC2**:

```
curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2/master/Install.sh | bash -s "/root/PoshC2"
```

### Cutting Edge Features

We want to keep the `master` branch stable to ensure that users are able to rely on it when required and for this reason changes can often be feature-complete but not yet present on `master` as they have not been tested completely and signed-off yet.

If you want to look at upcoming features in PoshC2 you can check out the `dev` branch, or any individual feature branches branched off of `dev`.

As features **are** tested before they are merged into `dev` this branch should still be fairly stable and operators can opt in to using this branch or a particular feature branch for their engagement.
This does trade stablity for new features however so do it at your own discretion.

To use `dev` or a feature branch first clone the repository:

```
git clone https://github.com/nettitude/PoshC2 /opt/PoshC2
cd /opt/PoshC2
```

Then checkout the desired branch:

```
git checkout dev
```

Then run the Install script and continue as you would do normally.

```
./Install.sh
```

### Installing for Docker

You can also run PoshC2 using Docker, this allows more stable and running and enables PoshC2 to easily run on other operating systems.

To start with, install Docker on the host and then add the PoshC2 installation and project directories to the Docker as shared directories. By default on Kali these are **/opt/PoshC2** and **/opt/PoshC2_Project**.

#### Kali based hosts

Automatic PoshC2 install for Python3 using curl & bash

```bash
curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2/master/Install-for-Docker.sh | bash
```

Manual install:

```bash
wget https://raw.githubusercontent.com/nettitude/PoshC2/master/Install-for-Docker.sh
chmod +x ./Install-for-Docker.sh
./Install-for-Docker.sh
```

To use the `dev` or feature branches with docker curl down the `Install-for-Docker.sh` on the appropriate branch and pass the branch name as an argument:

```bash
curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2/BRANCHNAME/Install-for-Docker.sh | bash -s BRANCHNAME -
```


#### Other OSs

On other *nix flavours and MacOS, copy the posh-docker\* commands to your path.
On Windows, import the PoshC2.psm1 PowerShell module.

See the Docker section below on running PoshC2 using Docker.

## Running PoshC2

Instructions on configuring and running PoshC2 are printed at the bottom of the installation script or available at https://poshc2.readthedocs.io/en/latest/.

## Updating PoshC2 Installations

When using a git cloned version of PoshC2 you can update your PoshC2 installation using the following command:

```
posh-update
```

This command will reset the PoshC2 installation to the latest master branch.

## Using older versions

You can use an older version of PoshC2 by referencing the appropriate tag. Note this only works if you have cloned down the repository.
You can list the tags for the repository by issuing:

```bash
git tag --list
```

If you have a local clone of PoshC2 you can change the version that is in use while offline by just checking out the version you want to use:

```bash
git reset --hard <tag name>
```

For example:

```bash
git reset --hard v4.8
```

However note that this will overwrite any local changes to files, such as changes to the configuration files, and you may have to re-run the install script for that version or re-setup the environment appropriately.

## License / Terms of Use

This software should only be used for **authorised** testing activity and not for malicious use.

By downloading this software you are accepting the terms of use and the licensing agreement.