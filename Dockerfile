# From the Kali Linux base image
FROM kalilinux/kali-rolling

# Update and apt install programs
RUN apt-get update && apt-get full-upgrade -y && apt-get autoremove -y
RUN apt-get install -y curl gnupg
RUN curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
RUN echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-stretch-prod stretch main" > /etc/apt/sources.list.d/dotnetdev.list
RUN apt-get update
RUN apt-get install -y git screen python3 python3-dev python3-pip build-essential mingw-w64-tools mingw-w64 mingw-w64-x86-64-dev mingw-w64-i686-dev mingw-w64-common espeak graphviz mono-complete apt-transport-https vim nano python2.7 libpq-dev sudo sqlite3 dotnet-runtime-2.2 dotnet-hostfxr-2.2 dotnet-host libssl1.1 libicu63

# Install PoshC2
ADD . /opt/PoshC2
RUN /opt/PoshC2/Install.sh

# Working directory
WORKDIR /opt/PoshC2