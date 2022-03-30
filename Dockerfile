# From the Kali Linux base image
FROM kalilinux/kali-rolling

# Install PoshC2
ADD . /opt/PoshC2
RUN /opt/PoshC2/Install.sh 
ADD . /opt/PoshC2

# Working directory
WORKDIR /opt/PoshC2