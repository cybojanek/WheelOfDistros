# Wheel of Distros

Quickly netboot various Linux distros from a Linux / OS X computer

# Requirements

* dnsmasq

* python

* isoinfo (CentOS on Linux)

# Supported Distros

* ArchLinux

* Debian

* CentOS

* Ubuntu

# Usage

1. Download specific distro

2. Configure interface serving dnsmasq to: 10.1.0.1

3. Serve up specific distro

4. Stop everything (for now universal, because cleanup is the same for everything)


```bash
# Help menu
./netboot.py --help
# Download an image
./netboot.py download debian squeeze amd64
# Configure an interface to have a 10.1.0.1 ip
sudo ifconfig eth0 10.1.0.1
# Serve it up, and optional internet as well
sudo ./netboot.py serve --interface eth0 --nat wlan0 debian squeeze amd64
# Stop everything
sudo ./netboot.py stop
```
