# Wheel of Distros

Quickly netboot various Linux distros from a Linux / OS X computer

# Requirements

* dnsmasq

* python

* isoinfo (cdrtools package) (Centos)

# Supported Distros

* ArchLinux

* Debian

* CentOS

* OpenSUSE

* Ubuntu

# Warnings

* When using the **NAT** feature, the program assumes nothing else is happening with networking, and upon stopping will flush ipfw/iptables, killall natd and stop ipv4 fowarding. If you were using that for something else, re-enable it, or undo the changes manually.

* On OS X if using ethernet, dnsmasq might not be able to start until the link is up (possible up until the point when the computer is trying to pxe boot). Just keep trying to run the serve command

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
