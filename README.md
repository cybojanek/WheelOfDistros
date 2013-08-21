# Wheel of Distros

Quickly netboot various Linux distros from a Linux / OS X computer

# Requirements

* dnsmasq

* python

* isoinfo (CentOS on Linux)

# Supported Distros

* ArchLinux

* Debian

* Ubuntu

# Usage

```
# Help menu
./netboot.py --help
# Download an image
./netboot.py download debian squeeze amd64
# Serve it up, and optional internet as well
sudo ./netboot.py serve --nat en0 debian squeeze amd64
# Stop everything
sudo ./netboot.py stop
```
