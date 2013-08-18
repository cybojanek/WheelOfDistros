# Wheel of Distros

Quickly netboot various Linux distros from a Linux / OS X computer

# Requirements

* dnsmasq

* wget

* sudo (to run dnsmasq and webserver)

* python (for ArchLinux)

# Supported Distros

* ArchLinux

* Ubuntu

* Debian

# Usage

Run the make command, and specify some required parameters

**Required**

* **DISTRO**
    - One of archlinux, ubuntu, debian

* **RELEASE**
    - For Ubuntu/Debian only: raring, wheezy etc..

**Optional**

* **NAT**
    - Enable IP forwarding and NATing and serve up internet to the machine

* **ARCHITECTURE**
    - Default amd64

* **DNSMASQ_ADD_OPTS**
    - Any additional options to pass to dnsmasq

* **other**
    - Look at *Makefile* for other parameters to override
