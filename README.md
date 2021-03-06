# Wheel of Distros

Quickly netboot various Linux distros from Linux / OS X

# Requirements

* dnsmasq

* python

* nfsd (for live cd)

* isoinfo (cdrtools package, for live cds)

# Supported Distros

| Distro           | Netboot Install | Live CD |
| ---------------- | --------------: | ------: |
| ArchLinux        |               x |         |
| Centos           |               x |         |
| Debian           |               x |         |
| ElementaryOS     |                 |       x |
| Fedora           |               x |         |
| FreeBSD          |                 |         |
| Linux Mint       |                 |       x |
| OpenSUSE         |               x |         |
| System Rescue CD |                 |       x |
| Ubuntu           |               x |       x |


Tested:
OSX
===
ArchLinux i386
Centos i386: (5.10, 6.5)
Debian i386: (squeeze, wheezy, jessie)
Elementary OS (i386)
Fedora i386: (18, 19, 20)
FreeBSD i386: (almost - but r/o errors but mac extraction uppercase)
Linux Mint Cinnamon i386: (13, 14, 15, 16, 17)
Linux Mint Mate i386: (13, 14, 15, 16, 17)
OpenSUSE i386: (13.1)
SystemRescueCD: (3.7.1, 4.2.0)
Ubuntu: (lucid, precise, quantal, raring, saucy, trusty)
# Mount doesnt work....use iso extract method?
UbuntuLive: ()

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
sudo ifconfig eth0 10.1.0.1/24
# Serve it up, and optional internet as well
sudo ./netboot.py serve --interface eth0 --nat wlan0 debian squeeze amd64
# Stop everything
sudo ./netboot.py stop
```

# Warnings

* When using the **NAT** feature, the program assumes nothing else is happening with networking, and upon stopping will flush ipfw/iptables, killall natd, stop ipv4 fowarding, and stop nfsd. If you were using that for something else, re-enable it, or undo the changes manually.

* When using LiveCDs, nfs exports will be updated. After calling the stop, all lines with "WheelOfDistros" will be removed from /etc/exports, by reading all the lines and then writing them back...there's a small chance that if python crashes while writing back, that some of the exports will be lost...so if you value that, then make a backup of /etc/exports

# FAQ

* I get errors while trying to download on OS X

	- You might need to flush DNS:

```bash
sudo killall -HUP mDNSResponder
```

* Pxeboot gets stuck at tftp or dhcp

	- Sometimes, you just need to restart dhcp on your server, and reboot the machine you're trying to pxeboot

* The serve command keeps failing

	- Did you set the ip for the interfaces you're trying to use?

	- On OS X if using direct ethernet, dnsmasq might not be able to start until the link is up (possible up until the point when the computer is trying to pxe boot). Just keep trying to run the serve command

