# Wheel of Distros

Quickly netboot various Linux distros from a Linux / OS X computer

# Requirements

* dnsmasq

* python

* isoinfo (cdrtools package, for live cds)

# Supported Distros

| Distro     | Netboot Install | Live CD |
| ---------- | --------------: | ------: |
| ArchLinux  |             Yes |      No |
| Centos     |             Yes |      No |
| Debian     |             Yes |      No |
| Fedora     |             Yes |      No |
| Linux Mint |              No |     Yes |
| OpenSUSE   |             Yes |      No |
| Ubuntu     |             Yes |     Yes |

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
