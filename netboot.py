#!/usr/bin/env python -u
import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tarfile
import time
import urllib2


def pretty_bytes(bytes, precision=2):
    """Nicely format an amount of bytes to use units

    Arguments:
    bytes - number of bytes
    precision - number of decimal points

    Return:
    string of the format: "1.67 MB"

    """
    s = "%%.%sf %%s" % precision
    if bytes == 0:
        return s % (bytes, "B")
    powers = [(2**40, "TB"), (2**30, "GB"), (2**20, "MB"), (2**10, "KB"),
              (1, "B")]
    p = filter(lambda x: bytes >= x[0], powers)[0]
    return s % (float(bytes) / p[0], p[1])


def checksum_file(f):
    """Return the sha256 digest of the file

    Arguments:
    f - file path

    Return:
    sha256 hext digest string

    """
    print "Validating checksum of: %s" % f
    file_name = os.path.basename(f)
    size = os.path.getsize(f)
    sha = hashlib.sha256()
    block_size = 65536
    input_file = open(f, "rb")
    checked, last_read, rate, time_left = 0, 0, 0.0, 0
    start = time.time()
    while True:
        buf = input_file.read(block_size)
        if not buf:
            break
        checked += len(buf)
        sha.update(buf)
        p = float(checked) / float(size)
        end = time.time()
        if end - start > 0.5:
            rate = (checked - last_read) / (end - start)
            last_read = checked
            start = end
            time_left = int((size - checked) / rate)
        # TODO: fix whitespace on the right due to non-overwriting
        print "%s    %05.2f %%    %02.0f:%02.0f:%02.0f    %s/s     \r" % (
            file_name, p * 100.0, time_left / 3600, time_left / 60,
            time_left % 60, pretty_bytes(rate)),
    print ""
    return sha.hexdigest()


def download_file(url, output, checksum=None):
        """Download a URL from the web

        Arguments:
        url - url to download from
        output - output file

        Keyword Arguments:
        checksum - check downloaded file sha256 againt this

        """
        # Make directory if it doesn't exist
        directory = os.path.dirname(output)
        if not os.path.exists(directory):
            os.makedirs(directory)
        # TODO: check if file exists and checksum - if ok, then don't download
        # Download
        file_name = url.split('/')[-1]
        u = urllib2.urlopen(url)
        size = int(u.info().getheaders("Content-Length")[0])
        downloaded, last_read, rate, time_left = 0, 0, 0.0, 0
        block_size = 65536
        start = time.time()
        print "Downloading: %s from: %s" % (pretty_bytes(size), url)
        print "Saving to: %s" % output
        if os.path.isfile(output) and os.path.getsize(output) == size:
            if checksum is None:
                print "File size matches. Skipping download."
                return
            else:
                print "File size matches. Skipping download."
                if checksum_file(output) != checksum:
                    print "Checksum doesn't match redownloading..."
                else:
                    print "Checksum validates. Skipping download."
                    return
        destination = open(output, "wb")
        while True:
            buf = u.read(block_size)
            if not buf:
                break
            downloaded += len(buf)
            destination.write(buf)
            p = float(downloaded) / float(size)
            end = time.time()
            if end - start > 0.5:
                rate = (downloaded - last_read) / (end - start)
                last_read = downloaded
                start = end
                time_left = int((size - downloaded) / rate)
            # TODO: fix whitespace on the right due to non-overwriting
            print "%s    %05.2f %%    %02.0f:%02.0f:%02.0f    %s/s     \r" % (
                file_name, p * 100.0, time_left / 3600, time_left / 60,
                time_left % 60, pretty_bytes(rate)),
        print ""
        destination.close()
        if checksum and checksum_file(output) != checksum:
            raise Exception("Checksum didn't validate")


class LinuxDistro(object):
    """Abstracts a Linux Distribution
    Expects that fetch, unpack, start, and stop will be subclassed
    and that self.tftp_root will be defined

    """
    def __init__(self):
        """Create a new LinuxDistro object
        """
        super(LinuxDistro, self).__init__()
        self.tftp_root = None

    def fetch(self):
        """Download resources from the web
        """
        raise NotImplementedError(type(self))

    def unpack(self):
        """Unpack downloaded resources
        """
        raise NotImplementedError(type(self))

    def start(self):
        """Do anything else before running dnsmasq
        """
        raise NotImplementedError(type(self))

    def stop(self):
        """Do anything else after dnsmasq is stopped
        """
        raise NotImplementedError(type(self))


class ArchLinux(LinuxDistro):
    """docstring for ArchLinux"""
    def __init__(self):
        super(ArchLinux, self).__init__()
        self.tftp_root = "%s/root/archlinux/" % (os.getcwd())
        self.dhcp_boot = "ipxe.pxe"

    def fetch(self):
        download_file("https://releng.archlinux.org/pxeboot/ipxe.pxe",
                      "%s/ipxe.pxe" % self.tftp_root)

    def unpack(self):
        # Nothing to do here - we just need dnsmasq
        pass

    def start(self):
        # Nothing to do here - we just need dnsmasq
        pass

    def stop(self):
        # Nothing to do here - we just need dnsmasq
        pass


class CentOS(LinuxDistro):
    """docstring for CentOS"""

    RESOURCE_URL = "http://mirrors.gigenet.com/centos/%s/isos/%s/" \
                   "CentOS-%s-%s-netinstall.iso"
    RELEASES = {
        "5.9": set(["i386", "x86_64"]),
        "6.4": set(["i386", "x86_64"])
    }

    def __init__(self, release, architecture):
        super(CentOS, self).__init__()
        self.release = release
        self.architecture = architecture
        # Check that its a valid release
        if self.release not in self.RELEASES:
            raise Exception("No such %s release: %s" % (type(self),
                                                        self.release))
        # Check that the architecture is supported for that release
        if self.architecture not in self.RELEASES[self.release]:
            raise Exception("No architecture %s in release %s" % (
                self.architecture, self.release))
        self.tftp_root = "%s/root/centos/%s/%s" % (os.getcwd(), self.release,
                                                   self.architecture)
        self.dhcp_boot = "pxelinux.0"

    def fetch(self):
        download_file(self.RESOURCE_URL % (self.release, self.architecture,
                      self.release, self.architecture),
                      "%s/netinstall.iso" % self.tftp_root)

    def unpack(self):
        iso = "%s/netinstall.iso" % self.tftp_root
        print "Extracting pxeboot from: %s" % iso
        if sys.platform == "darwin":
            directory = "%s/iso" % self.tftp_root
            if not os.path.exists(directory):
                os.makedirs(directory)
            subprocess.call(["hdiutil", "attach", iso, "-mountpoint",
                            directory], stdout=subprocess.PIPE)
            shutil.copy("%s/images/pxeboot/vmlinuz" % directory,
                        self.tftp_root)
            shutil.copy("%s/images/pxeboot/initrd.img" % directory,
                        self.tftp_root)
            subprocess.call(["hdiutil", "detach", directory],
                            stdout=subprocess.PIPE)
        elif sys.platform == "linux":
            with open("%s/vmlinuz" % self.tftp_root, "wb") as output:
                subprocess.call(["isoinfo", "-J", "-i", iso, "-x",
                                "/images/pxeboot/vmlinuz"], stdout=output)
            with open("%s/initrd.img" % self.tftp_root, "wb") as output:
                subprocess.call(["isoinfo", "-J", "-i", iso, "-x",
                                "/images/pxeboot/initrd.img"], stdout=output)
        # Copy syslinux files
        for x in ["pxelinux.0", "menu.c32", "ldlinux.c32", "libutil.c32"]:
            print "Copying syslinux file: %s" % x
            shutil.copy("syslinux/%s" % x, self.tftp_root)

        # Write out the menu
        directory = "%s/pxelinux.cfg" % self.tftp_root
        if not os.path.exists(directory):
            os.makedirs(directory)

        kernel_string = """
timeout 100
default menu.c32

menu title CentOS
label 1
    menu label ^1) Install CentOS
    kernel vmlinuz method=http://mirror.centos.org/centos/6/os/%s/
    append initrd=initrd.img devfs=nomount
                """ % self.architecture

        print "Writing default kernel boot: %s" % kernel_string
        with open('%s/default' % directory, 'w') as output:
            output.write(kernel_string)

    def start(self):
        # Nothing to do here - we just need dnsmasq
        pass

    def stop(self):
        # Nothing to do here - we just need dnsmasq
        pass


class Debian(LinuxDistro):
    """Debian Distribution"""

    RESOURCE_URL = "http://ftp.nl.debian.org/debian/dists/%s/main/" \
                   "installer-%s/current/images/netboot/netboot.tar.gz"

    RELEASES = {
        "squeeze": set(["amd64", "i386", "ia64", "kfreebsd-amd64",
                        "kfreebsd-i386"]),
        "wheezy": set(["amd64", "i386", "ia64", "kfreebsd-amd64",
                       "kfreebsd-i386"])
    }

    def __init__(self, release, architecture):
        """Debian

        Arguments:
        release - release version
        architecture - cpu architecture

        """
        super(Debian, self).__init__()
        self.release = release
        self.architecture = architecture
        # Check that its a valid release
        if self.release not in self.RELEASES:
            raise Exception("No such %s release: %s" % (
                type(self), self.release))
        # Check that the architecture is supported for that release
        if self.architecture not in self.RELEASES[self.release]:
            raise Exception("No architecture %s in release %s" % (
                self.architecture, self.release))
        # Set our tftp_root directory
        self.tftp_root = "%s/root/debian/%s/%s" % (os.getcwd(), self.release,
                                                   self.architecture)
        self.dhcp_boot = "pxelinux.0"

    def fetch(self):
        download_file(self.RESOURCE_URL % (self.release, self.architecture),
                      "%s/netboot.tar.gz" % self.tftp_root)

    def unpack(self):
        # Unpack the downloaded tar file
        print "Unpacking: %s/netboot.tar.gz" % self.tftp_root
        t = tarfile.open('%s/netboot.tar.gz' % self.tftp_root)
        t.extractall(self.tftp_root)

    def start(self):
        # Nothing to do here - we just need dnsmasq
        pass

    def stop(self):
        # Nothing to do here - we just need dnsmasq
        pass


class Ubuntu(Debian):
    """Ubuntu Distribution"""

    RESOURCE_URL = "http://archive.ubuntu.com/ubuntu/dists/%s/main/" \
                   "installer-%s/current/images/netboot/netboot.tar.gz"

    RELEASES = {
        "hardy": set(["amd64", "i386"]),
        "lucid": set(["amd64", "i386"]),
        "oneiric": set(["amd64", "i386"]),
        "precise": set(["amd64", "i386"]),
        "quantal": set(["amd64", "i386"]),
        "raring": set(["amd64", "i386"]),
        "saucy": set(["amd64", "i386"])
    }

    def __init__(self, *args):
        super(Ubuntu, self).__init__(*args)
        self.tftp_root = "%s/root/ubuntu/%s/%s" % (os.getcwd(), self.release,
                                                   self.architecture)


class DNSMasq(object):
    """docstring for DNSMasq"""
    def __init__(self, tftp_root, dhcp_boot, dhcp_range, interface=None):
        super(DNSMasq, self).__init__()
        self.tftp_root = tftp_root
        self.dhcp_boot = dhcp_boot
        self.dhcp_range = dhcp_range
        self.interface = interface

    def start(self):
        print "Running dnsmasq..."
        args = ["dnsmasq",
                "--pid-file=%s/dnsmasq.pid" % os.getcwd(),
                "--log-facility=%s/dnsmasq.log" % os.getcwd(),
                "--dhcp-leasefile=%s/dnsmasq.leases" % os.getcwd(),
                "--conf-file=/dev/null",
                "--enable-tftp", "--tftp-root=%s" % self.tftp_root,
                "--dhcp-range=%s" % self.dhcp_range,
                "--dhcp-boot=%s" % self.dhcp_boot]
        if self.interface is not None:
            args = args + ["--interface=%s" % self.interface]
        subprocess.call(args)

    @staticmethod
    def stop():
        print "Stopping dnsmasq..."
        pid = open('%s/dnsmasq.pid' % os.getcwd()).read().rstrip()
        subprocess.call(["kill", pid])


class NAT(object):
    """docstring for NAT"""
    def __init__(self, interface):
        super(NAT, self).__init__()
        self.interface = interface

    def start(self):
        if sys.platform == 'darwin':
            subprocess.call(["sysctl", "-w", "net.inet.ip.forwarding=1"])
            p = subprocess.Popen(["ifconfig", self.interface],
                                 stdout=subprocess.PIPE)
            out, err = p.communicate()
            if p.returncode != 0:
                raise Exception("Failed to get ip for NAT device: %s"
                                "" % self.interface)
            ip = filter(lambda x: x.lstrip().rstrip().startswith('inet '),
                        out.split('\n'))[0].split()[1]
            subprocess.call(["/usr/sbin/natd", "-alias_address", ip,
                             "-interface", self.interface, "-use_sockets",
                             "-same_ports", "-unregistered_only", "-dynamic",
                             "-clamp_mss"])
            subprocess.call(["ipfw", "add", "divert", "natd", "ip", "from",
                             "any", "to", "any", "via", self.interface])
        elif sys.platform == 'linux':
            subprocess.call(["sysctl", "-w", "net.ipv4.ip_forward=1"])
            subprocess.call(["iptables", "-t", "nat", "-A", "POSTROUTING",
                             "-o", self.interface, "-j", "MASQUERADE"])

    @staticmethod
    def stop():
        if sys.platform == 'darwin':
            subprocess.call(["sysctl", "-w", "net.inet.ip.forwarding=0"])
            subprocess.call(["killall", "-9", "natd"])
            subprocess.call(["ipfw", "-f", "flush"])
        elif sys.platform == 'linux':
            subprocess.call(["sysctl", "-w", "net.ipv4.ip_forward=0"])
            # TODO: change this to remove
            # subprocess.call(["iptables", "-t", "nat", "-A", "POSTROUTING",
                             # "-o", self.interface, "-j", "MASQUERADE"])


DistroMapping = {"archlinux": ArchLinux, "centos": CentOS, "debian": Debian,
                 "ubuntu": Ubuntu}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Install Linux over netboot")

    subcommands = parser.add_subparsers(help="Commands")

    ###########################################################################
    ################################# Download ################################
    ###########################################################################
    download = subcommands.add_parser("download")
    download.set_defaults(command="download")
    distros = download.add_subparsers(help="Distros")

    ################### ArchLinux ###################
    archlinux = distros.add_parser("archlinux")
    archlinux.set_defaults(distro="archlinux")
    ################### CentOS ###################
    # Distro release
    centos = distros.add_parser("centos")
    centos.add_argument("release",
                        choices=CentOS.RELEASES.keys(),
                        help="Distribution version")
    # Architecture
    centos.add_argument("architecture",
                        choices=set.union(*(CentOS.RELEASES.values())))
    centos.set_defaults(distro="centos")
    ################### Debian ###################
    # Distro release
    debian = distros.add_parser("debian")
    debian.add_argument("release",
                        choices=Debian.RELEASES.keys(),
                        help="Distribution version")
    # Architecture
    debian.add_argument("architecture",
                        choices=set.union(*(Debian.RELEASES.values())))
    debian.set_defaults(distro="debian")

    ################### Ubuntu ###################
    # Distro release
    ubuntu = distros.add_parser("ubuntu")
    ubuntu.add_argument("release",
                        choices=Ubuntu.RELEASES.keys(),
                        help="Distribution version")
    # Architecture
    ubuntu.add_argument("architecture",
                        choices=set.union(*(Ubuntu.RELEASES.values())))
    ubuntu.set_defaults(distro="ubuntu")

    ###########################################################################
    ################################### Serve #################################
    ###########################################################################
    serve = subcommands.add_parser("serve")
    serve.set_defaults(command="serve")

    # dnsmasq interface
    serve.add_argument("--interface", required=False,
                       help="Interface to serve dhcp and tftp")
    # NAT interface
    serve.add_argument("--nat", required=False, help="Interface for NAT")

    distros = serve.add_subparsers(help="Distros")

    ################### ArchLinux ###################
    archlinux = distros.add_parser("archlinux")
    archlinux.set_defaults(distro="archlinux")
    ################### CentOS ###################
    # Distro release
    centos = distros.add_parser("centos")
    centos.add_argument("release",
                        choices=CentOS.RELEASES.keys(),
                        help="Distribution version")
    # Architecture
    centos.add_argument("architecture",
                        choices=set.union(*(CentOS.RELEASES.values())))
    centos.set_defaults(distro="centos")
    ################### Debian ###################
    # Distro release
    debian = distros.add_parser("debian")
    debian.add_argument("release",
                        choices=Debian.RELEASES.keys(),
                        help="Distribution version")
    # Architecture
    debian.add_argument("architecture",
                        choices=set.union(*(Debian.RELEASES.values())))
    debian.set_defaults(distro="debian")

    ################### Ubuntu ###################
    # Distro release
    ubuntu = distros.add_parser("ubuntu")
    ubuntu.add_argument("release",
                        choices=Ubuntu.RELEASES.keys(),
                        help="Distribution version")
    # Architecture
    ubuntu.add_argument("architecture",
                        choices=set.union(*(Ubuntu.RELEASES.values())))
    ubuntu.set_defaults(distro="ubuntu")

    ###########################################################################
    ################################### Stop ##################################
    ###########################################################################
    stop = subcommands.add_parser("stop")
    stop.set_defaults(command="stop", distro=None)

    args = parser.parse_args()

    # Check for root
    if args.command in ("serve", "stop") and os.getuid() != 0:
        print "Need root priveleges to serve/stop"
        sys.exit(1)

    if args.distro == 'archlinux':
        linux = DistroMapping[args.distro]()
    elif args.distro in ('centos', 'debian', 'ubuntu'):
        linux = DistroMapping[args.distro](args.release, args.architecture)

    if args.command == "download":
        linux.fetch()
        linux.unpack()
    elif args.command == "serve":
        if args.nat is not None:
            nat = NAT(args.nat)
            nat.start()
        linux.start()
        dnsmasq = DNSMasq(linux.tftp_root, linux.dhcp_boot,
                          "10.1.0.100,10.1.0.200,12h",
                          interface=args.interface)
        dnsmasq.start()
    elif args.command == "stop":
        DNSMasq.stop()
        NAT.stop()
