#!/usr/bin/env python
import argparse
import os
import subprocess
import tarfile
import urllib2


class LinuxDistro(object):
    """Abstracts a Linux Distribution
    Expects that fetch, unpack and pre_run will be subclassed

    """
    def __init__(self, release, architecture):
        """Create a new LinuxDistro object

        Arguments:
        release - release version
        architecture - cpu architecture

        """
        super(LinuxDistro, self).__init__()
        self.release = release
        self.architecture = architecture
        self.tftp_root = None

    def fetch(self):
        """Download resources from the web
        """
        raise NotImplementedError(type(self))

    def unpack(self):
        """Unpack downloaded resources
        """
        raise NotImplementedError(type(self))

    def pre_run(self):
        """Do anything else before running dnsmasq
        """
        raise NotImplementedError(type(self))


class Debian(LinuxDistro):
    """Debian Distribution"""

    RESOURCE_URL = "http://ftp.nl.debian.org/debian/dists/%s/main/installer-%s/current/images/netboot/netboot.tar.gz"
    RELEASES = {
        "squeeze": set(["amd64", "armel", "i386", "ia64", "kfreebsd-amd64",
                        "kfreebsd-i386", "mips", "mipsel", "powerpc", "s390",
                        "sparc"]),
        "wheezy": set(["amd64", "armel", "armhf", "i386", "ia64",
                       "kfreebsd-amd64", "kfreebsd-i386", "mips", "mipsel",
                       "powerpc", "s390", "s390x" "sparc"])
    }

    def __init__(self, *args):
        super(Debian, self).__init__(*args)
        # Check that its a valid release
        if self.release not in self.RELEASES:
            raise Exception("No such %s release: %s" % (type(self), self.release))
        # Check that the architecture is supported for that release
        if self.architecture not in self.RELEASES[self.release]:
            raise Exception("No architecture %s in release %s" % (
                self.architecture, self.release))
        # Set our tftp_root directory
        self.tftp_root = "%s/root/%s/%s" % (os.getcwd(), self.release,
                                            self.architecture)

    def fetch(self):
        # Make directory if it doesn't exist
        if not os.path.exists(self.tftp_root):
            os.makedirs(self.tftp_root)
        # TODO: check if file exists and checksum - if ok, then don't download
        # Download
        print "Downloading: %s" % self.RESOURCE_URL % (self.release, self.architecture)
        f = urllib2.urlopen(self.RESOURCE_URL % (self.release, self.architecture))
        with open("%s/netboot.tar.gz" % self.tftp_root, "wb") as destination:
            destination.write(f.read())

    def unpack(self):
        # Unpack the downloaded tar file
        print "Unpacking: %s/netboot.tar.gz" % self.tftp_root
        t = tarfile.open('%s/netboot.tar.gz' % self.tftp_root)
        t.extractall(self.tftp_root)

    def pre_run(self):
        # Nothing to do here - we just need dnsmasq
        pass


class Ubuntu(Debian):
    """Ubuntu Distribution"""

    RESOURCE_URL = "http://archive.ubuntu.com/ubuntu/dists/%s/main/installer-%s/current/images/netboot/netboot.tar.gz"
    
    # Ported architectures have a different download url
    RESOURCE_URL_PORTS = "http://ports.ubuntu.com/ubuntu-ports/dists/%s/main/installer-%s/current/images/netboot/netboot.tar.gz"
    ARCHITECTURE_PORTS = set(["powerpc", "powerpc64", "e500", "e500mc"])

    RELEASES = {
        "hardy": set(["amd64", "i386", "powerpc", "powerpc64"]),
        "lucid": set(["amd64", "i386", "powerpc", "powerpc64"]),
        "oneiric": set(["amd64", "i386", "powerpc", "powerpc64"]),
        "precise": set(["amd64", "i386", "powerpc", "powerpc64"]),
        "quantal": set(["amd64", "i386", "powerpc", "powerpc64"]),
        "raring": set(["amd64", "i386", "powerpc", "powerpc64", "e500", "e500mc"]),
        "saucy": set(["amd64", "i386", "powerpc", "powerpc64", "e500", "e500mc"])
    }

    def __init__(self, *args):
        super(Ubuntu, self).__init__(*args)
        # Change the url if we're a ported architecture
        if self.architecture in self.ARCHITECTURE_PORTS:
            self.RESOURCE_URL = self.RESOURCE_URL_PORTS


class DNSMasq(object):
    """docstring for DNSMasq"""
    def __init__(self, tftp_root, dhcp_boot, dhcp_range):
        super(DNSMasq, self).__init__()
        self.tftp_root = tftp_root
        self.dhcp_boot = dhcp_boot
        self.dhcp_range = dhcp_range

    def run(self):
        print "Running dnsmasq..."
        subprocess.call(["dnsmasq",
            "--pid-file=%s/dnsmasq.pid" % os.getcwd(),
            "--log-facility=%s/dnsmasq.log" % os.getcwd(),
            "--dhcp-leasefile=%s/dnsmasq.leases" % os.getcwd(),
            "--conf-file=/dev/null",
            "--enable-tftp", "--tftp-root=%s" % self.tftp_root,
            "--dhcp-range=%s" % self.dhcp_range,
            "--dhcp-boot=%s" % self.dhcp_boot])

DistroMapping = {"debian": Debian, "ubuntu": Ubuntu}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Install Linux over netboot")

    # Linux Distro
    parser.add_argument("--distro", required=True,
                        choices=DistroMapping.keys(),
                        help="Linux Distribution")
    # Distro release
    parser.add_argument("--release", required=True,
                        choices=Debian.RELEASES.keys() + Ubuntu.RELEASES.keys(),
                        help="Distribution version")
    # Architecture
    parser.add_argument("--architecture", required=True,
                        choices=set.union(*(Debian.RELEASES.values() + 
                                            Ubuntu.RELEASES.values())))
    # Wow...what just happned hereeeeeeee ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    # Download or serve
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--download", action='store_true', default=False,
                            help="Download and unpack files")
    mode_group.add_argument("--serve", action='store_true', default=False,
                            help="Serve up files to netboot")

    args = parser.parse_args()

    linux = DistroMapping[args.distro](args.release, args.architecture)
    if args.download:
        linux.fetch()
        linux.unpack()
    elif args.serve:
        linux.pre_run()
        dnsmasq = DNSMasq(linux.tftp_root, "pxelinux.0", "10.1.0.100,10.1.0.200,12h")
        dnsmasq.run()
