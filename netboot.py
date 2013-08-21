#!/usr/bin/env python -u
import argparse
import os
import subprocess
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
    powers = [(2**40, "TB"), (2**30, "GB"), (2**20, "MB"), (2**10, "KB"), (1, "B")]
    p = filter(lambda x: bytes >= x[0], powers)[0]
    return s % (float(bytes) / p[0], p[1])


def download(url, output, checksum=None):
        """Download a URL from the web

        Arguments:
        url - url to download from
        output - output file

        Keyword Arguments:
        checksum - check downloaded file md5 againt this

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
        downloaded, last_read, rate = 0, 0, 0.0
        block_size = 65536
        start = time.time()
        print "Downloading: %s from: %s" % (pretty_bytes(size), url)
        destination = open(output, "wb")
        while True:
            buf = u.read(block_size)
            if not buf:
                break
            downloaded += len(buf)
            destination.write(buf)
            p = float(downloaded) / float(size)
            end = time.time()
            if end - start > 1.0:
                rate = (downloaded - last_read) / (end - start)
                last_read = downloaded
                start = end
            # TODO: fix whitespace on the right due to non-overwriting
            print "%s    %05.2f %%    %s/s     \r" % (file_name, p * 100.0, pretty_bytes(rate)),
        print ""
        destination.close()


class LinuxDistro(object):
    """Abstracts a Linux Distribution
    Expects that fetch, unpack, start, and stop will be subclassed

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

    def start(self):
        """Do anything else before running dnsmasq
        """
        raise NotImplementedError(type(self))

    def stop(self):
        """Do anything else after dnsmasq is stopped
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
        download(self.RESOURCE_URL % (self.release, self.architecture),
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
        # Nothin to do here - we just need dnsmasq
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

    def start(self):
        print "Running dnsmasq..."
        subprocess.call(["dnsmasq",
            "--pid-file=%s/dnsmasq.pid" % os.getcwd(),
            "--log-facility=%s/dnsmasq.log" % os.getcwd(),
            "--dhcp-leasefile=%s/dnsmasq.leases" % os.getcwd(),
            "--conf-file=/dev/null",
            "--enable-tftp", "--tftp-root=%s" % self.tftp_root,
            "--dhcp-range=%s" % self.dhcp_range,
            "--dhcp-boot=%s" % self.dhcp_boot])

    @staticmethod
    def stop():
        print "Stopping dnsmasq..."
        pid = open('%s/dnsmasq.pid' % os.getcwd()).read().rstrip()
        subprocess.call(["kill", pid])

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
    mode_group.add_argument("--stop", action='store_true', default=False,
                            help="Stop everything")

    args = parser.parse_args()

    linux = DistroMapping[args.distro](args.release, args.architecture)
    if args.download:
        linux.fetch()
        linux.unpack()
    elif args.serve:
        linux.start()
        dnsmasq = DNSMasq(linux.tftp_root, "pxelinux.0", "10.1.0.100,10.1.0.200,12h")
        dnsmasq.start()
    elif args.stop:
        DNSMasq.stop()
        linux.stop()
