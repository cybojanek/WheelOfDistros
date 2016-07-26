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


def colorize(string, color):
    """Use ANSI escape codes to colorize a string

    Arguments:
    string - string to colorize
    color - one of colorize.colors

    """
    colors = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'purple': '\033[95m',
        'white': '\033[97m',

    }
    if not sys.stdout.isatty():
        return string
    return '%s%s%s' % (colors[color], string, '\033[0m')


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
    powers = [(2**40, "TiB"), (2**30, "GiB"), (2**20, "MiB"), (2**10, "KiB"),
              (1, "B")]
    p = filter(lambda x: bytes >= x[0], powers)[0]
    return s % (float(bytes) / p[0], p[1])


def checksum_file(f, checksum_type="sha256"):
    """Return the hash digest of the file

    Arguments:
    f - file path

    Keyword Arguments:
    checksum_type - one of md5, sha1, sha224, sha256, sha384, sha512

    Return:
    sha256 hext digest string

    """
    hashes = {"md5": hashlib.md5, "sha1": hashlib.sha1,
              "sha224": hashlib.sha224, "sha256": hashlib.sha256,
              "sha384": hashlib.sha384, "sha512": hashlib.sha512}

    if checksum_type not in hashes:
        raise Exception("Unsupported hash type: %s" % checksum_type)

    print "%s %s" % (colorize("Checksuming:", "blue"), f)
    file_name = os.path.basename(f)
    size = os.path.getsize(f)
    h = hashes[checksum_type]()
    block_size = 262144
    input_file = open(f, "rb")
    checked, last_read, rate, time_left = 0, 0, 0.0, 0
    start = time.time()
    while True:
        buf = input_file.read(block_size)
        if not buf:
            break
        checked += len(buf)
        h.update(buf)
        p = float(checked) / float(size)
        end = time.time()
        if end - start > 0.5:
            rate = (checked - last_read) / (end - start)
            last_read = checked
            start = end
            time_left = int((size - checked) / rate)
        # TODO: fix whitespace on the right due to non-overwriting
        print "%s    %05.2f %%    %02.0f:%02.0f:%02.0f    %s/s     \r" % (
            file_name, p * 100.0, time_left / 3600, time_left / 60 % 60,
            time_left % 60, pretty_bytes(rate)),
    print ""
    return h.hexdigest()


def download_file(url, output, checksum=None, checksum_type="sha256"):
        """Download a URL from the web. Makes desintation directory.
        If file already exists and checksum given, then checks contents
        against checksum. If doesn't match, then tries to resume download,
        and checks checksum at the end.

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
        # Check if file already there
        if checksum and os.path.exists(output):
            if checksum_file(output, checksum_type) == checksum:
                print colorize("Checksum validates", "green")
                return
            else:
                print colorize("Checksum mismatch", "yellow")
        # Download
        file_name = url.split('/')[-1]
        req = urllib2.Request(url)
        u = urllib2.urlopen(req)
        size = int(u.info().getheaders("Content-Length")[0])
        downloaded, last_read, rate, time_left = 0, 0, 0.0, 0
        block_size = 262144
        start = time.time()
        print "%s %s from: %s to %s" % (
            colorize("Downloading:", "blue"),
            colorize(pretty_bytes(size), "green"), url, output)
        if checksum is None:
            print colorize("WARNING: No checksum for download", "red")
        if os.path.isfile(output) and os.path.getsize(output) == size:
            print colorize("File size matches. Skipping download.", "yellow")
            if checksum is None:
                return
            else:
                cf = checksum_file(output, checksum_type=checksum_type)
                if cf != checksum:
                    print colorize("Checksum doesn't match redownloading...",
                                   "yellow")
                    destination = open(output, "wb")
                else:
                    print colorize("Checksum validates. Skipping re-download.",
                                   "yellow")
                    return
        elif os.path.isfile(output) and os.path.getsize(output) < size:
            print colorize("Trying to continue partial download...", "yellow")
            downloaded = os.path.getsize(output)
            last_read = downloaded
            req.headers["Range"] = "bytes=%s-%s" % (downloaded, size - 1)
            u = urllib2.urlopen(req)
            destination = open(output, "ab")
        else:
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
                file_name, p * 100.0, time_left / 3600, time_left / 60 % 60,
                time_left % 60, pretty_bytes(rate)),
        print ""
        destination.close()
        if checksum is not None:
            cf = checksum_file(output, checksum_type=checksum_type)
            if cf != checksum:
                print colorize("Checksum didn't validate: %s != %s"
                               "" % (checksum, cf), "red")
                sys.exit(1)
            else:
                print colorize("Checksum validates", "green")


def extract_iso(iso, destination, temp_dir_mount=False):
    print "%s %s" % (colorize("Extracting:", "blue"), iso)

    if temp_dir_mount:
        temp = tempfile.mkdtemp()
        mount_iso(iso, temp)
        if os.path.exists(destination):
            shutil.rmtree(destination)
        p = subprocess.Popen(["cp", "-R", temp, destination])
        o, e = p.communicate()
        unmount_iso(temp)
        shutil.rmtree(temp)
        return

    if not os.path.exists(destination):
            os.makedirs(destination)


    # Get a list of all the directories
    p = subprocess.Popen(["isoinfo", "-J", "-l", "-i", iso],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    o, e = p.communicate()
    if p.returncode != 0:
        raise Exception("Exctraction listing failed: %s", e)
    last_dir = "/"
    for line in o.split('\n'):
        line = line.rstrip().lstrip()
        if line.startswith("Directory listing of "):
            # Create a new directory
            last_dir = line[len("Directory listing of "):]
            directory = "%s/%s" % (destination, last_dir)
            if not os.path.exists(directory):
                os.makedirs(directory)
        elif line.startswith('d'):
            # Its a nested directory - itll be taken care of later
            pass
        elif len(line) > 0:
            f = "%s%s" % (last_dir, line[line.find("]") + 2:])
            with open("%s/%s" % (destination, f), "w") as output:
                subprocess.call(["isoinfo", "-J", "-i", iso, "-x", f],
                                stdout=output)


def mount_iso(iso, destination):
    if not os.path.isdir(destination):
        os.makedirs(destination)
    p = subprocess.Popen(["hdiutil", "mount", "-mountpoint", destination, iso],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    o, e = p.communicate()
    if p.returncode != 0:
        raise Exception("Mounting iso failed: %s", e)


def unmount_iso(destination):
    p = subprocess.Popen(["umount", destination], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    o, e = p.communicate()
    if p.returncode != 0:
        raise Exception("Unmounting iso failed: %s", e)


class Distro(object):
    """Abstracts a Distribution
    Expects that fetch, unpack, start, and stop will be subclassed

    dhcp_boot default is pxelinux.0

    """
    def __init__(self, tftp_prefix):
        """Create a new Distro object

        Arguments:
        tftp_prefix - tftp_root directory name in cwd/root

        """
        super(Distro, self).__init__()
        self.tftp_root = "%s/root/%s" % (os.getcwd(), tftp_prefix)
        self.dhcp_boot = "pxelinux.0"
        self.dhcp_option = None

    def fetch(self):
        """Download resources from the web
        """
        pass

    def unpack(self):
        """Unpack downloaded resources
        """
        pass

    def start(self):
        """Do anything else before running dnsmasq
        """
        pass

    def stop(self):
        """Do anything else after dnsmasq is stopped
        """
        pass

    @classmethod
    def versions(cls):
        """Returns a list of possible versions
        """
        return []


class RelArchDistro(Distro):
    """Abstracts a Linux Distribution that has a release and architecture
    Checks that release and architecture are in self.RELEASES

    Expects all subclasses to implement the rest of Distro

    """

    RELEASES = {}

    def __init__(self, tftp_prefix, release, architecture):
        """Create a new RelArchDistro and check self.RELEASES

        Arguments:
        tftp_prefix - tftp_prefix to pass to Distro
        release - distribution version
        architecture - machine architecture

        """
        super(RelArchDistro, self).__init__(tftp_prefix)
        self.tftp_root = "%s/%s/%s" % (self.tftp_root, release, architecture)
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

    @classmethod
    def versions(cls):
        vs = []
        for version in sorted(cls.RELEASES.keys()):
            for architecture in cls.RELEASES[version].keys():
                vs.append("%s %s" % (version, architecture))
        return vs


class KernelInitrdDistro(RelArchDistro):
    """Abstracts a RelArchDistro which downloads a kernel and initrd
    The pxelinux configuration is built locally

    Expects a self.RESOURCE_URL which will have three %s placeholders:
    release, architecture, kernel/initrd

    """

    RESOURCE_URL = ""

    RELEASES = {}

    def __init__(self, tftp_prefix, release, architecture, kernel, initrd,
                 k_opts=None, i_opts=None):
        """Create a new KernelInitrdDistro. Ready to download kernel and initrd
        and to configure pxelinux

        Arguments:
        tftp_prefix - tftp_prefix to pass to Distro
        release - distribution version
        architecture - machine architecture
        kernel - kernel base name
        initrd - initrd base name

        Keyword Arguments:
        k_opts - kernel options to pass at boot
        i_opts - initrd options to pass at boot

        """
        super(KernelInitrdDistro, self).__init__(tftp_prefix, release,
                                                 architecture)
        self.kernel = kernel
        self.initrd = initrd
        self.k_opts = k_opts or ""
        self.i_opts = i_opts or ""

    def fetch(self):
        download_file(
            self.RESOURCE_URL % (self.release, self.architecture, self.kernel),
            "%s/%s" % (self.tftp_root, self.kernel),
            checksum=self.RELEASES[self.release][self.architecture][0][0],
            checksum_type=self.RELEASES[self.release][self.architecture][1])
        download_file(
            self.RESOURCE_URL % (self.release, self.architecture, self.initrd),
            "%s/%s" % (self.tftp_root, self.initrd),
            checksum=self.RELEASES[self.release][self.architecture][0][1],
            checksum_type=self.RELEASES[self.release][self.architecture][1])

    def unpack(self):
         # Copy syslinux files
        files_to_copy = ["pxelinux.0", "ldlinux.c32", "ldlinux.e32",
                         "ldlinux.e64"]
        for f in files_to_copy:
            print "%s %s" % (colorize("Copying:", "blue"), f)
            shutil.copy("syslinux/%s" % f, self.tftp_root)

        # Write out the menu
        directory = "%s/pxelinux.cfg" % self.tftp_root
        if not os.path.exists(directory):
            os.makedirs(directory)

        kernel_string = """
default linux
label linux
    kernel %s %s
    append initrd=%s %s
                """ % (self.kernel, self.k_opts, self.initrd, self.i_opts)

        print "%s %s" % (colorize("Writing default kernel boot:", "blue"),
                         colorize(kernel_string, "white"))
        with open('%s/default' % directory, 'w') as output:
            output.write(kernel_string)


class LiveCD(KernelInitrdDistro):
    """docstring for LiveCD"""

    RESOURCE_URL = ""

    def __init__(self, tftp_prefix, release, architecture, kernel, initrd,
                 k_opts=None, i_opts=None, nfs_root_name="nfsroot",
                 extract=False, temp_dir_mount=False, kid=True):
        super(LiveCD, self).__init__(
            tftp_prefix, release, architecture, os.path.basename(kernel),
            None if initrd is None else os.path.basename(initrd), k_opts,
            i_opts)
        self.live_kernel = kernel
        self.live_initrd = initrd
        self.nfs_root = "%s/iso" % (self.tftp_root)
        # Extend kernel opts with nfsroot
        self.k_opts = "%s %s=10.1.0.1:%s" % (self.k_opts, nfs_root_name,
                                             self.nfs_root)
        self.extract = extract
        self.temp_dir_mount = temp_dir_mount
        self.kid = kid

    def fetch(self):
        checksum, checksum_type = self.RELEASES[self.release][self.architecture]
        download_file(self.RESOURCE_URL % (self.release, self.architecture),
                      "%s/livecd.iso" % self.tftp_root, checksum=checksum,
                      checksum_type=checksum_type)

    def unpack(self):
        if self.kid:
            super(LiveCD, self).unpack()

        # Extract iso
        if not self.extract:
            mount_iso("%s/livecd.iso" % self.tftp_root, self.nfs_root)
        else:
            extract_iso("%s/livecd.iso" % self.tftp_root, self.nfs_root,
                        self.temp_dir_mount)

        # Copy kernel
        for f in filter(lambda x: x is not None,
                        [self.live_kernel, self.live_initrd]):
            base = os.path.basename(f)
            print "%s %s" % (colorize("Copying:", "blue"), base)
            shutil.copyfile("%s/%s" % (self.nfs_root, f),
                            "%s/%s" % (self.tftp_root, base))

        if not self.extract:
            unmount_iso(self.nfs_root)

    def start(self):
        if not self.extract:
            mount_iso("%s/livecd.iso" % self.tftp_root, self.nfs_root)

    def stop(self):
        if not self.extract:
            unmount_iso(self.nfs_root)


class ArchLinux(Distro):
    """docstring for ArchLinux"""
    def __init__(self):
        super(ArchLinux, self).__init__("archlinux")
        self.dhcp_boot = "ipxe.pxe"

    def fetch(self):
        # WARNING: this might easily break since archlinux is rolling...
        download_file("https://releng.archlinux.org/pxeboot/ipxe.pxe",
                      "%s/ipxe.pxe" % self.tftp_root,
                      checksum="2d0c3d05cff23e2382f19c68902554c7388d642e38a9a"
                               "32895db5b890cca4071", checksum_type="sha256")


class CentOS(KernelInitrdDistro):
    """docstring for CentOS"""

    RESOURCE_URL = "http://mirror.centos.org/centos/%s/os/%s/images/pxeboot/%s"

    RELEASES = {
        "5.10": {
            "i386": (("245dd430311de7b900d7708f4140a776f4224e576d454f906af7d20405ca1b06",
                      "17fc0c1774b95d1bfdbc5ddbe08ebfe2dc7c061a4b391e5cd3f89d3087c81866"),
                      "sha256"),
            "x86_64": (("d03153f8dc002c14564231026df49a21cd0b4df535ad606fc8c517cd336f4552",
                        "e291a8b402fc2bf27ebce4912753fca6b636bcc5432235610d9bf8ee5d05ae2c"),
                       "sha256"),
        },
        "6.5": {
            "i386": (("28a57fc36924be72d438ce4ec32debca7c5d3f9c19eef196b3aafd81d952fc65",
                      "9dba23e2be677f1ef78879e51207b6423144e29c5ae660b3fb1850caa3ef32f8"),
                      "sha256"),
            "x86_64": (("61723c1c5906e49733e409bedf705d68d8971221751a76b02186365464166db0",
                        "c5ee23c099a3bee1fb09726290303fb0a67e5ae96b4b49554f88b8a1cdc276ba"),
                       "sha256"),
        }
    }

    def __init__(self, release, architecture):
        super(CentOS, self).__init__(
            "centos", release, architecture, "vmlinuz", "initrd.img",
            k_opts="method=http://mirror.centos.org/centos/%s/os/%s/" % (
                release, architecture), i_opts="devfs=nomount")


class Debian(RelArchDistro):
    """Debian Distribution"""

    RESOURCE_URL = "http://ftp.nl.debian.org/debian/dists/%s/main/" \
                   "installer-%s/current/images/netboot/netboot.tar.gz"

    RELEASES = {
        "squeeze": {
            "amd64": ("45e3f518a93879c08484005d27916bf2", "md5"),
            "i386": ("cb132353a81d164b4c0c9f813e5a6599", "md5"),
            "ia64": ("c3e6e1f86d83515dbc1ac7aa85c646fd", "md5"),
            "kfreebsd-amd64": ("babf36ff6a98a5615baeaf761d2566ad", "md5"),
            "kfreebsd-i386": ("0ece309d52f70753ca93f663d132ffb7", "md5")
        },
        "wheezy": {
            "amd64": ("00c8997a3a4251aa6fc123123f504d44bc0f3f29228645dea2d5643974d4cc3a", "sha256"),
            "i386": ("febb9d04260ce25fc22dede81bd97d72fe534cf216b77fd18fd24ee73b6f74f7", "sha256"),
            "ia64": ("2f259024781a291801ca2e2b81cf41f461e2e37b09752cb2bb8dc85fe27ed569", "sha256"),
            "kfreebsd-amd64": ("4e716806dbd6cfd29dbbbb33a2bc724d9e7949d9d0663442946e305a01c9801a", "sha256"),
            "kfreebsd-i386": ("5996a5ce15153ba025d2adf4ecc891dfe85e6a853e805b94446eed4cf93e6091", "sha256")
        },
        "jessie": {
            "amd64": ("daa929579cb2cf0bca8ddb418c01e68d3032bd892fdb8ed6746cccb27569ee68", "sha256"),
            "i386": ("c37a5c2d28f35b8d0fdf8d24d09a82d650d0a76fb1879ed0d805eabc43d6a199", "sha256"),
            "arm64": ("f9d2c1713435d0d35b032c1ada8f8c67d1b1ebb84669861a129a8fb1d7a27fe7", "sha256")
        }
    }

    def __init__(self, release, architecture):
        """Debian

        Arguments:
        release - release version
        architecture - cpu architecture

        """
        super(Debian, self).__init__("debian", release, architecture)

    def fetch(self):
        checksum, checksum_type = self.RELEASES[self.release][self.architecture]
        download_file(self.RESOURCE_URL % (self.release, self.architecture),
                      "%s/netboot.tar.gz" % self.tftp_root, checksum=checksum,
                      checksum_type=checksum_type)

    def unpack(self):
        # Unpack the downloaded tar file
        print "%s %s/netboot.tar.gz" % (colorize("Unpacking:", "blue"),
                                        self.tftp_root)
        t = tarfile.open('%s/netboot.tar.gz' % self.tftp_root)
        t.extractall(self.tftp_root)


class ElementaryOSLive(LiveCD):
    """docstring for ElementaryOS"""

    RESOURCE_URL = "http://downloads.sourceforge.net/project/elementaryos/"\
                   "stable/elementaryos-stable-%s.%s.iso"

    RELEASES = {
        "20130810": {
            "i386": ("fb00edb0037e3ed6e4d15e035bd9e450e148c1aa18a15e26c839fb550e075051", "sha256"),
            "amd64": ("bfd2d56ec2936e7634f466372be6c839af12a8f7df956c0989664dcf9029da18", "sha256")
        }
    }

    def __init__(self, release, architecture):
        super(ElementaryOSLive, self).__init__(
            "elementary_os_live", release, architecture, "casper/vmlinuz",
            "casper/initrd.lz", k_opts="boot=casper netboot=nfs")

    def fetch(self):
        # Subclass because of iso name
        checksum, checksum_type = self.RELEASES[self.release][self.architecture]
        download_file(
            self.RESOURCE_URL % (self.architecture, self.release),
            "%s/livecd.iso" % self.tftp_root, checksum=checksum,
            checksum_type=checksum_type)


class Fedora(KernelInitrdDistro):
    """docstring for Fedora"""

    RESOURCE_URL = "http://download.fedoraproject.org/pub/fedora/linux" \
                   "/releases/%s/Fedora/%s/os/images/pxeboot/%s"

    RELEASES = {
        "18": {
            "i386": (("2ac09858ab5c54defcde2e0081ffa3ef88c2b9ab6aa633d5ac05b83f258ad9f8",
                      "ca52527c26f4f13f19c1acfcc202960ee4f9315c42a53941176cf8485321b681"),
                     "sha256"),
            "x86_64": (("1a27cb42559ce29237ac186699d063556ad69c8349d732bb1bd8d614e5a8cc2e",
                        "df98a668e869813b2b902f48b23a2052f1b39ad6d6981c023fa6c0e5d1867bb2"),
                       "sha256")
        },
        "19": {
            "i386": (("9feea4b21096916250f8b314050266ff6c2f9bca4ead4cfd4b8bf8e210236cff",
                      "b14373c7cffd6b7a737796ddf7903c2956583471de4202681cb964e9ee3813fd"),
                     "sha256"),
            "x86_64": (("22dcefccbb19cd6d9469153c462353bfeaa77aa2490b2ee54bff2bd5816f7104",
                        "3da1b214b7cf8e54417f3cdf444bb9270bfd0d7cabd41da11e76706b8f2e46a8"),
                       "sha256")
        },
        "20": {
            "i386": (("c49e2932ba93281ae45c8c28820fb6ff7dd5e9baffddf79dc24240e6be722d4d",
                      "aeeb3e20b0136bc4f8fcbb22c4e877c81eee74963207907c2b10f2c8e4d0cd11"),
                     "sha256"),
            "x86_64": (("d3a2fbfcf08ac76dfb8135771380ec97ae3129b4e623891adb21bb1cd8ba59f6",
                        "d0a81824e3425b6871ec4896a66e891aed35e291c50dfa30b08f6fc6ab04ca8b"),
                       "sha256")
        }
    }

    def __init__(self, release, architecture):
        super(Fedora, self).__init__(
            "fedora", release, architecture, "vmlinuz", "initrd.img",
            k_opts="inst.repo=http://download.fedoraproject.org/pub/fedora"
                    "/linux/releases/%s/Fedora/%s/os/" % (release,
                                                          architecture))


class FedoraLive(LiveCD):
    """docstring for FedoraLive"""

    RESOURCE_URL = "http://download.fedoraproject.org/pub/fedora/linux" \
                   "/releases/%s/Live/%s/Fedora-Live-Desktop-%s-19-1.iso"

    RELEASES = {
        "19": {
            "i386": (None, None),
            "x86_64": (None, None)
        }
    }

    def __init__(self, release, architecture):
        super(FedoraLive, self).__init__(
            "fedora_live", release, architecture, "isolinux/vmlinuz0",
            "isolinux/initrd0.img", k_opts="netboot=nfs root=/dev/nfs rootfstype=nfs rootflags=nolock")

    def fetch(self):
        download_file("http://mirror.metrocast.net/fedora/linux/releases/19/Live/i386/Fedora-Live-Desktop-i686-19-1.iso",
            "%s/livecd.iso" % self.tftp_root)


class FreeBSD(LiveCD):
    """docstring for FreeBSD"""
    """
    isoinfo -i livecd.iso -x "/BOOT/PXEBOOT.;1" > pxeboot
    """
    RESOURCE_URL = "ftp://ftp.freebsd.org/pub/FreeBSD/ISO-IMAGES-%s/%s/" \
                   "FreeBSD-%s-RELEASE-%s-bootonly.iso"

    RELEASES = {
        "10.0": {
            "amd64": ("a005b55a7d25e00b247b1e1bddbb9279faaecfa01f1a42846a92f62908229aa0", "sha256"),
            "i386": ("26c667ab930ddc2fa9f060518ec63cee7b0a63e97186ff5640919b431db09648", "sha256")
        }
    }

    def __init__(self, release, architecture):
        super(FreeBSD, self).__init__(
            "freebsd", release, architecture, "BOOT/PXEBOOT", None,
            extract=True, temp_dir_mount=True, kid=False)
        self.dhcp_boot = "pxeboot"
        self.dhcp_option = ["pxe,66,10.1.0.1",
                            "option:root-path,%s/iso" % self.tftp_root]

    def unpack(self):
        super(FreeBSD, self).unpack()
        with open("%s/iso/BOOT/DEFAULTS/LOADER.CONF", "a") as out:
            out.write('vfs.root.mountfrom="ufs:/dev/md0"\n')

    def fetch(self):
        # Subclass because of iso name
        checksum, checksum_type = self.RELEASES[self.release][self.architecture]
        download_file(
            self.RESOURCE_URL % (self.architecture, self.release, self.release,
                                 self.architecture),
            "%s/livecd.iso" % self.tftp_root, checksum=checksum,
            checksum_type=checksum_type)


class Gentoo(LiveCD):
    """docstring for Gentoo"""

    RESOURCE_URL = "http://distfiles.gentoo.org/releases/%s/%s/install-%s-minimal-20130820.iso"

    RELEASES = {
        "current-iso": {
            "amd64": (None, None),
            "x86": (None, None)
        }
    }

    def __init__(self, release, architecture):
        super(Gentoo, self).__init__(
            "gentoo", release, architecture, "isolinux/gentoo",
            "isolinux/gentoo.igz", k_opts="netboot=nfs ip=dhcp root=/dev/nfs")

    def fetch(self):
        checksum, checksum_type = self.RELEASES[self.release][self.architecture]
        print self.RESOURCE_URL % (self.architecture, self.release,
                                           self.architecture)
        download_file(self.RESOURCE_URL % (self.architecture, self.release,
                                           self.architecture),
                      "%s/livecd.iso" % self.tftp_root, checksum=checksum,
                      checksum_type=checksum_type)


class LinuxMintCinnamonLive(LiveCD):
    """docstring for LinuxMintLive"""

    RESOURCE_URL = "http://mirror.jmu.edu/pub/linuxmint/images/stable/%s" \
                   "/linuxmint-%s-cinnamon-dvd-%s.iso"

    RELEASES = {
        "13": {
            "32bit": ("48d8387d3d7e769c029f65c95b1f9fba4e837bfc352828db5d77dd87e13660a5", "sha256"),
            "64bit": ("609bd4dbe89b501fdb13ddc51bd919ebc2b9e14c9895569e1d0cdc225c44cbc8", "sha256")
        },
        "14": {
            "32bit": ("7e5657c9deb46de8490bcd2b9ce8100ecc0dbf7ec95507c2c069d311d5994c96", "sha256"),
            "64bit": ("c73347d753e77904888e9574adffe7d029b31791e238f123557cceccd158fc7c", "sha256"),
        },
        "15": {
            "32bit": ("db744ba03c7352edab9519c9ae4025c03df8b4915b5616119f68ab33eeb8ab66", "sha256"),
            "64bit": ("d9ab000786a9911076aeb3cf6ac89d3ebaf5cb9ab0aa6f50d72430897e21abef", "sha256")
        },
        "16": {
            "32bit": ("fa67c23cca0a5bb0f7e465be456c18888660bfa6f5fa5ec3b19655a61850076c", "sha256"),
            "64bit": ("b4c919630d9dd8e02668bcb4150fd3ca8768a3e45c9757490177a038184c070e", "sha256")
        },
        "17": {
            "32bit": ("3336cd2b494d417fc89aa5cc53e6870ccdec588170bdfc9e3598133125c1f6b8", "sha256"),
            "64bit": ("990680d83da6f28072c1959f2cab844accb3c951910e350f27fd4674975200fb", "sha256")
        }
    }

    def __init__(self, release, architecture):
        super(LinuxMintCinnamonLive, self).__init__(
            "mint_live_cinammon", release, architecture, "casper/vmlinuz",
            "casper/initrd.lz", k_opts="boot=casper netboot=nfs")

    def fetch(self):
        # Subclass because of iso name
        checksum, checksum_type = self.RELEASES[self.release][self.architecture]
        download_file(
            self.RESOURCE_URL % (self.release, self.release, self.architecture),
            "%s/livecd.iso" % self.tftp_root, checksum=checksum,
            checksum_type=checksum_type)


class LinuxMintMateLive(LinuxMintCinnamonLive):
    """docstring for LinuxMintLive"""

    RESOURCE_URL = "http://mirror.jmu.edu/pub/linuxmint/images/stable/%s" \
                   "/linuxmint-%s-mate-dvd-%s.iso"

    RELEASES = {
        "13": {
            "32bit": ("ead0e6da88e2c89677170c07c33005fbb969046965ccac7b17726106de2dab53", "sha256"),
            "64bit": ("ca6035ba7802f8912a7308b8480d8f3e58b0a39e556e761ee3577e2007b432d2", "sha256")
        },
        "14": {
            "32bit": ("52db51dd0ebf1cff7b99237f7e66e2ed9bf886ab83712a873691bcb9855f4f01", "sha256"),
            "64bit": ("ab6fc0360746072f0c92966e4e97f89b96ed0ad27a98a72665700bfda7a6e7fb", "sha256"),
        },
        "15": {
            "32bit": ("9956346701990a7d09a062f00bca6143427ac9b3d75704f53c5a1637d6cb3ce9", "sha256"),
            "64bit": ("886f2acb96b1dea843708c228273dd066aa2c39ad28b793ddbc7cca55ca5b3e9", "sha256")
        },
        "16": {
            "32bit": ("83ec8058ff3ddc0a4d528f64384feea68b2aa922c6c09f217d0d958dcbceab2b", "sha256"),
            "64bit": ("3e833ac287a0e38e8ababda8791238ac7fc4011b3d819a099d61be0cba8f2acd", "sha256")
        },
        "17": {
            "32bit": ("e94efeeddcb5ff328503b9151f59a614e1ae1f4f6d79b8f6bf87eeaf65019fdb", "sha256"),
            "64bit": ("5e2291ebbf75d2206764f6b37afbc7938be0f45bb7c459cfc9297b720a863d01", "sha256")
        }
    }

    def __init__(self, release, architecture):
        super(LinuxMintCinnamonLive, self).__init__(
            "mint_live_mate", release, architecture, "casper/vmlinuz",
            "casper/initrd.lz", k_opts="boot=casper netboot=nfs")


class OpenSUSE(KernelInitrdDistro):
    """docstring for OpenSUSE"""

    RESOURCE_URL = "http://download.opensuse.org/distribution/%s/repo/oss" \
                   "/boot/%s/loader/%s"

    RELEASES = {
        "11.4": {
            "i386": (("1a4649c968d9cccb14472b58cfb422d8ff6fdf88738877ca8f79d58d4609b500",
                      "9431b8b414e1724ba60fe0f701e3645d9e504146c579b1a7430671d5ca182c09"),
                     "sha256"),
            "x86_64": (("be44c620a1c2740a510b7b93b2d09d667634845fb50d43e5d4aa2d3ce4d7b339",
                        "46780f36a60f8916647ccbee9c882de2b7c3e611a256703d9d98362d32ed0006"),
                       "sha256")
        },
        "12.1": {
            "i386": (("e04debecd33bd6d359c2f54956da0b6f9e04b6505dc22025319489f4bcb47c29",
                      "1958d974748e5534cc4f32eed4002ff0bd90505ad2a289596ff3b32bc78fe437"),
                     "sha256"),
            "x86_64": (("b78b0b7087735b11683ee15228fc15cb2b1ad30f5f8ac0b3ffc7477a968b1162",
                        "c63f118a5e0974dcaec35a33eaf4300a09a046b903f719dc3350b8ad8d9f502f"),
                       "sha256")
        },
        "12.2": {
            "i386": (("9c92c0cd93b03e6e2e20a1f18d841df87e7103b551037e9d2b5188a182dce231",
                      "0465ded2af8a30ec84584fda1094637ce90d048315a946c335cfd7baedb08386"),
                     "sha256"),
            "x86_64": (("415e96219c26fd110e3002384909faf04a38d0270fc4c2761932f5eb2a97347d",
                        "69409f76cbf7fa799f3585a6a3301ed36dd2d186a2f092784a470ae70f33ffe4"),
                       "sha256")
        },
        "12.3": {
            "i386": (("d22d39044815a9b21e288ef6076f4445a292bcfdb459b9831ebe890092f84293",
                      "8299fdaa9e57c32b4b133071eab6b558d59ed8f7f2a2b8a4fbc9e16363f64ede"),
                     "sha256"),
            "x86_64": (("7846fee062340add40ab2da72360b701b4c1bc49c25bd6d4a1d730a3f984d7ea",
                        "75252dad880efd303c58bf0d14ca234acfc8b195d6f3202f0b4c24eacd90d176"),
                       "sha256")
        },
        "13.1": {
            "i386": (("b7a3c4eb6b9994dd97cbb2417330936e749e73edfb585a4ddd784f4e1d26c519",
                      "bc9a9477c4766fb657957b9768baa063ce26348a7f93892dcc9104f420317a43"),
                     "sha256"),
            "x86_64": (("8d7ebcc6110be10e4c92efcb22b9ec18eb7ca47082d0e1c75469762c3c6da896",
                        "7133889fd485bb79cd8faeaade82962bc1725b0e55ab25963e1c7079b33f55cc"),
                       "sha256")
        }
    }

    def __init__(self, release, architecture):
        super(OpenSUSE, self).__init__(
            "opensuse", release, architecture, "linux", "initrd",
            k_opts="install=http://download.opensuse.org/distribution/%s"
                   "/repo/oss/" % release)


class PuppyLinuxLive(LiveCD):
    """docstring for PuppyLinux"""
    """
    "isoinfo -i livecd.iso -x "/VMLINUZ.;1" > vmlinuz"
    But what about SFS?
    """

    RESOURCE_URL = "http://distro.ibiblio.org/puppylinux/"\
                   "puppy-slacko-%s/slacko-%s-%s.iso"

    RELEASES = {
        "5.7": {
            "NO-pae": ("83c3f4728814a7234f387a11041205337edb28d1000b10ddf075294a5095a1a4", "sha256"),
            "0-PAE": (None, None)
        }
    }

    def __init__(self, release, architecture):
        super(PuppyLinuxLive, self).__init__(
            "puppy_linux_live", release, architecture, "isolinux/asd", "asd")
        self.release = release
        self.architecture = architecture

    def fetch(self):
        # Subclass because of iso name
        checksum, checksum_type = self.RELEASES[self.release][self.architecture]
        download_file(
            self.RESOURCE_URL % (self.release, self.release, self.architecture),
            "%s/livecd.iso" % self.tftp_root, checksum=checksum,
            checksum_type=checksum_type)


class SystemRescueCD(LiveCD):
    """docstring for SystemRescueCD"""

    RESOURCE_URL = "http://downloads.sourceforge.net/project/systemrescuecd" \
                   "/sysresccd-%s/%s/systemrescuecd-%s-%s.iso"

    RELEASES = {
        "3.7.1": {
            "x86": ("97a6204bd01b88a3be48774ce832792f877c3baaf8f3f2602fcd3e3c30960051", "sha256")
        },
        "4.2.0": {
            "x86": ("b3b49f843d5f6c3131a26104eabc892a4bd99dcc408fdf769c106f7d5dbb2647", "sha256")
        }
    }

    def __init__(self, release, architecture):
        super(SystemRescueCD, self).__init__(
            "system_rescue_cd", release, architecture, "isolinux/rescue32",
            "isolinux/initram.igz", nfs_root_name="nfsboot")

    def fetch(self):
        checksum, checksum_type = self.RELEASES[self.release][self.architecture]
        download_file(self.RESOURCE_URL % (self.architecture, self.release,
                                           self.architecture, self.release),
                      "%s/livecd.iso" % self.tftp_root, checksum=checksum,
                      checksum_type=checksum_type)


class Ubuntu(Debian):
    """Ubuntu Distribution"""

    RESOURCE_URL = "http://archive.ubuntu.com/ubuntu/dists/%s/main" \
                   "/installer-%s/current/images/netboot/netboot.tar.gz"

    RELEASES = {
        "lucid": {
            "amd64": ("0bfd61ea320aff52a453dc9855516e98342930c5bddb87d2265174c2d040c2c0", "sha256"),
            "i386": ("820b9f1a049c43b0511f830e7b1db1ec6a0e73e1617288bdd6aabac39a797557", "sha256")
        },
        "precise": {
            "amd64": ("ac7f4fed04baa620ec9a6f746615cc62691bb6c6a2ffa0404d957e9ad64a8956", "sha256"),
            "i386": ("7ecda678385471238bed28b47113d8053b88b54b48b3df05f286f7cb7c20f0bd", "sha256")
        },
        "quantal": {
            "amd64": ("5975d5ba3147b106631cb3106a7e933b87772eb311dd8b3f430f1f058a5df773", "sha256"),
            "i386": ("517bbf6c3ff4fa5ad2b8fcc9c02243353543059e966abbab546a16ccf693fc6b", "sha256")
        },
        "raring": {
            "amd64": ("05265419c9fd12c9bbe4c5efa834df02f3bf72381a2c9443ed2706a705081b38", "sha256"),
            "i386": ("cdfed46d5f8f5cc96166b92a64248da620f8d07e80ca6141db7ebcdbae3fb899", "sha256")
        },
        "saucy": {
            "amd64": ("9e5b922013973d6b143bb3fdd59c1f16393d716fa355be6727d9ff20991b0bc2", "sha256"),
            "i386": ("e2ebf8f0dc12d261fcbed4c1db0af4771dff43a191728d83e973bda5df616619", "sha256")
        },
        "trusty": {
            "amd64": ("cad0f44d6a93be1fc6e78d47df431c05daf2687a4f9621e9b4195d06320e58af", "sha256"),
            "i386": ("93f3d887e5892c9db11201acec0eb426e93458387fefdb7177202ed829d97ebc", "sha256")
        },
        "vivid": {
            "amd64": ("", "sha256"),
            "i386": ("", "sha256")
        },
        "wily": {
            "amd64": ("", "sha256"),
            "i386": ("", "sha256")
        },
        "xenial": {
            "amd64": ("12af843b596ba433309eb9023ede8b8451ebd5f0e8269217665012afcebdfd26", "sha256"),
            "i386": ("", "sha256")
        },
    }

    def __init__(self, *args):
        super(Ubuntu, self).__init__(*args)
        # Fix up tftp_root
        self.tftp_root = self.tftp_root.replace("debian", "ubuntu")


class UbuntuLive(LiveCD):
    """docstring for UbuntuLive"""

    RESOURCE_URL = "http://releases.ubuntu.com/%s/ubuntu-%s-desktop-%s.iso"

    RELEASE_TO_INT = {"precise": "12.04.4", "quantal": "12.10",
                      "raring": "13.04", "saucy": "13.10", "trusty": "14.04",
                      "utopic": "14.10", "xenial": "16.04" }

    RELEASES = {
        "precise": {
            "amd64": ("fa28d4b4821d6e8c5e5543f8d9f5ed8176400e078fe9177fa2774214b7296c84", "sha256"),
            "i386": ("c0ba532d8fadaa3334023f96925b93804e859dba2b4c4e4cda335bd1ebe43064", "sha256")
        },
        "quantal": {
            "amd64": ("256a2cc652ec86ff366907fd7b878e577b631cc6c6533368c615913296069d80", "sha256"),
            "i386": ("d91eee1b74fb81f4235fdaed21e7566bbe8965ec6b7206a122f2025365621ad6", "sha256")
        },
        "raring": {
            "amd64": ("b4b20e0293c2305e83a60c605d39cabf43115794d574c68f1492d49fee0ab3d8", "sha256"),
            "i386": ("fe4c4de422734dccc9d33d0e3990ef3440b7648d5c05acae372d5ffc80ca719d", "sha256")
        },
        "saucy": {
            "amd64": ("369a1f604df30e097f063829b27c39941a26e5771c53b35aa9ea0e0e0abb3a56", "sha256"),
            "i386": ("a7f7fcb03e5323a3619b84218c935dd9e54a348ee6ebd55748d81886a3272171", "sha256")
        },
        "trusty": {
            "amd64": ("cab6b0458601520242eb0337ccc9797bf20ad08bf5b23926f354198928191da5", "sha256"),
            "i386": ("207a53944d5e8bbb278f4e1d8797491bfbb759c2ebd4a162f41e1383bde38ab2", "sha256")
        },
        "utopic": {
            "amd64": ("c753dbdf665a77e466f07b8f040af00111d609352484a5a915df82e66dd0d163", "sha256"),
            "i386": ("098a5fdd59b1d70ab1605f3e596502044911b98bf22648c29d58270a85d1ec68", "sha256")
        },
        "xenial": {
            "amd64": ("4bcec83ef856c50c6866f3b0f3942e011104b5ecc6d955d1e7061faff86070d4", "sha256"),
            "i386": ("b20b956b5f65dff3650b3ef4e758a78a2a87152101a04ea1804f993d8e551ceb", "sha256")
        },
    }

    def __init__(self, release, architecture):
        super(UbuntuLive, self).__init__(
            "ubuntu_live", release, architecture,
            "casper/vmlinuz%s" % ("" if architecture == "i386" or
                                  release == "quantal" else ".efi"),
            "casper/initrd.lz", k_opts="boot=casper netboot=nfs",
            extract=sys.platform == 'darwin')  # On Mac we can't mount

    def fetch(self):
        # Subclass because of ints in urls
        checksum, checksum_type = self.RELEASES[self.release][self.architecture]
        download_file(self.RESOURCE_URL % (self.release,
                                           self.RELEASE_TO_INT[self.release],
                                           self.architecture),
                      "%s/livecd.iso" % self.tftp_root, checksum=checksum,
                      checksum_type=checksum_type)


class Windows(Distro):
    """
wimextract windows_7/sources/boot.wim 1 Windows/Boot/PXE/pxeboot.n12
wimextract windows_7/sources/boot.wim 1 Windows/Boot/PXE/bootmgr.exe
wimextract windows_7/sources/boot.wim 1 Windows/Boot/PXE/wdsnbp.com

mv pxeboot.n12 windows_7_tftp/pxeboot.com
mv bootmgr.exe windows_7_tftp/
mv wdsnbp.com windows_7_tftp/

cp /Volumes/GSP1RMCPRFRER_EN_DVD/boot/boot.sdi windows_7_tftp
mkdir Boot
cp /Volumes/GSP1RMCPRFRER_EN_DVD/boot/bcd Boot/BCD


[LaunchApps]
%SYSTEMDRIVE%\sources\new\install.cmd
%SYSTEMDRIVE%\windows\system32\cmd.exe
perl -i -p -e 's/\n/\r\n/' winpehl.ini

    """

    def __init__(self):
        super(Windows, self).__init__("windows_7_tftp")
        self.dhcp_boot = "wdsnbp.com"




class DNSMasq(object):
    """docstring for DNSMasq"""
    def __init__(self, tftp_root, dhcp_boot, dhcp_range, interface=None,
                 dhcp_option=None):
        super(DNSMasq, self).__init__()
        self.tftp_root = tftp_root
        self.dhcp_boot = dhcp_boot
        self.dhcp_range = dhcp_range
        self.interface = interface
        self.dhcp_option = dhcp_option

    def start(self):
        print colorize("Running dnsmasq...", "blue")
        args = ["dnsmasq",
                "--pid-file=%s/dnsmasq.pid" % os.getcwd(),
                "--log-facility=%s/dnsmasq.log" % os.getcwd(),
                "--dhcp-leasefile=%s/dnsmasq.leases" % os.getcwd(),
                "--conf-file=/dev/null",
                "--enable-tftp", "--tftp-root=%s" % self.tftp_root,
                "--dhcp-range=%s" % self.dhcp_range,
                "--server=8.8.8.8",
                "--dhcp-boot=%s" % self.dhcp_boot]
        if self.interface is not None:
            args = args + ["--interface=%s" % self.interface]
        if self.dhcp_option is not None:
            args = args + ["--dhcp-option=%s" % d for d in self.dhcp_option]
        print args
        subprocess.call(args)

    @staticmethod
    def stop():
        print colorize("Stopping dnsmasq...", "blue")
        pid = open('%s/dnsmasq.pid' % os.getcwd()).read().rstrip()
        subprocess.call(["kill", pid])


class NAT(object):
    """docstring for NAT"""
    def __init__(self, external, internal):
        super(NAT, self).__init__()
        self.external = external
        self.internal = internal

    def start(self):
        if sys.platform == 'darwin':
            subprocess.call(["sysctl", "-w", "net.inet.ip.forwarding=1"])
            p = subprocess.Popen(["ifconfig", self.external],
                                 stdout=subprocess.PIPE)
            out, err = p.communicate()
            if p.returncode != 0:
                raise Exception("Failed to get ip for NAT device: %s"
                                "" % self.external)
            ip = filter(lambda x: x.lstrip().rstrip().startswith('inet '),
                        out.split('\n'))[0].split()[1]
            subprocess.call(["/usr/sbin/natd", "-alias_address", ip,
                             "-interface", self.external, "-use_sockets",
                             "-same_ports", "-unregistered_only", "-dynamic",
                             "-clamp_mss"])
            subprocess.call(["ipfw", "add", "divert", "natd", "ip", "from",
                             "any", "to", "any", "via", self.external])
        elif sys.platform.startswith('linux'):
            subprocess.call(["sysctl", "-w", "net.ipv4.ip_forward=1"])
            subprocess.call(["iptables", "-t", "nat", "-A", "POSTROUTING",
                             "-o", self.external, "-j", "MASQUERADE"])
            subprocess.call(["iptables", "-A", "FORWARD", "-i", self.external,
                             "-o", self.internal, "-m", "STATE",
                             "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
            subprocess.call(["iptables", "-A", "FORWARD", "-i", self.internal,
                             "-o", self.external, "-j", "ACCEPT"])

    @staticmethod
    def stop():
        if sys.platform == 'darwin':
            subprocess.call(["sysctl", "-w", "net.inet.ip.forwarding=0"])
            subprocess.call(["killall", "-9", "natd"])
            subprocess.call(["ipfw", "-f", "flush"])
        elif sys.platform.startswith('linux'):
            subprocess.call(["sysctl", "-w", "net.ipv4.ip_forward=0"])
            # TODO: change this to remove
            # subprocess.call(["iptables", "-t", "nat", "-A", "POSTROUTING",
                             # "-o", self.external, "-j", "MASQUERADE"])


class NFS(object):
    """docstring for NFS"""
    def __init__(self, path, export_ip, netmask):
        super(NFS, self).__init__()
        self.path = path
        self.export_ip = export_ip
        self.netmask = netmask
        if sys.platform == 'darwin':
            self.export_string = "%s -maproot=root:wheel -alldirs -network %s -mask %s -ro" % (self.path, self.export_ip, self.netmask)
        elif sys.platform.startswith('linux'):
            self.export_string = "%s %s/%s (rw,sync,no_subtree_check)" % (self.path, self.export_ip, self.netmask)

    def start(self):
        with open("/etc/exports", "a") as exports:
            exports.write("%s\n" % self.export_string)
        if sys.platform == 'darwin':
            subprocess.call(["nfsd", "restart"])
        elif sys.platform.startswith('linux'):
            # shit...now we have to guess what distro we're on
            subprocess.call(["..."])

    @staticmethod
    def stop():
        # WARNING: not the safest thing to do... :/
        # Get all the lines, and remove ours
        lines = open("/etc/exports", "r").readlines()
        lines = filter(lambda x: "WheelOfDistros" not in x, lines)
        # Now write back everything else
        with open("/etc/exports", "w") as exports:
            for line in lines:
                exports.write(line)
        if sys.platform == 'darwin':
            subprocess.call(["nfsd", "stop"])


DistroMapping = {"archlinux": ArchLinux,
                 "centos": CentOS,
                 "debian": Debian,
                 "elementary_os_live": ElementaryOSLive,
                 "fedora": Fedora,
                 "freebsd": FreeBSD,
                 "mint_live_cinammon": LinuxMintCinnamonLive,
                 "mint_live_mate": LinuxMintMateLive,
                 "opensuse": OpenSUSE,
                 "puppy_linux_live": PuppyLinuxLive,
                 "systemrescuecd": SystemRescueCD,
                 "ubuntu": Ubuntu, "ubuntu_live": UbuntuLive,
                 "windows": Windows}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Install Linux over netboot")
    subcommands = parser.add_subparsers(help="Commands")

    ###########################################################################
    ############################ Download & Serve #############################
    ###########################################################################
    download = subcommands.add_parser("download")
    download.set_defaults(command="download")

    serve = subcommands.add_parser("serve")
    serve.set_defaults(command="serve")
    # dnsmasq interface
    serve.add_argument("--interface", required=True,
                       help="Interface to serve dhcp and tftp")
    # NAT interface
    serve.add_argument("--nat", required=False, help="Interface for NAT")

    # Add subcommands for each distro to download and serve
    for cmd in (download, serve):
        distros = cmd.add_subparsers(help="Distros")

        ################### ArchLinux ###################
        archlinux = distros.add_parser("archlinux")
        archlinux.set_defaults(distro="archlinux")

        windows = distros.add_parser("windows")
        windows.set_defaults(distro="windows")

        ################### Others ###################
        for x in filter(lambda x: issubclass(DistroMapping[x], RelArchDistro),
                        DistroMapping.keys()):
            d = distros.add_parser(x)
            dc = DistroMapping[x]
            # Distro release
            d.add_argument("release", choices=dc.RELEASES.keys(),
                           help="Distribution version")
            # Architecture
            d.add_argument("architecture",
                           choices=set.union(*[set(dc.RELEASES[z].keys())
                                               for z in dc.RELEASES]))
            d.set_defaults(distro=x)

    ###########################################################################
    ################################### Stop ##################################
    ###########################################################################
    stop = subcommands.add_parser("stop")
    stop.set_defaults(command="stop", distro=None)

    list_all = subcommands.add_parser("list")
    list_all.set_defaults(command="list", distro=None)

    args = parser.parse_args()

    # Check for root
    if args.command in ("serve", "stop") and os.getuid() != 0:
        sys.stderr.write(colorize("Need root priveleges to serve/stop\n",
                                  "red"))
        sys.exit(1)

    # Parse the distro class
    if args.distro is not None:
        linux_class = DistroMapping[args.distro]
        if issubclass(linux_class, RelArchDistro):
            linux = linux_class(args.release, args.architecture)
        else:
            linux = linux_class()

    if args.command == "download":
        try:
            linux.fetch()
            linux.unpack()
        except KeyboardInterrupt:
            pass
    elif args.command == "serve":
        if args.nat is not None:
            nat = NAT(args.nat, args.interface)
            nat.start()
        linux.start()
        dnsmasq = DNSMasq(linux.tftp_root, linux.dhcp_boot,
                          "10.1.0.100,10.1.0.200,12h",
                          interface=args.interface,
                          dhcp_option=linux.dhcp_option)
        dnsmasq.start()
        if isinstance(linux, LiveCD):
            nfs = NFS(linux.nfs_root, "10.1.0.0", "255.255.255.0")
            nfs.start()
    elif args.command == "stop":
        DNSMasq.stop()
        NAT.stop()
        #NFS.stop()
    elif args.command == "list":
        for distro in sorted(DistroMapping.keys()):
            print "%s" % distro
            for version in DistroMapping[distro].versions():
                print "  * %s" % (version)
