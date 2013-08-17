SHELL=/bin/bash
PREFIX=$(shell pwd)
ROOT=$(PREFIX)/root
DOWNLOAD_DIR=downloads
NAT=
DISTRO=
# RELEASE=
ARCHITECTURE=amd64
KERNEL=$(shell uname)

###############################################################################
################################### DNSMASQ ###################################
###############################################################################
DNSMASQ_PID_FILE=$(PREFIX)/dnsmasq.pid
DNSMASQ_LEASE_FILE=$(PREFIX)/dnsmasq.leases
DNSMASQ_LOG_FILE=$(PREFIX)/dnsmasq.log
DNSMASQ_CONF_FILE=/dev/null
TFTP_ROOT=
DHCP_BOOT=pxelinux.0
DHCP_RANGE=10.1.0.100,10.1.0.200,12h
DNSMASQ_ADD_OPTS=

# If ArchLinux
ifeq ($(DISTRO), ArchLinux)
	TFTP_ROOT=$(ROOT)/archlinux/
	DHCP_BOOT=arch/boot/syslinux/pxelinux.0,,10.1.0.1
	DNSMASQ_ADD_OPTS=--dhcp-option-force=209,boot/syslinux/archiso.cfg --dhcp-option-force=210,/arch/
else ifeq ($(DISTRO), ubuntu)
	# ifndef $(RELEASE)
		# @echo "RELEASE needs to be specified: lucid, precise, quantal, raring etc..."
		# exit 1
	# endif
	TFTP_ROOT="$(ROOT)/ubuntu/$(RELEASE)/$(ARCHITECTURE)"
endif

all:
	@echo "Nothing to do for all. Specify something"

stop:
	-sudo killall -9 dnsmasq
	-sudo killall -9 natd
	sudo ipfw -f flush
	sudo sysctl -w net.inet.ip.forwarding=0


dnsmasq_start:
	sudo dnsmasq --pid-file=$(DNSMASQ_PID_FILE) --log-facility=$(DNSMASQ_LOG_FILE) \
		--conf-file=$(DNSMASQ_CONF_FILE) --dhcp-leasefile=$(DNSMASQ_LEASE_FILE) \
		--enable-tftp --tftp-root=$(TFTP_ROOT) \
		--dhcp-range=$(DHCP_RANGE) --dhcp-boot=$(DHCP_BOOT) $(DNSMASQ_ADD_OPTS)

# webserver_archlinux:
	# @echo webserver
	# python -m simplehttpd

downloads:
	mkdir downloads

nat:
	@ if [[ ! -z "$(NAT)" ]]; then \
		if [[ "$(KERNEL)" == "Darwin" ]]; then \
			sudo sysctl -w net.inet.ip.forwarding=1; \
			alias_ip=$(ifconfig $(NAT) | grep inet | grep -v inet6 | awk '{print $2}' | head -1); \
			sudo /usr/sbin/natd -alias_address $alias_ip -interface $(NAT) -use_sockets -same_ports -unregistered_only -dynamic -clamp_mss; \
			sudo ipfw add divert natd ip from any to any via "$(NAT)"; \
		fi \
	elif [[ "$(KERNEL)" == "Linux" ]]; then \
	 		exit 1; \
	fi

###############################################################################
################################## Archlinux ##################################
###############################################################################
# downloads/archlinux.iso: downloads
# 	wget -c -O downloads/archlinux.iso https://mirrors.kernel.org/archlinux/iso/2013.08.01/archlinux-2013.08.01-dual.iso

# archlinux: downloads/archlinux.iso webserver_archlinux dnsmasq_start nat
	# mkdir -p $(ROOT)/archlinux
	# sudo umount $(ROOT)/archlinux
	# sudo mount archlinux.iso $(ROOT)/archlinux

###############################################################################
################################### Ubuntu ####################################
###############################################################################
$(ROOT)/ubuntu/$(RELEASE)/$(ARCHITECTURE)/netboot.tar.gz:
	mkdir -p $(ROOT)/ubuntu/$(RELEASE)/$(ARCHITECTURE)
	wget -c -O $(ROOT)/ubuntu/$(RELEASE)/$(ARCHITECTURE)/netboot.tar.gz http://archive.ubuntu.com/ubuntu/dists/$(RELEASE)/main/installer-$(ARCHITECTURE)/current/images/netboot/netboot.tar.gz

ubuntu: $(ROOT)/ubuntu/$(RELEASE)/$(ARCHITECTURE)/netboot.tar.gz dnsmasq_start
	cd $(ROOT)/ubuntu/$(RELEASE)/$(ARCHITECTURE) && tar -xf netboot.tar.gz

###############################################################################
################################### Debian ####################################
###############################################################################
debian_tar:
	wget -c http://debian....$(RELEASE)

debian: debian_tar
	mkdir -p $(ROOT)/debian/$(RELEASE)

