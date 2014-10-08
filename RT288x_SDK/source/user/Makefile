#
#	Makefile -- Build instructions for user level apps
#

.EXPORT_ALL_VARIABLES:
.PHONY: config all romfs clean prune

#
# Include architecture specific build rules.
#
ifndef ROOTDIR
ROOTDIR=..
endif

UCLINUX_BUILD_USER=1
-include $(LINUX_CONFIG)
-include $(CONFIG_CONFIG)
-include $(BUSYBOX_CONFIG)
-include $(ARCH_CONFIG)
-include $(MODULES_CONFIG)

VEND=$(ROOTDIR)/vendors

#
# must run the vendor build first
#
dir_v = $(VEND)/$(CONFIG_VENDOR)/$(CONFIG_PRODUCT)/.
dir_p = $(ROOTDIR)/prop

dir_y = 
dir_n =
dir_  =


dir_y	+= mongoose
dir_y	+= rt2880_app
dir_y 	+= wireless_tools
dir_y	+= apclid
dir_y 	+= lua
dir_y	+= mtd_write
dir_y	+= bridge-utils
dir_y	+= goahead

# dir_$(CONFIG_USER_802_1X)		    += 802.1x
# dir_$(CONFIG_USER_ACCEL_PPTP)		    += accel-pptp
# dir_$(CONFIG_USER_ARPTABLES)		    += arptable-0.0.3
# dir_$(CONFIG_USER_RT2561_802_1X)	    += rt61apd
# dir_$(CONFIG_USER_BIGPOND) 		    += bigpond
# dir_$(CONFIG_USER_BONNIE)		    += bonnie++
# dir_$(CONFIG_USER_BRCTL_BRCTL)              += bridge-utils
# dir_$(CONFIG_USER_BT_UTILS)                 += bt-utils
# dir_$(CONFIG_USER_BUSYBOX_BUSYBOX)          += busybox
# dir_$(CONFIG_USER_CACHEBENCH)		    += llcbench/cachebench
# dir_$(CONFIG_USER_CPU)			    += cpu
# dir_$(CONFIG_USER_CTORRENT)                 += ctorrent-dnh3.2
# dir_$(CONFIG_USER_DHCP6)                    += dhcp6
# dir_$(CONFIG_USER_DROPBEAR)                 += dropbear-0.52
# dir_$(CONFIG_DHRYSTONE)		    	    += dhrystone
# dir_$(CONFIG_DHCPFWD)		    	    += dhcpforwarder
# dir_$(CONFIG_USER_DNSMASQ)                  += dnsmasq-2.40
# dir_$(CONFIG_USER_DISKTYPE)		    += disktype-9
# dir_$(CONFIG_USER_DMS)			    += dlna_src/src
# dir_$(CONFIG_USER_EBTABLES)		    += ebtables-v2.0.9-2
# dir_$(CONFIG_USER_ECMH)			    += ecmh
# dir_$(CONFIG_USER_ETHTOOL)		    += ethtool
# dir_$(CONFIG_USER_GDBREPLAY)                += gdbserver
# dir_$(CONFIG_USER_GDBSERVER)                += gdbserver
# dir_$(CONFIG_USER_MATRIXSSL)                += matrixssl-1.8.3
# dir_$(CONFIG_USER_NBENCH)                   += nbench-byte-2.2.3
# dir_$(CONFIG_USER_GOAHEAD_HTTPD)            += goahead

#TEST
dir_$(CONFIG_USER_HELLO_WORLD)		    += hello_world
#--

all: config
	$(MAKE) -j$(HOST_NCPU) $(sort $(dir_y) $(dir_v) $(dir_p)) || exit $$?

#
# add directory dependancies here
#
.PHONY: $(sort $(dir_y) $(dir_p))

$(sort $(dir_y) $(dir_p)):  config
	[ ! -d "$@" ] || ( touch $@/.sgbuilt_user && $(MAKE) -j1 -C $@ ) || exit $$?

%_only:
	touch $(@:_only=)/.sgbuilt_user && $(MAKE) -j1 -C $(@:_only=)

%_clean:
	$(MAKE) -j1 -C $(@:_clean=) clean; rm -f $(@:_clean=)/.sgbuilt_user; true

romfs:
	for i in $(sort $(dir_y)) $(dir_p) ; do \
		[ ! -d $$i ] || $(MAKE) -C $$i romfs || exit $$? ; \
	done

clean:
	-for i in $(dir_v) $(sort $(dir_y) $(dir_n) $(dir_)) $(dir_p) ; do \
		if [ -f $$i/.sgbuilt_user ]; then \
			$(MAKE) -C $$i clean ; \
			rm -f $$i/.sgbuilt_user; \
		fi; \
	done

prune:
	-for i in $(sort $(dir_n) $(dir_)) ; do \
		found=0; \
		for j in $(sort $(dir_y)) ; do \
			if [ $$i == $$j ]; then \
				found=1; \
			fi; \
		done; \
		if [ $$found == 0 ]; then \
			[ "$$i" = "openswan" ] && make prune_openswan; \
			rm -fr $$i; \
		fi; \
	done

prune_openswan:
	@mkdir $(ROOTDIR)/$@
	@mv $(ROOTDIR)/openswan/linux/net/ipsec/{Config.in*,Kconfig} $(ROOTDIR)/$@/
	@rm -fr $(ROOTDIR)/openswan
	@mkdir -p $(ROOTDIR)/openswan/linux/net/ipsec
	@mv $(ROOTDIR)/$@/* $(ROOTDIR)/openswan/linux/net/ipsec/
	@rm -fr $(ROOTDIR)/$@
