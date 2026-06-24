#!/usr/bin/env bash
#
# Shell script for building Phoenix-RTOS firmware
#
# Builder for Phoenix-RTOS core components
#
# Copyright 2018-2026 Phoenix Systems
# Author: Kaja Swat, Aleksander Kaminski, Pawel Pisarczyk
#

# fail immediately if any of the commands fails
set -e

b_log "Building phoenix-rtos-kernel"
make -C "phoenix-rtos-kernel" all

if [ "$LIBPHOENIX_DEVEL_MODE" = "y" ]; then
	make -C "phoenix-rtos-kernel" install-headers

	b_log "Building libphoenix"
	make -C "libphoenix" all install
fi

b_log "Building phoenix-rtos-corelibs"
make -C "phoenix-rtos-corelibs" all

b_log "Building phoenix-rtos-filesystems"
make -C "phoenix-rtos-filesystems" all install

b_log "Building phoenix-rtos-usb (libusb, usb-headers)"
make -C "phoenix-rtos-usb" libusb usb-headers install

b_log "Building phoenix-rtos-devices"
make -C "phoenix-rtos-devices" all install

b_log "Building phoenix-rtos-usb (usb)"
# libvcmbox follows libusbxhci on the HCD link line: the BCM2711 PCIe/VL805
# bring-up in libusbxhci (bcm2711-pcie.c) calls vcmbox_call() to route its
# firmware-notify mailbox transaction through the serializing rpi4-vcmbox
# server. libvcmbox.a is built+installed into the shared per-target prefix by
# the preceding "phoenix-rtos-devices all install"; order matters so the linker
# resolves the libusbxhci -> libvcmbox reference.
make -C "phoenix-rtos-usb" usb usb-install USB_HCD_LIBS="libusbxhci libvcmbox" USB_HOSTDRV_LIBS="libusbdrv-usbkbd libusbdrv-usbmouse"

b_log "Building coreutils"
make -C "phoenix-rtos-utils" all install

if [ "$CORE_NETWORKING_DISABLE" != "y" ]; then
	b_log "phoenix-rtos-lwip"
	make -C "phoenix-rtos-lwip" all
	b_install "$PREFIX_PROG_STRIPPED/lwip" /sbin
fi

b_log "Building posixsrv"
make -C "phoenix-rtos-posixsrv" all install
