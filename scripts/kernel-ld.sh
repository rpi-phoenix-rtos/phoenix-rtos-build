#!/usr/bin/env bash
#
# Shell script for editing Phoenix-RTOS kernel linker-script
#

# Defaults
CUSTOM_BSS_START="__phoenix_bss_start__ = .;"
CUSTOM_BSS_END="__phoenix_bss_end__ = .;"

DEFAULT_BSS_START="_no_target_found_"
DEFAULT_BSS_END="_no_target_found_"
SYSPAGE_STARTING_POINT="_no_target_found_"

TARGET_ARCH=32

case "$TARGET" in
    *ia32*)
        DEFAULT_BSS_START="__bss_start"
        DEFAULT_BSS_END="_end = .;"
        SYSPAGE_STARTING_POINT=". = DATA_SEGMENT_END"
        ;;

    *armv*)
        DEFAULT_BSS_START="__bss_start = .;"
        DEFAULT_BSS_END="_bss_end"
        SYSPAGE_STARTING_POINT=". = DATA_SEGMENT_END"
        ;;

    *aarch64*)
        DEFAULT_BSS_START="__bss_start = .;"
        DEFAULT_BSS_END="_bss_end"
        SYSPAGE_STARTING_POINT="_end = "
        TARGET_ARCH=64
        ;;

    *riscv64*)
        DEFAULT_BSS_START="__bss_start = .;"
        DEFAULT_BSS_END="__BSS_END__"
        SYSPAGE_STARTING_POINT=". = DATA_SEGMENT_END"
        TARGET_ARCH=64
        ;;

    *sparcv8*)
        DEFAULT_BSS_START="__bss_start = .;"
        DEFAULT_BSS_END="_end = .;"
        SYSPAGE_STARTING_POINT=". = DATA_SEGMENT_END"
        TARGET_ARCH=64   # sparcv8 uses 8-byte alignment
        ;;
esac

SYSPAGE_SECTION="
  .syspage :
  {
      . = ALIGN($TARGET_ARCH / 8);
      *(.syspage);
  }
  . = ALIGN($TARGET_ARCH / 8);
"

 export SYSPAGE_SECTION CUSTOM_BSS_START CUSTOM_BSS_END DEFAULT_BSS_START DEFAULT_BSS_END SYSPAGE_STARTING_POINT
