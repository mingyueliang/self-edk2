# @file
#  Definition for Device Path Tool.

# Copyright (c) 2017 - 2018, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#

import argparse
import logging
import sys

from DevicePathFromText import *

#
# Utility version information
#
UTILITY_NAME = "DevicePath"
UTILITY_MAJOR_VERSION = 0
UTILITY_MINOR_VERSION = 1

__BUILD_VERSION = "Developer Build based on Revision: Unknown"

STATUS_ERROR = 2
STATUS_SUCCESS = 0
END_DEVICE_PATH_TYPE = 0x7f
END_ENTIRE_DEVICE_PATH_SUBTYPE = 0xFF
END_INSTANCE_DEVICE_PATH_SUBTYPE = 0x01

logger = logging.getLogger('DevicePath')

parser = argparse.ArgumentParser(description="A Device Path Tool", prog=UTILITY_NAME)
parser.add_argument("DevicePathString",
                    help="Device Path string is specified, no space character.Example: \"PciRoot(0)/Pci(0,0)\"")
parser.add_argument("--version", action="version", version='%s Version %s.%s %s' % (
    UTILITY_NAME, UTILITY_MAJOR_VERSION, UTILITY_MINOR_VERSION, __BUILD_VERSION),
                    help="Show program's version number and exit.")


def main():
    args = parser.parse_args()
    if len(sys.argv) == 1:
        logger.error("Missing options", "No input options specified.")
        parser.print_help()
        return STATUS_ERROR

    Str = args.DevicePathString
    if not Str:
        logger.error("Invalid option value, Device Path can't be NULL")
        return STATUS_ERROR

    DevicePath = UefiDevicePathLibConvertTextToDevicePath(Str)

    if not DevicePath:
        logger.error("Convert fail, Cannot convert text to a device path")
        return STATUS_ERROR
    output = " ".join(["0x{:02x}".format(i) for i in DevicePath])
    print(output)

    return STATUS_SUCCESS


if __name__ == "__main__":
    exit(main())
