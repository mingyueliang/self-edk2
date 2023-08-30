#@file
#  Definition for Device Path Tool.

#Copyright (c) 2017 - 2018, Intel Corporation. All rights reserved.<BR>
#SPDX-License-Identifier: BSD-2-Clause-Patent

#
import argparse
from Struct import *
import sys
import logging
import copy

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
parser.add_argument("DevicePathString",help="Device Path string is specified, no space character.Example: \"PciRoot(0)/Pci(0,0)\"")
# parser.add_argument("-h","--help",help="Show this help message and exit.")
parser.add_argument("--version", action="version", version='%s Version %s.%s %s' %(UTILITY_NAME,UTILITY_MAJOR_VERSION, UTILITY_MINOR_VERSION, __BUILD_VERSION),
                    help="Show program's version number and exit.")


def PrintMem(Buffer:EFI_DEVICE_PATH_PROTOCOL,Count:int):
    Bytes = Buffer
    for Idx in range(Count):
        print("0x%02x" %Bytes[Idx])
        

#Write ascii string as unicode string format to FILE
def Ascii2UnicodeString(String:str,UniString:c_uint16) -> EFI_DEVICE_PATH_PROTOCOL:
    for i in range(len(String)):
        if String[i] != '\0':
            UniString[i] = c_uint16(String[i])
    Unistring +='\0'


#Convert text to the binary representation of a device path
def UefiDevicePathLibConvertTextToDevicePath(TextDevicePath:str) ->bytearray:
    # if TextDevicePath == None or IS_NULL(TextDevicePath):
    #     return None
    
    DevicePath = EFI_DEVICE_PATH_PROTOCOL()
    DevicePath = bytearray(struct2stream(SetDevicePathEndNode(DevicePath)))
    # DevicePath = bytearray()
    DevicePathStr = TextDevicePath
    #DevicePathStr = copy.deepcopy(TextDevicePath)
    
    Str = DevicePathStr
    IsInstanceEnd = False
    res = GetNextDeviceNodeStr (Str)
    if res == None:
        DeviceNodeStr = None
    else:
        DeviceNodeStr = res[0]
        Str = res[1]
        # IsInstanceEnd = res[2]

    while DeviceNodeStr:
        DeviceNode = UefiDevicePathLibConvertTextToDeviceNode (DeviceNodeStr)
        # NewDevicePath = EFI_DEVICE_PATH_PROTOCOL()
        DevicePath = AppendDevicePathNode (DevicePath, bytearray(struct2stream(DeviceNode)))

        # DevicePath = NewDevicePath
        # DevicePath += bytearray(struct2stream(DeviceNode))
        #
        # if IsInstanceEnd:
        #     DeviceNode = EFI_DEVICE_PATH_PROTOCOL()
        #     DevicePath = SetDevicePathEndNode(DeviceNode)
        #     DeviceNode.SubType = END_INSTANCE_DEVICE_PATH_SUBTYPE
        #
        #     # NewDevicePath = EFI_DEVICE_PATH_PROTOCOL()
        #     # NewDevicePath = AppendDevicePathNode(DevicePath, bytearray(struct2stream(DeviceNode)))
        #     # DevicePath = NewDevicePath
        #     DevicePath += bytearray(struct2stream(DeviceNode))

        res = GetNextDeviceNodeStr(Str)
        if res == None:
            DeviceNodeStr = None
        else:
            DeviceNodeStr = res[0]
            Str = res[1]
    return DevicePath
    

    
def main():
    # DevicePath = EFI_DEVICE_PATH_PROTOCOL()

    
    args = parser.parse_args()

    if len(sys.argv) == 1:
        logger.error("Missing options", "No input options specified.")
        parser.print_help()
        return STATUS_ERROR
    
    Str = sys.argv[1]
    if not Str:
        logger.error("Invalid option value, Device Path can't be NULL")
        return STATUS_ERROR
    #Str16 = ''
    #Ascii2UnicodeString(Str,Str16)
    DevicePath = UefiDevicePathLibConvertTextToDevicePath(Str)

    if not DevicePath:
        logger.error("Convert fail, Cannot convert text to a device path")
        return STATUS_ERROR
    output = " ".join(["0x{:02x}".format(i) for i in DevicePath])
    print(output)
    # while not IsDevicePathEnd(DevicePath):
    #
    # while (DevicePath.Type == END_DEVICE_PATH_TYPE)==0 and DevicePath.SubType == END_ENTIRE_DEVICE_PATH_SUBTYPE:
    #     PrintMem(DevicePath,DevicePath.Length[0] | DevicePath.Length[1] << 8)
    #     DevicePath = EFI_DEVICE_PATH_PROTOCOL(DevicePath + (DevicePath.Length[0] | DevicePath.Length[1] << 8))
    # PrintMem(DevicePath, DevicePath.Length[0] | DevicePath.Length[1] << 8)
    return STATUS_SUCCESS


if __name__=="__main__":
    exit(main())