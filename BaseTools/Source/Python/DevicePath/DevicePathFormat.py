## @file
# This file is used to define needed C Struct and functions.
#
# Copyright (c) 2021-, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import ctypes
import os.path
import sys

from ctypes import *
from FirmwareStorageFormat.Common import *

END_DEVICE_PATH_TYPE = 0x7f
END_ENTIRE_DEVICE_PATH_SUBTYPE = 0xFF
# END_DEVICE_PATH_LENGTH = 0x01
MAX_UINT8 = c_uint8(0xFF).value
MAX_UINT16 = c_uint16(0xFFFF).value
MAX_UINT32 = c_uint32(0xFFFFFFFF).value
MAX_UINT64 = c_uint64(0xFFFFFFFFFFFFFFFF).value
MAX_DEVICE_PATH_NODE_COUNT = 1024

HARDWARE_DEVICE_PATH = 0x01
HW_PCI_DP = 0x01
HW_PCCARD_DP = 0x02
HW_VENDOR_DP = 0x04
HW_CONTROLLER_DP = 0x05
HW_BMC_DP = 0x06
ACPI_DP = 0x01
ACPI_ADR_DP = 0x03
PNP_EISA_ID_CONST = 0x41d0

ACPI_DEVICE_PATH = 0x02
ACPI_EXTENDED_DP = 0x02
MESSAGING_DEVICE_PATH = 0x03
MSG_ATAPI_DP = 0x01
MSG_SCSI_DP = 0x02
MSG_FIBRECHANNEL_DP = 0x03
MSG_1394_DP = 0x04
MSG_USB_DP = 0x05
MSG_I2O_DP = 0x06
MSG_INFINIBAND_DP = 0x09
MSG_VENDOR_DP = 0x0a
MSG_SASEX_DP = 0x16
MSG_NVME_NAMESPACE_DP = 0x17
MSG_UFS_DP = 0x19
MSG_SD_DP = 0x1A
MSG_EMMC_DP = 0x1D
MSG_MAC_ADDR_DP = 0x0b
RFC_1700_UDP_PROTOCOL = 17
RFC_1700_TCP_PROTOCOL = 6
MSG_IPv4_DP = 0x0c
MSG_IPv6_DP = 0x0d
MSG_UART_DP = 0x0e
MSG_ISCSI_DP = 0x13
MSG_BLUETOOTH_DP = 0x1b

USB_CLASS_AUDIO = 1
USB_CLASS_CDCCONTROL = 2
USB_CLASS_HID = 3
USB_CLASS_IMAGE = 6
USB_CLASS_PRINTER = 7
USB_CLASS_MASS_STORAGE = 8
USB_CLASS_HUB = 9
USB_CLASS_CDCDATA = 10
USB_CLASS_SMART_CARD = 11
USB_CLASS_VIDEO = 14
USB_CLASS_DIAGNOSTIC = 220
USB_CLASS_WIRELESS = 224
USB_CLASS_RESERVE = 254
USB_SUBCLASS_FW_UPDATE = 1
USB_SUBCLASS_IRDA_BRIDGE = 2
USB_SUBCLASS_TEST = 3

MSG_USB_WWID_DP = 0x10
MSG_DEVICE_LOGICAL_UNIT_DP = 0x11
MSG_VLAN_DP = 0x14
MSG_DNS_DP = 0x1F
# MAX_UINT16 = c_uint16(0xFFFF).value
MSG_URI_DP = 0x18
MSG_WIFI_DP = 0x1C
MSG_BLUETOOTH_LE_DP = 0x1E
MEDIA_DEVICE_PATH = 0x04
MEDIA_HARDDRIVE_DP = 0x01
SIGNATURE_TYPE_MBR = 0x01
SIGNATURE_TYPE_GUID = 0x02
MEDIA_CDROM_DP = 0x02
MEDIA_VENDOR_DP = 0x03
MEDIA_PROTOCOL_DP = 0x05
MEDIA_PIWG_FW_VOL_DP = 0x07
MEDIA_PIWG_FW_FILE_DP = 0x06
MEDIA_RELATIVE_OFFSET_RANGE_DP = 0x08
MEDIA_RAM_DISK_DP = 0x09

BBS_BBS_DP = 0x01
BBS_TYPE_FLOPPY = 0x01
BBS_TYPE_HARDDRIVE = 0x02
BBS_TYPE_CDROM = 0x03
BBS_TYPE_PCMCIA = 0x04
BBS_TYPE_USB = 0x05
BBS_TYPE_EMBEDDED_NETWORK = 0x06
BBS_TYPE_BEV = 0x80
BBS_TYPE_UNKNOWN = 0xFF
BBS_DEVICE_PATH = 0x05
MSG_SATA_DP = 0x12
MEDIA_FILEPATH_DP = 0x04

BIT0 = 0x00000001
BIT1 = 0x00000002
BIT2 = 0x00000004
BIT3 = 0x00000008
BIT4 = 0x00000001

SIZE_64KB = 0x00010000

#
# ERROR Code
#
RETURN_SUCCESS = EFI_SUCCESS = 0
EFI_BUFFER_TOO_SMALL = 0x8000000000000000 | (5)
EFI_ABORTED = 0x8000000000000000 | (21)
EFI_OUT_OF_RESOURCES = 0x8000000000000000 | (9)
EFI_INVALID_PARAMETER = 0x8000000000000000 | (2)
EFI_NOT_FOUND = 0x8000000000000000 | (14)
RETURN_INVALID_PARAMETER = 0x8000000000000000 | (2)
RETURN_UNSUPPORTED = 0x8000000000000000 | (3)


def EFI_ERROR(A):
    if (-2 ** 63) < A < (2 ** 63 - 1):
        return False
    return True


#############Structures
class EFI_GUID(Structure):
    _pack_ = 1
    _fields_ = [
        ('Data1', c_uint32),
        ('Data2', c_uint16),
        ('Data', c_uint16),
        ('Data4', ARRAY(c_uint8, 8))
    ]


class EFI_DEVICE_PATH_PROTOCOL(Structure):
    _pack_ = 1
    _fields_ = [
        ('Type', c_uint8),
        ('SubType', c_uint8),
        ('Length', ARRAY(c_uint8, 2))
    ]


END_DEVICE_PATH_LENGTH = sizeof(EFI_DEVICE_PATH_PROTOCOL)
mUefiDevicePathLibEndDevicePath = EFI_DEVICE_PATH_PROTOCOL(END_DEVICE_PATH_TYPE, END_ENTIRE_DEVICE_PATH_SUBTYPE,
                                                           (END_DEVICE_PATH_LENGTH, 0))


class DEVICE_PATH_FROM_TEXT_TABLE():
    # _pack_ = 1
    # _fields_ = [
    #     ('DevicePathNodeText', c_wchar_p),
    #     ('Function', c_char)
    # ]
    def __init__(self, DevicePathNodeText, Function):
        self.DevicePathNodeText = DevicePathNodeText
        self.Function = Function


class PCI_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('Function', c_uint8),
        ('Device', c_uint8)
    ]


class PCCARD_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('FunctionNumber', c_uint8)
    ]


class MEMMAP_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('MemoryType', c_uint32),
        ('StartingAddress', c_uint64),
        ('EndingAddress', c_uint64),
    ]


class VENDOR_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('Guid', GUID),
    ]


class CONTROLLER_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('ControllerNumber', c_uint32),
    ]


class BMC_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('ControlInterfaceTypelerNumber', c_uint8),
        ('BaseAddress', ARRAY(c_uint8, 8))
    ]


class ACPI_HID_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('HID', c_uint32),
        ('UID', c_uint32),
    ]


class ACPI_EXTENDED_HID_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('HID', c_uint32),
        ('UID', c_uint32),
        ('CID', c_uint32),
    ]


def Get_ACPI_ADR_DEVICE_PATH(nums: int):
    class ACPI_ADR_DEVICE_PATH(Structure):
        _pack_ = 1
        _fields_ = [
            ('Header', EFI_DEVICE_PATH_PROTOCOL),
            ('ADR', ARRAY(c_uint32, nums)),
        ]


class ATAPI_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('PrimarySecondary', c_uint8),
        ('SlaveMaster', c_uint8),
        ('Lun', c_uint16),
    ]


class SCSI_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('Pun', c_uint16),
        ('Lun', c_uint16),
    ]


class FIBRECHANNEL_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('Reserved', c_uint32),
        ('WWN', c_uint64),
        ('Lun', c_uint64),
    ]


class F1394_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('Reserved', c_uint32),
        ('Guid', c_uint64),
    ]


class USB_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('ParentPortNumber', c_uint8),
        ('InterfaceNumber', c_uint8),
    ]


class I2O_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('Tid', c_uint32),
    ]


class INFINIBAND_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('ResourceFlags', c_uint32),
        ('PortGid', ARRAY(c_uint8, 16)),
        ('ServiceId', c_uint64),
        ('TargetPortId', c_uint64),
        ('DeviceId', c_uint64),
    ]


class UART_FLOW_CONTROL_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('Guid', GUID),
        ('FlowControlMap', c_uint32),
    ]


class SAS_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('Guid', GUID),
        ('Reserved', c_uint32),
        ('SasAddress', c_uint64),
        ('Lun', c_uint64),
        ('DeviceTopology', c_uint16),
        ('RelativeTargetPort', c_uint16),
    ]


class NVME_NAMESPACE_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('NamespaceId', c_uint32),
        ('NamespaceUuid', ARRAY(c_uint8, 8)),
    ]


class UFS_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('Pun', c_uint8),
        ('Lun', c_uint8),
    ]


class SD_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('SlotNumber', c_uint8),
    ]


class EMMC_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('SlotNumber', c_uint8),
    ]


class EFI_MAC_ADDRESS(Structure):
    _pack_ = 1
    _fields_ = [
        ('Addr', ARRAY(c_uint8, 32)),
    ]


class MAC_ADDR_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('MacAddress', EFI_MAC_ADDRESS),
        ('IfType', c_uint8),
    ]


class EFI_IPv4_ADDRESS(Structure):
    _pack_ = 1
    _fields_ = [
        ('Addr', ARRAY(c_uint8, 4)),
    ]


class IPv4_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('LocalIpAddress', EFI_IPv4_ADDRESS),
        ('RemoteIpAddress', EFI_IPv4_ADDRESS),
        ('LocalPort', c_uint16),
        ('RemotePort', c_uint16),
        ('Protocol', c_uint16),
        ('StaticIpAddress', c_bool),
        ('GatewayIpAddress', EFI_IPv4_ADDRESS),
        ('SubnetMask', EFI_IPv4_ADDRESS),
    ]


class EFI_IPv6_ADDRESS(Structure):
    _pack_ = 1
    _fields_ = [
        ('Addr', ARRAY(c_uint8, 16)),
    ]


class IPv6_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('LocalIpAddress', EFI_IPv6_ADDRESS),
        ('RemoteIpAddress', EFI_IPv6_ADDRESS),
        ('LocalPort', c_uint16),
        ('RemotePort', c_uint16),
        ('Protocol', c_uint16),
        ('IpAddressOrigin', c_uint8),
        ('PrefixLength', c_uint8),
        ('GatewayIpAddress', EFI_IPv6_ADDRESS),
    ]


class UART_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('Reserved', c_uint32),
        ('BaudRate', c_uint64),
        ('DataBits', c_uint8),
        ('Parity', c_uint8),
        ('StopBits', c_uint8),
    ]


class USB_CLASS_TEXT(Structure):
    _pack_ = 1
    _fields_ = [
        ('ClassExist', c_bool),
        ('Class', c_uint8),
        ('SubClassExist', c_bool),
        ('SubClass', c_uint8),
    ]


class USB_CLASS_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('ClassExist', c_bool),
        ('VendorId', c_uint16),
        ('ProductId', c_uint16),
        ('DeviceClass', c_uint8),
        ('DeviceSubClass', c_uint8),
        ('DeviceProtocol', c_uint8),
    ]


class USB_WWID_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('ClassExist', c_bool),
        ('InterfaceNumber', c_uint16),
        ('VendorId', c_uint16),
        ('ProductId', c_uint16),
    ]


class DEVICE_LOGICAL_UNIT_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('ClassExist', c_bool),
        ('Lun', c_uint8),
    ]


class ISCSI_DEVICE_PATH_WITH_NAME(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('NetworkProtocol', c_uint16),
        ('LoginOption', c_uint16),
        ('Lun', c_uint64),
        ('TargetPortalGroupTag', c_uint16),
        # TODO: Fix bug
        ('TargetName', ARRAY(c_char, 1)),
    ]


class VLAN_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('VlanId', c_uint16),
    ]


class EFI_IP_ADDRESS(Union):
    _pack_ = 1
    _fields_ = [
        ('Addr', ARRAY(c_uint32, 4)),
        ('v4', EFI_IPv4_ADDRESS),
        ('v6', EFI_IPv6_ADDRESS),
    ]


def Get_DNS_DEVICE_PATH(nums: int):
    class DNS_DEVICE_PATH(Structure):
        _pack_ = 1
        _fields_ = [
            ('Header', EFI_DEVICE_PATH_PROTOCOL),
            ('IsIPv6', c_uint8),
            ('DnsServerIp', ARRAY(EFI_IP_ADDRESS, nums)),
        ]

    return DNS_DEVICE_PATH


def Get_URI_DEVICE_PATH(nums: int):
    class URI_DEVICE_PATH(Structure):
        _pack_ = 1
        _fields_ = [
            ('Header', EFI_DEVICE_PATH_PROTOCOL),
            ('Uri', ARRAY(c_char, nums)),
        ]

    return URI_DEVICE_PATH


class BLUETOOTH_ADDRESS(Structure):
    _pack_ = 1
    _fields_ = [
        ('Address', ARRAY(c_uint8, 6)),
    ]


class BLUETOOTH_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('BD_ADDR', BLUETOOTH_ADDRESS),
    ]


class WIFI_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('SSId', ARRAY(c_uint8, 32)),
    ]


class BLUETOOTH_LE_ADDRESS(Structure):
    _pack_ = 1
    _fields_ = [
        ('Address', ARRAY(c_uint8, 6)),
        ('Type', c_uint8),
    ]


class BLUETOOTH_LE_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('Address', BLUETOOTH_LE_ADDRESS)
    ]


class HARDDRIVE_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('PartitionNumber', c_uint32),
        ('PartitionStart', c_uint64),
        ('PartitionSize', c_uint64),
        ('Signature', GUID),
        ('MBRType', c_uint8),
        ('SignatureType', c_uint8)
    ]


class CDROM_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('BootEntry', c_uint32),
        ('PartitionStart', c_uint64),
        ('PartitionSize', c_uint64),
    ]


class MEDIA_PROTOCOL_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('Protocol', GUID),
    ]


class MEDIA_FW_VOL_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('FvName', GUID),
    ]


class MEDIA_FW_VOL_FILEPATH_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('FvFileName', GUID),
    ]


class MEDIA_RELATIVE_OFFSET_RANGE_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('Reserved', c_uint32),
        ('StartingOffset', c_uint64),
        ('EndingOffset', c_uint64),
    ]


class MEDIA_RAM_DISK_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('StartingAddr', ARRAY(c_uint32, 2)),
        ('EndingAddr', ARRAY(c_uint32, 2)),
        ('TypeGuid', GUID),
        ('Instance', c_uint16),
    ]


class BBS_BBS_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('DeviceType', c_uint16),
        ('StatusFlag', c_uint16),
        ('String', ARRAY(c_char, 1)),
    ]


class SATA_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ = [
        ('Header', EFI_DEVICE_PATH_PROTOCOL),
        ('HBAPortNumber', c_uint16),
        ('PortMultiplierPortNumber', c_uint16),
        ('Lun', c_uint16),
    ]


def Get_FILEPATH_DEVICE_PATH(nums: int):
    class FILEPATH_DEVICE_PATH(Structure):
        _pack_ = 1
        _fields_ = [
            ('Header', EFI_DEVICE_PATH_PROTOCOL),
            ('PathName', ARRAY(c_uint16, nums)),
        ]

        def Size(self):
            return sizeof(EFI_DEVICE_PATH_PROTOCOL) + 2 * nums

    return FILEPATH_DEVICE_PATH


def Get_GENERIC_PATH(nums: int):
    class GENERIC_PATH(Structure):
        _pack_ = 1
        _fields_ = [
            ('Header', EFI_DEVICE_PATH_PROTOCOL),
            ('Data', ARRAY(c_uint8, nums))
        ]

    return GENERIC_PATH


def InternalIsDecimalDigitCharacter(char: str):
    return '0' <= char <= '9'


def InternalIsHexaDecimalDigitCharacter(char: str):
    return InternalIsDecimalDigitCharacter(char) or 'A' <= char <= 'F' or 'a' <= char <= 'f'


RSIZE_MAX = 1000000


def InternalHexCharToUintn(char: str):
    if InternalIsDecimalDigitCharacter(char):
        return ord(char) - ord('0')
    return 10 + ord(char.upper()) - ord('A')


def StrHexToBytes(Str: str, Length: int, MaxBufferSize: int, Buffer):
    """
      Convert a Null-terminated Unicode hexadecimal string to a byte array.

      This function outputs a byte array by interpreting the contents of
      the Unicode string specified by String in hexadecimal format. The format of
      the input Unicode string String is:

                      [XX]*

      X is a hexadecimal digit character in the range [0-9], [a-f] and [A-F].
      The function decodes every two hexadecimal digit characters as one byte. The
      decoding stops after Length of characters and outputs Buffer containing
      (Length / 2) bytes.

      If String is not aligned in a 16-bit boundary, then ASSERT().

      If String is NULL, then ASSERT().

      If Buffer is NULL, then ASSERT().

      If Length is not multiple of 2, then ASSERT().

      If PcdMaximumUnicodeStringLength is not zero and Length is greater than
      PcdMaximumUnicodeStringLength, then ASSERT().

      If MaxBufferSize is less than (Length / 2), then ASSERT().

      @param  String                   Pointer to a Null-terminated Unicode string.
      @param  Length                   The number of Unicode characters to decode.
      @param  Buffer                   Pointer to the converted bytes array.
      @param  MaxBufferSize            The maximum size of Buffer.

      @retval RETURN_SUCCESS           Buffer is translated from String.
      @retval RETURN_INVALID_PARAMETER If String is NULL.
                                       If Data is NULL.
                                       If Length is not multiple of 2.
                                       If PcdMaximumUnicodeStringLength is not zero,
                                        and Length is greater than
                                        PcdMaximumUnicodeStringLength.
      @retval RETURN_UNSUPPORTED       If Length of characters from String contain
                                        a character that is not valid hexadecimal
                                        digit characters, or a Null-terminator.
      @retval RETURN_BUFFER_TOO_SMALL  If MaxBufferSize is less than (Length / 2).
    """

    # 1. None of String shall be a null pointer.
    if not Str:
        raise Exception("None of String shall be a None.")
    # 2. The length of String shall not be greater than RSIZE_MAX.
    if len(Str) > RSIZE_MAX:
        raise Exception("The length of String shall not be greater than RSIZE_MAX.")
    # 3. Length shall not be odd.
    if Length & BIT0 != 0:
        raise Exception("Length shall not be odd.")

    if MaxBufferSize >= Length / 2:
        raise Exception("MaxBufferSize is less than (Length / 2)")

    Index = 0
    for Index in range(Length):
        if not InternalIsHexaDecimalDigitCharacter(Str[Index]):
            break

    if (Index != Length):
        raise Exception("String length mismatch")

    # Convert the hex string to bytes.
    for index in range(Length):
        if index & BIT0 == 0:
            Buffer[index // 2] = InternalHexCharToUintn(Str[index]) << 4
        else:
            Buffer[index // 2] |= InternalHexCharToUintn(Str[index])

    return Buffer

############Functions
def Strtoi(Str: str):
    Str = Str.strip()
    if Str.startswith('0x') or Str.startswith('0X'):
        return int(Str, 16)
    else:
        return int(Str)


def EFI_PNP_ID(_Id):
    return PNP_EISA_ID_CONST | _Id << 16


def IS_SLASH(a):
    if a == '/':
        return True
    else:
        return False


def IS_LEFT_PARENTH(a):
    if a == '(':
        return True
    else:
        return False


def IS_RIGHT_PARENTH(a):
    if a == ')':
        return True
    else:
        return False


def IS_COMMA(a):
    if a == ',':
        return True
    else:
        return False


def ReadUnaligned16(Buffer: int) -> int:
    return Buffer


# Get data from ctypes to bytes.
def struct2stream(s) -> bytes:
    length = sizeof(s)
    p = cast(pointer(s), POINTER(c_char * length))
    return p.contents.raw
