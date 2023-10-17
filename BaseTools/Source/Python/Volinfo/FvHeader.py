from struct import *
from ctypes import *
from PI.ExtendCType import *

# 
# define Signature
#
SIGNATURE_32 = '_FVH'

#
# Attributes bit definitions
#
EFI_FVB2_READ_DISABLED_CAP  = 0x00000001
EFI_FVB2_READ_ENABLED_CAP   = 0x00000002
EFI_FVB2_READ_STATUS        = 0x00000004
EFI_FVB2_WRITE_DISABLED_CAP = 0x00000008
EFI_FVB2_WRITE_ENABLED_CAP  = 0x00000010
EFI_FVB2_WRITE_STATUS       = 0x00000020
EFI_FVB2_LOCK_CAP           = 0x00000040
EFI_FVB2_LOCK_STATUS        = 0x00000080
EFI_FVB2_STICKY_WRITE       = 0x00000200
EFI_FVB2_MEMORY_MAPPED      = 0x00000400
EFI_FVB2_ERASE_POLARITY     = 0x00000800
EFI_FVB2_READ_LOCK_CAP      = 0x00001000
EFI_FVB2_READ_LOCK_STATUS   = 0x00002000
EFI_FVB2_WRITE_LOCK_CAP     = 0x00004000
EFI_FVB2_WRITE_LOCK_STATUS  = 0x00008000
EFI_FVB2_ALIGNMENT          = 0x001F0000
EFI_FVB2_WEAK_ALIGNMENT     = 0x80000000
EFI_FVB2_ALIGNMENT_1        = 0x00000000
EFI_FVB2_ALIGNMENT_2        = 0x00010000
EFI_FVB2_ALIGNMENT_4        = 0x00020000
EFI_FVB2_ALIGNMENT_8        = 0x00030000
EFI_FVB2_ALIGNMENT_16       = 0x00040000
EFI_FVB2_ALIGNMENT_32       = 0x00050000
EFI_FVB2_ALIGNMENT_64       = 0x00060000
EFI_FVB2_ALIGNMENT_128      = 0x00070000
EFI_FVB2_ALIGNMENT_256      = 0x00080000
EFI_FVB2_ALIGNMENT_512      = 0x00090000
EFI_FVB2_ALIGNMENT_1K       = 0x000A0000
EFI_FVB2_ALIGNMENT_2K       = 0x000B0000
EFI_FVB2_ALIGNMENT_4K       = 0x000C0000
EFI_FVB2_ALIGNMENT_8K       = 0x000D0000
EFI_FVB2_ALIGNMENT_16K      = 0x000E0000
EFI_FVB2_ALIGNMENT_32K      = 0x000F0000
EFI_FVB2_ALIGNMENT_64K      = 0x00100000
EFI_FVB2_ALIGNMENT_128K     = 0x00110000
EFI_FVB2_ALIGNMENT_256K     = 0x00120000
EFI_FVB2_ALIGNMENT_512K     = 0x00130000
EFI_FVB2_ALIGNMENT_1M       = 0x00140000
EFI_FVB2_ALIGNMENT_2M       = 0x00150000
EFI_FVB2_ALIGNMENT_4M       = 0x00160000
EFI_FVB2_ALIGNMENT_8M       = 0x00170000
EFI_FVB2_ALIGNMENT_16M      = 0x00180000
EFI_FVB2_ALIGNMENT_32M      = 0x00190000
EFI_FVB2_ALIGNMENT_64M      = 0x001A0000
EFI_FVB2_ALIGNMENT_128M     = 0x001B0000
EFI_FVB2_ALIGNMENT_256M     = 0x001C0000
EFI_FVB2_ALIGNMENT_512M     = 0x001D0000
EFI_FVB2_ALIGNMENT_1G       = 0x001E0000
EFI_FVB2_ALIGNMENT_2G       = 0x001F0000


PI_SPECIFICATION_VERSION = 0x00010000


class EFI_FV_BLOCK_MAP_ENTRY(Structure):
    _pack_ = 1
    _fields_ = [
        ('NumBlocks',            c_uint32),
        ('Length',               c_uint32),
    ]

    @property
    def HeaderLength(self):
        return 8

def struct2stream(s):
    length = sizeof(s)
    p = cast(pointer(s), POINTER(c_char * length))
    return p.contents.raw


class EFI_FIRMWARE_VOLUME_HEADER(Structure):
    _fields_ = [
        ('ZeroVector',           ARRAY(c_uint8, 16)),
        ('FileSystemGuid',       GUID),
        ('FvLength',             c_uint64),
        ('Signature',            c_uint32),
        ('Attributes',           c_uint32),
        ('HeaderLength',         c_uint16),
        ('Checksum',             c_uint16),
        ('ExtHeaderOffset',      c_uint16),
        ('Reserved',             c_uint8),
        ('Revision',             c_uint8),
        ('BlockMap',             ARRAY(EFI_FV_BLOCK_MAP_ENTRY, 1)),
        ]

    @property
    def HeaderLength(self):
        return 64

def Refine_FV_Header(nums):
    class EFI_FIRMWARE_VOLUME_HEADER(Structure):
        _fields_ = [
            ('ZeroVector',           ARRAY(c_uint8, 16)),
            ('FileSystemGuid',       GUID),
            ('FvLength',             c_uint64),
            ('Signature',            c_uint32),
            ('Attributes',           c_uint32),
            ('HeaderLength',         c_uint16),
            ('Checksum',             c_uint16),
            ('ExtHeaderOffset',      c_uint16),
            ('Reserved',             c_uint8),
            ('Revision',             c_uint8),
            ('BlockMap',             ARRAY(EFI_FV_BLOCK_MAP_ENTRY, nums)),
            ]
    return EFI_FIRMWARE_VOLUME_HEADER

class EFI_FIRMWARE_VOLUME_EXT_HEADER(Structure):
    _fields_ = [
        ('FvName',               GUID),
        ('ExtHeaderSize',        c_uint32)
        ]


