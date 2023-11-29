from ctypes import *

from FirmwareStorageFormat.Common import *

class EFI_CAPSULE_HEADER(Structure):
    _pack_ = 1
    _fields_ = [
        ("CapsuleGuid", GUID),
        ("HeaderSize", c_uint32),
        ("Flags", c_uint32),
        ("CapsuleImageSize", c_uint32)
    ]


CAPSULE_FLAGS_PERSIST_ACROSS_RESET          = 0x00010000
CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE         = 0x00020000
CAPSULE_FLAGS_INITIATE_RESET                = 0x00040000
