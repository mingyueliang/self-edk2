# -*- coding: utf-8 -*-
# @Time : 1/12/2022 10:46 AM
# @Author : mliang2x
# @Email : mingyuex.liang@intel.com
# @File : PeImage.py
# @Project : GitHub_edk2


from ctypes import *
from struct import *


EFI_IMAGE_DOS_SIGNATURE = 0x5A4D       # MZ
EFI_IMAGE_OS2_SIGNATURE = 0x454E       # NE
EFI_IMAGE_OS2_SIGNATURE_LE = 0x454c    # LE
EFI_IMAGE_NT_SIGNATURE = 0x00004550    # PE00
EFI_IMAGE_EDOS_SIGNATURE = 0x44454550  # PEED

EFI_TE_IMAGE_HEADER_SIGNATURE = 0x5A56  # VZ

#
# PE32+ Machine type for EFI images
#
IMAGE_FILE_MACHINE_I386 = 0x014c
IMAGE_FILE_MACHINE_EBC = 0x0EBC
IMAGE_FILE_MACHINE_X64 = 0x8664
IMAGE_FILE_MACHINE_ARM = 0x01c0
IMAGE_FILE_MACHINE_ARMT = 0x01c2
IMAGE_FILE_MACHINE_ARM64 = 0xAA64
IMAGE_FILE_MACHINE_RISCV64 = 0x5064

#
#  Support old names for backward compatible
#
EFI_IMAGE_MACHINE_IA32 = IMAGE_FILE_MACHINE_I386
EFI_IMAGE_MACHINE_EBC = IMAGE_FILE_MACHINE_EBC
EFI_IMAGE_MACHINE_X64 = IMAGE_FILE_MACHINE_X64
EFI_IMAGE_MACHINE_ARMT = IMAGE_FILE_MACHINE_ARMT
EFI_IMAGE_MACHINE_AARCH64 = IMAGE_FILE_MACHINE_ARM64
EFI_IMAGE_MACHINE_RISCV64 = IMAGE_FILE_MACHINE_RISCV64

EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b

#
# PE32+ Subsystem type for EFI images
#
EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION = 10
EFI_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11
EFI_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12
EFI_IMAGE_SUBSYSTEM_SAL_RUNTIME_DRIVER = 13

EFI_IMAGE_FILE_RELOCS_STRIPPED = 0x0001

EFI_IMAGE_DEBUG_TYPE_CODEVIEW = 2

#
# Directory Entries
#
EFI_IMAGE_DIRECTORY_ENTRY_EXPORT      = 0
EFI_IMAGE_DIRECTORY_ENTRY_IMPORT      = 1
EFI_IMAGE_DIRECTORY_ENTRY_RESOURCE    = 2
EFI_IMAGE_DIRECTORY_ENTRY_EXCEPTION   = 3
EFI_IMAGE_DIRECTORY_ENTRY_SECURITY    = 4
EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC   = 5
EFI_IMAGE_DIRECTORY_ENTRY_DEBUG       = 6
EFI_IMAGE_DIRECTORY_ENTRY_COPYRIGHT   = 7
EFI_IMAGE_DIRECTORY_ENTRY_GLOBALPTR   = 8
EFI_IMAGE_DIRECTORY_ENTRY_TLS         = 9
EFI_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10

#
# Return status codes from the PE/COFF Loader services
# BUGBUG: Find where used and see if can be replaced by RETURN_STATUS codes
#
IMAGE_ERROR_SUCCESS                      = 0
IMAGE_ERROR_IMAGE_READ                   = 1
IMAGE_ERROR_INVALID_PE_HEADER_SIGNATURE  = 2
IMAGE_ERROR_INVALID_MACHINE_TYPE         = 3
IMAGE_ERROR_INVALID_SUBSYSTEM            = 4
IMAGE_ERROR_INVALID_IMAGE_ADDRESS        = 5
IMAGE_ERROR_INVALID_IMAGE_SIZE           = 6
IMAGE_ERROR_INVALID_SECTION_ALIGNMENT    = 7
IMAGE_ERROR_SECTION_NOT_LOADED           = 8
IMAGE_ERROR_FAILED_RELOCATION            = 9
IMAGE_ERROR_FAILED_ICACHE_FLUSH          = 10
IMAGE_ERROR_UNSUPPORTED                  = 11


def SIGNATURE_16(A, B):
    return (A | (B << 8))

def SIGNATURE_32(A, B, C, D):
    return (SIGNATURE_16(A, B) | (SIGNATURE_16(C, D) << 16))

def SIGNATURE_64(A, B, C, D, E, F, G, H):
    pass
#
#
#
CODEVIEW_SIGNATURE_NB10 = 0x3031424E  # "NB10"
CODEVIEW_SIGNATURE_RSDS = 0x53445352  # "RSDS"
CODEVIEW_SIGNATURE_MTOC = SIGNATURE_32('M', 'T', 'O', 'C')


class EFI_IMAGE_DATA_DIRECTORY(Structure):
    _pack_ = 1
    _fields_ = [
        ("VirtualAddress", c_uint32),
        ("Size", c_uint32)
    ]


class EFI_TE_IMAGE_HEADER(Structure):
    _pack_ = 1
    _fields_ = [
        ("Signature", c_uint16),
        ("Machine", c_uint16),
        ("NumberOfSections", c_uint8),
        ("Subsystem", c_uint8),
        ("StrippedSize", c_uint16),
        ("AddressOfEntryPoint", c_uint32),
        ("BaseOfCode", c_uint32),
        ("ImageBase", c_uint64),
        ("DataDirectory", ARRAY(EFI_IMAGE_DATA_DIRECTORY, 2))
    ]

    @property
    def Size(self):
        return 32


class PE_COFF_LOADER_IMAGE_CONTEXT(Structure):
    _pack_ = 1
    _fields_ = [
        ("ImageAddress", c_char_p),
        ("ImageSize", c_uint64),
        ("DestinationAddress", c_uint64),
        ("EntryPoint", c_uint64),
        # ("ImageRead", c_uint64),
        ("Handle", c_char_p),
        ("FixupData", c_char_p),
        ("SectionAlignment", c_uint32),
        ("PeCoffHeaderOffset", c_uint32),
        ("DebugDirectoryEntryRva", c_uint32),
        ("CodeView", c_char_p),  # TODO: To be considered
        ("PdbPointer", c_char),
        ("SizeOfHeaders", c_uint64),
        ("ImageCodeMemoryType", c_uint32),
        ("ImageDataMemoryType", c_uint32),
        ("ImageError", c_uint32),
        ("FixupDataSize", c_uint64),
        ("Machine", c_uint16),
        ("ImageType", c_uint16),
        ("RelocationsStripped", c_ubyte),
        ("IsTeImage", c_ubyte)
    ]


class EFI_IMAGE_FILE_HEADER(Structure):
    _pack_ = 1
    _fields_ = [
        ("Machine", c_uint16),
        ("NumberOfSections", c_uint16),
        ("TimeDateStamp", c_uint32),
        ("PointerToSymbolTable", c_uint32),
        ("NumberOfSymbols", c_uint32),
        ("SizeOfOptionalHeader", c_uint16),
        ("Characteristics", c_uint16),
    ]

    @property
    def Size(self):
        return 20


class EFI_IMAGE_OPTIONAL_HEADER32(Structure):
    _pack_ = 1
    _fields_ = [
        # Standard fields.
        ("Magic", c_uint16),
        ("MajorLinkerVersion", c_uint8),
        ("MinorLinkerVersion", c_uint8),
        ("SizeOfCode", c_uint32),
        ("SizeOfInitializedData", c_uint32),
        ("SizeOfUninitializedData", c_uint32),
        ("AddressOfEntryPoint", c_uint32),
        ("BaseOfCode", c_uint32),
        ("BaseOfData", c_uint32),
        # NT additional fields.
        ("ImageBase", c_uint32),
        ("SectionAlignment", c_uint32),
        ("FileAlignment", c_uint32),
        ("MajorOperatingSystemVersion", c_uint16),
        ("MinorOperatingSystemVersion", c_uint16),
        ("MajorImageVersion", c_uint16),
        ("MinorImageVersion", c_uint16),
        ("MajorSubsystemVersion", c_uint16),
        ("MinorSubsystemVersion", c_uint16),
        ("Win32VersionValue", c_uint32),
        ("SizeOfImage", c_uint32),
        ("SizeOfHeaders", c_uint32),
        ("CheckSum", c_uint32),
        ("Subsystem", c_uint16),
        ("DllCharacteristics", c_uint16),
        ("SizeOfStackReserve", c_uint32),
        ("SizeOfStackCommit", c_uint32),
        ("SizeOfHeapReserve", c_uint32),
        ("SizeOfHeapCommit", c_uint32),
        ("LoaderFlags", c_uint32),
        ("NumberOfRvaAndSizes", c_uint32),
        ("DataDirectory", ARRAY(EFI_IMAGE_DATA_DIRECTORY, 16))
    ]


class EFI_IMAGE_OPTIONAL_HEADER64(Structure):
    _pack_ = 1
    _fields_ = [
        # Standard fields.
        ("Magic", c_uint16),
        ("MajorLinkerVersion", c_uint8),
        ("MinorLinkerVersion", c_uint8),
        ("SizeOfCode", c_uint32),
        ("SizeOfInitializedData", c_uint32),
        ("SizeOfUninitializedData", c_uint32),
        ("AddressOfEntryPoint", c_uint32),
        ("BaseOfCode", c_uint32),
        ("BaseOfData", c_uint32),
        # NT additional fields.
        ("ImageBase", c_uint64),
        ("SectionAlignment", c_uint32),
        ("FileAlignment", c_uint32),
        ("MajorOperatingSystemVersion", c_uint16),
        ("MinorOperatingSystemVersion", c_uint16),
        ("MajorImageVersion", c_uint16),
        ("MinorImageVersion", c_uint16),
        ("MajorSubsystemVersion", c_uint16),
        ("MinorSubsystemVersion", c_uint16),
        ("Win32VersionValue", c_uint32),
        ("SizeOfImage", c_uint32),
        ("SizeOfHeaders", c_uint32),
        ("CheckSum", c_uint32),
        ("Subsystem", c_uint16),
        ("DllCharacteristics", c_uint16),
        ("SizeOfStackReserve", c_uint64),
        ("SizeOfStackCommit", c_uint64),
        ("SizeOfHeapReserve", c_uint64),
        ("SizeOfHeapCommit", c_uint64),
        ("LoaderFlags", c_uint32),
        ("NumberOfRvaAndSizes", c_uint32),
        ("DataDirectory", ARRAY(EFI_IMAGE_DATA_DIRECTORY, 16))
    ]


class EFI_IMAGE_NT_HEADERS32(Structure):
    _pack_ = 1
    _fields_ = [
        ("Signature", c_uint32),
        ("FileHeader", EFI_IMAGE_FILE_HEADER),
        ("OptionalHeader", EFI_IMAGE_OPTIONAL_HEADER32)
    ]


class EFI_IMAGE_NT_HEADERS64(Structure):
    _pack_ = 1
    _fields_ = [
        ("Signature", c_uint32),
        ("FileHeader", EFI_IMAGE_FILE_HEADER),
        ("OptionHeader", EFI_IMAGE_OPTIONAL_HEADER64)
    ]


class EFI_IMAGE_OPTIONAL_HEADER_UNION(Union):
    _pack_ = 1
    _fields_ = [
        ("Pe32", EFI_IMAGE_NT_HEADERS32),
        ("Pe32Plus", EFI_IMAGE_NT_HEADERS64),
        ("Te", EFI_TE_IMAGE_HEADER)
    ]


class Misc(Union):
    _pack_ = 1
    _fields_ = [
        ("PhysicalAddress", c_uint32),
        ("VirtualSize", c_uint32)
    ]

class EFI_IMAGE_SECTION_HEADER(Structure):
    _pack_ = 1
    _fields_ = [
        ("Name", c_uint8),
        ("Misc", Misc),
        ("VirtualAddress", c_uint32),
        ("SizeOfRawData", c_uint32),
        ("PointerToRawData", c_uint32),
        ("PointerToRelocations", c_uint32),
        ("PointerToLinenumbers", c_uint32),
        ("NumberOfRelocations", c_uint16),
        ("NumberOfLinenumbers", c_uint16),
        ("Characteristics", c_uint32),
    ]

    @property
    def Size(self):
        return 37


class EFI_IMAGE_DOS_HEADER(Structure):
    _pack_ = 1
    _fields_ = [
        ("e_magic", c_uint16),
        ("e_cblp", c_uint16),
        ("e_cp", c_uint16),
        ("e_crlc", c_uint16),
        ("e_cparhdr", c_uint16),
        ("e_minalloc", c_uint16),
        ("e_maxalloc", c_uint16),
        ("e_ss", c_uint16),
        ("e_sp", c_uint16),
        ("e_csum", c_uint16),
        ("e_ip", c_uint16),
        ("e_cs", c_uint16),
        ("e_lfarlc", c_uint16),
        ("e_ovno", c_uint16),
        ("e_res", ARRAY(c_uint16, 4)),
        ("e_oemid", c_uint16),
        ("e_oeminfo", c_uint16),
        ("e_res2", ARRAY(c_uint16, 10)),
        ("e_lfanew", c_uint32),
    ]

    @property
    def Size(self):
        return 64


    @property
    def Pe_signature_offset(self):
        return 60


class EFI_IMAGE_OPTIONAL_HEADER_POINTER(Union):
    _fields_ = [
        ("Header", c_buffer),
        ("Optional32", EFI_IMAGE_OPTIONAL_HEADER32),
        ("Optional64", EFI_IMAGE_OPTIONAL_HEADER64)
    ]


class EFI_IMAGE_DEBUG_DIRECTORY_ENTRY(Structure):
    _dields_ = [
        ("Characteristics", c_uint32),
        ("TimeDateStamp", c_uint32),
        ("MajorVersion", c_uint16),
        ("MinorVersion", c_uint16),
        ("Type", c_uint32),
        ("SizeOfData", c_uint32),
        ("RVA", c_uint32),
        ("FileOffset", c_uint32),
    ]

    @property
    def Size(self):
        return 28


class GUID(Structure):
    _pack_ = 1
    _fields_ = [
        ("Data1", c_uint32),
        ("Data2", c_uint16),
        ("Data3", c_uint16),
        ("Data4", ARRAY(c_uint8, 4)),
    ]

    @property
    def Size(self):
        return 12


class EFI_IMAGE_DEBUG_CODEVIEW_NB10_ENTRY(Structure):
    _fields_ = [
        ("Signature", c_uint32),
        ("Unknowm", c_uint32),
        ("Unknown2", c_uint32),
        ("unknown3", c_uint32)
    ]

    @property
    def Size(self):
        return 16


class EFI_IMAGE_DEBUG_CODEVIEW_RSDS_ENTRY(Structure):
    _pack_ = 1
    _fields_ = [
        ("Signature", c_uint32),
        ("Unknown2", c_uint32),
        ("Unknown3", c_uint32),
        ("Unknown4", c_uint32),
        ("Unknown5", c_uint32)
    ]

    @property
    def Size(self):
        return 20

class EFI_IMAGE_DEBUG_CODEVIEW_MTOC_ENTRY(Structure):
    _pack_ = 1
    _fields_ = [
        ("Signature", c_uint32),
        ("MachOUuid", GUID)
    ]


    @property
    def Size(self):
        return 4 + GUID().Size


if __name__ == '__main__':
    # PE_COFF_LOADER_IMAGE_CONTEXT.ImageRead = RebaseImage
    # res = PE_COFF_LOADER_IMAGE_CONTEXT.ImageRead(1, 3)
    # print(res)
    pass


