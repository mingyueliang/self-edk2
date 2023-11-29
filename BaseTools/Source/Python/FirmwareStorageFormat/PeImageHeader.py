# @file
#  EFI image format for PE32+. Please note some data structures are different
#  for IA-32 and Itanium-based images, look for UINTN and the #ifdef EFI_IA64
#
#  @bug Fix text - doc as defined in MSFT EFI specification.
#
#  Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
#  Portions copyright (c) 2011 - 2013, ARM Ltd. All rights reserved.<BR>
#  Copyright (c) 2020, Hewlett Packard Enterprise Development LP. All rights reserved.<BR>
#  Copyright (c) 2022, Loongson Technology Corporation Limited. All rights reserved.<BR>
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#

from ctypes import *
from FirmwareStorageFormat.Common import *
from GenFv.common import GetReverseCode

#
# PE32+ Subsystem type for EFI images
#
EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION = 10
EFI_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11
EFI_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12
EFI_IMAGE_SUBSYSTEM_SAL_RUNTIME_DRIVER = 13

#
# BugBug: Need to get a real answer for this problem. This is not in the
#         PE specification.
#
#         A SAL runtime driver does not get fixed up when a transition to
#         virtual mode is made. In all other cases it should be treated
#         like a EFI_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER image
#
# EFI_IMAGE_SUBSYSTEM_SAL_RUNTIME_DRIVER  = 13

#
# PE32+ Machine type for EFI images
#
IMAGE_FILE_MACHINE_I386 = 0x014c
IMAGE_FILE_MACHINE_EBC = 0x0EBC
IMAGE_FILE_MACHINE_X64 = 0x8664
IMAGE_FILE_MACHINE_ARM = 0x01c0  # Thumb only
IMAGE_FILE_MACHINE_ARMT = 0x01c2  # 32bit Mixed ARM and Thumb/Thumb 2  Little Endian
IMAGE_FILE_MACHINE_ARM64 = 0xAA64  # 64bit ARM Architecture, Little Endian
IMAGE_FILE_MACHINE_RISCV64 = 0x5064  # 64bit RISC-V ISA
IMAGE_FILE_MACHINE_LOONGARCH64 = 0x6264  # 64bit LoongArch Architecture

#
# Support old names for backward compatible
#
EFI_IMAGE_MACHINE_IA32 = IMAGE_FILE_MACHINE_I386
EFI_IMAGE_MACHINE_EBC = IMAGE_FILE_MACHINE_EBC
EFI_IMAGE_MACHINE_X64 = IMAGE_FILE_MACHINE_X64
EFI_IMAGE_MACHINE_ARMT = IMAGE_FILE_MACHINE_ARMT
EFI_IMAGE_MACHINE_AARCH64 = IMAGE_FILE_MACHINE_ARM64
EFI_IMAGE_MACHINE_RISCV64 = IMAGE_FILE_MACHINE_RISCV64
EFI_IMAGE_MACHINE_LOONGARCH64 = IMAGE_FILE_MACHINE_LOONGARCH64

EFI_IMAGE_DOS_SIGNATURE = 0x5A4D  # MZ
EFI_IMAGE_OS2_SIGNATURE = 0x454E  # NE
EFI_IMAGE_OS2_SIGNATURE_LE = 0x454C  # LE
EFI_IMAGE_NT_SIGNATURE = 0x00004550  # PE00
EFI_IMAGE_EDOS_SIGNATURE = 0x44454550  # PEED

EFI_TE_IMAGE_DIRECTORY_ENTRY_BASERELOC = 0
EFI_TE_IMAGE_DIRECTORY_ENTRY_DEBUG = 1


#
# Common struct
#
class MEMORY_FILE(Structure):
    _pack_ = 1
    _fields_ = [
        ("FileImage", c_char_p),
        ("CurrentFilePointer", c_int),
        ("Eof", c_int)
    ]


class EFI_IMAGE_DATA_DIRECTORY(Structure):
    _pack_ = 1
    _fields_ = [
        ('VirtualAddress', c_uint32),
        ('Size', c_uint32)
    ]


#
# Header format for TE images
#
class EFI_TE_IMAGE_HEADER(Structure):
    _pack_ = 1
    _fields_ = [
        ('Signature', c_uint16),
        ('Machine', c_uint16),
        ('NumberOfSections', c_uint8),
        ('Subsystem', c_uint8),
        ('StrippedSize', c_uint16),
        ('AddressOfEntryPoint', c_uint32),
        ('BaseOfCode', c_uint32),
        ('ImageBase', c_uint64),
        ('DataDirectory', ARRAY(EFI_IMAGE_DATA_DIRECTORY, 2)),
    ]

    def ExtHeaderSize(self) -> int:
        return 40


EFI_TE_IMAGE_HEADER_SIGNATURE = 0x5A56  # "VZ"


#
# PE images can start with an optional DOS header, so if an image is run
#  under DOS it can print an error message.
#

class EFI_IMAGE_DOS_HEADER(Structure):
    _pack_ = 1
    _fields_ = [
        ('e_magic', c_uint16),
        ('e_cblp', c_uint16),
        ('e_cp', c_uint16),
        ('e_crlc', c_uint16),
        ('e_cparhdr', c_uint16),
        ('e_minalloc', c_uint16),
        ('e_maxalloc', c_uint16),
        ('e_ss', c_uint16),
        ('e_sp', c_uint16),
        ('e_csum', c_uint16),
        ('e_ip', c_uint16),
        ('e_cs', c_uint16),
        ('e_lfarlc', c_uint16),
        ('e_ovno', c_uint16),
        ('e_res', ARRAY(c_uint16, 4)),
        ('e_oemid', c_uint16),
        ('e_oeminfo', c_uint16),
        ('e_res2', ARRAY(c_uint16, 10)),
        ('e_lfanew', c_uint32)
    ]


class EFI_IMAGE_FILE_HEADER(Structure):
    _pack_ = 1
    _fields_ = [
        ('Machine', c_uint16),
        ('NumberOfSections', c_uint16),
        ('TimeDateStamp', c_uint32),
        ('PointerToSymbolTable', c_uint32),
        ('NumberOfSymbols', c_uint32),
        ('SizeOfOptionalHeader', c_uint16),
        ('Characteristics', c_uint16)
    ]


EFI_IMAGE_SIZEOF_FILE_HEADER = 20

EFI_IMAGE_FILE_RELOCS_STRIPPED = 0x0001  # Relocation info stripped from file.
EFI_IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002  # File is executable  (i.e. no unresolved externel references).
EFI_IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004  # Line nunbers stripped from file.
EFI_IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008  # Local symbols stripped from file.
EFI_IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020  # Supports addresses > 2-GB
EFI_IMAGE_FILE_BYTES_REVERSED_LO = 0x0080  # Bytes of machine word are reversed.
EFI_IMAGE_FILE_32BIT_MACHINE = 0x0100  # 32 bit word machine.
EFI_IMAGE_FILE_DEBUG_STRIPPED = 0x0200  # Debugging info stripped from file in .DBG file
EFI_IMAGE_FILE_SYSTEM = 0x1000  # System File.
EFI_IMAGE_FILE_DLL = 0x2000  # File is a DLL.
EFI_IMAGE_FILE_BYTES_REVERSED_HI = 0x8000  # Bytes of machine word are reversed.
EFI_IMAGE_FILE_MACHINE_UNKNOWN = 0
EFI_IMAGE_FILE_MACHINE_I386 = 0x14c  # Intel 386.
EFI_IMAGE_FILE_MACHINE_R3000 = 0x162  # MIPS* little-endian, 0540 big-endian
EFI_IMAGE_FILE_MACHINE_R4000 = 0x166  # MIPS* little-endian
EFI_IMAGE_FILE_MACHINE_ALPHA = 0x184  # Alpha_AXP*
EFI_IMAGE_FILE_MACHINE_POWERPC = 0x1F0  # IBM* PowerPC Little-Endian
EFI_IMAGE_FILE_MACHINE_TAHOE = 0x7cc  # Intel EM machine


class EFI_IMAGE_DATA_DIRECTORY(Structure):
    _pack_ = 1
    _fields_ = [
        ('VirtualAddress', c_uint32),
        ('Size', c_uint32)
    ]


EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES = 16


# typedef struct {
#   UINT16  Magic;
#   UINT8   MajorLinkerVersion;
#   UINT8   MinorLinkerVersion;
#   UINT32  SizeOfCode;
#   UINT32  SizeOfInitializedData;
#   UINT32  SizeOfUninitializedData;
#   UINT32  AddressOfEntryPoint;
#   UINT32  BaseOfCode;
#   UINT32  BaseOfData;
#   UINT32  BaseOfBss;
#   UINT32  GprMask;
#   UINT32  CprMask[4];
#   UINT32  GpValue;
# } EFI_IMAGE_ROM_OPTIONAL_HEADER;

# EFI_IMAGE_ROM_OPTIONAL_HDR_MAGIC      = 0x107
# EFI_IMAGE_SIZEOF_ROM_OPTIONAL_HEADER  = sizeof (EFI_IMAGE_ROM_OPTIONAL_HEADER)

# typedef struct {
#   EFI_IMAGE_FILE_HEADER         FileHeader;
#   EFI_IMAGE_ROM_OPTIONAL_HEADER OptionalHeader;
# } EFI_IMAGE_ROM_HEADERS;

class EFI_IMAGE_OPTIONAL_HEADER32(Structure):
    _pack_ = 1
    _fields_ = [
        # Standard fields
        ('Magic', c_uint16),
        ('MajorLinkerVersion', c_uint8),
        ('MinorLinkerVersion', c_uint8),
        ('SizeOfCode', c_uint32),
        ('SizeOfInitializedData', c_uint32),
        ('SizeOfUninitializedData', c_uint32),
        ('AddressOfEntryPoint', c_uint32),
        ('BaseOfCode', c_uint32),
        ('BaseOfData', c_uint32),

        # NT additional fields
        ('ImageBase', c_uint32),
        ('SectionAlignment', c_uint32),
        ('FileAlignment', c_uint32),
        ('MajorOperatingSystemVersion', c_uint16),
        ('MinorOperatingSystemVersion', c_uint16),
        ('MajorImageVersion', c_uint16),
        ('MinorImageVersion', c_uint16),
        ('MajorSubsystemVersion', c_uint16),
        ('MinorSubsystemVersion', c_uint16),
        ('Win32VersionValue', c_uint32),
        ('SizeOfImage', c_uint32),
        ('SizeOfHeaders', c_uint32),
        ('CheckSum', c_uint32),
        ('Subsystem', c_uint16),
        ('DllCharacteristics', c_uint16),
        ('SizeOfStackReserve', c_uint32),
        ('SizeOfStackCommit', c_uint32),
        ('SizeOfHeapReserve', c_uint32),
        ('SizeOfHeapCommit', c_uint32),
        ('LoaderFlags', c_uint32),
        ('NumberOfRvaAndSizes', c_uint32),
        ('DataDirectory',
         ARRAY(EFI_IMAGE_DATA_DIRECTORY, EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES))
    ]


EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b


class EFI_IMAGE_OPTIONAL_HEADER64(Structure):
    _pack_ = 1
    _fields_ = [
        # Standard fields
        ('Magic', c_uint16),
        ('MajorLinkerVersion', c_uint8),
        ('MinorLinkerVersion', c_uint8),
        ('SizeOfCode', c_uint32),
        ('SizeOfInitializedData', c_uint32),
        ('SizeOfUninitializedData', c_uint32),
        ('AddressOfEntryPoint', c_uint32),
        ('BaseOfCode', c_uint32),

        # NT additional fields
        ('ImageBase', c_uint64),
        ('SectionAlignment', c_uint32),
        ('FileAlignment', c_uint32),
        ('MajorOperatingSystemVersion', c_uint16),
        ('MinorOperatingSystemVersion', c_uint16),
        ('MajorImageVersion', c_uint16),
        ('MinorImageVersion', c_uint16),
        ('MajorSubsystemVersion', c_uint16),
        ('MinorSubsystemVersion', c_uint16),
        ('Win32VersionValue', c_uint32),
        ('SizeOfImage', c_uint32),
        ('SizeOfHeaders', c_uint32),
        ('CheckSum', c_uint32),
        ('Subsystem', c_uint16),
        ('DllCharacteristics', c_uint16),
        ('SizeOfStackReserve', c_uint64),
        ('SizeOfStackCommit', c_uint64),
        ('SizeOfHeapReserve', c_uint64),
        ('SizeOfHeapCommit', c_uint64),
        ('LoaderFlags', c_uint32),
        ('NumberOfRvaAndSizes', c_uint32),
        ('DataDirectory',
         ARRAY(EFI_IMAGE_DATA_DIRECTORY, EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES))
    ]


EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b


class EFI_IMAGE_NT_HEADERS32(Structure):
    _pack_ = 1
    _fields_ = [
        ('Signature', c_uint32),
        ('FileHeader', EFI_IMAGE_FILE_HEADER),
        ('OptionalHeader', EFI_IMAGE_OPTIONAL_HEADER32)
    ]


EFI_IMAGE_SIZEOF_NT_OPTIONAL32_HEADER = sizeof(EFI_IMAGE_NT_HEADERS32)


class EFI_IMAGE_NT_HEADERS64(Structure):
    _pack_ = 1
    _fields_ = [
        ('Signature', c_uint32),
        ('FileHeader', EFI_IMAGE_FILE_HEADER),
        ('OptionalHeader', EFI_IMAGE_OPTIONAL_HEADER64)
    ]


class EFI_IMAGE_OPTIONAL_HEADER_UNION(Union):
    _pack_ = 1
    _fields_ = [
        ('Pe32', EFI_IMAGE_NT_HEADERS32),
        ('Pe32Plus', EFI_IMAGE_NT_HEADERS64),
        ('Te', EFI_TE_IMAGE_HEADER)
    ]


EFI_IMAGE_SIZEOF_NT_OPTIONAL64_HEADER = sizeof(EFI_IMAGE_NT_HEADERS64)

#
# Subsystem Values
#
EFI_IMAGE_SUBSYSTEM_UNKNOWN = 0
EFI_IMAGE_SUBSYSTEM_NATIVE = 1
EFI_IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
EFI_IMAGE_SUBSYSTEM_WINDOWS_CUI = 3.
EFI_IMAGE_SUBSYSTEM_OS2_CUI = 5
EFI_IMAGE_SUBSYSTEM_POSIX_CUI = 7

#
# Directory Entries
#
EFI_IMAGE_DIRECTORY_ENTRY_EXPORT = 0
EFI_IMAGE_DIRECTORY_ENTRY_IMPORT = 1
EFI_IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
EFI_IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3
EFI_IMAGE_DIRECTORY_ENTRY_SECURITY = 4
EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
EFI_IMAGE_DIRECTORY_ENTRY_DEBUG = 6
EFI_IMAGE_DIRECTORY_ENTRY_COPYRIGHT = 7
EFI_IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8
EFI_IMAGE_DIRECTORY_ENTRY_TLS = 9
EFI_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10

#
# Section header format.
#
EFI_IMAGE_SIZEOF_SHORT_NAME = 8


class Misc(Union):
    _pack_ = 1
    _fields_ = [
        ("PhysicalAddress", c_uint32),
        ("VirtualSize", c_uint32)
    ]


class EFI_IMAGE_SECTION_HEADER(Structure):
    _pack_ = 1
    _fields_ = [
        ('Name', c_char * 8),
        ('Misc', Misc),
        ('VirtualAddress', c_uint32),
        ('SizeOfRawData', c_uint32),
        ('PointerToRawData', c_uint32),
        ('PointerToRelocations', c_uint32),
        ('PointerToLinenumbers', c_uint32),
        ('NumberOfRelocations', c_uint16),
        ('NumberOfLinenumbers', c_uint16),
        ('Characteristics', c_uint32)
    ]


EFI_IMAGE_SIZEOF_SECTION_HEADER = 40

EFI_IMAGE_SCN_TYPE_NO_PAD = 0x00000008  # Reserved.
EFI_IMAGE_SCN_CNT_CODE = 0x00000020
EFI_IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
EFI_IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080

EFI_IMAGE_SCN_LNK_OTHER = 0x00000100  # Reserved.
EFI_IMAGE_SCN_LNK_INFO = 0x00000200  # Section contains comments or some other type of information.
EFI_IMAGE_SCN_LNK_REMOVE = 0x00000800  # Section contents will not become part of image.
EFI_IMAGE_SCN_LNK_COMDAT = 0x00001000

EFI_IMAGE_SCN_ALIGN_1BYTES = 0x00100000
EFI_IMAGE_SCN_ALIGN_2BYTES = 0x00200000
EFI_IMAGE_SCN_ALIGN_4BYTES = 0x00300000
EFI_IMAGE_SCN_ALIGN_8BYTES = 0x00400000
EFI_IMAGE_SCN_ALIGN_16BYTES = 0x00500000
EFI_IMAGE_SCN_ALIGN_32BYTES = 0x00600000
EFI_IMAGE_SCN_ALIGN_64BYTES = 0x00700000

EFI_IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
EFI_IMAGE_SCN_MEM_NOT_CACHED = 0x04000000
EFI_IMAGE_SCN_MEM_NOT_PAGED = 0x08000000
EFI_IMAGE_SCN_MEM_SHARED = 0x10000000
EFI_IMAGE_SCN_MEM_EXECUTE = 0x20000000
EFI_IMAGE_SCN_MEM_READ = 0x40000000
EFI_IMAGE_SCN_MEM_WRITE = 0x80000000

#
# Symbol format.
#
EFI_IMAGE_SIZEOF_SYMBOL = 18

#
# Section values.
#
# Symbols have a section number of the section in which they are
# defined. Otherwise, section numbers have the following meanings:
#
EFI_IMAGE_SYM_UNDEFINED = 0  # Symbol is undefined or is common.
EFI_IMAGE_SYM_ABSOLUTE = -1  # Symbol is an absolute value.
EFI_IMAGE_SYM_DEBUG = -2  # Symbol is a special debug item.
#
# Type (fundamental) values.
#
EFI_IMAGE_SYM_TYPE_NULL = 0  # no type.
EFI_IMAGE_SYM_TYPE_VOID = 1  #
EFI_IMAGE_SYM_TYPE_CHAR = 2  # type character.
EFI_IMAGE_SYM_TYPE_SHORT = 3  # type short integer.
EFI_IMAGE_SYM_TYPE_INT = 4
EFI_IMAGE_SYM_TYPE_LONG = 5
EFI_IMAGE_SYM_TYPE_FLOAT = 6
EFI_IMAGE_SYM_TYPE_DOUBLE = 7
EFI_IMAGE_SYM_TYPE_STRUCT = 8
EFI_IMAGE_SYM_TYPE_UNION = 9
EFI_IMAGE_SYM_TYPE_ENUM = 10  # enumeration.
EFI_IMAGE_SYM_TYPE_MOE = 11  # member of enumeration.
EFI_IMAGE_SYM_TYPE_BYTE = 12
EFI_IMAGE_SYM_TYPE_WORD = 13
EFI_IMAGE_SYM_TYPE_UINT = 14
EFI_IMAGE_SYM_TYPE_DWORD = 15

#
# Type (derived) values.
#
EFI_IMAGE_SYM_DTYPE_NULL = 0  # no derived type.
EFI_IMAGE_SYM_DTYPE_POINTER = 1
EFI_IMAGE_SYM_DTYPE_FUNCTION = 2
EFI_IMAGE_SYM_DTYPE_ARRAY = 3

#
# Storage classes.
#
EFI_IMAGE_SYM_CLASS_END_OF_FUNCTION = -1
EFI_IMAGE_SYM_CLASS_NULL = 0
EFI_IMAGE_SYM_CLASS_AUTOMATIC = 1
EFI_IMAGE_SYM_CLASS_EXTERNAL = 2
EFI_IMAGE_SYM_CLASS_STATIC = 3
EFI_IMAGE_SYM_CLASS_REGISTER = 4
EFI_IMAGE_SYM_CLASS_EXTERNAL_DEF = 5
EFI_IMAGE_SYM_CLASS_LABEL = 6
EFI_IMAGE_SYM_CLASS_UNDEFINED_LABEL = 7
EFI_IMAGE_SYM_CLASS_MEMBER_OF_STRUCT = 8
EFI_IMAGE_SYM_CLASS_ARGUMENT = 9
EFI_IMAGE_SYM_CLASS_STRUCT_TAG = 10
EFI_IMAGE_SYM_CLASS_MEMBER_OF_UNION = 11
EFI_IMAGE_SYM_CLASS_UNION_TAG = 12
EFI_IMAGE_SYM_CLASS_TYPE_DEFINITION = 13
EFI_IMAGE_SYM_CLASS_UNDEFINED_STATIC = 14
EFI_IMAGE_SYM_CLASS_ENUM_TAG = 15
EFI_IMAGE_SYM_CLASS_MEMBER_OF_ENUM = 16
EFI_IMAGE_SYM_CLASS_REGISTER_PARAM = 17
EFI_IMAGE_SYM_CLASS_BIT_FIELD = 18
EFI_IMAGE_SYM_CLASS_BLOCK = 100
EFI_IMAGE_SYM_CLASS_FUNCTION = 101
EFI_IMAGE_SYM_CLASS_END_OF_STRUCT = 102
EFI_IMAGE_SYM_CLASS_FILE = 103
EFI_IMAGE_SYM_CLASS_SECTION = 104
EFI_IMAGE_SYM_CLASS_WEAK_EXTERNAL = 105

#
# type packing constants
#
# EFI_IMAGE_N_BTMASK  = 017
# EFI_IMAGE_N_TMASK   = 060
# EFI_IMAGE_N_TMASK1  = 0300
# EFI_IMAGE_N_TMASK2  = 0360
# EFI_IMAGE_N_BTSHFT  = 4
# EFI_IMAGE_N_TSHIFT  = 2

#
# Communal selection types.
#
EFI_IMAGE_COMDAT_SELECT_NODUPLICATES = 1
EFI_IMAGE_COMDAT_SELECT_ANY = 2
EFI_IMAGE_COMDAT_SELECT_SAME_SIZE = 3
EFI_IMAGE_COMDAT_SELECT_EXACT_MATCH = 4
EFI_IMAGE_COMDAT_SELECT_ASSOCIATIVE = 5

EFI_IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY = 1
EFI_IMAGE_WEAK_EXTERN_SEARCH_LIBRARY = 2
EFI_IMAGE_WEAK_EXTERN_SEARCH_ALIAS = 3

PHYSICAL_ADDRESS = c_uint64


class PE_COFF_LOADER_IMAGE_CONTEXT(Structure):
    _pack_ = 1
    _fields_ = [('ImageAddress', PHYSICAL_ADDRESS),
                ('ImageSize', c_uint64),
                ('DestinationAddress', PHYSICAL_ADDRESS),
                ('EntryPoint', PHYSICAL_ADDRESS),
                ('ImageRead', c_int),
                ('Handle', c_void_p),
                ('FixupData', c_void_p),
                ('SectionAlignment', c_uint32),
                ('PeCoffHeaderOffset', c_uint32),
                ('DebugDirectoryEntryRva', c_uint32),
                ('CodeView', c_void_p),
                ('PdbPointer', c_void_p),
                ('SizeOfHeaders', c_uint64),
                ('ImageCodeMemoryType', c_uint32),
                ('ImageDataMemoryType', c_uint32),
                ('ImageError', c_uint32),
                ('FixupDataSize', c_uint64),
                ('Machine', c_uint16),
                ('ImageType', c_uint16),
                ('RelocationsStripped', c_bool),
                ('IsTeImage', c_bool)]


class EFI_IMAGE_NT_HEADERS32(Structure):
    _pack_ = 1
    _fields_ = [
        ('Signature', c_uint32),
        ('FileHeader', EFI_IMAGE_FILE_HEADER),
        ('OptionalHeader', EFI_IMAGE_OPTIONAL_HEADER32)
    ]


#
# Return status codes from the PE/COFF Loader services
# BUGBUG: Find where used and see if can be replaced by RETURN_STATUS codes
#
IMAGE_ERROR_SUCCESS = 0
IMAGE_ERROR_IMAGE_READ = 1
IMAGE_ERROR_INVALID_PE_HEADER_SIGNATURE = 2
IMAGE_ERROR_INVALID_MACHINE_TYPE = 3
IMAGE_ERROR_INVALID_SUBSYSTEM = 4
IMAGE_ERROR_INVALID_IMAGE_ADDRESS = 5
IMAGE_ERROR_INVALID_IMAGE_SIZE = 6
IMAGE_ERROR_INVALID_SECTION_ALIGNMENT = 7
IMAGE_ERROR_SECTION_NOT_LOADED = 8
IMAGE_ERROR_FAILED_RELOCATION = 9
IMAGE_ERROR_FAILED_ICACHE_FLUSH = 10


class EFI_IMAGE_OPTIONAL_HEADER_POINTER(Union):
    _pack_ = 1
    _fields_ = [
        # ('Header',c_char_p),
        ('Optional32', EFI_IMAGE_OPTIONAL_HEADER32),
        ('Optional64', EFI_IMAGE_OPTIONAL_HEADER64)
    ]


class EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION(Union):
    _pack_ = 1
    _fields_ = [
        # ('Header',c_char_p),
        ('Pe32', EFI_IMAGE_NT_HEADERS32),
        ('Pe32Plus', EFI_IMAGE_NT_HEADERS64),
        ('Te', EFI_TE_IMAGE_HEADER),
        ('Union', EFI_IMAGE_OPTIONAL_HEADER_UNION),
    ]


CODEVIEW_SIGNATURE_NB10 = 0x3031424E  # "NB10"


class EFI_IMAGE_DEBUG_CODEVIEW_NB10_ENTRY(Structure):
    _pack_ = 1
    _fields_ = [
        ("Signature", c_uint32),
        ("Unknown", c_uint32),
        ("Unknown2", c_uint32),
        ("Unknown3", c_uint32),
    ]


CODEVIEW_SIGNATURE_RSDS = 0x53445352  # “RSDS”


class EFI_IMAGE_DEBUG_CODEVIEW_RSDS_ENTRY(Structure):
    _pack_ = 1
    _fields_ = [
        ("Signature", c_uint32),
        ("Unknown", c_uint32),
        ("Unknown2", c_uint32),
        ("Unknown3", c_uint32),
        ("Unknown4", c_uint32),
        ("Unknown5", c_uint32),
    ]


# TODO
# define CODEVIEW_SIGNATURE_MTOC  SIGNATURE_32('M', 'T', 'O', 'C')
CODEVIEW_SIGNATURE_MTOC = int.from_bytes(b"MTOC", "little")


class EFI_IMAGE_DEBUG_CODEVIEW_MTOC_ENTRY(Structure):
    _pack_ = 1
    _fields_ = [
        ("Signature", c_uint32),
        ("MachOUuid", GUID)
    ]


#
# Based relocation format.
#
class EFI_IMAGE_BASE_RELOCATION(Structure):
    _pack_ = 1
    _fields_ = [
        ("VirtualAddress", c_uint32),
        ("SizeOfBlock", c_uint32),
    ]


#
# Based relocation types.
#
EFI_IMAGE_REL_BASED_ABSOLUTE = 0
EFI_IMAGE_REL_BASED_HIGH = 1
EFI_IMAGE_REL_BASED_LOW = 2
EFI_IMAGE_REL_BASED_HIGHLOW = 3
EFI_IMAGE_REL_BASED_HIGHADJ = 4
EFI_IMAGE_REL_BASED_MIPS_JMPADDR = 5
EFI_IMAGE_REL_BASED_ARM_MOV32A = 5
EFI_IMAGE_REL_BASED_RISCV_HI20 = 5
EFI_IMAGE_REL_BASED_ARM_MOV32T = 7
EFI_IMAGE_REL_BASED_RISCV_LOW12I = 7
EFI_IMAGE_REL_BASED_RISCV_LOW12S = 8
EFI_IMAGE_REL_BASED_LOONGARCH32_MARK_LA = 8
EFI_IMAGE_REL_BASED_LOONGARCH64_MARK_LA = 8
EFI_IMAGE_REL_BASED_IA64_IMM64 = 9
EFI_IMAGE_REL_BASED_DIR64 = 10

#
# Debug Format
#
EFI_IMAGE_DEBUG_TYPE_CODEVIEW = 2


class EFI_IMAGE_DEBUG_DIRECTORY_ENTRY(Structure):
    _pack_ = 1
    _fields_ = [
        ("Characteristics", c_uint32),
        ("TimeDateStamp", c_uint32),
        ("MajorVersion", c_uint16),
        ("MinorVersion", c_uint16),
        ("Type", c_uint32),
        ("SizeOfData", c_uint32),
        ("RVA", c_uint32),
        ("FileOffset", c_uint32)
    ]


def ALIGN_POINTER(p, s):
    return (p + ((s - p) & (s - 1)))


def RV_X(x, s, n):
    return (x >> s) & ((1 << n) - 1)


# Macro definitions for RISC-V architecture.
RISCV_IMM_BITS = 12

RISCV_IMM_REACH = (1 << RISCV_IMM_BITS)


def RISCV_CONST_HIGH_PART(Value):
    return ((Value + (RISCV_IMM_REACH // 2)) & GetReverseCode(
        RISCV_IMM_REACH - 1))
