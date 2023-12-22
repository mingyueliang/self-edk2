## @file
# This file contains describes the public interfaces to the GenFvImage Library.
# The basic purpose of the library is to create Firmware Volume images.
#
# Copyright (c) 2004 - 2018, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
import os.path
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from ctypes import *

from FirmwareStorageFormat.Common import struct2stream, GUID, ModifyGuidFormat
from FirmwareStorageFormat.FvHeader import *
from FirmwareStorageFormat.FfsFileHeader import *
from FirmwareStorageFormat.PeImageHeader import *
from FirmwareStorageFormat.SectionHeader import *
from FirmwareStorageFormat.FvHeader import *
from Common.BuildToolError import *
from Common.BasePeCoff import *
from Common.BuildToolError import *
from Common import EdkLogger
from GenFvs.common import *
from GenFvs.ParseInf import *
from GenFvs.GenerateFv import GenerateFvFile

# Different file separator for Linux and Windows
FILE_SEP_CHAR = '/'

# The maximum number of Pad file guid entries.
MAX_NUMBER_OF_PAD_FILE_GUIDS = 1024

# The maximum number of block map entries supported by the library
MAX_NUMBER_OF_FV_BLOCKS = 100

# The maximum number of files in the FV supported by the library
MAX_NUMBER_OF_FILES_IN_FV = 1000
MAX_NUMBER_OF_FILES_IN_CAP = 1000
EFI_FFS_FILE_HEADER_ALIGNMENT = 8

# INF file strings
OPTIONS_SECTION_STRING = "[options]"
ATTRIBUTES_SECTION_STRING = "[attributes]"
FILES_SECTION_STRING = "[files]"
FV_BASE_ADDRESS_STRING = "[FV_BASE_ADDRESS]"

EFI_FV_BASE_ADDRESS_STRING = "EFI_BASE_ADDRESS"
EFI_FV_FILE_NAME_STRING = "EFI_FILE_NAME"
EFI_NUM_BLOCKS_STRING = "EFI_NUM_BLOCKS"
EFI_BLOCK_SIZE_STRING = "EFI_BLOCK_SIZE"
EFI_GUID_STRING = "EFI_GUID"
EFI_FV_FILESYSTEMGUID_STRING = "EFI_FV_GUID"
EFI_FV_NAMEGUID_STRING = "EFI_FVNAME_GUID"
EFI_CAPSULE_GUID_STRING = "EFI_CAPSULE_GUID"
EFI_CAPSULE_HEADER_SIZE_STRING = "EFI_CAPSULE_HEADER_SIZE"
EFI_CAPSULE_FLAGS_STRING = "EFI_CAPSULE_FLAGS"
EFI_OEM_CAPSULE_FLAGS_STRING = "EFI_OEM_CAPSULE_FLAGS"
EFI_CAPSULE_VERSION_STRING = "EFI_CAPSULE_VERSION"

EFI_FV_TOTAL_SIZE_STRING = "EFI_FV_TOTAL_SIZE"
EFI_FV_TAKEN_SIZE_STRING = "EFI_FV_TAKEN_SIZE"
EFI_FV_SPACE_SIZE_STRING = "EFI_FV_SPACE_SIZE"

#
# Attributes section
#
EFI_FVB2_READ_DISABLED_CAP_STRING = "EFI_READ_DISABLED_CAP"
EFI_FVB2_READ_ENABLED_CAP_STRING = "EFI_READ_ENABLED_CAP"
EFI_FVB2_READ_STATUS_STRING = "EFI_READ_STATUS"

EFI_FVB2_WRITE_DISABLED_CAP_STRING = "EFI_WRITE_DISABLED_CAP"
EFI_FVB2_WRITE_ENABLED_CAP_STRING = "EFI_WRITE_ENABLED_CAP"
EFI_FVB2_WRITE_STATUS_STRING = "EFI_WRITE_STATUS"

EFI_FVB2_LOCK_CAP_STRING = "EFI_LOCK_CAP"
EFI_FVB2_LOCK_STATUS_STRING = "EFI_LOCK_STATUS"

EFI_FVB2_STICKY_WRITE_STRING = "EFI_STICKY_WRITE"
EFI_FVB2_MEMORY_MAPPED_STRING = "EFI_MEMORY_MAPPED"
EFI_FVB2_ERASE_POLARITY_STRING = "EFI_ERASE_POLARITY"

EFI_FVB2_READ_LOCK_CAP_STRING = "EFI_READ_LOCK_CAP"
EFI_FVB2_READ_LOCK_STATUS_STRING = "EFI_READ_LOCK_STATUS"
EFI_FVB2_WRITE_LOCK_CAP_STRING = "EFI_WRITE_LOCK_CAP"
EFI_FVB2_WRITE_LOCK_STATUS_STRING = "EFI_WRITE_LOCK_STATUS"

EFI_FVB2_ALIGNMENT_1_STRING = "EFI_FVB2_ALIGNMENT_1"
EFI_FVB2_ALIGNMENT_2_STRING = "EFI_FVB2_ALIGNMENT_2"
EFI_FVB2_ALIGNMENT_4_STRING = "EFI_FVB2_ALIGNMENT_4"
EFI_FVB2_ALIGNMENT_8_STRING = "EFI_FVB2_ALIGNMENT_8"
EFI_FVB2_ALIGNMENT_16_STRING = "EFI_FVB2_ALIGNMENT_16"
EFI_FVB2_ALIGNMENT_32_STRING = "EFI_FVB2_ALIGNMENT_32"
EFI_FVB2_ALIGNMENT_64_STRING = "EFI_FVB2_ALIGNMENT_64"
EFI_FVB2_ALIGNMENT_128_STRING = "EFI_FVB2_ALIGNMENT_128"
EFI_FVB2_ALIGNMENT_256_STRING = "EFI_FVB2_ALIGNMENT_256"
EFI_FVB2_ALIGNMENT_512_STRING = "EFI_FVB2_ALIGNMENT_512"
EFI_FVB2_ALIGNMENT_1K_STRING = "EFI_FVB2_ALIGNMENT_1K"
EFI_FVB2_ALIGNMENT_2K_STRING = "EFI_FVB2_ALIGNMENT_2K"
EFI_FVB2_ALIGNMENT_4K_STRING = "EFI_FVB2_ALIGNMENT_4K"
EFI_FVB2_ALIGNMENT_8K_STRING = "EFI_FVB2_ALIGNMENT_8K"
EFI_FVB2_ALIGNMENT_16K_STRING = "EFI_FVB2_ALIGNMENT_16K"
EFI_FVB2_ALIGNMENT_32K_STRING = "EFI_FVB2_ALIGNMENT_32K"
EFI_FVB2_ALIGNMENT_64K_STRING = "EFI_FVB2_ALIGNMENT_64K"
EFI_FVB2_ALIGNMENT_128K_STRING = "EFI_FVB2_ALIGNMENT_128K"
EFI_FVB2_ALIGNMENT_256K_STRING = "EFI_FVB2_ALIGNMENT_256K"
EFI_FVB2_ALIGNMENT_512K_STRING = "EFI_FVB2_ALIGNMENT_512K"
EFI_FVB2_ALIGNMENT_1M_STRING = "EFI_FVB2_ALIGNMENT_1M"
EFI_FVB2_ALIGNMENT_2M_STRING = "EFI_FVB2_ALIGNMENT_2M"
EFI_FVB2_ALIGNMENT_4M_STRING = "EFI_FVB2_ALIGNMENT_4M"
EFI_FVB2_ALIGNMENT_8M_STRING = "EFI_FVB2_ALIGNMENT_8M"
EFI_FVB2_ALIGNMENT_16M_STRING = "EFI_FVB2_ALIGNMENT_16M"
EFI_FVB2_ALIGNMENT_32M_STRING = "EFI_FVB2_ALIGNMENT_32M"
EFI_FVB2_ALIGNMENT_64M_STRING = "EFI_FVB2_ALIGNMENT_64M"
EFI_FVB2_ALIGNMENT_128M_STRING = "EFI_FVB2_ALIGNMENT_128M"
EFI_FVB2_ALIGNMENT_256M_STRING = "EFI_FVB2_ALIGNMENT_256M"
EFI_FVB2_ALIGNMENT_512M_STRING = "EFI_FVB2_ALIGNMENT_512M"
EFI_FVB2_ALIGNMENT_1G_STRING = "EFI_FVB2_ALIGNMENT_1G"
EFI_FVB2_ALIGNMENT_2G_STRING = "EFI_FVB2_ALIGNMENT_2G"

EFI_FV_WEAK_ALIGNMENT_STRING = "EFI_WEAK_ALIGNMENT"

#
# File sections
#
EFI_FILE_NAME_STRING = "EFI_FILE_NAME"

ONE_STRING = "1"
ZERO_STRING = "0"
TRUE_STRING = "TRUE"
FALSE_STRING = "FALSE"
NULL_STRING = "NULL"

#
# Fv extend File name
#
EFI_FV_EXT_HEADER_FILE_NAME = "EFI_FV_EXT_HEADER_FILE_NAME"

#
# Fv Default attributes
#
FV_DEFAULT_ATTRIBUTE = 0x0004FEFF

mEfiFirmwareFileSystem2Guid = ModifyGuidFormat(
    '8C8CE578-8A3D-4f1c-9935-896185C32DD3')
mEfiFirmwareFileSystem3Guid = ModifyGuidFormat(
    '5473C07A-3DCB-4dca-BD6F-1E9689E7349A')

mFileGuidArray = list()

mFvbAttributeName = [
    EFI_FVB2_READ_DISABLED_CAP_STRING,
    EFI_FVB2_READ_ENABLED_CAP_STRING,
    EFI_FVB2_READ_STATUS_STRING,
    EFI_FVB2_WRITE_DISABLED_CAP_STRING,
    EFI_FVB2_WRITE_ENABLED_CAP_STRING,
    EFI_FVB2_WRITE_STATUS_STRING,
    EFI_FVB2_LOCK_CAP_STRING,
    EFI_FVB2_LOCK_STATUS_STRING,
    None,
    EFI_FVB2_STICKY_WRITE_STRING,
    EFI_FVB2_MEMORY_MAPPED_STRING,
    EFI_FVB2_ERASE_POLARITY_STRING,
    EFI_FVB2_READ_LOCK_CAP_STRING,
    EFI_FVB2_READ_LOCK_STATUS_STRING,
    EFI_FVB2_WRITE_LOCK_CAP_STRING,
    EFI_FVB2_WRITE_LOCK_STATUS_STRING
]

mFvbAlignmentName = [
    EFI_FVB2_ALIGNMENT_1_STRING,
    EFI_FVB2_ALIGNMENT_2_STRING,
    EFI_FVB2_ALIGNMENT_4_STRING,
    EFI_FVB2_ALIGNMENT_8_STRING,
    EFI_FVB2_ALIGNMENT_16_STRING,
    EFI_FVB2_ALIGNMENT_32_STRING,
    EFI_FVB2_ALIGNMENT_64_STRING,
    EFI_FVB2_ALIGNMENT_128_STRING,
    EFI_FVB2_ALIGNMENT_256_STRING,
    EFI_FVB2_ALIGNMENT_512_STRING,
    EFI_FVB2_ALIGNMENT_1K_STRING,
    EFI_FVB2_ALIGNMENT_2K_STRING,
    EFI_FVB2_ALIGNMENT_4K_STRING,
    EFI_FVB2_ALIGNMENT_8K_STRING,
    EFI_FVB2_ALIGNMENT_16K_STRING,
    EFI_FVB2_ALIGNMENT_32K_STRING,
    EFI_FVB2_ALIGNMENT_64K_STRING,
    EFI_FVB2_ALIGNMENT_128K_STRING,
    EFI_FVB2_ALIGNMENT_256K_STRING,
    EFI_FVB2_ALIGNMENT_512K_STRING,
    EFI_FVB2_ALIGNMENT_1M_STRING,
    EFI_FVB2_ALIGNMENT_2M_STRING,
    EFI_FVB2_ALIGNMENT_4M_STRING,
    EFI_FVB2_ALIGNMENT_8M_STRING,
    EFI_FVB2_ALIGNMENT_16M_STRING,
    EFI_FVB2_ALIGNMENT_32M_STRING,
    EFI_FVB2_ALIGNMENT_64M_STRING,
    EFI_FVB2_ALIGNMENT_128M_STRING,
    EFI_FVB2_ALIGNMENT_256M_STRING,
    EFI_FVB2_ALIGNMENT_512M_STRING,
    EFI_FVB2_ALIGNMENT_1G_STRING,
    EFI_FVB2_ALIGNMENT_2G_STRING
]

mArm = False
mLoongArch = False
mRiscV = False
mFvBaseAddress = list()


def SIGNATURE_16(A, B):
    return (A | (B << 8))


def SIGNATURE_32(A, B, C, D):
    return SIGNATURE_16(A, B) | (SIGNATURE_16(C, D) << 16)


def SIGNATURE_64(A, B, C, D, E, F, G, H):
    return (SIGNATURE_32(A, B, C, D) | (
        (SIGNATURE_32(E, F, G, H)) << 32) & 0xffffffffffffffff)


#
# VTF (Firmware Volume Top File) signatures
#
IA32_X64_VTF_SIGNATURE_OFFSET = 0x14
IA32_X64_VTF0_SIGNATURE = SIGNATURE_32(ord('V'), ord('T'), ord('F'), 0)

#
# Defines to calculate the offset for PEI CORE entry points
#
IA32_PEI_CORE_ENTRY_OFFSET = 0x20

#
# Defines to calculate the offset for IA32 SEC CORE entry point
#
IA32_SEC_CORE_ENTRY_OFFSET = 0xD

#
# Symbol file definitions, current max size if 512K
#
SYMBOL_FILE_SIZE = 0x80000

FV_IMAGES_TOP_ADDRESS = 0x100000000
FvImage = None

#
# Following definition is used for FIT in IPF
#
COMP_TYPE_FIT_PEICORE = 0x10
COMP_TYPE_FIT_UNUSED = 0x7F

FIT_TYPE_MASK = 0x7F
CHECKSUM_BIT_MASK = 0x80

MAX_LONG_FILE_PATH = 4096

ARM64_UNCONDITIONAL_JUMP_INSTRUCTION = 0x14000000

#
# Arm instruction to jump to Fv entry instruction in Arm or Thumb mode.
# From ARM Arch Ref Manual versions b/c/d, section A8.8.25 BL, BLX (immediate)
# BLX (encoding A2) branches to offset in Thumb instruction set mode.
# BL (encoding A1) branches to offset in Arm instruction set mode.
#
ARM_JUMP_OFFSET_MAX = 0xffffff

#
# Arm instruction to return from exception (MOVS PC, LR)
#
ARM_RETURN_FROM_EXCEPTION = 0xE1B0F07E


class FV_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ("BaseAddressSet", c_bool),
        ("BaseAddress", c_uint64),
        ("FvFileSystemGuid", GUID),
        ("FvFileSystemGuidSet", c_bool),
        ("FvNameGuid", GUID),
        ("FvNameGuidSet", c_bool),
        ("FvExtHeaderFile", c_wchar_p),
        ("Size", c_uint),
        ("FvAttributes", c_uint32),
        ("FvName", c_wchar_p),
        ("FvBlocks", ARRAY(EFI_FV_BLOCK_MAP_ENTRY, MAX_NUMBER_OF_FV_BLOCKS)),
        ("FvFiles", ARRAY(c_wchar_p, MAX_NUMBER_OF_FILES_IN_FV)),
        ("SizeOfFvFiles", ARRAY(c_uint32, MAX_NUMBER_OF_FV_BLOCKS)),
        ("IsPiFvImage", c_bool),
        ("ForceRebase", c_int8),
    ]


class CAP_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ("CapGuid", GUID),
        ("HeaderSize", c_uint32),
        ("Flags", c_uint32),
        ("CapName", c_int8),
        ("CapFiles",
         ARRAY(c_wchar_p, MAX_NUMBER_OF_FILES_IN_CAP))
    ]


class FvLibrary(object):
    def __init__(self, Fv: bytes):
        self.FvHeader = None
        self.FvLength = 0
        self.FvBuffer = Fv
        self.InitializeFvLib()

    def InitializeFvLib(self):
        # Veriry input arguments
        if not self.FvBuffer:
            EdkLogger.error(None, PARAMETER_INVALID,
                            gErrorMessage[PARAMETER_INVALID])
        self.FvHeader = self.GetFvHeader(self.FvBuffer)
        self.FvLength = self.FvHeader.FvLength

    def GetFvHeader(self, FvBuffer: bytes):
        FvHeader = EFI_FIRMWARE_VOLUME_HEADER.from_buffer_copy(
            FvBuffer)
        FvHeaderLength = FvHeader.HeaderLength
        HeaderBuffer = FvBuffer[:FvHeaderLength]
        Nums = (len(HeaderBuffer) - sizeof(EFI_FIRMWARE_VOLUME_HEADER) + sizeof(
            EFI_FV_BLOCK_MAP_ENTRY)) // sizeof(EFI_FV_BLOCK_MAP_ENTRY)
        return Refine_FV_Header(Nums).from_buffer_copy(HeaderBuffer)

    def VerifyFfsFile(self, FfsFileBuffer: bytes):
        FfsHeader = GetFfsHeader(FfsFileBuffer)
        # Verify library has been initialized.
        if self.FvHeader == None or self.FvLength == 0:
            EdkLogger.error('', ABORT_ERROR, "Library not initialized.")
        # Verify FV header
        self.VerifyFv()
        FfsHeaderSize = FfsHeader.HeaderLength
        # Get the erase polarity.
        ErasePolarity = self.GetErasePolarity()
        if ErasePolarity:
            BlankHeader = bytes([0xff for i in range(FfsHeaderSize)])
        else:
            BlankHeader = bytes(FfsHeaderSize)

        # Check if we have free space
        if BlankHeader == struct2stream(FfsHeader):
            EdkLogger.error(None, PARAMETER_INVALID,
                            "Ffs header is free space.")

        # Convert the GUID to a string so we can at least report which file
        # if we find an error.
        FileGuidString = PrintGuidToBuffer(FfsHeader.Name, True)

        # Verify file header checksum
        SavedState = FfsHeader.State
        FfsHeader.State = 0
        SavedCheckSum = FfsHeader.IntegrityCheck.Checksum.File
        FfsHeader.IntegrityCheck.Checksum.File = 0
        CheckSum = CalculateSum8(struct2stream(FfsHeader))

        FfsHeader.State = SavedState
        FfsHeader.IntegrityCheck.Checksum.File = SavedCheckSum
        if CheckSum != 0:
            EdkLogger.error(None, 0,
                            "invalid FFS file header checksum, Ffs file with Guid %s" % FileGuidString)

        # Verify file checksum
        if FfsHeader.Attributes & FFS_ATTRIB_CHECKSUM:
            # Verify file data checksum
            FileLength = FfsHeader.Size
            CheckSum = CalculateChecksum8(FfsFileBuffer[FfsHeaderSize:])

            CheckSum = CheckSum + FfsHeader.IntegrityCheck.Checksum.File
            if CheckSum != 0:
                EdkLogger.error(None, 0,
                                "invalid FFS file header checksum, Ffs file with Guid %s" % FileGuidString)
        else:
            # File does not hace a checksum
            # Verify contents are 0xAA as spec'd
            if FfsHeader.IntegrityCheck.Checksum.File != FFS_FIXED_CHECKSUM:
                EdkLogger.error(None, PARAMETER_INVALID,
                                "invalid FFS file header checksum, Ffs file with Guid %s" % FileGuidString)

    def GetErasePolarity(self):
        if self.FvHeader == None or self.FvLength == 0:
            EdkLogger.error(None, PARAMETER_INVALID,
                            gErrorMessage.get(PARAMETER_INVALID))
        # Verify Fv header
        self.VerifyFv()

        if self.FvHeader.Attributes & EFI_FVB2_ERASE_POLARITY:
            ErasePolarity = True
        else:
            ErasePolarity = False
        return ErasePolarity

    def VerifyFv(self):
        # Verify input arguments
        if self.FvHeader == None:
            EdkLogger.error(None, 0,
                            gErrorMessage.get(PARAMETER_INVALID))

        if self.FvHeader.Signature != int.from_bytes(EFI_FVH_SIGNATURE,
                                                     byteorder='little'):
            EdkLogger.error("", FORMAT_NOT_SUPPORTED,
                            "Invalid Fv Header signature.")

        # Verify FV header checksum
        Checksum = CheckSum16(struct2stream(self.FvHeader))
        if Checksum != 0:
            EdkLogger.error(None, FORMAT_NOT_SUPPORTED,
                            "Invalid FV header checksum.")

    def GetNextFile(self, CurrentFileOff: int):
        """
        Get next file offset.
        @param CurrentFileOff: Current file start pos
        @return:
        """
        if self.FvHeader == None or self.FvLength == 0:
            EdkLogger.error(None, PARAMETER_INVALID,
                            gErrorMessage.get(PARAMETER_INVALID))

        self.VerifyFv()

        # Get first file
        if CurrentFileOff == 0:
            CurrentFileOff = sizeof(self.FvHeader)

            # Verify ffs file is valid
            self.VerifyFfsFile(self.FvBuffer[CurrentFileOff:])
            NextFileOff = CurrentFileOff
        else:
            # Verify file is in this FV
            CurrentFileSize = GetFfsHeader(
                self.FvBuffer[CurrentFileOff:]).FFS_FILE_SIZE
            if CurrentFileOff + CurrentFileSize > self.FvLength:
                NextFileOff = None
            else:
                NextFileOff = CurrentFileOff + CurrentFileSize
        while NextFileOff & (
            EFI_FFS_FILE_HEADER_ALIGNMENT - 1) != 0:
            NextFileOff += 1
        return NextFileOff

    def GetFileByType(self, FileType, Instance):
        if self.FvHeader == None or self.FvLength == 0:
            EdkLogger.error(None, PARAMETER_INVALID,
                            gErrorMessage.get(PARAMETER_INVALID))

        # Verify FV header
        self.VerifyFv()

        # Initialize the number of matching files found.
        FileCount = 0
        # Get next file
        CurrentFileOff = self.GetNextFile(0)

        while CurrentFileOff:
            CurrentFile = GetFfsHeader(self.FvBuffer[CurrentFileOff:])
            if not CurrentFile:
                return
            if FileType == EFI_FV_FILETYPE_ALL or CurrentFile.Type == FileType:
                FileCount += 1

            if FileCount == Instance:
                return CurrentFileOff

            CurrentFileOff = self.GetNextFile(CurrentFileOff)
            if not CurrentFileOff:
                EdkLogger.warn(None, 0,
                               "Error parsing FV image, FFS file with FileType 0x%x can't be found." % FileType)
                break
        return


def GetSectionByType(FfsBuffer: bytes, SectionType: str, Instance: int):
    """
    Find a section in a file by type and instance.  An instance of 1 is the first
    instance.  The function will return NULL if a matching section cannot be found.
    GUID-defined sections, if special processing is not needed, are handled in a
    depth-first manner.
    @param File:        Ffs file buffer.
    @param SectionType: Type of file to search for
    @param Instance:    Instance of the section to return.
    @return:            Section offset in the Ffs file image.
    """
    if not FfsBuffer or Instance == 0:
        return

    # We have already verified the FFS header before this.
    # So pass
    FfsHeader = GetFfsHeader(FfsBuffer)

    # Initialize the number of matching sections found.
    SectionCount = 0
    # Get the first section
    FirstSectionOff = FfsHeader.HeaderLength

    return SearchSectionByType(FirstSectionOff, FfsBuffer, SectionType,
                               SectionCount,
                               Instance)


def SearchSectionByType(FirstSectionOff, FfsBuffer, SectionType, StartIndex,
                        Instance):
    GuidSecAttr = 0
    GuidDataOffset = 0
    CurrentSectionOff = FirstSectionOff

    while CurrentSectionOff < len(FfsBuffer):
        CurrentCommonSection = EFI_COMMON_SECTION_HEADER.from_buffer_copy(
            FfsBuffer[CurrentSectionOff:])
        if CurrentCommonSection.Type == SectionType:
            StartIndex += 1

        if StartIndex == Instance:
            SectionPointer = CurrentSectionOff
            return SectionPointer

        # If the requesting section is not GUID-defined and
        # we find a GUID-defined section that doesn't need
        # special processing, go ahead to search the requesting
        # section inside the GUID-defined section.
        if CurrentCommonSection.Type == EFI_SECTION_GUID_DEFINED:
            if CurrentCommonSection.SECTION_SIZE == 0xffffff:
                CurrentCommonSection = EFI_COMMON_SECTION_HEADER2.from_buffer_copy(
                    FfsBuffer[CurrentSectionOff:])
            else:
                CurrentCommonSection = EFI_COMMON_SECTION_HEADER.from_buffer_copy(
                    FfsBuffer[CurrentSectionOff:])
            GuidSection = EFI_GUID_DEFINED_SECTION.from_buffer_copy(FfsBuffer[
                                                                    CurrentSectionOff + CurrentCommonSection.Common_Header_Size():])
            GuidSecAttr = GuidSection.Attributes
            GuidDataOffset = GuidSection.DataOffset

        if SectionType != EFI_SECTION_GUID_DEFINED and CurrentCommonSection.Type == EFI_SECTION_GUID_DEFINED and not (
            GuidSecAttr & EFI_GUIDED_SECTION_PROCESSING_REQUIRED):
            InnerCommonSectionOff = FirstSectionOff + CurrentCommonSection.Common_Header_Size() + GuidDataOffset

            SearchSectionByType(InnerCommonSectionOff, FfsBuffer, SectionType,
                                StartIndex, Instance)

        # Find next section (including compensating for alignment issues.
        SectionSize = CurrentCommonSection.SECTION_SIZE
        CurrentSectionOff += (SectionSize + 0x03) & (~ 3)

    # EdkLogger.warn(None, 0, "%s not found in this FFS file." % SectionType)
    return

    # @staticmethod


def GetFfsHeader(FfsBuffer: bytes):
    if len(FfsBuffer) == 0:
        return
    FfsHeader = EFI_FFS_FILE_HEADER.from_buffer_copy(FfsBuffer)
    if FfsHeader.Attributes & FFS_ATTRIB_LARGE_FILE:
        FfsHeader = EFI_FFS_FILE_HEADER2.from_buffer_copy(FfsBuffer)
    return FfsHeader


def _ARM_JUMP_TO_THUMB(Imm32):
    return (0xfa000000 |
            (((Imm32) & (1 << 1)) << (24 - 1)) |
            (((Imm32) >> 2) & 0x7fffff))


def ARM_JUMP_TO_THUMB(Offset):
    return _ARM_JUMP_TO_THUMB((Offset) - 8)
