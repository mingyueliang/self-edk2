## @file
# This file contains describes the public interfaces to the GenFvImage Library.
# The basic purpose of the library is to create Firmware Volume images.
#
# Copyright (c) 2004 - 2018, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
import os.path
import re
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from ctypes import *

from FirmwareStorageFormat.Common import struct2stream, GUID, ModifyGuidFormat
from FirmwareStorageFormat.FvHeader import *
from FirmwareStorageFormat.FfsFileHeader import *
from FirmwareStorageFormat.PeImageHeader import *
from FirmwareStorageFormat.SectionHeader import *
from Common import EdkLogger
from Common.BuildToolError import *
from Common.LongFilePathSupport import LongFilePath

from GenFv.ParseInf import *
from GenFv.common import CalculateChecksum16, CalculateChecksum8, \
    GetReverseCode, ModCheckSum
from GenFv.FvLib import *
from Common.BasePeCoff import *

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
#
#
EFI_FV_EXT_HEADER_FILE_NAME = "EFI_FV_EXT_HEADER_FILE_NAME"

#
# VTF (Firmware Volume Top File) signatures
#
IA32_X64_VTF_SIGNATURE_OFFSET = 0x14
# IA32_X64_VTF0_SIGNATURE = SIGNATURE_32('V','T','F',0)

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


class COMPONENT_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ('Size', c_uint8),
        ('ComponentName', c_wchar_p)
    ]


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


class FIT_TABLE(Structure):
    _pack_ = 1
    _fields_ = [
        ("CompAddress", c_uint64),
        ("CompSize", c_uint32),
        ("CompVersion", c_uint16),
        ("CvAndType", c_uint8),
        ("CheckSum", c_uint8)
    ]


class MEMORY_FILE(Structure):
    _pack_ = 1
    _fields_ = [
        ("FileImage", c_wchar_p),
        ("CurrentFilePointer", c_uint),
        ("Eof", c_uint)
    ]


FV_DEFAULT_ATTRIBUTE = 0x0004FEFF
mFvDataInfo = FV_INFO()
mCapDataInfo = CAP_INFO()

mEfiFirmwareFileSystem2Guid = ModifyGuidFormat(
    '8C8CE578-8A3D-4f1c-9935-896185C32DD3')
mEfiFirmwareFileSystem3Guid = ModifyGuidFormat(
    '5473C07A-3DCB-4dca-BD6F-1E9689E7349A')
mFvTotalSize = 0
mFvTakenSize = 0

mFileGuidArray = list()
MaxFfsAlignment = 0

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

mIsLargeFfs = False

mFvBaseAddress = list()

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


def ARM_JUMP_TO_ARM(Offset):
    return (0xeb000000 | ((Offset - 8) >> 2))


def _ARM_JUMP_TO_THUMB(Imm32):
    return (0xfa000000 |
            (((Imm32) & (1 << 1)) << (24 - 1)) |
            (((Imm32) >> 2) & 0x7fffff))


def ARM_JUMP_TO_THUMB(Offset):
    return _ARM_JUMP_TO_THUMB((Offset) - 8)


def ParseCapInf(InfFileImage: bytes) -> None:
    Inf = ParseInf(InfFileImage)
    Options = Inf.InfDict.get(OPTIONS_SECTION_STRING[1:-1])
    if Options != None:
        # Read the Capsuel guid
        CapGuid = Options.get(EFI_CAPSULE_GUID_STRING)
        if CapGuid != None:
            mCapDataInfo.CapGuid = ModifyGuidFormat(CapGuid)
            EdkLogger.info(
                "Capsule Guid, %s = %s" % (EFI_CAPSULE_GUID_STRING, CapGuid))
        else:
            EdkLogger.error(None, PARAMETER_INVALID,
                            "Invalid parameter, %s = %s" % (
                            EFI_CAPSULE_GUID_STRING, CapGuid))
        # Read the Capsule Header Size
        HeaderSize = Options.get(EFI_CAPSULE_HEADER_SIZE_STRING)
        if HeaderSize != None:
            mCapDataInfo.HeaderSize = HeaderSize & 0xffffffff
            EdkLogger.info("Capsule Header Size, %s = %s" % (
            EFI_CAPSULE_HEADER_SIZE_STRING, HeaderSize))
        else:
            EdkLogger.error(None, PARAMETER_INVALID,
                            "Invalid parameter, %s = %s" % (
                                EFI_CAPSULE_HEADER_SIZE_STRING, HeaderSize))
        # Read the Capsule Flag
        Flags = Options.get(EFI_CAPSULE_FLAGS_STRING)
        if Flags != None:
            if Flags.find("PopulateSystemTable") != -1:
                mCapDataInfo.Flags |= (
                        CAPSULE_FLAGS_PERSIST_ACROSS_RESET | CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE)
            elif Flags.find("InitiateReset") != -1:
                mCapDataInfo.Flags |= CAPSULE_FLAGS_INITIATE_RESET
            elif Flags.find("PersistAcrossReset") != -1:
                mCapDataInfo.Flags |= CAPSULE_FLAGS_INITIATE_RESET
            else:
                EdkLogger.error(None, PARAMETER_INVALID,
                                "Invalid parameter, invalid Flag setting for %s." % EFI_CAPSULE_FLAGS_STRING)
            EdkLogger.info("Capsule Flag %s" % Flags)
        OemFlags = Options.get(OPTIONS_SECTION_STRING)
        if OemFlags != None:
            if OemFlags > 0xffff:
                EdkLogger.error(None, PARAMETER_INVALID,
                                "invalid Flag setting for %s. Must be integer value between 0x0000 and 0xffff." % OemFlags)
            mCapDataInfo.Flags |= OemFlags
            EdkLogger.info("Capsule Extend Flag %s" % OemFlags)

        # Read Capsule file name
        CapName = Options.get(EFI_FILE_NAME_STRING)
        if CapName != None:
            mCapDataInfo.CapName = CapName
        # Read the capsule file image
        FileSection = Inf.InfDict.get(FILES_SECTION_STRING[1:-1])
        CapsuleFiles = FileSection.get(EFI_FILE_NAME_STRING)
        Number = 0
        for Index in range(len(CapsuleFiles)):
            mCapDataInfo.CapFiles[Index] = CapsuleFiles[Index]
            Number += 1

        if Number == 0:
            EdkLogger.warn("Capsule compenents are not specified.")


def GenerateCapImage(InfFileImage: bytes, CapFileName: str) -> None:
    """
    This is the main function which will be called from application to create UEFI Capsule image.
    :param InfFileImage: Buffer containing the INF file contents.
    :param CapFileName:  Requested name for the Cap file.
    :return:
    """
    # 1. Read the Capsule guid, parse inf file for Capsule Guid
    if len(InfFileImage) != 0:
        # Parse the Cap inf file for header information
        ParseCapInf(InfFileImage)

    if mCapDataInfo.HeaderSize == 0:
        # Make header size align 16 bytes
        mCapDataInfo.HeaderSize = sizeof(EFI_CAPSULE_HEADER)

    if mCapDataInfo.HeaderSize < sizeof(EFI_CAPSULE_HEADER):
        EdkLogger.error(None, PARAMETER_INVALID,
                        "The specified HeaderSize cannot be less than the size of EFI_CAPSULE_HEADER.")

    if CapFileName == None and mCapDataInfo.CapName:
        CapFileName = mCapDataInfo.CapName

    if not CapFileName:
        EdkLogger.error(None, PARAMETER_MISSING,
                        "Missing required argument, Output Capsule file name")

    # Calculate the size of capsule iamge
    CapSize = mCapDataInfo.HeaderSize
    for Index in range(MAX_NUMBER_OF_FILES_IN_CAP):
        if mCapDataInfo.CapFiles[Index]:
            with open(mCapDataInfo.CapFiles[Index], 'rb') as file:
                CapSize += len(file.read())

    # Allocate buffer for capsule image.
    CapBuffer = bytearray(CapSize)
    # create capsule header and get capsule body
    CapsuleHeader = EFI_CAPSULE_HEADER()
    CapsuleHeader.CapsuleGuid = mCapDataInfo.CapGuid
    CapsuleHeader.HeaderSize = mCapDataInfo.HeaderSize
    CapsuleHeader.Flags = mCapDataInfo.Flags
    CapsuleHeader.CapsuleImageSize = CapSize
    CapBuffer[:mCapDataInfo.HeaderSize] = struct2stream(CapsuleHeader)

    CurCapPointer = CapsuleHeader.HeaderSize
    for file in mCapDataInfo.CapFiles:
        if file:
            with open(file, 'rb') as file:
                FileBuffer = file.read()
                FileSize = len(FileBuffer)
                CapBuffer[CurCapPointer:CurCapPointer + FileSize] = FileBuffer

    # write capsule data into the output file
    WriteFile(CapFileName, CapBuffer)


def ParseFvInf(Stream: bytes) -> None:
    """
    This function parses a FV.INF file and copies info into a FV_INFO structure.
    @param Stream: Fv inf file data - bytes
    @return: Return code
    """
    # Parse the FV inf file for header information
    Inf = ParseInf(Stream)
    options = Inf.InfDict.get(OPTIONS_SECTION_STRING[1:-1])
    # 1. Read the FV base address
    if not mFvDataInfo.BaseAddressSet:
        if options != None:
            BaseAddress = options.get(EFI_FV_BASE_ADDRESS_STRING)
            if BaseAddress != None:
                mFvDataInfo.BaseAddress = int(BaseAddress[0], 16)
                mFvDataInfo.BaseAddressSet = True
    # 2. Read the FV File System Guid
    if not mFvDataInfo.FvFileSystemGuidSet:
        if options != None:
            GuidValue = options.get(EFI_FV_FILESYSTEMGUID_STRING)
            if GuidValue != None:
                mFvDataInfo.FvFileSystemGuid = GuidValue[0]
                mFvDataInfo.FvFileSystemGuidSet = True
    # 3. Read the FV Extension Header File Name
    Attributes = Inf.InfDict.get(ATTRIBUTES_SECTION_STRING[1:-1])
    ExtHeaderFile = Attributes.get(EFI_FV_EXT_HEADER_FILE_NAME)
    if ExtHeaderFile != None:
        mFvDataInfo.FvExtHeaderFile = ExtHeaderFile[0]
    # 4. Read the FV file name
    FvFileName = options.get(EFI_FV_FILE_NAME_STRING)
    if FvFileName != None:
        mFvDataInfo.FvName = FvFileName[0]
    # 5. Read Fv Attribute
    for Index in range(len(mFvbAttributeName)):
        AttrNameFromInf = Attributes.get(mFvbAttributeName[Index])
        if mFvbAttributeName[Index] != None and AttrNameFromInf != None:
            if AttrNameFromInf[0] == TRUE_STRING or AttrNameFromInf[
                0] == ONE_STRING:
                mFvDataInfo.FvAttributes |= 1 << Index
            elif AttrNameFromInf[0] != FALSE_STRING and AttrNameFromInf[
                0] != ZERO_STRING:
                EdkLogger.error("GenFv",
                                "Invalid parameter, %s expected %s | %s" % (
                                    mFvbAttributeName[Index], "TRUE", "FALSE"))

    # 6. Read Fv Alignment
    for Index in range(len(mFvbAlignmentName)):
        Alignment = Attributes.get(mFvbAttributeName[Index])
        if Alignment != None:
            if Alignment[0] == TRUE_STRING:
                mFvDataInfo.FvAttributes |= Index << 16
                EdkLogger.info(
                    "FV file Alignment, Align = %s" % mFvbAlignmentName[Index])
                break

    # 7. Read weak alignment flag
    AlignmentFlag = Attributes.get(EFI_FV_WEAK_ALIGNMENT_STRING)
    if AlignmentFlag != None:
        if AlignmentFlag[0] == TRUE_STRING or AlignmentFlag[0] == ONE_STRING:
            mFvDataInfo.FvAttributes |= EFI_FVB2_WEAK_ALIGNMENT
        elif AlignmentFlag[0] != FALSE_STRING and AlignmentFlag[
            0] != ZERO_STRING:
            EdkLogger.error('GenFv', PARAMETER_INVALID,
                            "Invalid parameter, Weak alignment value expected one of TRUE, FALSE, 1 or 0.")

    # 8. Read block maps
    flag = 0
    BlockSize = options.get(EFI_BLOCK_SIZE_STRING)
    NumBlock = options.get(EFI_NUM_BLOCKS_STRING)
    for Index in range(MAX_NUMBER_OF_FV_BLOCKS):
        if mFvDataInfo.FvBlocks[Index].Length == 0 and Index < len(BlockSize):
            # Read block size

            if BlockSize:
                # Update block size
                mFvDataInfo.FvBlocks[Index].Length = int(BlockSize[Index], 16)
                EdkLogger.info("FV Block Size, %s = %s" % (
                    EFI_BLOCK_SIZE_STRING, BlockSize[Index]))
            else:
                #
                # If there is no blocks size, but there is the number of block, then we have a mismatched pair
                # and should return an error.
                #

                if not NumBlock:
                    EdkLogger.error('GenFv', PARAMETER_INVALID,
                                    'Invalid patameter, both %s and %s must be specified.' % (
                                        EFI_NUM_BLOCKS_STRING,
                                        EFI_BLOCK_SIZE_STRING))

                else:
                    break
            # Read blocks number
            # BlockNumber = options.get(EFI_NUM_BLOCKS_STRING)
            if NumBlock:
                mFvDataInfo.FvBlocks[Index].NumBlocks = int(NumBlock[Index], 16)
                EdkLogger.info("FV Block Number, %s = %s" % (
                    EFI_NUM_BLOCKS_STRING, NumBlock[Index]))
        else:
            break
        flag += 1

    if flag == 0:
        EdkLogger.error("GenFv", PARAMETER_MISSING,
                        "Missing reqeired argument, block size.")

    # 9. Read files

    FfsFiles = Inf.InfDict.get(FILES_SECTION_STRING[1:-1]).get(
        EFI_FILE_NAME_STRING)
    if FfsFiles:
        for index in range(len(FfsFiles)):
            mFvDataInfo.FvFiles[index] = FfsFiles[index]
    else:
        EdkLogger.warn('', "FV components are not specified.")


def CalculateFvSize(FvInfo: FV_INFO) -> None:
    """
    Calculate Fv Size.
    @param FvInfo: Fv Structure
    @return: Return code
    """
    FvExtHeaderSize = 0
    MaxPadFileSize = 0
    VtfFileSize = 0
    global mIsLargeFfs
    mIsLargeFfs = False
    FfsHeader = None
    # Compute size for easy access later
    for Index in range(MAX_NUMBER_OF_FV_BLOCKS):
        if FvInfo.FvBlocks[Index].NumBlocks > 0 and FvInfo.FvBlocks[
            Index].Length > 0:
            FvInfo.Size += FvInfo.FvBlocks[Index].NumBlocks * FvInfo.FvBlocks[
                Index].Length

    # Calculate the required sizes for all FFS files.
    CurrentOffset = sizeof(EFI_FIRMWARE_VOLUME_HEADER())

    for Index in range(MAX_NUMBER_OF_FV_BLOCKS):
        CurrentOffset += sizeof(EFI_FV_BLOCK_MAP_ENTRY())
        if FvInfo.FvBlocks[Index].NumBlocks == 0 or FvInfo.FvBlocks[
            Index].Length == 0:
            break

    # Calculate PI extension header
    if FvInfo.FvExtHeaderFile:
        with open(FvInfo.FvExtHeaderFile, 'rb') as file:
            FvExtHeaderSize = len(file.read())
        if sizeof(EFI_FFS_FILE_HEADER()) + FvExtHeaderSize >= MAX_FFS_SIZE:
            CurrentOffset += sizeof(EFI_FFS_FILE_HEADER2()) + FvExtHeaderSize
            mIsLargeFfs = True
        else:
            CurrentOffset += sizeof(EFI_FFS_FILE_HEADER()) + FvExtHeaderSize
        CurrentOffset = (CurrentOffset + 7) & (~7)
    elif FvInfo.FvNameGuidSet:
        CurrentOffset += sizeof(EFI_FFS_FILE_HEADER()) + sizeof(
            EFI_FIRMWARE_VOLUME_EXT_HEADER())
        CurrentOffset = (CurrentOffset + 7) & (~7)

    # Accumulate every FFS file size.
    for Index in range(MAX_NUMBER_OF_FILES_IN_FV):
        if FvInfo.FvFiles[Index]:
            # OPen ffs file
            with open(LongFilePath(FvInfo.FvFiles[Index]), 'rb') as file:
                FfsData = file.read()
                FfsFileSize = len(FfsData)
            if FfsFileSize >= MAX_FFS_SIZE:
                FfsHeaderSize = sizeof(EFI_FFS_FILE_HEADER2())
                mIsLargeFfs = True
            else:
                FfsHeaderSize = sizeof(EFI_FFS_FILE_HEADER())
            # Read ffs file header
            FfsHeader = EFI_FFS_FILE_HEADER.from_buffer_copy(FfsData)

            if FvInfo.IsPiFvImage:
                # Check whether this ffs file is vtf file
                if IsVtfFile(FfsHeader):
                    if VtfFileFlag:
                        EdkLogger.error('', FILE_CHECKSUM_FAILURE,
                                        "Invalid, One Fv image can't have two vtf files.")
                        return FILE_CHECKSUM_FAILURE
                    VtfFileFlag = True
                    VtfFileSize = FfsFileSize
                    continue
                # Get the alignment of FFS file
                FfsAlignment = ReadFfsAlignment(FfsHeader)
                FfsAlignment = 1 << FfsAlignment
                # Add Pad file
                if (CurrentOffset + FfsHeaderSize) % FfsAlignment != 0:
                    # Only EFI_FFS_FILE_HEADER is needed for a pad section.
                    OrigOffset = CurrentOffset
                    CurrentOffset = (CurrentOffset + FfsHeaderSize + sizeof(
                        EFI_FFS_FILE_HEADER()) + FfsAlignment - 1) & ~(
                        FfsAlignment - 1)
                    CurrentOffset -= FfsHeaderSize
                    if (CurrentOffset - OrigOffset) > MaxPadFileSize:
                        MaxPadFileSize = CurrentOffset - OrigOffset

            # Add ffs file size
            if FvInfo.SizeOfFvFiles[Index] > FfsFileSize:
                CurrentOffset += FvInfo.SizeOfFvFiles[Index]
            else:
                CurrentOffset += FfsFileSize
            # Make next ffs file start at QWord Boundary
            if FvInfo.IsPiFvImage:
                CurrentOffset = (
                                    CurrentOffset + EFI_FFS_FILE_HEADER_ALIGNMENT - 1) & ~(
                    EFI_FFS_FILE_HEADER_ALIGNMENT - 1)

    CurrentOffset += VtfFileSize
    EdkLogger.info(
        "FvImage size, the calculated fv image size is 0x%X and the current set fv image size is 0x%x" % (
            CurrentOffset, FvInfo.Size))

    # Update FvInfo data
    if FvInfo.Size == 0:
        FvInfo.FvBlocks[0].NumBlocks = CurrentOffset // FvInfo.FvBlocks[
            0].Length + (1 if CurrentOffset % FvInfo.FvBlocks[0].Length else 0)
        FvInfo.Size = FvInfo.FvBlocks[0].NumBlocks * FvInfo.FvBlocks[0].Length
        FvInfo.FvBlocks[0].NumBlocks = 0
        FvInfo.FvBlocks[0].Length = 0
    elif FvInfo.Size < CurrentOffset:
        # Not Invalid
        EdkLogger.error("", PARAMETER_INVALID,
                        "Invalid, the required fv image size 0x%x exceeds the set fv image size 0x%x" % (
                            CurrentOffset, FvInfo.Size))

    # Set Fv Size Information
    global mFvTotalSize, mFvTakenSize
    mFvTotalSize = FvInfo.Size
    mFvTakenSize = CurrentOffset
    if mFvTakenSize == mFvTotalSize and MaxPadFileSize > 0:
        mFvTakenSize = mFvTakenSize - MaxPadFileSize


def ReadFfsAlignment(FfsHeader) -> int:
    Alignment = (FfsHeader.Attributes >> 3) & 0x07
    if Alignment == 0:
        # 1 byte alignment
        # if bit 1 have set, 128K byte alignment
        if FfsHeader.Attributes & FFS_ATTRIB_DATA_ALIGNMENT2:
            return 17
        else:
            return 0
    elif Alignment == 1:
        # 16 byte alignment
        # if bit 1 have set, 256K byte alignment
        if FfsHeader.Attributes & FFS_ATTRIB_DATA_ALIGNMENT2:
            return 18
        else:
            return 4
    elif Alignment == 2:
        # 128 byte alignment
        # if bit 1 have set, 512K byte alignment
        if FfsHeader.Attributes & FFS_ATTRIB_DATA_ALIGNMENT2:
            return 19
        else:
            return 7
    elif Alignment == 3:
        # 512 byte alignment
        # if bit 1 have set, 1M byte alignment
        if FfsHeader.Attributes & FFS_ATTRIB_DATA_ALIGNMENT2:
            return 20
        else:
            return 9
    elif Alignment == 4:
        # 1K byte alignment
        # if bit 1 have set, 2M byte alignment
        if FfsHeader.Attributes & FFS_ATTRIB_DATA_ALIGNMENT2:
            return 21
        else:
            return 10
    elif Alignment == 5:
        # 4K byte alignment
        # if bit 1 have set, 4M byte alignment
        if FfsHeader.Attributes & FFS_ATTRIB_DATA_ALIGNMENT2:
            return 22
        else:
            return 12
    elif Alignment == 6:
        # 32K byte alignment
        # if bit 1 have set , 8M byte alignment
        if FfsHeader.Attributes & FFS_ATTRIB_DATA_ALIGNMENT2:
            return 23
        else:
            return 15
    elif Alignment == 7:
        # 64K byte alignment
        # if bit 1 have set, 16M alignment
        if FfsHeader.Attributes & FFS_ATTRIB_DATA_ALIGNMENT2:
            return 24
        else:
            return 16
    return 0


def IsVtfFile(FfsHeader) -> bool:
    if not FfsHeader.Name.__cmp__(EFI_FFS_VOLUME_TOP_FILE_GUID):
        return True
    return False


def GenerateFvImage(Stream: bytes, FvFileName: str, MapFileName: str = None) -> None:
    FvExtHeader = None
    # Parse the FV inf file for header information
    ParseFvInf(Stream)

    # Update the file name return values
    if not FvFileName and mFvDataInfo.FvName:
        FvFileName = mFvDataInfo.FvName
    if not FvFileName:
        EdkLogger.error("GenFv", OPTION_MISSING,
                        "Missing options, Output file name")

    if mFvDataInfo.FvBlocks[0].Length == 0:
        EdkLogger.error("GenFv", OPTION_MISSING,
                        "Missing required argument, Block Size")

    # Debug message Fv File System Guid
    if mFvDataInfo.FvFileSystemGuidSet:
        EdkLogger.info(
            "FV File System Guid, %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X" % (
                mFvDataInfo.FvFileSystemGuid.Guid1,
                mFvDataInfo.FvFileSystemGuid.Guid2,
                mFvDataInfo.FvFileSystemGuid.Guid3,
                mFvDataInfo.FvFileSystemGuid.Guid4[0],
                mFvDataInfo.FvFileSystemGuid.Guid4[1],
                mFvDataInfo.FvFileSystemGuid.Guid4[2],
                mFvDataInfo.FvFileSystemGuid.Guid4[3],
                mFvDataInfo.FvFileSystemGuid.Guid4[4],
                mFvDataInfo.FvFileSystemGuid.Guid4[5],
                mFvDataInfo.FvFileSystemGuid.Guid4[6],
                mFvDataInfo.FvFileSystemGuid.Guid4[7]))
    # Add PI FV extension header
    if mFvDataInfo.FvExtHeaderFile:
        # Open the FV Extension Header file
        with open(LongFilePath(mFvDataInfo.FvExtHeaderFile), 'rb') as file:
            FvExtFileBuffer = file.read()
            FvExtHeader = EFI_FIRMWARE_VOLUME_EXT_HEADER.from_buffer_copy(
                FvExtFileBuffer)
        # See if there is an override for the FV Name GUID
        if mFvDataInfo.FvNameGuidSet:
            FvExtHeader.FvName = mFvDataInfo.FvNameGuid
        mFvDataInfo.FvNameGuid = FvExtHeader.FvName
        mFvDataInfo.FvNameGuidSet = True
    elif mFvDataInfo.FvNameGuidSet:
        FvExtHeader.FvName = mFvDataInfo.FvNameGuid
        FvExtHeader.ExtHeaderSize = sizeof(EFI_FIRMWARE_VOLUME_EXT_HEADER())

    # Debug message Fv Name Guid
    if mFvDataInfo.FvNameGuidSet:
        EdkLogger.info(
            "FV Name Guid, %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X" % (
                mFvDataInfo.FvNameGuid.Guid1,
                mFvDataInfo.FvNameGuid.Guid2,
                mFvDataInfo.FvNameGuid.Guid3,
                mFvDataInfo.FvNameGuid.Guid4[0],
                mFvDataInfo.FvNameGuid.Guid4[1],
                mFvDataInfo.FvNameGuid.Guid4[2],
                mFvDataInfo.FvNameGuid.Guid4[3],
                mFvDataInfo.FvNameGuid.Guid4[4],
                mFvDataInfo.FvNameGuid.Guid4[5],
                mFvDataInfo.FvNameGuid.Guid4[6],
                mFvDataInfo.FvNameGuid.Guid4[7]))
    if mFvDataInfo.FvFileSystemGuid.__cmp__(
        mEfiFirmwareFileSystem2Guid) or mFvDataInfo.FvFileSystemGuid.__cmp__(
        mEfiFirmwareFileSystem3Guid):
        mFvDataInfo.IsPiFvImage = True

    # FvMap file to log the function address of all modules in one Fvimage
    if MapFileName:
        if len(MapFileName) > MAX_LONG_FILE_PATH - 1:
            EdkLogger.error("", OPTION_VALUE_INVALID,
                            "Invalid option value, MapFileName %s is too long!" % MapFileName)

        FvMapName = MapFileName
    else:
        if len(FvFileName + '.map') > MAX_LONG_FILE_PATH + 1:
            EdkLogger.error("", OPTION_VALUE_INVALID,
                            "Invalid option value, FvFileName %s is too long!" % MapFileName)

        FvMapName = os.path.splitext(FvFileName)[0] + ".map"
    EdkLogger.info("FV Map file name is %s" % FvMapName)
    # FvReport file to log the FV information in one Fvimage
    if len(FvFileName + '.txt') > MAX_LONG_FILE_PATH - 1:
        EdkLogger.error("", OPTION_VALUE_INVALID,
                        "Invalid option value, FvFileName %s is too long!" % MapFileName)
    FvReportName = FvFileName + ".txt"
    #
    # Calculate the FV size and Update Fv Size based on the actual FFS files.
    # And Update mFvDataInfo data.
    #
    CalculateFvSize(mFvDataInfo)

    EdkLogger.info("The generated FV image size is %u bytes" % mFvDataInfo.Size)

    # support fv image and empty fv image
    FvImageSize = mFvDataInfo.Size

    # Allocate the FV, assure FvImage Header 8 byte alignment
    # FvBufferHeaderSize = FvImageSize + 8
    # FvImage pointer
    # FvImage = bytearray((FvBufferHeaderSize + 7) & ~ 7)
    FvImagePointer = 0

    if mFvDataInfo.FvAttributes == 0:
        # Set Default Fv Attribute
        mFvDataInfo.FvAttributes = FV_DEFAULT_ATTRIBUTE

    # TODO: Malloc Memery question.
    if mFvDataInfo.FvAttributes & EFI_FVB2_ERASE_POLARITY:
        # Init FvImage is 0xff
        FvImage = bytearray(
            [0xff for i in range((FvImageSize + 7) & ~ 7)])
    else:
        # Init FvImage is 0
        FvImage = bytearray(((FvImageSize + 7) & ~ 7))

    # Initialize FV header
    NumOfBlocks = 0
    for Index in range(MAX_NUMBER_OF_FV_BLOCKS):
        if mFvDataInfo.FvBlocks[Index].Length != 0:
            NumOfBlocks += 1
    # Need terminated block map
    FvHeader = Refine_FV_Header(NumOfBlocks + 1)()
    # Initialize the zero vector to all zeros.
    # Copy the Fv file system GUID
    FvHeader.FileSystemGuid = mFvDataInfo.FvFileSystemGuid
    FvHeader.FvLength = FvImageSize
    FvHeader.Signature = int.from_bytes(EFI_FVH_SIGNATURE, byteorder='little')
    FvHeader.Attributes = mFvDataInfo.FvAttributes
    FvHeader.Revision = EFI_FVH_REVISION
    FvHeader.ExtHeaderOffset = 0
    FvHeader.Reserved = 0

    # Copy firmware block map
    for Index in range(MAX_NUMBER_OF_FV_BLOCKS):
        if Index >= NumOfBlocks:
            # Add block map terminator, because default is zero
            # FvHeader.BlockMap[Index].NumBlocks = 0
            # FvHeader.BlockMap[Index].Length = 0
            break
        if mFvDataInfo.FvBlocks[Index].Length != 0:
            FvHeader.BlockMap[Index].NumBlocks = mFvDataInfo.FvBlocks[
                Index].NumBlocks
            FvHeader.BlockMap[Index].Length = mFvDataInfo.FvBlocks[Index].Length

    # Complete the header
    FvHeader.HeaderLength = sizeof(FvHeader)
    FvHeader.Checksum = 0
    FvHeader.Checksum = CalculateChecksum16(struct2stream(FvHeader))
    # FvHeader.Checksum = ModCheckSum(FvHeader)
    # FvBuf = struct2stream(FvHeader)
    FvImage[:FvHeader.HeaderLength] = struct2stream(FvHeader)
    # Initialize our "file" view of the buffer
    # TODO: Check?
    # FvImageMemoryFile = MEMORY_FILE()
    # FvImageMemoryFile.FileImage = FvImage
    # FvImageMemoryFile.CurrentFilePointer = FvHeader.HeaderLength
    # FvImageMemoryFile.Eof = FvImageSize

    # If there is no FFS file, generate one empty FV
    if not mFvDataInfo.FvFiles[0] and not mFvDataInfo.FvNameGuidSet:
        WriteFile(FvFileName, FvImage)
        return

    # record FV size information into FvMap file.
    with open(LongFilePath(FvMapName), 'w') as file:
        if mFvTotalSize != 0:
            file.write("%s = 0x%x\n" % (EFI_FV_TOTAL_SIZE_STRING, mFvTotalSize))
        if mFvTakenSize != 0:
            file.write("%s = 0x%x\n" % (EFI_FV_TAKEN_SIZE_STRING, mFvTakenSize))
        if mFvTotalSize != 0 and mFvTakenSize != 0:
            file.write("%s = 0x%x\n" % (
                EFI_FV_SPACE_SIZE_STRING, mFvTotalSize - mFvTakenSize))

    # record FV size information to FvReportFile.
    with open(LongFilePath(FvReportName), 'w') as file:
        file.write("%s = 0x%x\n" % (EFI_FV_TOTAL_SIZE_STRING, mFvTotalSize))
        file.write("%s = 0x%x\n" % (EFI_FV_TAKEN_SIZE_STRING, mFvTakenSize))
    # Vtf file image offset
    VtfFileImageAddress = FvImageSize
    FvImagePointer += FvHeader.HeaderLength
    # Add PI FV extendsize header
    if FvExtHeader != None:
        # Add FV Extended Header contents to the FV as a PAD file
        FvImage, FvImagePointer = AddPadFile(FvImage, 4,
                                             VtfFileImageAddress,
                                             FvExtHeader, 0,
                                             FvExtFileBuffer,
                                             FvImagePointer, NumOfBlocks)
        FvHeader = Refine_FV_Header(NumOfBlocks + 1).from_buffer_copy(FvImage)
        FvHeader.Checksum = 0
        FvHeader.Checksum = CalculateChecksum16(struct2stream(FvHeader))
        # FvHeader.Checksum = ModCheckSum(FvHeader)
        FvImage[:FvHeader.HeaderLength] = struct2stream(FvHeader)
    # Add files to FV
    for Index in range(MAX_NUMBER_OF_FILES_IN_FV):
        if mFvDataInfo.FvFiles[Index]:
            FvImage, FvImagePointer = AddFile(FvImage, FvImagePointer,
                                              mFvDataInfo, Index,
                                              VtfFileImageAddress, FvMapName,
                                              FvReportName)

    # If there is a VTF file, some special actions need to occur.
    if VtfFileImageAddress != FvImageSize:
        # Pad from the end of the last file to the beginning of the VTF file.
        # If the left space is less than sizeof (EFI_FFS_FILE_HEADER)?
        FvImage, FvImagePointer = PadFvImage(FvImage, FvImagePointer,
                                             FvImageSize, VtfFileImageAddress,
                                             NumOfBlocks)
        if not mArm and not mRiscV and not mLoongArch:
            #
            # Update reset vector (SALE_ENTRY for IPF)
            # Now for IA32 and IA64 platform, the fv which has bsf file must have the
            # EndAddress of 0xFFFFFFFF (unless the section was rebased).
            # Thus, only this type fv needs to update the  reset vector.
            # If the PEI Core is found, the VTF file will probably get
            # corrupted by updating the entry point.
            #
            if (mFvDataInfo.ForceRebase == 1) or (
                mFvDataInfo.BaseAddress + mFvDataInfo.Size == FV_IMAGES_TOP_ADDRESS):
                FvImage = UpdateResetVector(FvImage,
                                            FvImagePointer,
                                            mFvDataInfo,
                                            VtfFileImageAddress)
                EdkLogger.info("Update Reset vector in VTF file")

    if mArm:
        FvImage = UpdateArmResetVectorIfNeeded(FvImage, mFvDataInfo)
        # Update CheckSum for FvHeader
        FvHeader = Refine_FV_Header(NumOfBlocks + 1).from_buffer_copy(FvImage)
        # FvHeader = EFI_FIRMWARE_VOLUME_HEADER.from_buffer_copy(FvImage)
        FvHeader.Checksum = 0
        FvHeader.Checksum = CalculateChecksum16(FvImage[:FvHeader.HeaderLength])
        # FvHeader.Checksum = ModCheckSum(FvHeader)
        FvImage[:FvHeader.HeaderLength] = struct2stream(FvHeader)

    if mRiscV:
        FvImage = UpdateRiscvResetVectorIfNeeded(FvImage, mFvDataInfo)
        # Update CheckSum for FvHeader
        FvHeader = Refine_FV_Header(NumOfBlocks + 1).from_buffer_copy(FvImage)
        # FvHeader = EFI_FIRMWARE_VOLUME_HEADER.from_buffer_copy(FvImage)
        FvHeader.Checksum = 0
        FvHeader.Checksum = CalculateChecksum16(FvImage[:FvHeader.HeaderLength])
        # FvHeader.Checksum = ModCheckSum(FvHeader)
        FvImage[:FvHeader.HeaderLength] = struct2stream(FvHeader)
    if mLoongArch:
        FvImage = UpdateLoongArchResetVectorIfNeeded(FvImage, mFvDataInfo)
        # Update CheckSum for FvHeader
        FvHeader = Refine_FV_Header(NumOfBlocks + 1).from_buffer_copy(FvImage)
        # FvHeader = EFI_FIRMWARE_VOLUME_HEADER.from_buffer_copy(FvImage)
        FvHeader.Checksum = 0
        FvHeader.Checksum = CalculateChecksum16(FvImage[:FvHeader.HeaderLength])
        # FvHeader.Checksum = ModCheckSum(FvHeader)
        FvImage[:FvHeader.HeaderLength] = struct2stream(FvHeader)

    # Update FV Alignment attribute to the largest alignment of all the FFS files in the FV
    FvHeader = Refine_FV_Header(NumOfBlocks + 1).from_buffer_copy(FvImage)
    if ((
            FvHeader.Attributes & EFI_FVB2_WEAK_ALIGNMENT) != EFI_FVB2_WEAK_ALIGNMENT) and \
        (((FvHeader.Attributes & EFI_FVB2_ALIGNMENT) >> 16)) < MaxFfsAlignment:
        FvHeader.Attributes = (
            (MaxFfsAlignment << 16) | (FvHeader.Attributes & 0xFFFF))
        FvHeader.Checksum = 0
        FvHeader.Checksum = CalculateChecksum16(FvImage[:FvHeader.HeaderLength])
        # FvHeader.Checksum = ModCheckSum(FvHeader)
        FvImage[:FvHeader.HeaderLength] = struct2stream(FvHeader)

    # If there are large FFS in FV, the file system GUID should set to system 3 GUID.
    FvHeader = Refine_FV_Header(NumOfBlocks + 1).from_buffer_copy(FvImage)
    if mIsLargeFfs and FvHeader.FileSystemGuid.__cmp__(
        mEfiFirmwareFileSystem2Guid):
        FvHeader.FileSystemGuid = mEfiFirmwareFileSystem3Guid
        FvHeader.Checksum = 0
        FvHeader.Checksum = CalculateChecksum16(FvImage[:FvHeader.HeaderLength])
        # FvHeader.Checksum = ModCheckSum(FvHeader)
        FvImage[:FvHeader.HeaderLength] = struct2stream(FvHeader)
    WriteFile(FvFileName, FvImage)


def UpdateRiscvResetVectorIfNeeded(FvImage: bytearray, FvInfo):
    """
    This parses the FV looking for SEC and patches that address into the
    beginning of the FV header.

    For RISC-V ISA, the reset vector is at 0xfff~ff00h or 200h
    :param FvImage: FV image.
    :param FvInfo:  Information read from INF file.
    :return:
    """
    # Find the Sec Core
    SecPe32Off = FindCorePeSection(FvImage, EFI_FV_FILETYPE_SECURITY_CORE)
    if not SecPe32Off:
        EdkLogger.info("skip because Secutiry Core not found\n")
        return FvImage

    EdkLogger.info("Update SEC core in FV Header")
    SecHeader = GetCommonSectionByBuffer(FvImage[SecPe32Off:])
    MachineType = GetCoreMachineType(
        FvImage[SecPe32Off:SecPe32Off + SecHeader.SECTION_SIZE], SecHeader)
    if MachineType != IMAGE_FILE_MACHINE_RISCV64:
        EdkLogger.error(None, 0,
                        "Could not update SEC core because Machine type is not RiscV.")

    SecCoreEntryAddress, FvImage = GetCoreEntryPointAddress(FvImage, FvInfo,
                                                            SecPe32Off)
    EdkLogger.info("SecCore entry point Address = 0x%X" % SecCoreEntryAddress)
    EdkLogger.info("BaseAddress = 0x%X" % FvInfo.BaseAddress)
    bSecCore = SecCoreEntryAddress - FvInfo.BaseAddress
    EdkLogger.info("Offset = 0x%X" % bSecCore)

    if bSecCore > 0x0fffff:
        EdkLogger.error(None, 0,
                        "SEC Entry point must be within 1MB of start of the FV")

    tmp = bSecCore
    bSecCore = 0
    bSecCore = (tmp & 0x100000) << 11
    bSecCore |= (tmp & 0x0007FE) << 20
    bSecCore |= (tmp & 0x000800) << 9
    bSecCore |= (tmp & 0x0FF000)
    bSecCore |= 0x6F

    FvImage[:4] = FvImage[bSecCore:bSecCore + 4]

    return FvImage


def UpdateLoongArchResetVectorIfNeeded(FvImage: bytearray, FvInfo):
    """
    This parses the FV looking for SEC and patches that address into the
    beginning of the FV header.
    :param FvImage: Fv image
    :param FvInfo:  Information read from INF file.
    :return:        Fv image
    """
    # Locate an SEC Core instance and if found extract the machine type and entry point address
    SecPe32Off = FindCorePeSection(FvImage, EFI_FV_FILETYPE_SECURITY_CORE)
    if SecPe32Off:
        SecHeader = GetCommonSectionByBuffer(FvImage)
        MachineType = GetCoreMachineType(
            FvImage[SecPe32Off:SecHeader.SECTION_SIZE], SecHeader)
        SecCoreEntryAddress, FvImage = GetCoreEntryPointAddress(FvImage, FvInfo,
                                                                SecPe32Off)
        UpdateVectorSec = True
        if not UpdateVectorSec:
            return FvImage

        if MachineType == IMAGE_FILE_MACHINE_LOONGARCH64:
            ResetVecotr = [0]
            if UpdateVectorSec:
                EdkLogger.info(
                    "UpdateLoongArchResetVectorIfNeeded updating LOONGARCH64 SEC vector")
                ResetVecotr[0] = ((
                                      SecCoreEntryAddress - FvInfo.BaseAddress) & 0x3FFFFFF) >> 2
                ResetVecotr[0] = ((ResetVecotr[0] & 0x0FFFF) << 16) | (
                    (ResetVecotr[0] >> 16) & 0x3FF)
                ResetVecotr[0] = 0x50000000
            # Copy to the beginning of the FV
            FvImage[:8] = b''.join(
                [i.to_bytes(4, 'little') for i in ResetVecotr])
        else:
            EdkLogger.error(None, 0, "Unknown machine type")
    return FvImage


def UpdateArmResetVectorIfNeeded(FvImage: bytearray, FvInfo):
    """
    This parses the FV looking for SEC and patches that address into the
    beginning of the FV header.
    For ARM32 the reset vector is at 0x00000000 or 0xFFFF0000.
    For AArch64 the reset vector is at 0x00000000.
    This would commonly map to the first entry in the ROM.
    ARM32 Exceptions:
    Reset            +0
    Undefined        +4
    SWI              +8
    Prefetch Abort   +12
    Data Abort       +16
    IRQ              +20
    FIQ              +24

    We support two schemes on ARM.
    1) Beginning of the FV is the reset vector
    2) Reset vector is data bytes FDF file and that code branches to reset vector
      in the beginning of the FV (fixed size offset).

    Need to have the jump for the reset vector at location zero.
    We also need to store the address or PEI (if it exists).
    We stub out a return from interrupt in case the debugger
     is using SWI (not done for AArch64, not enough space in struct).
    The optional entry to the common exception handler is
   to support full featured exception handling from ROM and is currently
    not support by this tool.
    :param FvImage: Fv image
    :param FvInfo:  Information read from INF file
    :return:
    """
    UpdateVectorSec = False
    MachineType = 0
    UpdateVectorPei = False
    SecCoreEntryAddress = 0
    PeiCoreEntryAddress = 0

    # Locate an SEC Core instance and if found extract the machine type and entry point address
    SecPe32Off = FindCorePeSection(FvImage, EFI_FV_FILETYPE_SECURITY_CORE)
    if SecPe32Off:
        SecPe32SectionHeader = GetCommonSectionByBuffer(FvImage[SecPe32Off:])
        MachineType = GetCoreMachineType(FvImage[SecPe32Off:],
                                         SecPe32SectionHeader)

        SecCoreEntryAddress, FvImage = GetCoreEntryPointAddress(FvImage, FvInfo,
                                                                SecPe32Off)
        EdkLogger.info(
            "UpdateArmResetVectorIfNeeded found SEC core entry at 0x%x" % SecCoreEntryAddress)
        UpdateVectorSec = True

    # Locate a PEI Core instance and if found extract the machine type and entry point address
    PeiPe32Off = FindCorePeSection(FvImage, EFI_FV_FILETYPE_PEI_CORE)
    if PeiPe32Off:
        PeiSectionHeader = GetCommonSectionByBuffer(FvImage[PeiPe32Off:])
        PeiMachineType = GetCoreMachineType(FvImage[PeiPe32Off:],
                                            PeiSectionHeader)

        PeiCoreEntryAddress, FvImage = GetCoreEntryPointAddress(FvImage, FvInfo,
                                                                PeiPe32Off)
        EdkLogger.info(
            "UpdateArmResetVectorIfNeeded found PEI core entry at 0x%x" % PeiCoreEntryAddress)
        # if we previously found an SEC Core make sure machine types match
        if UpdateVectorSec and (MachineType != PeiMachineType):
            EdkLogger.error(None, 0,
                            "SEC and PEI machine types do not match, can't update reset vector")
        else:
            MachineType = PeiMachineType
        UpdateVectorPei = True
    if not UpdateVectorSec and not UpdateVectorPei:
        return FvImage

    if MachineType == IMAGE_FILE_MACHINE_ARMTHUMB_MIXED:
        # ARM: Array of 4 UINT32s:
        # 0 - is branch relative to SEC entry point
        # 1 - PEI Entry Point
        # 2 - movs pc,lr for a SWI handler
        # 3 - Place holder for Common Exception Handler
        ResetVector = [0 for i in range(4)]
        if UpdateVectorSec:
            EdkLogger.info(
                "UpdateArmResetVectorIfNeeded updating ARM SEC vector")
            EntryOffset = SecCoreEntryAddress - FvInfo.BaseAddress
            if EntryOffset > ARM_JUMP_OFFSET_MAX:
                EdkLogger.error(None, 0,
                                "SEC Entry point offset above 1MB of the start of the FV")
            if SecCoreEntryAddress & 1 != 0:
                ResetVector[0] = ARM_JUMP_TO_THUMB(EntryOffset)
            else:
                ResetVector[0] = ARM_JUMP_TO_ARM(EntryOffset)

            # SWI handler movs   pc,lr. Just in case a debugger uses SWI
            ResetVector[2] = ARM_RETURN_FROM_EXCEPTION

            # Place holder to support a common interrupt handler from ROM.
            # Currently not supported. For this to be used the reset vector would not be in this FV
            # and the exception vectors would be hard coded in the ROM and just through this address
            # to find a common handler in the a module in the FV.
            ResetVector[3] = 0

        # if a PEI core entry was found place its address in the vector area
        if UpdateVectorPei:
            EdkLogger.info(
                "UpdateArmResetVectorIfNeeded updating ARM PEI address")
            ResetVector[1] = PeiCoreEntryAddress
        # Copy to the beginning of the FV
        FvImage[:32] = b''.join([i.to_bytes(4, 'little') for i in ResetVector])
    elif MachineType == IMAGE_FILE_MACHINE_ARM64:
        ResetVector = [0 for i in range(2)]
        if UpdateVectorSec:
            EdkLogger.info(
                "UpdateArmResetVectorIfNeeded updating AArch64 SEC vector")
            ResetVector[0] = (SecCoreEntryAddress - FvInfo.BaseAddress) >> 2
            if ResetVector[0] > 0x03FFFFFF:
                EdkLogger.error(None, 0,
                                "SEC Entry point must be within 128MB of the start of the FV")
            ResetVector[0] |= ARM64_UNCONDITIONAL_JUMP_INSTRUCTION
        if UpdateVectorPei:
            EdkLogger.info(
                "UpdateArmResetVectorIfNeeded updating AArch64 PEI address")
            ResetVector[1] = PeiCoreEntryAddress
            FvImage[:16] = b''.join(
                [i.to_bytes(8, 'little') for i in ResetVector])
    else:
        EdkLogger.error(None, 0, "Unknown machine type")

    return FvImage


def GetCoreEntryPointAddress(FvImage: bytearray, FvInfo, SecPe32):
    """
    Returns the physical address of the core (SEC or PEI) entry point.
    :param FvImage: Fv image
    :param FvInfo:  Information read from INF file.
    :param SecPe32: Pe32 section pointer in Fv.
    :return:
    """
    SecHdrSize = GetCommonSectionByBuffer(FvImage[SecPe32:]).HeaderLength
    Res = GetPe32Info(FvImage[SecPe32 + SecHdrSize:])
    if not Res:
        EdkLogger.error(None, 0,
                        "Could not get the PE32 entry point for the core.")
    EntryPoint = Res[0]
    # Physical address is FV base + offset of PE32 + offset of the entry point
    EntryPhysicalAddress = FvInfo.BaseAddress
    EntryPhysicalAddress += SecPe32 + SecHdrSize + EntryPoint
    # Set value starting of FV
    FvImage[0] = EntryPhysicalAddress

    return EntryPhysicalAddress, FvImage


def UpdateResetVector(FvImage: bytearray, FvImagePointer: int, FvInfo,
                      VtfFileImage: int):
    """
    This parses the FV looking for the PEI core and then plugs the address into
    the SALE_ENTRY point of the BSF/VTF for IPF and does BUGBUG TBD action to
    complete an IA32 Bootstrap FV.
    :param FvImage:        FV image.
    :param FvImagePointer: Current Fv Pointer.
    :param FvInfo:         FV infomation.
    :param VtfFileImage:   VTF file address.
    :return:
    """
    # Initialize FV library
    FvLib = FvLibrary(FvImage)
    # Verify VTF file
    FvLib.VerifyFfsFile(FvImage[VtfFileImage:])

    if (VtfFileImage >= IA32_X64_VTF_SIGNATURE_OFFSET) and (
        VtfFileImage - IA32_X64_VTF_SIGNATURE_OFFSET == IA32_X64_VTF0_SIGNATURE):
        Vtf0Detected = True
    else:
        Vtf0Detected = False
    #
    # Find the Sec Core
    #
    SecCoreFileOff = FvLib.GetFileByType(EFI_FV_FILETYPE_SECURITY_CORE, 1)
    if not SecCoreFileOff:
        if Vtf0Detected:
            return FvImage
        EdkLogger.error(None, 0, "Could not find the SEC core file in the FV.")
    SecCoreFileBuffer = FvLib.FvBuffer[SecCoreFileOff:]
    # Sec Core found, now find PE32 section
    Pe32SectionOff = GetSectionByType(SecCoreFileBuffer, EFI_SECTION_PE32, 1)
    if not Pe32SectionOff:
        Pe32SectionOff = GetSectionByType(SecCoreFileBuffer, EFI_SECTION_TE, 1)
    if not Pe32SectionOff:
        EdkLogger.error(None, 0,
                        "Could not find a PE32 seciton in the SEC core file.")

    SecHeaderSize = GetCommonSectionByBuffer(
        SecCoreFileBuffer[Pe32SectionOff:]).Common_Header_Size
    EntryPoint, BaseOfCode, MachineType = GetPe32Info(
        SecCoreFileBuffer[Pe32SectionOff + SecHeaderSize:])

    if Vtf0Detected and (
        MachineType == IMAGE_FILE_MACHINE_I386 or MachineType == IMAGE_FILE_MACHINE_X64):
        return FvImage
    # Physical address is FV base + offset of PE32 + offset of the entry point
    SecCorePhysicalAddress = FvInfo.BaseAddress + Pe32SectionOff + SecHeaderSize + EntryPoint
    EdkLogger.info(
        "SecCore physical entry point address, Address = 0x%X" % SecCorePhysicalAddress)
    #
    # Find the PEI Core
    #
    PeiCorePhysicalAddress = 0
    Pe32SectionOff = None
    PeiCoreFileOff = FvLib.GetFileByType(EFI_FV_FILETYPE_PEI_CORE, 1)
    if PeiCoreFileOff:
        # PEI Core found, now find PE32 or TE section
        PeiCoreFileBuffer = FvLib.FvBuffer[PeiCoreFileOff:]
        Pe32SectionOff = GetSectionByType(PeiCoreFileBuffer, EFI_SECTION_PE32,
                                          1)
        if not Pe32SectionOff:
            Pe32SectionOff = GetSectionByType(PeiCoreFileBuffer, EFI_SECTION_TE,
                                              1)
        if not Pe32SectionOff:
            EdkLogger.error(None, 0,
                            "Could not find either a PE32 or a Te section in PET core file.")

        SecHeaderSize = GetCommonSectionByBuffer(
            PeiCoreFileBuffer[Pe32SectionOff:]).Common_Header_Size
        EntryPoint, BaseOfCode, MachineType = GetPe32Info(
            PeiCoreFileBuffer[Pe32SectionOff + SecHeaderSize:])

        # Physical address is FV base + offset of PE32 + offset of the entry point
        PeiCorePhysicalAddress = FvInfo.BaseAddress + Pe32SectionOff + SecHeaderSize + EntryPoint
        EdkLogger.info(
            "PeiCore physical entry point address, Address = 0x%X" % PeiCorePhysicalAddress)

    if MachineType == IMAGE_FILE_MACHINE_I386 or MachineType == IMAGE_FILE_MACHINE_X64:
        if PeiCorePhysicalAddress != 0:
            # Get the location to update
            # Write lower 32 bits of physical address for Pei Core entry
            FvImage[
                VtfFileImage - IA32_PEI_CORE_ENTRY_OFFSET] = PeiCorePhysicalAddress
        # Write SecCore Entry point relative address into the jmp instruction in reset vector.
        Ia32SecEntryOffset = SecCorePhysicalAddress - (
            FV_IMAGES_TOP_ADDRESS - IA32_SEC_CORE_ENTRY_OFFSET + 2)
        if Ia32SecEntryOffset <= (-65536):
            EdkLogger.error(None, 0,
                            "The SEC EXE file size is too large, it must be less than 64K.")
        FvImage[VtfFileImage - IA32_SEC_CORE_ENTRY_OFFSET] = Ia32SecEntryOffset

        # Update the BFV base address
        FvImage[VtfFileImage - 4] = FvInfo.BaseAddress
        EdkLogger.info(
            "update BFV base address in the top FV image, BFV base address = 0x%X." % FvInfo.BaseAddress)
    elif MachineType == IMAGE_FILE_MACHINE_ARMTHUMB_MIXED:
        # Since the ARM reset vector is in the FV Header you really don't need a
        # Volume Top File, but if you have one for some reason don't crash...
        pass
    elif MachineType == IMAGE_FILE_MACHINE_ARM64:
        # Since the AArch64 reset vector is in the FV Header you really don't need a
        # Volume Top File, but if you have one for some reason don't crash...
        pass
    else:
        EdkLogger.error(None, 0,
                        "Invalid machine type=0x%X in PEI core." % MachineType)

    # Now Updare file checksum
    VtfFile = GetFfsHeader(FvImage[VtfFileImage:])
    SavedState = VtfFile.State
    VtfFile.IntegrityCheck.Checksum.File = 0
    VtfFile.State = 0
    if VtfFile.Attributes & FFS_ATTRIB_CHECKSUM:
        VtfFile.IntegrityCheck.Checksum.File = CalculateChecksum8(FvImage[
                                                                  VtfFileImage + VtfFile.HeaderLenth:VtfFileImage + VtfFile.FFS_FILE_SIZE])
    else:
        VtfFile.IntegrityCheck.Checksum.File = FFS_FIXED_CHECKSUM

    VtfFile.State = SavedState
    VtfFileBuffer = struct2stream(VtfFile) + FvImage[
                                             VtfFileImage + VtfFile.HeaderLenth:]
    FvImage[VtfFileImage:VtfFileImage + VtfFile.FFS_FILE_SIZE] = VtfFileBuffer

    return FvImage


def GetPe32Info(Pe32: bytes):
    """
    Retrieves the PE32 entry point offset and machine type from PE image or TeImage.
    See EfiImage.h for machine types.  The entry point offset is from the beginning
    of the PE32 buffer passed in.
    :param Pe32: Pe32 image
    :return:
        EntryPoint:  Offset from the beginning of the PE32 to the image entry point.
        BaseOfCode:  Base address of code.
        MachineType: Magic number for the machine type.
    """
    if len(Pe32) == 0:
        EdkLogger.error(None, 0, "Input parameters is invalid.")

    TeHeader = EFI_TE_IMAGE_HEADER.from_buffer_copy(Pe32)
    if TeHeader.Signature == EFI_TE_IMAGE_HEADER_SIGNATURE:
        # By TeImage Header to get output
        EntryPoint = TeHeader.AddressOfEntryPoint + sizeof(
            EFI_TE_IMAGE_HEADER) - TeHeader.StrippedSize
        BaseOfCode = TeHeader.BaseOfCode + sizeof(
            EFI_TE_IMAGE_HEADER) - TeHeader.StrippedSize
        MachineType = TeHeader.Machine
    else:
        # Then check whether
        # Fitst id the DOS header
        DosHeader = EFI_IMAGE_DOS_HEADER.from_buffer_copy(Pe32)
        if DosHeader.e_magic != EFI_IMAGE_DOS_SIGNATURE:
            EdkLogger.error(None, 0,
                            "Unknown magic number in the DOS header, 0x%04x" % DosHeader.e_magic)
        # Immediately following is the NT header.
        ImgHdr = EFI_IMAGE_OPTIONAL_HEADER_UNION.from_buffer_copy(
            Pe32[DosHeader.e_lfanew:])
        # Verify NT header is expected
        if ImgHdr.Pe32.Signature != EFI_IMAGE_NT_SIGNATURE:
            EdkLogger.error(None, 0,
                            "Unrecognized image isgnature 0x%08X." % ImgHdr.Pe32.Signature)
        # Get output
        EntryPoint = ImgHdr.Pe32.OptionalHeader.AddressOfEntryPoint
        BaseOfCode = ImgHdr.Pe32.OptionalHeader.BaseOfCode
        MachineType = ImgHdr.Pe32.FileHeader.Machine

        # Verify machine type is supported
        if MachineType != IMAGE_FILE_MACHINE_I386 and \
            MachineType != IMAGE_FILE_MACHINE_X64 and \
            MachineType != IMAGE_FILE_MACHINE_EBC and \
            MachineType != IMAGE_FILE_MACHINE_ARMTHUMB_MIXED and \
            MachineType != IMAGE_FILE_MACHINE_ARM64 and \
            MachineType != IMAGE_FILE_MACHINE_RISCV64 and \
            MachineType != IMAGE_FILE_MACHINE_LOONGARCH64:
            EdkLogger.error(None, 0,
                            "Unrecognized machine type in the PE32 file.")

    return EntryPoint, BaseOfCode, MachineType


def PadFvImage(FvImage: bytearray, FvImagePointer: int, FvImageSize: int,
               VtfFileImage: int, NumOfBlocks: int):
    """
    This function places a pad file between the last file in the FV and the VTF
    file if the VTF file exists.
    :param FvImage:
    :param FvImagePointer:
    :param FvImageSize:
    :param VtfFileImage:
    :return:
    """
    # If there is no VTF or the VTF naturally follows the previous file without a
    # pad file, then there's nothing to do
    if VtfFileImage == FvImagePointer or VtfFileImage == FvImageSize:
        return FvImage, FvImagePointer

    if VtfFileImage < FvImagePointer:
        EdkLogger.error(None, 0,
                        "FV space is full, cannot add pad file between the last file and the VTF file.")

    # Pad file starts at beginning of free space
    PadFile = EFI_FFS_FILE_HEADER()
    # write PadFile FFS header with PadType, don't need to set PAD file guid in its header.
    PadFile.Type = EFI_FV_FILETYPE_FFS_PAD
    PadFile.Attributes = 0
    # FileSize includes the EFI_FFS_FILE_HEADER
    FileSize = VtfFileImage - FvImagePointer
    if FileSize > MAX_FFS_SIZE:
        PadFile = EFI_FFS_FILE_HEADER2()
        PadFile.Attributes |= FFS_ATTRIB_LARGE_FILE
        PadFile.ExtendedSize = FileSize
        global mIsLargeFfs
        mIsLargeFfs = True
    else:
        PadFile.Size[0] = FileSize & 0xFF
        PadFile.Size[1] = (FileSize & 0xFF00) >> 8
        PadFile.Size[2] = (FileSize & 0xFF0000) >> 16

    # Fill in checksums and state, must be zero during checksum calculation.
    PadFile.IntegrityCheck.Checksum.Header = 0
    PadFile.IntegrityCheck.Checksum.File = 0
    PadFile.State = 0
    PadFile.IntegrityCheck.Checksum.Header = CalculateChecksum8(
        struct2stream(PadFile))
    PadFile.State = EFI_FILE_HEADER_CONSTRUCTION | EFI_FILE_HEADER_VALID | EFI_FILE_DATA_VALID
    PadFile = UpdateFfsFileState(PadFile,
                                 Refine_FV_Header(
                                     NumOfBlocks + 1).from_buffer_copy(FvImage))
    FvImage[FvImagePointer:FvImageSize] = struct2stream(PadFile)
    # Update the current FV pointer
    FvImagePointer = FvImageSize
    return FvImage, FvImagePointer


def AddFile(FvImage, FvImagePointer, FvInfo, Index, VtfFileImage, FvMapFile,
            FvReportFile):
    """
    This function adds a file to the FV image.  The file will pad to the
    appropriate alignment if required.
    @param FvImage: The memory image of the FV to add it to.  The current offset
                must be valid.
    @param FvInfo: Pointer to information about the FV.
    @param Index: The file in the FvInfo file list to add.
    @param VtfFileImage: A pointer to the VTF file within the FvImage.  If this is equal
                to the end of the FvImage then no VTF previously found.
    @param FvMapFile: Pointer to FvMap File
    @param FvReportFile: Pointer to FvReport File
    @return:
    """
    # Verify input parameters.
    if not FvImage or not FvInfo or not FvInfo.FvFiles[0] or not VtfFileImage:
        EdkLogger.error(None, PARAMETER_INVALID,
                        gErrorMessage[PARAMETER_INVALID])

    # Read the file to add
    try:
        with open(LongFilePath(FvInfo.FvFiles[Index]), 'rb') as file:
            NewFileBuffer = bytearray(file.read())
            NewFileSize = len(NewFileBuffer)
    except Exception as X:
        EdkLogger.error("GenFv", FILE_OPEN_FAILURE,
                        "Error reading file: %s" % FvInfo.FvFiles[Index])

    # For None PI Ffs file, directly add them into FvImage.
    if not FvInfo.IsPiFvImage:
        FvImage[
        FvImagePointer: FvImagePointer + NewFileSize] = NewFileBuffer
        if FvInfo.SizeofFvFiles[Index] > NewFileSize:
            FvImagePointer += FvInfo.SizeofFiles[Index]
        else:
            FvImagePointer += NewFileSize
        return FvImage, FvImagePointer

    # Init FV library
    # FvHeader = EFI_FIRMWARE_VOLUME_HEADER.from_buffer_copy(FvImage)
    Fvlib = FvLibrary(FvImage)
    # Verify Ffs file
    Fvlib.VerifyFfsFile(NewFileBuffer)

    # Verify space exists to add the file
    if NewFileSize > (VtfFileImage - FvImagePointer):
        EdkLogger.error(None, RESOURCE_FULL,
                        "Resource, FV space is full, not enough room to add file %s" %
                        FvInfo.FvFiles[Index])

    # Verify the input file is the duplicated file in this Fv image
    FfsHeader = EFI_FFS_FILE_HEADER.from_buffer_copy(NewFileBuffer)
    if FfsHeader.Name in mFileGuidArray:
        EdkLogger.error(None, PARAMETER_INVALID,
                        "Invalid parameter, the %s file have the same GUID." % FfsHeader.Name)
    mFileGuidArray.append(FfsHeader.Name)

    # Update the file statue based on polarity of the FV.
    FfsHeader = UpdateFfsFileState(FfsHeader,
                                   EFI_FIRMWARE_VOLUME_HEADER.from_buffer_copy(
                                       FvImage))
    # Update FfsHeader in New FFS image
    NewFileBuffer[:FfsHeader.HeaderLength] = struct2stream(FfsHeader)
    # Check if alignment is required
    FfsAlignment = ReadFfsAlignment(FfsHeader)
    # Find the largest alignment of all the FFS files in the FV
    global MaxFfsAlignment
    if FfsAlignment > MaxFfsAlignment:
        MaxFfsAlignment = FfsAlignment
    # if we have a VTF file, add it at the top
    if IsVtfFile(FfsHeader):
        if VtfFileImage == len(FvImage):
            # No previous VTF, add this one.
            VtfFileImage = FvInfo.Size - NewFileSize
            # Sanity check, The file MUST align appropriately
            if (VtfFileImage + FfsHeader.HeaderLength) % (1 << FfsAlignment):
                EdkLogger.error(None, FORMAT_INVALID,
                                "Invalid, VTF file cannot be aligned on a %u-byte boundary." % (
                                    1 << FfsAlignment))
            # Rebase the PE or TE image in FileBuffer of FFS file for XIP
            # Rebase for the debug genfvmap tool
            VtfImage = FfsRebase(FvInfo, FvInfo.FvFiles[Index], NewFileBuffer,
                                 VtfFileImage,
                                 FvMapFile)
            if not VtfImage:
                EdkLogger.error(None, 0,
                                "Could not rebase %s." % FvInfo.FvFiles[Index])

            # Copy VTF file To FV image
            FvImage[VtfFileImage:] = VtfImage

            FileGuidToString = PrintGuidToBuffer(FfsHeader.Name, True)
            with open(FvReportFile, 'w') as FRF:
                FRF.write("0x%08X %s\n" % (VtfFileImage, FileGuidToString))
            EdkLogger.info("Add VTF FFS file in FV image.")
            return FvImage, FvImagePointer
        else:
            EdkLogger.error(None, 0,
                            "Invalid, multiple VTF files are not permitted within a single FV.")

    # Add pad file if necessary
    Flag, NewFileBuffer = AdjustInternalFfsPadding(NewFileBuffer, FvImage,
                                                   FvImagePointer,
                                                   1 << FfsAlignment,
                                                   NewFileSize)
    NewFileSize = len(NewFileBuffer)
    if Flag == False:
        FvImage, FvImagePointer = AddPadFile(FvImage, 1 << FfsAlignment,
                                             VtfFileImage, None,
                                             len(NewFileBuffer),
                                             None, FvImagePointer)

    # Add file
    if FvImagePointer + NewFileSize <= VtfFileImage:
        NewFileBuffer = FfsRebase(FvInfo, FvInfo.FvFiles[Index], NewFileBuffer,
                                  FvImagePointer, FvMapFile)

        # Copy the file
        FvImage[FvImagePointer:FvImagePointer + len(NewFileBuffer)] = bytes(
            NewFileBuffer)

        FileGuidString = PrintGuidToBuffer(
            EFI_FFS_FILE_HEADER.from_buffer_copy(NewFileBuffer).Name, True)
        with open(FvReportFile, 'a') as Fp:
            Fp.write("0x%08X %s\n" % (FvImagePointer, FileGuidString))
        FvImagePointer += NewFileSize
    else:
        EdkLogger.error(None, 0,
                        "FV space is full, cannot add file %s" % FvInfo.FvFiles[
                            Index])

    # Make next file start at QWord Boundary
    while FvImagePointer & (EFI_FFS_FILE_HEADER_ALIGNMENT - 1) != 0:
        FvImagePointer += 1

    return FvImage, FvImagePointer


mEfiFfsSectionAlignmentPaddingGuid = EFI_FFS_SECTION_ALIGNMENT_PADDING_GUID


def GetFfsHeader(FfsBuffer: bytes):
    if len(FfsBuffer) == 0:
        return 0
    FfsHeader = EFI_FFS_FILE_HEADER.from_buffer_copy(FfsBuffer)
    if FfsHeader.Attributes & FFS_ATTRIB_LARGE_FILE:
        FfsHeader = EFI_FFS_FILE_HEADER2.from_buffer_copy(FfsBuffer)
    return FfsHeader


def AdjustInternalFfsPadding(FfsBuffer: bytes, FvImage: bytearray,
                             FvImagePointer: int, Alignment: int, FileSize):
    """
    This function looks for a dedicated alignment padding section in the FFS, and
    shrinks it to the size required to line up subsequent sections correctly.
    :param FfsBuffer: Ffs file image
    :param FvImage:   Fv file image
    :param Alignment: Current Ffs file alignment
    :param FileSize:  Current Ffs file size
    :return: False or New ffs file buffer
    """

    # Figure out the misalignment: all FFS sections are aligned relative to the
    # start of the FFS payload, so use that as the base of the misalignment computation.
    FfsHeader = GetFfsHeader(FfsBuffer)
    FfsHeaderLength = FfsHeader.HeaderLength
    # TODO: Check
    Misalignment = FvImagePointer - FfsHeaderLength
    Misalignment &= Alignment - 1
    if Misalignment == 0:
        return True, FfsBuffer

    # We only apply this optimization to FFS files with the FIXED attribute set,
    # since the FFS will not be loadable at arbitrary offsets anymore after
    # we adjust the size of the padding section.
    if FfsHeader.Attributes & FFS_ATTRIB_FIXED == 0:
        return False, FfsBuffer

    # Look for a dedicated padding section that we can adjust to compensate
    # for the misalignment. If such a padding section exists, it precedes all
    # sections with alignment requirements, and so the adjustment will correct
    # all of them.
    PadSectionOff = GetSectionByType(FfsBuffer,
                                     EFI_SECTION_FREEFORM_SUBTYPE_GUID,
                                     1)
    NewFfsBuffer = FfsBuffer[:PadSectionOff]
    CommonSecHdr = GetCommonSectionByBuffer(
        FfsBuffer[PadSectionOff:])
    PadSection = EFI_FREEFORM_SUBTYPE_GUID_SECTION.from_buffer_copy(
        FfsBuffer[PadSectionOff + CommonSecHdr.Common_Header_Size:])
    if not PadSectionOff or not PadSection.SubTypeGuid.__cmp__(
        mEfiFfsSectionAlignmentPaddingGuid):
        return False, FfsBuffer

    # Find out if the size of the padding section is sufficient to compensate
    # for the misalignment.
    PadSize = CommonSecHdr.SECTION_SIZE
    if Misalignment > PadSize - sizeof(CommonSecHdr) - sizeof(PadSection):
        return False, FfsBuffer

    # Move the remainder of the FFS file towards the front, and adjust the
    # file size output parameter.
    Remainder = PadSectionOff + PadSize

    FileSize -= Misalignment

    # Update the padding section's length with the new values. Note that the
    # padding is always < 64 KB, so we can ignore EFI_COMMON_SECTION_HEADER2
    # ExtendedSize.
    PadSize -= Misalignment
    CommonSecHdr.Size[0] = PadSize & 0xff
    CommonSecHdr.Size[1] = (PadSize & 0xff00) >> 8
    CommonSecHdr.Size[2] = (PadSize & 0xff0000) >> 16

    PadSectionBuffer = struct2stream(CommonSecHdr) + struct2stream(
        PadSection) + FfsBuffer[PadSectionOff + sizeof(CommonSecHdr) + sizeof(
        PadSection):Remainder - Misalignment]
    NewFfsBuffer += PadSectionBuffer + FfsBuffer[Remainder:]
    # Update the FFS header with the new overall length
    NewFfsHdr = GetFfsHeader(NewFfsBuffer)
    NewFfsHdrLength = NewFfsHdr.HeaderLength
    if NewFfsHdrLength > sizeof(EFI_FFS_FILE_HEADER):
        NewFfsHdr.ExtendedSize = FileSize
    NewFfsHdr.Size[0] = FileSize & 0x000000FF
    NewFfsHdr.Size[1] = (FileSize & 0x0000FF00) >> 8
    NewFfsHdr.Size[2] = (FileSize & 0x00FF0000) >> 16

    NewFfsHdr.Attributes &= ~(
        FFS_ATTRIB_DATA_ALIGNMENT | FFS_ATTRIB_DATA_ALIGNMENT2)

    # IntegrityCheck = NewFfsHdr.IntegrityCheck
    NewFfsHdr.IntegrityCheck.Checksum.Header = 0x100 - NewFfsHdr.State
    NewFfsHdr.IntegrityCheck.Checksum.File = 0
    NewFfsHdr.IntegrityCheck.Checksum.Header = CalculateChecksum8(
        NewFfsBuffer[:NewFfsHdrLength])

    if NewFfsHdr.Attributes & FFS_ATTRIB_CHECKSUM:
        NewFfsHdr.IntegrityCheck.Checksum.File = CalculateChecksum8(
            NewFfsBuffer[NewFfsHdrLength:])
    else:
        NewFfsHdr.IntegrityCheck.Checksum.File = FFS_FIXED_CHECKSUM

    NewFfsBuffer = struct2stream(NewFfsHdr) + NewFfsBuffer[NewFfsHdrLength:]

    return True, NewFfsBuffer


def FfsRebase(FvInfo: FV_INFO, FfsFile: str, FfsBuffer: bytes, XipOffset: int,
              FvMapFile: str):
    """
    This function determines if a file is XIP and should be rebased.  It will
    rebase any PE32 sections found in the file using the base address.
    @param FvInfo:    A pointer to FV_INFO structure.
    @param FfsFile:   Ffs File PathName
    @param FfsHeader: A pointer to Ffs file image.
    @param XipOffset: The offset address to use for rebasing the XIP file image.
    @param FvMapFile: FvMapFile to record the function address in one Fvimage
    @return:
    """
    NewFfsFileBuffer = bytearray(FfsBuffer)

    # Don't need to relocate image when BaseAddress is zero and no ForceRebase Flag specified.
    if FvInfo.BaseAddress == 0 and FvInfo.ForceRebase == -1:
        return bytes(NewFfsFileBuffer)

    # If ForceRebase Flag specified to FALSE, will always not take rebase action.
    if FvInfo.ForceRebase == 0:
        return bytes(NewFfsFileBuffer)

    XipBase = FvInfo.BaseAddress + XipOffset
    FfsHeader = EFI_FFS_FILE_HEADER.from_buffer_copy(FfsBuffer)
    # We only process files potentially containing PE32 sections.
    if FfsHeader.Type == EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE:
        GetChildFvFromFfs(FvInfo, FfsBuffer, XipOffset)
    elif FfsHeader.Type == EFI_FV_FILETYPE_SECURITY_CORE or \
        FfsHeader.Type == EFI_FV_FILETYPE_PEI_CORE or \
        FfsHeader.Type == EFI_FV_FILETYPE_PEIM or \
        FfsHeader.Type == EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER or \
        FfsHeader.Type == EFI_FV_FILETYPE_DRIVER or \
        FfsHeader.Type == EFI_FV_FILETYPE_DXE_CORE:
        pass
    else:
        return bytes(NewFfsFileBuffer)

    # Rebase each PE32 section
    Index = 1
    while True:
        # Find Pe Image
        # Current PE32Section is offset of Pe32 section in Ffsfile
        PE32Section = GetSectionByType(FfsBuffer, EFI_SECTION_PE32, Index)
        if not PE32Section:
            break

        CurSecHdr = GetCommonSectionByBuffer(
            FfsBuffer[PE32Section:])
        CurSecHdrSize = CurSecHdr.Common_Header_Size()
        CurSecLength = CurSecHdr.SECTION_SIZE
        # Pe image process
        ImageContext = PE_COFF_LOADER_IMAGE_CONTEXT()
        PeImage = FfsBuffer[
                  PE32Section + CurSecHdrSize:PE32Section + CurSecHdrSize + CurSecLength]
        ImageContext.Handle = PE32Section + CurSecHdrSize

        ImageContext = PeCoffLoaderGetImageInfo(ImageContext, PeImage)

        if ImageContext.Machine == IMAGE_FILE_MACHINE_ARMT or ImageContext.Machine == IMAGE_FILE_MACHINE_ARM64:
            global mArm
            mArm = True

        if ImageContext.Machine == IMAGE_FILE_MACHINE_RISCV64:
            global mRiscV
            mRiscV = True

        if ImageContext.Machine == IMAGE_FILE_MACHINE_LOONGARCH64:
            global mLoongArch
            mLoongArch = True

        # Keep Image Context for PE image in FV
        OrigImageContext = PE_COFF_LOADER_IMAGE_CONTEXT.from_buffer_copy(
            struct2stream(ImageContext))

        # Get file Pdb pointer
        PdbPointer = PeCoffLoaderGetPdbPointer(PeImage)

        # Get PeHeader pointer
        ImgHdrOff = PE32Section + CurSecHdrSize + ImageContext.PeCoffHeaderOffset
        ImgHdr = EFI_IMAGE_OPTIONAL_HEADER_UNION.from_buffer_copy(
            FfsBuffer[ImgHdrOff:])
        # Calculate the PE32 base address, based on file type
        if FfsHeader.Type == EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER or \
            FfsHeader.Type == EFI_FV_FILETYPE_PEIM or \
            FfsHeader.Type == EFI_FV_FILETYPE_PEI_CORE or \
            FfsHeader.Type == EFI_FV_FILETYPE_SECURITY_CORE:
            # Check if section-alignment and file-alignment match or not
            if ImgHdr.Pe32.OptionalHeader.SectionAlignment != ImgHdr.Pe32.OptionalHeader.FileAlignment:
                EdkLogger.error(
                    "Invalid, PE image Section-Alignment and File-Alignment do not match : %s." % FfsFile)

            # PeImage has no reloc section. It will try to get reloc data from the original EFI image.
            if ImageContext.RelocationsStripped:
                # Construct the original efi file Name
                if len(FfsFile) >= MAX_LONG_FILE_PATH:
                    EdkLogger.error(None, FILE_NOT_FOUND,
                                    "The file name %s is too long." % FfsFile)

                PeFileName = os.path.join(os.path.basename(FfsFile), ".efi")
                with open(LongFilePath(PeFileName), 'rb') as file:
                    PeFileBuffer = file.read()
                    PeFileSize = len(PeFileBuffer)
                    if PeFileSize == 0:
                        EdkLogger.warn(
                            "The file %s has no .reloc section." % FfsFile)
                        continue
                PeImage = PeFileBuffer

                ImageContext = PeCoffLoaderGetImageInfo(ImageContext,
                                                        PeImage)
                if not ImageContext:
                    EdkLogger.error(None, 0,
                                    "The input file is %s and the return status is %s" % FfsFile)

                ImageContext.RelocationsStripped = False

            NewPe32BaseAddress = XipBase + PE32Section + CurSecHdrSize


        elif FfsHeader.Type == EFI_FV_FILETYPE_DXE_CORE or \
            FfsHeader.Type == EFI_FV_FILETYPE_DRIVER:
            if ImgHdr.Pe32.OptionalHeader.SectionAlignment != ImgHdr.Pe32.OptionalHeader.FileAlignment:
                EdkLogger.error(None, 0,
                                "PE image Section-Alignment and File-Alignment do not match : %s." % FfsFile)
            NewPe32BaseAddress = XipBase + PE32Section + CurSecHdrSize

        else:
            EdkLogger.info("Not supported file type")
            return bytes(NewFfsFileBuffer)

        # Relocation doesn't exist
        if ImageContext.RelocationsStripped:
            EdkLogger.warn("Invalid, The file %s no .reloc section." % FfsFile)
            continue

        # malloc memory
        # MemoryImagePointer = ImageContext.ImageSize + ImageContext.SectionAlignment
        ImageContext.ImageAddress = 0
        NewPeImage, ImageContext = PeCoffLoaderLoadImage(ImageContext,
                                                         PeImage)

        ImageContext.DestinationAddress = NewPe32BaseAddress

        ImageContext, NewPeImage = PeCoffLoaderRelocateImage(ImageContext,
                                                             NewPeImage)
        # if not ImageContext:
        #     EdkLogger.error(None, 0,
        #                     "Invalid, RelocateImage() call failed on rebase of %s" % FfsFile)

        # Copy Relocated data to raw image file.
        SectionHeaderOff = ImgHdrOff + sizeof(c_uint32) + sizeof(
            EFI_IMAGE_FILE_HEADER) + ImgHdr.Pe32.FileHeader.SizeOfOptionalHeader
        # NewFfsFileBuffer = FfsBuffer[:SectionHeaderOff]
        for Index in range(ImgHdr.Pe32.FileHeader.NumberOfSections):
            SectionHeader = EFI_IMAGE_SECTION_HEADER.from_buffer_copy(
                FfsBuffer[SectionHeaderOff:])
            NewFfsFileBuffer[
            PE32Section + CurSecHdrSize + SectionHeader.PointerToRawData:PE32Section
                                                                         + CurSecHdrSize + SectionHeader.PointerToRawData + SectionHeader.SizeOfRawData] = \
                NewPeImage[
                SectionHeader.VirtualAddress:SectionHeader.VirtualAddress + SectionHeader.SizeOfRawData]
            SectionHeaderOff += sizeof(EFI_IMAGE_SECTION_HEADER)

        # Update Image Base address
        if ImgHdr.Pe32.OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            ImgHdr.Pe32.OptionalHeader.ImageBase = NewPe32BaseAddress
            NewFfsFileBuffer[
            PE32Section + CurSecHdrSize + ImageContext.PeCoffHeaderOffset + sizeof(
                c_uint32) + sizeof(
                EFI_IMAGE_FILE_HEADER):PE32Section + CurSecHdrSize + ImageContext.PeCoffHeaderOffset + sizeof(
                c_uint32) + sizeof(EFI_IMAGE_FILE_HEADER) + sizeof(
                ImgHdr.Pe32.OptionalHeader)] = struct2stream(
                ImgHdr.Pe32.OptionalHeader)
        elif ImgHdr.Pe32Plus.OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            ImgHdr.Pe32Plus.OptionalHeader.ImageBase = NewPe32BaseAddress
            NewFfsFileBuffer[
            PE32Section + CurSecHdrSize + ImageContext.PeCoffHeaderOffset + sizeof(
                c_uint32) + sizeof(
                EFI_IMAGE_FILE_HEADER):PE32Section + CurSecHdrSize + ImageContext.PeCoffHeaderOffset + sizeof(
                c_uint32) + sizeof(EFI_IMAGE_FILE_HEADER) + sizeof(
                ImgHdr.Pe32Plus.OptionalHeader)] = struct2stream(
                ImgHdr.Pe32Plus.OptionalHeader)
        else:
            EdkLogger.error(None, 0,
                            "Invalid, unknown PE magic signature %X in PE32 image %s" % (
                                ImgHdr.Pe32.OptionalHeader.Magic, FfsFile))

        # Now update file checksum
        NewFfsHeader = EFI_FFS_FILE_HEADER.from_buffer_copy(NewFfsFileBuffer)
        if NewFfsHeader.Attributes & FFS_ATTRIB_CHECKSUM:
            SavedState = NewFfsHeader.State
            NewFfsHeader.IntegrityCheck.Checksum.File = 0
            NewFfsHeader.State = 0
            NewFfsHeader.IntegrityCheck.Checksum.File = CalculateChecksum8(
                NewFfsFileBuffer[NewFfsHeader.HeaderLength:])
            NewFfsHeader.State = SavedState

        NewFfsFileBuffer[:NewFfsHeader.HeaderLength] = struct2stream(
            NewFfsHeader)

        # Get this module function address from ModulePeMapFile and add them into FvMap file
        # Default use FileName as map file path
        if PdbPointer == None:
            PdbPointer = FfsFile

        WriteMapFile(FvMapFile, PdbPointer, NewFfsHeader, NewPe32BaseAddress,
                     OrigImageContext, bytearray(PeImage))

        Index += 1

    if FfsHeader.Type != EFI_FV_FILETYPE_SECURITY_CORE and \
        FfsHeader.Type != EFI_FV_FILETYPE_PEI_CORE and \
        FfsHeader.Type != EFI_FV_FILETYPE_PEIM and \
        FfsHeader.Type != EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER and \
        FfsHeader.Type != EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE:
        # Only Peim code may have a TE section
        return bytes(NewFfsFileBuffer)

    # Now precess TE section
    Index = 1
    while True:
        NewPe32BaseAddress = 0
        TeSection = GetSectionByType(FfsBuffer, EFI_SECTION_TE, Index)
        if not TeSection:
            break

        TeSecHdr = GetCommonSectionByBuffer(
            FfsBuffer[TeSection:])
        TeSecHdrSize = TeSecHdr.Common_Header_Size()
        TeSecLength = TeSecHdr.SECTION_SIZE

        TeHeader = GetCommonSectionByBuffer(
            FfsBuffer[TeSection:])
        ImageContext = PE_COFF_LOADER_IMAGE_CONTEXT()
        ImageContext.Handle = TeSection + TeSecHdrSize
        TeImage = FfsBuffer[
                  TeSection + TeSecHdrSize: TeSection + TeSecHdrSize + TeSecLength]
        ImageContext = PeCoffLoaderGetImageInfo(ImageContext, TeImage)

        if ImageContext.Machine == IMAGE_FILE_MACHINE_ARMTHUMB_MIXED or \
            ImageContext.Machine == IMAGE_FILE_MACHINE_ARM64:
            mArm = True

        if ImageContext.Machine == IMAGE_FILE_MACHINE_LOONGARCH64:
            mLoongArch = True

        OrigImageContext = PE_COFF_LOADER_IMAGE_CONTEXT.from_buffer_copy(
            struct2stream(ImageContext))

        PdbPointer = PeCoffLoaderGetPdbPointer(TeImage)

        NewPe32BaseAddress = XipBase + TeSection + TeSecHdrSize + sizeof(
            EFI_TE_IMAGE_HEADER) \
                             - TeHeader.StrippedSize

        if ImageContext.RelocationsStripped:
            PeFileName = os.path.basename(FfsFile) + '.efi'
            # read pe file
            with open(PeFileName, 'rb') as file:
                PeFileBuffer = file.read()
                PeFileSize = len(PeFileBuffer)
                if PeFileSize == 0:
                    EdkLogger.warn(
                        "The file %s has no .reloc section." % FfsFile)
                else:
                    TeImage = PeFileBuffer
                    ImageContext = PeCoffLoaderGetImageInfo(TeImage)
                    if not ImageContext:
                        EdkLogger.error(None, 0,
                                        "The input file is %s and the return status is %s" % FfsFile)
                    ImageContext.RelocationsStripped = False

        if ImageContext.RelocationsStripped:
            continue

        # ImageContext.ImageAddress = (ImageContext.SectionAlignment - 1) & (
        #     ~(ImageContext.SectionAlignment - 1))

        NewTeImage, ImageContext = PeCoffLoaderLoadImage(ImageContext, TeImage)
        # if not ImageContext:
        #     EdkLogger.error(None, 0,
        #                     "LocateImage() call failed on rebase of %s" % FfsFile)

        # Reloacate TeImage
        ImageContext.DestinationAddress = NewPe32BaseAddress
        ImageContext, NewTeImage = PeCoffLoaderRelocateImage(ImageContext,
                                                             NewTeImage)
        # if not ImageContext:
        #     EdkLogger.error(None, 0,
        #                     "RelocateImage() call failed on rebase of TE image %s" % FfsFile)
        # Copy the reloacated image into raw image file
        TeSectionHeaderOff = TeSection + sizeof(EFI_TE_IMAGE_HEADER)
        for index in range(TeHeader.NumberOfSections):
            TeSectionHeader = EFI_IMAGE_SECTION_HEADER.from_buffer_copy(
                FfsBuffer[TeSectionHeaderOff:])
            if not ImageContext.IsTeImage:
                NewFfsFileBuffer[TeSection + sizeof(EFI_TE_IMAGE_HEADER) - \
                                 TeHeader.StrippedSize + TeSectionHeader.PointerToRawData: \
                                 TeSection + sizeof(
                                     EFI_TE_IMAGE_HEADER) - TeHeader.StrippedSize \
                                 + TeSectionHeader.PointerToRawData + TeSectionHeader.SizeOfRawData \
                ] = NewTeImage[
                    TeSectionHeader.VirtualAddress:TeSectionHeader.VirtualAddress + TeSectionHeader.SizeOfRawData]

            else:
                NewFfsFileBuffer[TeSection + sizeof(EFI_TE_IMAGE_HEADER) - \
                                 TeHeader.StrippedSize + TeSectionHeader.PointerToRawData: \
                                 TeSection + sizeof(
                                     EFI_TE_IMAGE_HEADER) - TeHeader.StrippedSize \
                                 + TeSectionHeader.PointerToRawData + TeSectionHeader.SizeOfRawData \
                ] = NewTeImage[
                    TeSectionHeader.VirtualAddress:TeSectionHeader.VirtualAddress + TeSectionHeader.SizeOfRawData]

            TeSectionHeaderOff += sizeof(EFI_IMAGE_SECTION_HEADER)
        # Update Image Base Address
        TeHeader.ImageBase = NewPe32BaseAddress
        NewFfsFileBuffer[
        TeSection:TeSection + sizeof(EFI_TE_IMAGE_HEADER)] = struct2stream(
            TeHeader)
        # Now update file checksum
        FfsHeader = EFI_FFS_FILE_HEADER.from_buffer_copy(NewFfsFileBuffer)
        if FfsHeader.Attributes & FFS_ATTRIB_CHECKSUM:
            SavedState = FfsHeader.State
            FfsHeader.IntegrityCheck.Checksum.File = 0
            FfsHeader.State = 0
            FfsHeader.IntegrityCheck.Checksum.File = CalculateChecksum8(
                NewFfsFileBuffer[FfsHeader.HeaderLength:])
            FfsHeader.State = SavedState

        NewFfsFileBuffer[:FfsHeader.HeaderLength] = struct2stream(
            FfsHeader)

        if PdbPointer == None:
            PdbPointer = FfsFile

        WriteMapFile(FvMapFile, PdbPointer, FfsHeader, NewPe32BaseAddress,
                     OrigImageContext, NewFfsFileBuffer)

    return bytes(NewFfsFileBuffer)


def WriteMapFile(FvMapFile: str, FfsFileName: str, FfsFile: EFI_FFS_FILE_HEADER,
                 ImageBaseAddress: int,
                 ImageContext: PE_COFF_LOADER_IMAGE_CONTEXT,
                 FileBuffer: bytearray):
    """
    This function gets the basic debug information (entrypoint, baseaddress, .text, .data section base address)
    from PE/COFF image and abstracts Pe Map file information and add them into FvMap file for Debug.
    :param FvMapFile:        FvMap file name
    :param FfsFileName:      Ffs file path name
    :param FfsFile:          Ffs file image
    :param ImageBaseAddress: PeImage Base Address
    :param ImageContext:     Image Context Imfomation
    :return:                 None
    """
    # Print FileGuid to strint buffer
    FileGuidName = PrintGuidToBuffer(FfsFile.Name, True)

    # Get Map file and format path
    PeMapFileName = os.path.normpath(os.path.splitext(FfsFileName)[0] + '.map')

    # AddressOfEntryPoint and Offset in Image
    if not ImageContext.IsTeImage:
        ImgHdr = EFI_IMAGE_OPTIONAL_HEADER_UNION.from_buffer_copy(
            FileBuffer[ImageContext.PeCoffHeaderOffset:])
        AddressOfEntryPoint = ImgHdr.Pe32.OptionalHeader.AddressOfEntryPoint
        Offset = 0
        SectionHeaderOff = ImageContext.PeCoffHeaderOffset + sizeof(
            c_uint32) + sizeof(
            EFI_IMAGE_FILE_HEADER) + ImgHdr.Pe32.FileHeader.SizeOfOptionalHeader
        SectionNumber = ImgHdr.Pe32.FileHeader.NumberOfSections
    else:
        TeImageHeader = EFI_TE_IMAGE_HEADER.from_buffer_copy(
            FileBuffer)
        AddressOfEntryPoint = TeImageHeader.AddressOfEntryPoint
        Offset = TeImageHeader.StrippedSize - sizeof(EFI_TE_IMAGE_HEADER)
        SectionHeaderOff = 1
        SectionNumber = TeImageHeader.NumberOfSections

    # Open map file
    with open(PeMapFileName, 'r') as file:
        MapFileLines = file.readlines()

    # Get Module name
    ModuleName = MapFileLines[0].strip()
    # Module information content output
    ModuleContent = ''
    if ImageBaseAddress == 0:
        ModuleContent += "%s (dummy) (" % ModuleName
        ModuleContent += "BaseAddress=0x%010x, " % ImageBaseAddress
    else:
        ModuleContent += "%s (Fixed Flash Address, " % ModuleName
        ModuleContent += "BaseAddress=0x%010x, " % (ImageBaseAddress + Offset)

    ModuleContent += "EntryPoint=0x%010x, " % (
        ImageBaseAddress + AddressOfEntryPoint)

    if not ImageContext.IsTeImage:
        ModuleContent += "Type=PE"
    else:
        ModuleContent += "Type=TE"
    ModuleContent += ")\n"

    ModuleContent += "(GUID=%s" % FileGuidName

    TextVirtualAddress = 0
    DataVirtualAddress = 0
    for section in range(SectionNumber):
        SectionHeader = EFI_IMAGE_SECTION_HEADER.from_buffer_copy(
            FileBuffer[SectionHeaderOff:])
        if SectionHeader.Name == b'.text':
            TextVirtualAddress = SectionHeader.VirtualAddress
        elif SectionHeader.Name == b'.data':
            DataVirtualAddress = SectionHeader.VirtualAddress
        elif SectionHeader.Name == b'.sdata':
            DataVirtualAddress = SectionHeader.VirtualAddress
        SectionHeaderOff += sizeof(SectionHeader)

    ModuleContent += " .textbaseaddress=0x%010x" % (
        ImageBaseAddress + TextVirtualAddress)
    ModuleContent += " .databaseaddress=0x%010x" % (
        ImageBaseAddress + DataVirtualAddress)
    ModuleContent += ")\n\n"
    # Output Functions information into Fv Map file
    LinkTimeBaseAddress = 0
    IsUseClang = False
    FunctionType = 0
    for line in MapFileLines:
        # Skip blank line
        if not line:
            FunctionType = 0
            continue

        if FunctionType == 0:
            if re.match(r"Address", line.strip()):
                matchList = re.findall(r'[a-zA-Z]+\s+[a-zA-Z]+', line)
                for key in matchList:
                    if key.split(' ')[1] == "Size":
                        IsUseClang = True
                        FunctionType = 1
                        continue
                FunctionType = 1

            elif re.match(r'Static', line.strip()):
                FunctionType = 2

            elif re.match(r'Preferred', line.strip()):
                LinkTimeBaseAddress = int(line.strip().split(' ')[-1], 16)
            continue

        if FunctionType == 1:
            if IsUseClang:
                match = re.match(r'\s*[a-zA-Z0-9]+\s+\w+\s+\w+\s+\b', line)
                if match:
                    matchObjlst = match.group().split(' ')
                    FunctionAddress = int(matchObjlst[0].strip(), 16)
                    FunctionTypeName = matchObjlst[-1].strip()
                    if FunctionTypeName[0] != '/' and FunctionTypeName[
                        0] != '.' and FunctionTypeName[1] != ':':
                        ModuleContent += "  0x%010x    " % (
                            ImageBaseAddress + FunctionAddress - LinkTimeBaseAddress)
                        ModuleContent += "%s\n" % FunctionTypeName
            else:
                match = re.match(r'\s*\S+\s+\w+\s+[a-zA-Z0-9]+\s+[a-zA-Z]{1}\b',
                                 line)
                if match:
                    matchObjlst = [i for i in match.group().split(' ') if i]
                    FunctionName = matchObjlst[1].strip()
                    FunctionAddress = int(matchObjlst[2].strip(), 16)
                    FunctionTypeName = matchObjlst[3].strip()
                    if FunctionTypeName[0] == 'f' or FunctionTypeName[0] == 'F':
                        ModuleContent += '  0x%010x    ' % (
                            ImageBaseAddress + FunctionAddress - LinkTimeBaseAddress)
                        ModuleContent += '%s\n' % FunctionName
        elif FunctionType == 2:
            match = re.match(r'\s*\w+\s+\w+\s+[a-zA-Z0-9]+\s+[a-zA-Z]{1}\b',
                             line)
            if match:
                matchObjlst = match.group().split(' ')
                FunctionAddress = int(matchObjlst[2].strip(), 16)
                FunctionTypeName = matchObjlst[3].strip()
                FunctionName = matchObjlst[1].strip()
                if FunctionTypeName[0] == 'f' or FunctionTypeName[0] == 'F':
                    ModuleContent += "  0x%010x     " % (
                        ImageBaseAddress + FunctionAddress - LinkTimeBaseAddress)
                    ModuleContent += "%s\n"
    ModuleContent += "\n\n"
    with open(FvMapFile, 'a') as mapfile:
        mapfile.write(ModuleContent)


def GetChildFvFromFfs(FvInfo, FfsBuffer, XipOffset):
    """
    This function gets all child FvImages in the input FfsFile, and records
    their base address to the parent image.
    @param FvInfo:    FV_INFO structure
    @param FfsBuffer: Ffs file image that may contain FvImage.
    @param XipOffset: The offset address to the parent FvImage base.
    @return: Base address of child Fv image is recorded.
    """
    Index = 1
    while True:
        SubFvSectionPointer, SubFvSection = GetSectionByType(FfsBuffer,
                                                             EFI_SECTION_FIRMWARE_VOLUME_IMAGE,
                                                             Index)

        SubFvImagePointer = SubFvSectionPointer + SubFvSection.SECTION_SIZE

        #  See if there's an SEC core in the child FV
        CorePe32 = FindCorePeSection(FfsBuffer[SubFvImagePointer:],
                                     EFI_FV_FILETYPE_SECURITY_CORE)
        if not CorePe32:
            CorePe32 = FindCorePeSection(FfsBuffer[SubFvImagePointer:],
                                         EFI_FV_FILETYPE_PEI_CORE)

        if CorePe32:
            CommonHeader = GetCommonSectionByBuffer(FfsBuffer[CorePe32:])
            MachineType = GetCoreMachineType(FfsBuffer[CorePe32:], CommonHeader)

        if MachineType == IMAGE_FILE_MACHINE_ARMTHUMB_MIXED or MachineType == IMAGE_FILE_MACHINE_ARM64:
            EdkLogger.info("Located ARM/AArch64 SEC/PEI core in child FV")
            mArm = True

        if MachineType == IMAGE_FILE_MACHINE_LOONGARCH64:
            EdkLogger.info("Located LoongArch64 SEC core in child FV")
            mLoongArch = True

        # Rebase on Flash
        SubFvBaseAddress = FvInfo.BaseAddress + SubFvImagePointer + XipOffset
        mFvBaseAddress.append(SubFvBaseAddress)


def GetCommonSectionByBuffer(Buffer: bytes):
    CommonHeader = EFI_COMMON_SECTION_HEADER.from_buffer_copy(Buffer)
    if CommonHeader.SECTION_SIZE == 0xffffff:
        CommonHeader = EFI_COMMON_SECTION_HEADER2.from_buffer_copy(Buffer)

    return CommonHeader


def GetCoreMachineType(Pe32Section: bytes, CorePe32SectionHeader):
    res = GetPe32Info(Pe32Section[sizeof(CorePe32SectionHeader):])
    if not res:
        EdkLogger.error(None, 0,
                        "Could not get the PE32 machine type for the core.")
    MachineType = res[2]
    return MachineType


def FindCorePeSection(FvImageBuffer: bytes, FileType):
    """
    Recursively searches the FV for the FFS file of specified type (typically
    SEC or PEI core) and extracts the PE32 section for further processing.
    @param FvImageBuffer: Buffer containing FV data
    @param FileType:      Type of FFS file to search for
    @return: PE32 section pointer when FFS file is found.
    """
    # Initialize FV library, saving previous values
    Fvlib = FvLibrary(FvImageBuffer)
    CoreFfsFileOff = Fvlib.GetFileByType(FileType, 1)
    if CoreFfsFileOff:
        # Core found, now find PE32 or TE section
        Pe32Section = GetSectionByType(Fvlib.FvBuffer[CoreFfsFileOff:],
                                       EFI_SECTION_PE32, 1)
        if not Pe32Section:
            Pe32Section = GetSectionByType(Fvlib.FvBuffer[CoreFfsFileOff:],
                                           EFI_SECTION_TE, 1)
        if not Pe32Section:
            EdkLogger.error(None, FILE_PARSE_FAILURE,
                            "Invalid, could not find a PE32 section in the core file.")

        return Pe32Section

    FvImageFileCount = 1
    while True:
        FvImageFileOff = Fvlib.GetFileByType(
            EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE, FvImageFileCount)
        if not FvImageFileOff:
            break
        EncapFvSectionCount = 1
        while True:
            EncapFvSection = GetSectionByType(FvImageBuffer[FvImageFileOff:],
                                              EFI_SECTION_FIRMWARE_VOLUME_IMAGE,
                                              EncapFvSectionCount)
            if not EncapFvSectionCount:
                break
            EncapsulatedFvOff = EncapFvSection
            CommonHeader = EFI_COMMON_SECTION_HEADER.from_buffer_copy(
                FvImageBuffer[EncapsulatedFvOff:])
            if CommonHeader.SECTION_SIZE == 0xffffff:
                CommonHeader = EFI_COMMON_SECTION_HEADER2.from_buffer_copy(
                    FvImageBuffer[EncapsulatedFvOff:])
            if CommonHeader.Type == EFI_SECTION_COMPRESSION:
                EncapsulatedFvHeaderLength = CommonHeader.Common_Header_Size + sizeof(
                    EFI_SECTION_COMPRESSION)
            if CommonHeader.Type == EFI_SECTION_GUID_DEFINED:
                EncapsulatedFvHeaderLength = CommonHeader.Common_Header_Size + sizeof(
                    EFI_SECTION_GUID_DEFINED)
            Pe32Section = FindCorePeSection(FvImageBuffer[
                                            EncapsulatedFvOff + EncapsulatedFvHeaderLength:],
                                            FileType)

            if Pe32Section:
                return Pe32Section

    return


def UpdateFfsFileState(FfsFile: EFI_FFS_FILE_HEADER, FvHeader):
    if FvHeader.Attributes & EFI_FVB2_ERASE_POLARITY:
        FfsFile.State = GetReverseCode(FfsFile.State)
    return FfsFile


def AddPadFile(FvImage: bytearray, DataAlignment: int, FvEnd: int,
               FvExtHeader,
               NextFfsSize, ExtFileBuffer=None, FvImagePointer=0,
               NumOfBlocks=0):
    """
    This function adds a pad file to the FV image if it required to align the
    data of the next file.
    @param FvImage:        The memory image of the FV to add it to.
    @param DataAlignment:  The current offset must be valid.
    @param FvEnd:          The data alignment of the next FFS file.
    @param ExtHeader:      PI FvExtHeader Optional
    @return: FvImage
    """
    FvHeader = Refine_FV_Header(NumOfBlocks + 1).from_buffer_copy(FvImage)
    # PadFileSize = 0
    PadFileHeader = EFI_FFS_FILE_HEADER()
    CurFfsHeaderSize = PadFileHeader.HeaderLength

    if FvExtHeader != None:
        PadFileSize = FvExtHeader.ExtHeaderSize
        if PadFileSize + CurFfsHeaderSize >= MAX_FFS_SIZE:
            CurFfsHeaderSize = EFI_FFS_FILE_HEADER2().HeaderLength
        PadFileSize += CurFfsHeaderSize
    else:
        NextFfsHeaderSize = PadFileHeader.HeaderLength
        if NextFfsSize > MAX_FFS_SIZE:
            NextFfsHeaderSize = EFI_FFS_FILE_HEADER2().HeaderLength
        # Check if a pad file is necessary
        if (FvImagePointer + NextFfsHeaderSize) % DataAlignment == 0:
            return FvImage, FvImagePointer

        PadFileSize = FvImagePointer + sizeof(
            PadFileHeader) + NextFfsHeaderSize
        # Add whatever it takes to get to the next aligned address
        while PadFileSize % DataAlignment != 0:
            PadFileSize += 1
        # Subtract the next file header size
        PadFileSize -= NextFfsHeaderSize
        # Subtract the starting offset to get size
        PadFileSize -= FvImagePointer
    # Verify that we have enough space for the file header
    if FvImagePointer + PadFileSize > FvEnd:
        EdkLogger.error(None, RESOURCE_OVERFLOW, "Not have enough space.")

    # Write pad file header
    # PadFileHeader.Name = ModifyGuidFormat(
    #     "ffffffff-ffff-ffff-ffff-ffffffffffff")
    PadFileHeader.Type = EFI_FV_FILETYPE_FFS_PAD
    PadFileHeader.Attributes = 0

    # Write pad file size (calculated size minus next file header size)
    if PadFileSize >= MAX_FFS_SIZE:
        PadFileHeader = EFI_FFS_FILE_HEADER2()
        PadFileHeader.ExtendedSize = PadFileSize
        PadFileHeader.Attributes |= FFS_ATTRIB_LARGE_FILE
    else:
        PadFileHeader.Size[0] = PadFileSize & 0xFF
        PadFileHeader.Size[1] = (PadFileSize >> 8) & 0xFF
        PadFileHeader.Size[2] = (PadFileSize >> 16) & 0xFF

    # Fill in checksums and state, they must be 0 for checksumming.
    PadFileHeader.Name = ModifyGuidFormat(
        "ffffffff-ffff-ffff-ffff-ffffffffffff")
    PadFileHeader.IntegrityCheck.Checksum.Header = 0
    PadFileHeader.IntegrityCheck.Checksum.File = 0
    PadFileHeader.State = 0

    PadFileHeader.IntegrityCheck.Checksum.Header = CalculateChecksum8(
        struct2stream(PadFileHeader))
    PadFileHeader.IntegrityCheck.Checksum.File = FFS_FIXED_CHECKSUM

    PadFileHeader.State = EFI_FILE_HEADER_CONSTRUCTION | EFI_FILE_HEADER_VALID | EFI_FILE_DATA_VALID
    PadFileHeader = UpdateFfsFileState(PadFileHeader, FvHeader)
    # PadFile = struct2stream(PadFileHeader)

    # Write pad file header to in FvImage
    FvImage[
    FvImagePointer + 16:FvImagePointer + CurFfsHeaderSize] = struct2stream(
        PadFileHeader)[16:]
    PadFilePointer = FvImagePointer
    FvImagePointer += PadFileSize

    if FvExtHeader != None:
        ExtFileBuffer = bytearray(ExtFileBuffer)
        # Copy Fv Extension Header and Set Fv Extension header offset
        if FvExtHeader.ExtHeaderSize > sizeof(EFI_FIRMWARE_VOLUME_EXT_HEADER):
            Index = sizeof(EFI_FIRMWARE_VOLUME_EXT_HEADER)
            while Index < FvExtHeader.ExtHeaderSize:
                FvExtEntryHeader = EFI_FIRMWARE_VOLUME_EXT_ENTRY.from_buffer_copy(
                    ExtFileBuffer[Index:])
                if FvExtEntryHeader.ExtEntryType == EFI_FV_EXT_TYPE_USED_SIZE_TYPE:
                    FvExtEryUSTypeHdr = EFI_FIRMWARE_VOLUME_EXT_ENTRY_USED_SIZE_TYPE.from_buffer_copy(
                        ExtFileBuffer[Index:])
                    if VtfFileFlag:
                        FvExtEryUSTypeHdr.UsedSize = mFvTotalSize
                    else:
                        FvExtEryUSTypeHdr.UsedSize = mFvTakenSize
                    ExtFileBuffer[Index:Index + sizeof(
                        EFI_FIRMWARE_VOLUME_EXT_ENTRY_USED_SIZE_TYPE)] = struct2stream(
                        FvExtEryUSTypeHdr)
                    break
                Index += FvExtEntryHeader.ExtEntrySize
        # PadFile += ExtFileBuffer
        FvImage[
        PadFilePointer + CurFfsHeaderSize:PadFilePointer + CurFfsHeaderSize + FvExtHeader.ExtHeaderSize] = ExtFileBuffer

        FvHeader.ExtHeaderOffset = PadFilePointer + CurFfsHeaderSize
        # Update Fv header image
        FvImage[:FvHeader.HeaderLength] = struct2stream(FvHeader)
        while FvImagePointer & (EFI_FFS_FILE_HEADER_ALIGNMENT - 1) != 0:
            FvImagePointer += 1

    return FvImage, FvImagePointer


def WriteFile(FileName: str, Image: bytes):
    with open(LongFilePath(FileName), 'wb') as file:
        file.write(Image)


if __name__ == '__main__':
    print(sizeof(mCapDataInfo))
