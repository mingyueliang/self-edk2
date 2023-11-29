## @file
#     his contains all code necessary to build the GenFvImage.exe utility.
#       This utility relies heavily on the GenFvImage Lib.  Definitions for both
#       can be found in the Tiano Firmware Volume Generation Utility
#       Specification, review draft.
#
# Copyright (c) 2007 - 2018, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#

import argparse
import os.path
import logging
import sys

from FvInternalLib import *
from UefiCapsule import *

from Common.LongFilePathSupport import LongFilePath
from Common.BuildVersion import gBUILD_VERSION
from Common import EdkLogger
from Common.BuildToolError import *

UTILITY_NAME = "GenFv"
versionNumber = "1.0" + ' ' + gBUILD_VERSION
__version__ = "%prog Version " + versionNumber
__copyright__ = "Copyright (c) 2007 - 2018, Intel Corporation  All rights reserved."


def Version():
    EdkLogger.info("%s Version %s\n" % (UTILITY_NAME, versionNumber))


def MyOptionsParser():
    parser = argparse.ArgumentParser(
        description=__copyright__, usage="%s [option]" % UTILITY_NAME)

    parser.add_argument("-o", "--outputfile", dest="OutFileName", required=True,
                        help="File is the FvImage or CapImage to be created.")
    parser.add_argument("-i", "--inputfile", dest="InFileName", required=True,
                        help="File is the input FV.inf or Cap.inf to specify how to construct FvImage or CapImage.")
    parser.add_argument("-b", "--blocksize", dest="BlockSize",
                        help="BlockSize is one HEX or DEC format value BlockSize is required by Fv Image.")

    parser.add_argument("-n", "--numberblock", dest="NumberBlock",
                        help="NumberBlock is one HEX or DEC format value,NumberBlock is one optional parameter")
    parser.add_argument("-f", "--ffsfile", dest="FfsFile",
                        help="FfsFile is placed into Fv Image multi files can input one by one")
    parser.add_argument("-r", "--baseaddr", dest="Address",
                        help="Address is the rebase start address for drivers that run in Flash. It supports DEC or HEX digital format.If it is set to zero, no rebase action will be taken")
    parser.add_argument("-s", "--filetakesize", dest="FileTakeSize",
                        help="FileTakenSize specifies the size of the required space that the input file is placed in Fvimage. It is specified together with the input file.")
    parser.add_argument("-F", "--force-rebase", dest="ForceRebase",
                        help="If value is TRUE, will always take rebase action, If value is FALSE, will always not take reabse action, If not specified, will take rebase action if rebase address greater than zero, will not take rebase action if rebase address is zero.")
    parser.add_argument("-a", "--addrfile", dest="AddressFile",
                        help="AddressFile is one file used to record the child FV base address when current FV base address is set.")
    parser.add_argument("-m", "--map", dest="Map",
                        help="Logfile is the output fv map file name. if it is not given, the FvName.map will be the default map file name")
    parser.add_argument("-g", "--guid", dest="Guid",
                        help="GuidValue is one specific capsule guid value or fv file system guid value.Its format is xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
    parser.add_argument("--FvNameGuid", dest="FvNameGuid",
                        help="Guid is used to specify Fv Name.Its format is xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
    parser.add_argument("--capflag", dest="CapFlag",
                        help=" Capsule Reset Flag can be PersistAcrossReset,r PopulateSystemTable or InitiateReset or not set")
    parser.add_argument("--capoemflag", dest="CapOEMFlag",
                        help="Capsule OEM Flag is an integer between 0x0000 and 0xffff")
    parser.add_argument("--capguid", dest="CapGUid", help="")
    parser.add_argument("--capheadsize", dest="CapHeadSize",
                        help="HeadSize is one HEX or DEC format value. HeadSize is required by Capsule Image.")
    parser.add_argument("-c", "--capsule", dest="capsule", action="store_true",
                        help="Create Capsule Image.")
    parser.add_argument("-p", "--dump", dest="dump", action="store_true",
                        help="Dump Capsule Image header.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Turn on verbose output with informational messages.")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Disable all messages except key message and fatal error")
    parser.add_argument("-d", "--debug", action="store", type=int,
                        help="Enable debug messages, at input debug level.")
    parser.add_argument("--version", action="store_true",
                        help="Show program's version number and exit.")

    if "--version" in sys.argv:
        Version()
        exit()

    if "-h" in sys.argv or "--help" in sys.argv:
        Version()

    if len(sys.argv) == 1:
        parser.print_help()
        exit()

    Options = parser.parse_args()

    return Options


def GenFvApi():
    GenFvObject = GenerateFvFile()
    GenFvObject.ParseMyOptions()
    if GenFvObject.DumpCapsule:
        EdkLogger.info(
            "Dump the capsule header information for the input capsule image %s" % GenFvObject.InFileName)
        #
        # Dump Capsule Image Header Information
        #
        CapsuleHeader = EFI_CAPSULE_HEADER.from_buffer_copy(
            GenFvObject.InfFileImage)

        if GenFvObject.OutFileName == None:
            FpFile = sys.stdout
        else:
            FpFile = open(LongFilePath(GenFvObject.OutFileName), 'w')

        if FpFile != None:
            FpFile.write(
                "Capsule %s Image Header Information\n" % GenFvObject.InfFileName)
            FpFile.write(
                "  GUID                              %08s-%04s-%04s-%02s%02s-%02s%02s%02s%02s%02s%02s\n" % (
                    CapsuleHeader.CapsuleGuid.Guid1,
                    CapsuleHeader.CapsuleGuid.Guid2,
                    CapsuleHeader.CapsuleGuid.Guid3,
                    CapsuleHeader.CapsuleGuid.Guid4[0],
                    CapsuleHeader.CapsuleGuid.Guid4[1],
                    CapsuleHeader.CapsuleGuid.Guid4[2],
                    CapsuleHeader.CapsuleGuid.Guid4[3],
                    CapsuleHeader.CapsuleGuid.Guid4[4],
                    CapsuleHeader.CapsuleGuid.Guid4[5],
                    CapsuleHeader.CapsuleGuid.Guid4[6],
                    CapsuleHeader.CapsuleGuid.Guid4[7]))
            FpFile.write(
                "  Header size              0x%08s\n" % CapsuleHeader.HeaderSize)
            FpFile.write(
                "  Flags                    0x%08s\n" % CapsuleHeader.HeaderSize)
            FpFile.write(
                "  Capsule image size       0x%08s\n" % CapsuleHeader.HeaderSize)
            FpFile.close()
    elif GenFvObject.CapsuleFlag:
        EdkLogger.info("Create capsule image")
        GenFvObject.CapDataInfo.CapFiles = GenFvObject.FvDataInfo.FvFiles
        #
        # Call the GenerateFvImage to generate Fv Image
        #
        GenFvObject.GenerateCapImage()
    else:
        EdkLogger.info("Create Fv image and its map file.")
        #
        # Will take rebase action at below situation:
        # 1. ForceRebase Flag specified to TRUE;
        # 2. ForceRebase Flag not specified, BaseAddress greater than zero.
        #
        if (
            GenFvObject.FvDataInfo.BaseAddress > 0 and GenFvObject.FvDataInfo.ForceRebase == -1) or GenFvObject.FvDataInfo.ForceRebase == 1:
            EdkLogger.info(
                "FvImage Rebase Address is 0x%s" % GenFvObject.FvDataInfo.BaseAddress)

        #
        # Call the GenerateFvImage to Generate Fv Image
        #
        GenFvObject.GenerateFvImage()

        # update boot driver address and runtime driver address in address file
    if GenFvObject.AddrFileName and len(mFvBaseAddress) > 0:
        FpFile = open(LongFilePath(GenFvObject.AddrFileName), "w")
        FpFile.write(FV_BASE_ADDRESS_STRING)
        FpFile.write("\n")
        for Index in range(len(mFvBaseAddress)):
            FpFile.write("0x%x\n" % mFvBaseAddress[Index])
        FpFile.close()

    EdkLogger.info("The Total Fv Size, %s = %s" % (
        EFI_FV_TOTAL_SIZE_STRING, GenFvObject.FvTotalSize))
    EdkLogger.info("The used Fv Size, %s = %s" % (
        EFI_FV_TAKEN_SIZE_STRING, mFvTakenSize))
    EdkLogger.info("The space Fv Size, %s = %s" % (
        EFI_FV_SPACE_SIZE_STRING,
        GenFvObject.FvTotalSize - GenFvObject.FvTakenSize))


class MemoryFile:
    def __init__(self):
        self.FileImage = None
        self.CurrentFilePointer = None
        self.Eof = None


class GenerateFvFile(object):
    def __init__(self):
        self.Options = MyOptionsParser()

        self.CapDataInfo = CAP_INFO()
        self.FvDataInfo = FV_INFO()
        self.FvDataInfo.FvFileSystemGuid = mEfiFirmwareFileSystem2Guid
        self.FvDataInfo.ForceRebase = -1

        self.OutFileName = None
        self.InfFileName = None
        self.AddrFileName = None
        self.InfFileImage = None
        self.InfFileSize = 0

        self.MapFileName = None
        self.FvReportName = None

        self.CapsuleFlag = False
        self.DumpCapsule = False

        self.LogLevel = 0
        self.TempNumber = 0
        self.Index = 0

        self.FvTotalSize = 0
        self.FvTakenSize = 0
        self.FvImage = None
        self.FvHeader = None
        self.FvImagePointer = None
        self.NumOfBlocks = 0

        self.IsLargeFfs = None
        self.MaxFfsAlignment = 0

        self.VtfFileImageAddress = None

        # self.Arm = None

    def ParseMyOptions(self):
        if self.Options.verbose:
            EdkLogger.SetLevel(EdkLogger.VERBOSE)

        if self.Options.quiet:
            EdkLogger.SetLevel(EdkLogger.QUIET)

        if self.Options.debug:
            EdkLogger.SetLevel(self.Options.debug + 1)
        else:
            EdkLogger.SetLevel(EdkLogger.INFO)

        if self.Options.InFileName:
            self.InFileName = self.Options.InFileName

        if self.Options.OutFileName:
            self.OutFileName = self.Options.OutFileName

        if self.Options.AddressFile:
            self.AddrFileName = self.Options.AddressFile

        if self.Options.Address:
            # 1. Ascii string to c_uint64
            self.TempNumber = self.Options.Address
            # 2.
            self.FvDataInfo.BaseAddress = self.TempNumber
            self.FvDataInfo.BaseAddressSet = True

        if self.Options.BlockSize:
            if self.Options.BlockSize == 0:
                EdkLogger.error(UTILITY_NAME, 0,
                                "Invalid option value, Fv block size can't be set to zero.")

            self.FvDataInfo.FvBlocks[0].Length = self.Options.BlockSize
            EdkLogger.info(
                "FV Block Size, %s = %s" % (
                    EFI_BLOCK_SIZE_STRING, self.Options.BlockSize))

        if self.Options.NumberBlock:
            # 1. Ascii string to c_uint64
            if self.Options.NumberBlock == 0:
                EdkLogger.error(UTILITY_NAME, 0,
                                "Invalid option value, Fv block size can't be set to zero.")

            self.FvDataInfo.FvBlocks[0].NumBlocks = self.Options.NumberBlock
            EdkLogger.info("FV Number Block %s = %s" % (
                EFI_NUM_BLOCKS_STRING, self.Options.NumberBlock))

        if self.Options.FfsFile and self.Options.FileTakeSize:
            if len(self.Options.FfsFile) > (MAX_LONG_FILE_PATH - 1):
                EdkLogger.error(UTILITY_NAME, 0,
                                "Invalid option value, Input Ffsfile name %s is too long!: %s" % self.Options.FfsFile)

            if not os.path.exists(self.Options.FfsFile):
                EdkLogger.error(UTILITY_NAME, 0,
                                "Invalid option value, Input Ffsfile not exist.")

            self.FvDataInfo.FvFiles[self.Index] = self.Options.FfsFile
            self.FvDataInfo.SizeofFvFiles[
                self.Index] = self.Options.FileTakeSize

        # else:
        #     logger.error(
        #         "Invalid option, It must be specified together with -f option to specify the file size.")
        #     return STATUS_ERROR

        if self.Options.capsule:
            self.CapsuleFlag = True

        if self.Options.ForceRebase:
            if self.Options.ForceRebase == "TRUE":
                self.FvDataInfo.ForceRebase = 1
            elif self.Options.ForceRebase == "FALSE":
                self.FvDataInfo.ForceRebase = 0
            else:
                EdkLogger.error(UTILITY_NAME, 0,
                                "Invalid option value, froce rebase flag value must be TRUE or FALSE")

        if self.Options.CapHeadSize:
            self.CapDataInfo.HeaderSize = self.Options.CapHeadSize
            EdkLogger.info("Capsule Header size, %s = %s" % (
                EFI_CAPSULE_HEADER_SIZE_STRING, self.Options.CapHeadSize))

        if self.Options.CapFlag:
            if self.Options.CapFlag == "PopulateSystemTable":
                self.CapDataInfo.Flags |= CAPSULE_FLAGS_PERSIST_ACROSS_RESET | CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE
            elif self.Options.CapFlag == "PersistAcrossReset":
                self.CapDataInfo.Flags |= CAPSULE_FLAGS_PERSIST_ACROSS_RESET
            elif self.Options.CapFlags == "InitiateReset":
                self.CapDataInfo.Flags |= CAPSULE_FLAGS_PERSIST_ACROSS_RESET | CAPSULE_FLAGS_INITIATE_RESET
            else:
                EdkLogger.error(UTILITY_NAME, 0,
                                "Invalid option value, %s = %s" % (
                                    "CapFlag", self.Options.CapFlag))

        if self.Options.CapOEMFlag:
            # 1. Ascii string to c_uint64
            # 2.
            if self.Options.CapOEMFlag > 0xffff:
                EdkLogger.error(UTILITY_NAME, 0,
                                "Invalid option value, Capsule OEM flag value must be integer value between 0x000 and 0xfffff")

        if self.Options.CapGUid:
            self.CapDataInfo.CapGuid = ModifyGuidFormat(self.Options.CapGuid)
            EdkLogger.info(
                "Capsule Guid, %s = %s " % (
                    EFI_CAPSULE_GUID_STRING, self.Options.CapGuid))

        if self.Options.Guid:
            self.CapDataInfo.CapGuid = ModifyGuidFormat(self.Options.CapGuid)
            self.FvDataInfo.FvFileSystemGuid = ModifyGuidFormat(
                self.Options.CapGuid)
            EdkLogger.info(
                "Capsule Guid: %s = %s" % (
                    EFI_CAPSULE_GUID_STRING, self.Options.CapGuid))
            EdkLogger.info(
                "FV Guid: %s = %s" % (
                    EFI_FV_FILESYSTEMGUID_STRING, self.Options.CapGuid))

        if self.Options.FvNameGuid:
            self.FvDataInfo.FvNameGuid = ModifyGuidFormat(
                self.Options.FvNameGuid)
            self.FvDataInfo.FvNameGuidSet = True
            EdkLogger.info(
                "FV Name Guid: %s = %s" % (
                    EFI_FV_NAMEGUID_STRING, self.Options.FvNameGuid))

        if self.Options.dump:
            self.DumpCapsule = True

        if self.Options.Map:
            self.MapFileName = self.Options.Map

        #
        # check input parameter, InfFileName can be NULL
        #
        if not os.path.exists(self.InFileName) and self.DumpCapsule:
            EdkLogger.error(UTILITY_NAME, 0,
                            "Missing option, Input Capsule Image.")

        if not self.DumpCapsule and self.OutFileName == None:
            EdkLogger.error(UTILITY_NAME, 0, "Missing option, Output file.")
        # Read INF file image
        with open(LongFilePath(self.InFileName), 'rb') as file:
            self.InfFileImage = file.read()
            self.InfFileSize = len(self.InfFileImage)

    def GenerateFvImage(self):
        FvExtHeader = None
        # Parse the FV inf file for header information
        self.ParseFvInf()

        # Update the file name return values
        if not self.OutFileName and self.FvDataInfo.FvName:
            self.OutFileName = self.FvDataInfo.FvName
        if not self.OutFileName:
            EdkLogger.error("GenFv", OPTION_MISSING,
                            "Missing options, Output file name")

        if self.FvDataInfo.FvBlocks[0].Length == 0:
            EdkLogger.error("GenFv", OPTION_MISSING,
                            "Missing required argument, Block Size")

        # Debug message Fv File System Guid
        if self.FvDataInfo.FvFileSystemGuidSet:
            EdkLogger.info(
                "FV File System Guid, %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X" % (
                    self.FvDataInfo.FvFileSystemGuid.Guid1,
                    self.FvDataInfo.FvFileSystemGuid.Guid2,
                    self.FvDataInfo.FvFileSystemGuid.Guid3,
                    self.FvDataInfo.FvFileSystemGuid.Guid4[0],
                    self.FvDataInfo.FvFileSystemGuid.Guid4[1],
                    self.FvDataInfo.FvFileSystemGuid.Guid4[2],
                    self.FvDataInfo.FvFileSystemGuid.Guid4[3],
                    self.FvDataInfo.FvFileSystemGuid.Guid4[4],
                    self.FvDataInfo.FvFileSystemGuid.Guid4[5],
                    self.FvDataInfo.FvFileSystemGuid.Guid4[6],
                    self.FvDataInfo.FvFileSystemGuid.Guid4[7]))
        # Add PI FV extension header
        if self.FvDataInfo.FvExtHeaderFile:
            # Open the FV Extension Header file
            with open(LongFilePath(self.FvDataInfo.FvExtHeaderFile),
                      'rb') as file:
                FvExtFileBuffer = file.read()
                FvExtHeader = EFI_FIRMWARE_VOLUME_EXT_HEADER.from_buffer_copy(
                    FvExtFileBuffer)
            # See if there is an override for the FV Name GUID
            if self.FvDataInfo.FvNameGuidSet:
                FvExtHeader.FvName = self.FvDataInfo.FvNameGuid
            self.FvDataInfo.FvNameGuid = FvExtHeader.FvName
            self.FvDataInfo.FvNameGuidSet = True
        elif self.FvDataInfo.FvNameGuidSet:
            FvExtHeader.FvName = self.FvDataInfo.FvNameGuid
            FvExtHeader.ExtHeaderSize = sizeof(EFI_FIRMWARE_VOLUME_EXT_HEADER)

        # Debug message Fv Name Guid
        if self.FvDataInfo.FvNameGuidSet:
            EdkLogger.info(
                "FV Name Guid, %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X" % (
                    self.FvDataInfo.FvNameGuid.Guid1,
                    self.FvDataInfo.FvNameGuid.Guid2,
                    self.FvDataInfo.FvNameGuid.Guid3,
                    self.FvDataInfo.FvNameGuid.Guid4[0],
                    self.FvDataInfo.FvNameGuid.Guid4[1],
                    self.FvDataInfo.FvNameGuid.Guid4[2],
                    self.FvDataInfo.FvNameGuid.Guid4[3],
                    self.FvDataInfo.FvNameGuid.Guid4[4],
                    self.FvDataInfo.FvNameGuid.Guid4[5],
                    self.FvDataInfo.FvNameGuid.Guid4[6],
                    self.FvDataInfo.FvNameGuid.Guid4[7]))
        if self.FvDataInfo.FvFileSystemGuid.__cmp__(
            mEfiFirmwareFileSystem2Guid) or self.FvDataInfo.FvFileSystemGuid.__cmp__(
            mEfiFirmwareFileSystem3Guid):
            self.FvDataInfo.IsPiFvImage = True

        # FvMap file to log the function address of all modules in one Fvimage
        if self.MapFileName:
            if len(self.MapFileName) > MAX_LONG_FILE_PATH - 1:
                EdkLogger.error("", OPTION_VALUE_INVALID,
                                "Invalid option value, MapFileName %s is too long!" % self.MapFileName)

            # FvMapName = self.MapFileName
        else:
            self.MapFileName = os.path.splitext(self.OutFileName)[0] + ".map"
            if len(self.MapFileName) > MAX_LONG_FILE_PATH + 1:
                EdkLogger.error("", OPTION_VALUE_INVALID,
                                "Invalid option value, FvFileName %s is too long!" % self.MapFileName)

        EdkLogger.info("FV Map file name is %s" % self.MapFileName)
        # FvReport file to log the FV information in one Fvimage
        if len(self.OutFileName + '.txt') > MAX_LONG_FILE_PATH - 1:
            EdkLogger.error("", OPTION_VALUE_INVALID,
                            "Invalid option value, FvFileName %s is too long!" % self.MapFileName)
        self.FvReportName = self.OutFileName + ".txt"
        #
        # Calculate the FV size and Update Fv Size based on the actual FFS files.
        # And Update self.FvDataInfo data.
        #
        self.CalculateFvSize()

        EdkLogger.info(
            "The generated FV image size is %u bytes" % self.FvDataInfo.Size)

        # support fv image and empty fv image
        FvImageSize = self.FvDataInfo.Size

        # Allocate the FV, assure FvImage Header 8 byte alignment
        self.FvImagePointer = 0

        if self.FvDataInfo.FvAttributes == 0:
            # Set Default Fv Attribute
            self.FvDataInfo.FvAttributes = FV_DEFAULT_ATTRIBUTE

        # TODO: Malloc Memery question.
        if self.FvDataInfo.FvAttributes & EFI_FVB2_ERASE_POLARITY:
            # Init FvImage is 0xff
            self.FvImage = bytearray(
                [0xff for i in range((FvImageSize + 7) & ~ 7)])
        else:
            # Init FvImage is 0
            self.FvImage = bytearray(((FvImageSize + 7) & ~ 7))

        # Initialize FV header
        self.NumOfBlocks = 0
        for Index in range(MAX_NUMBER_OF_FV_BLOCKS):
            if self.FvDataInfo.FvBlocks[Index].Length != 0:
                self.NumOfBlocks += 1
        # Need terminated block map
        self.FvHeader = Refine_FV_Header(self.NumOfBlocks + 1)()
        # Initialize the zero vector to all zeros.
        # Copy the Fv file system GUID
        self.FvHeader.FileSystemGuid = self.FvDataInfo.FvFileSystemGuid
        self.FvHeader.FvLength = FvImageSize
        self.FvHeader.Signature = int.from_bytes(EFI_FVH_SIGNATURE,
                                                 byteorder='little')
        self.FvHeader.Attributes = self.FvDataInfo.FvAttributes
        self.FvHeader.Revision = EFI_FVH_REVISION
        # self.FvHeader.ExtHeaderOffset = 0
        # self.FvHeader.Reserved = 0

        # Copy firmware block map
        for Index in range(MAX_NUMBER_OF_FV_BLOCKS):
            if Index >= self.NumOfBlocks:
                # Add block map terminator, because default is zero
                # FvHeader.BlockMap[Index].NumBlocks = 0
                # FvHeader.BlockMap[Index].Length = 0
                break
            if self.FvDataInfo.FvBlocks[Index].Length != 0:
                self.FvHeader.BlockMap[Index].NumBlocks = \
                    self.FvDataInfo.FvBlocks[
                        Index].NumBlocks
                self.FvHeader.BlockMap[Index].Length = self.FvDataInfo.FvBlocks[
                    Index].Length

        # Complete the header
        self.FvHeader.HeaderLength = sizeof(self.FvHeader)
        self.FvHeader.Checksum = 0
        self.FvHeader.Checksum = CalculateChecksum16(
            struct2stream(self.FvHeader))

        self.FvImage[:self.FvHeader.HeaderLength] = struct2stream(self.FvHeader)
        # Initialize our "file" view of the buffer
        # If there is no FFS file, generate one empty FV
        if not self.FvDataInfo.FvFiles[0] and not self.FvDataInfo.FvNameGuidSet:
            self.WriteFile()
            return

        # record FV size information into FvMap file.
        with open(LongFilePath(self.MapFileName), 'w') as file:
            if self.FvTotalSize != 0:
                file.write(
                    "%s = 0x%x\n" % (
                        EFI_FV_TOTAL_SIZE_STRING, self.FvTotalSize))
            if self.FvTakenSize != 0:
                file.write(
                    "%s = 0x%x\n" % (
                        EFI_FV_TAKEN_SIZE_STRING, self.FvTakenSize))
            if self.FvTotalSize != 0 and self.FvTakenSize != 0:
                file.write("%s = 0x%x\n" % (
                    EFI_FV_SPACE_SIZE_STRING,
                    self.FvTotalSize - self.FvTakenSize))

        # record FV size information to FvReportFile.
        with open(LongFilePath(self.FvReportName), 'w') as file:
            file.write(
                "%s = 0x%x\n" % (EFI_FV_TOTAL_SIZE_STRING, self.FvTotalSize))
            file.write(
                "%s = 0x%x\n" % (EFI_FV_TAKEN_SIZE_STRING, self.FvTakenSize))
        # Vtf file image offset
        self.VtfFileImageAddress = FvImageSize
        self.FvImagePointer += self.FvHeader.HeaderLength
        # Add PI FV extendsize header
        if FvExtHeader != None:
            # Add FV Extended Header contents to the FV as a PAD file
            self.AddPadFile(4, 0, FvExtHeader, FvExtFileBuffer)
            FvHeader = Refine_FV_Header(self.NumOfBlocks + 1).from_buffer_copy(
                self.FvImage)
            FvHeader.Checksum = 0
            FvHeader.Checksum = CalculateChecksum16(struct2stream(FvHeader))
            self.FvImage[:FvHeader.HeaderLength] = struct2stream(FvHeader)
        # Add files to FV
        for Index in range(MAX_NUMBER_OF_FILES_IN_FV):
            if self.FvDataInfo.FvFiles[Index]:
                self.AddFile(Index)

        # If there is a VTF file, some special actions need to occur.
        if self.VtfFileImageAddress != FvImageSize:
            # Pad from the end of the last file to the beginning of the VTF file.
            # If the left space is less than sizeof (EFI_FFS_FILE_HEADER)?
            self.PadFvImage(FvImageSize)
            if not mArm and not mRiscV and not mLoongArch:
                #
                # Update reset vector (SALE_ENTRY for IPF)
                # Now for IA32 and IA64 platform, the fv which has bsf file must have the
                # EndAddress of 0xFFFFFFFF (unless the section was rebased).
                # Thus, only this type fv needs to update the  reset vector.
                # If the PEI Core is found, the VTF file will probably get
                # corrupted by updating the entry point.
                #
                if (self.FvDataInfo.ForceRebase == 1) or (
                    self.FvDataInfo.BaseAddress + self.FvDataInfo.Size == FV_IMAGES_TOP_ADDRESS):
                    self.UpdateResetVector()
                    EdkLogger.info("Update Reset vector in VTF file")

        if mArm:
            self.UpdateArmResetVectorIfNeeded()
            # Update CheckSum for FvHeader
            FvHeader = Refine_FV_Header(self.NumOfBlocks + 1).from_buffer_copy(
                self.FvImage)
            FvHeader.Checksum = 0
            FvHeader.Checksum = CalculateChecksum16(struct2stream(FvHeader))
            self.FvImage[:FvHeader.HeaderLength] = struct2stream(FvHeader)

        if mRiscV:
            self.UpdateRiscvResetVectorIfNeeded()
            # Update CheckSum for FvHeader
            FvHeader = Refine_FV_Header(self.NumOfBlocks + 1).from_buffer_copy(
                self.FvImage)
            FvHeader.Checksum = 0
            FvHeader.Checksum = CalculateChecksum16(struct2stream(FvHeader))
            self.FvImage[:FvHeader.HeaderLength] = struct2stream(FvHeader)
        if mLoongArch:
            self.UpdateLoongArchResetVectorIfNeeded()
            # Update CheckSum for FvHeader
            FvHeader = Refine_FV_Header(self.NumOfBlocks + 1).from_buffer_copy(
                self.FvImage)
            FvHeader.Checksum = 0
            FvHeader.Checksum = CalculateChecksum16(struct2stream(FvHeader))
            self.FvImage[:FvHeader.HeaderLength] = struct2stream(FvHeader)

        # Update FV Alignment attribute to the largest alignment of all the FFS files in the FV
        FvHeader = Refine_FV_Header(self.NumOfBlocks + 1).from_buffer_copy(
            self.FvImage)
        if ((
                FvHeader.Attributes & EFI_FVB2_WEAK_ALIGNMENT) != EFI_FVB2_WEAK_ALIGNMENT) and \
            (((
                  FvHeader.Attributes & EFI_FVB2_ALIGNMENT) >> 16)) < self.MaxFfsAlignment:
            FvHeader.Attributes = (
                (self.MaxFfsAlignment << 16) | (FvHeader.Attributes & 0xFFFF))
            FvHeader.Checksum = 0
            FvHeader.Checksum = CalculateChecksum16(struct2stream(FvHeader))
            self.FvImage[:FvHeader.HeaderLength] = struct2stream(FvHeader)

        # If there are large FFS in FV, the file system GUID should set to system 3 GUID.
        FvHeader = Refine_FV_Header(self.NumOfBlocks + 1).from_buffer_copy(
            self.FvImage)
        if self.IsLargeFfs and FvHeader.FileSystemGuid.__cmp__(
            mEfiFirmwareFileSystem2Guid):
            FvHeader.FileSystemGuid = mEfiFirmwareFileSystem3Guid
            FvHeader.Checksum = 0
            FvHeader.Checksum = CalculateChecksum16(struct2stream(FvHeader))
            self.FvImage[:FvHeader.HeaderLength] = struct2stream(FvHeader)
        self.WriteFile()

    def GenerateCapImage(self):
        """
            This is the main function which will be called from application to create UEFI Capsule image.
            :param InfFileImage: Buffer containing the INF file contents.
            :param CapFileName:  Requested name for the Cap file.
            :return:
            """
        # 1. Read the Capsule guid, parse inf file for Capsule Guid
        if len(self.InfFileImage) != 0:
            # Parse the Cap inf file for header information
            ParseCapInf(self.InfFileImage)

        if self.CapDataInfo.HeaderSize == 0:
            # Make header size align 16 bytes
            self.CapDataInfo.HeaderSize = sizeof(EFI_CAPSULE_HEADER)

        if self.CapDataInfo.HeaderSize < sizeof(EFI_CAPSULE_HEADER):
            EdkLogger.error(None, PARAMETER_INVALID,
                            "The specified HeaderSize cannot be less than the size of EFI_CAPSULE_HEADER.")

        if self.OutFileName == None and self.CapDataInfo.CapName:
            self.OutFileName = self.CapDataInfo.CapName

        if not self.OutFileName:
            EdkLogger.error(None, PARAMETER_MISSING,
                            "Missing required argument, Output Capsule file name")

        # Calculate the size of capsule iamge
        CapSize = self.CapDataInfo.HeaderSize
        for Index in range(MAX_NUMBER_OF_FILES_IN_CAP):
            if self.CapDataInfo.CapFiles[Index]:
                with open(self.CapDataInfo.CapFiles[Index], 'rb') as file:
                    CapSize += len(file.read())

        # Allocate buffer for capsule image.
        CapBuffer = bytearray(CapSize)
        # create capsule header and get capsule body
        CapsuleHeader = EFI_CAPSULE_HEADER()
        CapsuleHeader.CapsuleGuid = self.CapDataInfo.CapGuid
        CapsuleHeader.HeaderSize = self.CapDataInfo.HeaderSize
        CapsuleHeader.Flags = self.CapDataInfo.Flags
        CapsuleHeader.CapsuleImageSize = CapSize
        CapBuffer[:self.CapDataInfo.HeaderSize] = struct2stream(
            CapsuleHeader)

        CurCapPointer = CapsuleHeader.HeaderSize
        for file in self.CapDataInfo.CapFiles:
            if file:
                with open(file, 'rb') as file:
                    FileBuffer = file.read()
                    FileSize = len(FileBuffer)
                    CapBuffer[
                    CurCapPointer:CurCapPointer + FileSize] = FileBuffer

        # write capsule data into the output file
        WriteFile(self.OutFileName, CapBuffer)

    def ParseFvInf(self):
        """
            This function parses a FV.INF file and copies info into a FV_INFO structure.
            @param Stream: Fv inf file data - bytes
            @return: Return code
            """
        # Parse the FV inf file for header information
        Inf = ParseInf(self.InfFileImage)
        options = Inf.InfDict.get(OPTIONS_SECTION_STRING[1:-1])
        # 1. Read the FV base address
        if not self.FvDataInfo.BaseAddressSet:
            if options != None:
                BaseAddress = options.get(EFI_FV_BASE_ADDRESS_STRING)
                if BaseAddress != None:
                    self.FvDataInfo.BaseAddress = int(BaseAddress[0], 16)
                    self.FvDataInfo.BaseAddressSet = True
        # 2. Read the FV File System Guid
        if not self.FvDataInfo.FvFileSystemGuidSet:
            if options != None:
                GuidValue = options.get(EFI_FV_FILESYSTEMGUID_STRING)
                if GuidValue != None:
                    self.FvDataInfo.FvFileSystemGuid = GuidValue[0]
                    self.FvDataInfo.FvFileSystemGuidSet = True
        # 3. Read the FV Extension Header File Name
        Attributes = Inf.InfDict.get(ATTRIBUTES_SECTION_STRING[1:-1])
        ExtHeaderFile = Attributes.get(EFI_FV_EXT_HEADER_FILE_NAME)
        if ExtHeaderFile != None:
            self.FvDataInfo.FvExtHeaderFile = ExtHeaderFile[0]
        # 4. Read the FV file name
        FvFileName = options.get(EFI_FV_FILE_NAME_STRING)
        if FvFileName != None:
            self.FvDataInfo.FvName = FvFileName[0]
        # 5. Read Fv Attribute
        for Index in range(len(mFvbAttributeName)):
            AttrNameFromInf = Attributes.get(mFvbAttributeName[Index])
            if mFvbAttributeName[Index] != None and AttrNameFromInf != None:
                if AttrNameFromInf[0] == TRUE_STRING or AttrNameFromInf[
                    0] == ONE_STRING:
                    self.FvDataInfo.FvAttributes |= 1 << Index
                elif AttrNameFromInf[0] != FALSE_STRING and AttrNameFromInf[
                    0] != ZERO_STRING:
                    EdkLogger.error("GenFv",
                                    "Invalid parameter, %s expected %s | %s" % (
                                        mFvbAttributeName[Index], "TRUE",
                                        "FALSE"))

        # 6. Read Fv Alignment
        for Index in range(len(mFvbAlignmentName)):
            Alignment = Attributes.get(mFvbAttributeName[Index])
            if Alignment != None:
                if Alignment[0] == TRUE_STRING:
                    self.FvDataInfo.FvAttributes |= Index << 16
                    EdkLogger.info(
                        "FV file Alignment, Align = %s" % mFvbAlignmentName[
                            Index])
                    break

        # 7. Read weak alignment flag
        AlignmentFlag = Attributes.get(EFI_FV_WEAK_ALIGNMENT_STRING)
        if AlignmentFlag != None:
            if AlignmentFlag[0] == TRUE_STRING or AlignmentFlag[
                0] == ONE_STRING:
                self.FvDataInfo.FvAttributes |= EFI_FVB2_WEAK_ALIGNMENT
            elif AlignmentFlag[0] != FALSE_STRING and AlignmentFlag[
                0] != ZERO_STRING:
                EdkLogger.error('GenFv', PARAMETER_INVALID,
                                "Invalid parameter, Weak alignment value expected one of TRUE, FALSE, 1 or 0.")

        # 8. Read block maps
        flag = 0
        BlockSize = options.get(EFI_BLOCK_SIZE_STRING)
        NumBlock = options.get(EFI_NUM_BLOCKS_STRING)
        for Index in range(MAX_NUMBER_OF_FV_BLOCKS):
            if self.FvDataInfo.FvBlocks[Index].Length == 0 and Index < len(
                BlockSize):
                # Read block size

                if BlockSize:
                    # Update block size
                    self.FvDataInfo.FvBlocks[Index].Length = int(
                        BlockSize[Index],
                        16)
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
                    self.FvDataInfo.FvBlocks[Index].NumBlocks = int(
                        NumBlock[Index],
                        16)
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
                self.FvDataInfo.FvFiles[index] = FfsFiles[index]
        else:
            EdkLogger.warn('', "FV components are not specified.")

    def ParseCapInf(self):
        Inf = ParseInf(self.InfFileImage)
        Options = Inf.InfDict.get(OPTIONS_SECTION_STRING[1:-1])
        if Options != None:
            # Read the Capsuel guid
            CapGuid = Options.get(EFI_CAPSULE_GUID_STRING)
            if CapGuid != None:
                self.CapDataInfo.CapGuid = ModifyGuidFormat(CapGuid)
                EdkLogger.info(
                    "Capsule Guid, %s = %s" % (
                        EFI_CAPSULE_GUID_STRING, CapGuid))
            else:
                EdkLogger.error(None, PARAMETER_INVALID,
                                "Invalid parameter, %s = %s" % (
                                    EFI_CAPSULE_GUID_STRING, CapGuid))
            # Read the Capsule Header Size
            HeaderSize = Options.get(EFI_CAPSULE_HEADER_SIZE_STRING)
            if HeaderSize != None:
                self.CapDataInfo.HeaderSize = HeaderSize & 0xffffffff
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
                    self.CapDataInfo.Flags |= (
                        CAPSULE_FLAGS_PERSIST_ACROSS_RESET | CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE)
                elif Flags.find("InitiateReset") != -1:
                    self.CapDataInfo.Flags |= CAPSULE_FLAGS_INITIATE_RESET
                elif Flags.find("PersistAcrossReset") != -1:
                    self.CapDataInfo.Flags |= CAPSULE_FLAGS_INITIATE_RESET
                else:
                    EdkLogger.error(None, PARAMETER_INVALID,
                                    "Invalid parameter, invalid Flag setting for %s." % EFI_CAPSULE_FLAGS_STRING)
                EdkLogger.info("Capsule Flag %s" % Flags)
            OemFlags = Options.get(OPTIONS_SECTION_STRING)
            if OemFlags != None:
                if OemFlags > 0xffff:
                    EdkLogger.error(None, PARAMETER_INVALID,
                                    "invalid Flag setting for %s. Must be integer value between 0x0000 and 0xffff." % OemFlags)
                self.CapDataInfo.Flags |= OemFlags
                EdkLogger.info("Capsule Extend Flag %s" % OemFlags)

            # Read Capsule file name
            CapName = Options.get(EFI_FILE_NAME_STRING)
            if CapName != None:
                self.CapDataInfo.CapName = CapName
            # Read the capsule file image
            FileSection = Inf.InfDict.get(FILES_SECTION_STRING[1:-1])
            CapsuleFiles = FileSection.get(EFI_FILE_NAME_STRING)
            Number = 0
            for Index in range(len(CapsuleFiles)):
                self.CapDataInfo.CapFiles[Index] = CapsuleFiles[Index]
                Number += 1

            if Number == 0:
                EdkLogger.warn("Capsule compenents are not specified.")

    def CalculateFvSize(self):
        MaxPadFileSize = 0
        VtfFileSize = 0
        # global mIsLargeFfs
        self.IsLargeFfs = False
        FfsHeader = None
        # Compute size for easy access later
        for Index in range(MAX_NUMBER_OF_FV_BLOCKS):
            if self.FvDataInfo.FvBlocks[Index].NumBlocks > 0 and \
                self.FvDataInfo.FvBlocks[
                    Index].Length > 0:
                self.FvDataInfo.Size += self.FvDataInfo.FvBlocks[
                                            Index].NumBlocks * \
                                        self.FvDataInfo.FvBlocks[
                                            Index].Length

        # Calculate the required sizes for all FFS files.
        CurrentOffset = sizeof(EFI_FIRMWARE_VOLUME_HEADER())

        for Index in range(MAX_NUMBER_OF_FV_BLOCKS):
            CurrentOffset += sizeof(EFI_FV_BLOCK_MAP_ENTRY())
            if self.FvDataInfo.FvBlocks[Index].NumBlocks == 0 or \
                self.FvDataInfo.FvBlocks[
                    Index].Length == 0:
                break

        # Calculate PI extension header
        if self.FvDataInfo.FvExtHeaderFile:
            with open(self.FvDataInfo.FvExtHeaderFile, 'rb') as file:
                FvExtHeaderSize = len(file.read())
            if sizeof(EFI_FFS_FILE_HEADER()) + FvExtHeaderSize >= MAX_FFS_SIZE:
                CurrentOffset += sizeof(
                    EFI_FFS_FILE_HEADER2()) + FvExtHeaderSize
                self.IsLargeFfs = True
            else:
                CurrentOffset += sizeof(EFI_FFS_FILE_HEADER()) + FvExtHeaderSize
            CurrentOffset = (CurrentOffset + 7) & (~7)
        elif self.FvDataInfo.FvNameGuidSet:
            CurrentOffset += sizeof(EFI_FFS_FILE_HEADER()) + sizeof(
                EFI_FIRMWARE_VOLUME_EXT_HEADER())
            CurrentOffset = (CurrentOffset + 7) & (~7)

        # Accumulate every FFS file size.
        for Index in range(MAX_NUMBER_OF_FILES_IN_FV):
            if self.FvDataInfo.FvFiles[Index]:
                # OPen ffs file
                with open(LongFilePath(self.FvDataInfo.FvFiles[Index]),
                          'rb') as file:
                    FfsData = file.read()
                    FfsFileSize = len(FfsData)
                if FfsFileSize >= MAX_FFS_SIZE:
                    FfsHeaderSize = sizeof(EFI_FFS_FILE_HEADER2())
                    self.IsLargeFfs = True
                else:
                    FfsHeaderSize = sizeof(EFI_FFS_FILE_HEADER())
                # Read ffs file header
                FfsHeader = EFI_FFS_FILE_HEADER.from_buffer_copy(FfsData)

                if self.FvDataInfo.IsPiFvImage:
                    # Check whether this ffs file is vtf file
                    if IsVtfFile(FfsHeader):
                        if VtfFileFlag:
                            EdkLogger.error('', FILE_CHECKSUM_FAILURE,
                                            "Invalid, One Fv image can't have two vtf files.")
                            # return FILE_CHECKSUM_FAILURE
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
                if self.FvDataInfo.SizeOfFvFiles[Index] > FfsFileSize:
                    CurrentOffset += self.FvDataInfo.SizeOfFvFiles[Index]
                else:
                    CurrentOffset += FfsFileSize
                # Make next ffs file start at QWord Boundary
                if self.FvDataInfo.IsPiFvImage:
                    CurrentOffset = (
                                        CurrentOffset + EFI_FFS_FILE_HEADER_ALIGNMENT - 1) & ~(
                        EFI_FFS_FILE_HEADER_ALIGNMENT - 1)

        CurrentOffset += VtfFileSize
        EdkLogger.info(
            "FvImage size, the calculated fv image size is 0x%X and the current set fv image size is 0x%x" % (
                CurrentOffset, self.FvDataInfo.Size))

        # Update self.FvDataInfo data
        if self.FvDataInfo.Size == 0:
            self.FvDataInfo.FvBlocks[0].NumBlocks = CurrentOffset // \
                                                    self.FvDataInfo.FvBlocks[
                                                        0].Length + (
                                                        1 if CurrentOffset %
                                                             self.FvDataInfo.FvBlocks[
                                                                 0].Length else 0)
            self.FvDataInfo.Size = self.FvDataInfo.FvBlocks[0].NumBlocks * \
                                   self.FvDataInfo.FvBlocks[
                                       0].Length
            self.FvDataInfo.FvBlocks[0].NumBlocks = 0
            self.FvDataInfo.FvBlocks[0].Length = 0
        elif self.FvDataInfo.Size < CurrentOffset:
            # Not Invalid
            EdkLogger.error("", PARAMETER_INVALID,
                            "Invalid, the required fv image size 0x%x exceeds the set fv image size 0x%x" % (
                                CurrentOffset, self.FvDataInfo.Size))

        # Set Fv Size Information
        # global mFvTotalSize, mFvTakenSize
        self.FvTotalSize = self.FvDataInfo.Size
        self.FvTakenSize = CurrentOffset
        if self.FvTakenSize == self.FvTotalSize and MaxPadFileSize > 0:
            self.FvTakenSize = self.FvTakenSize - MaxPadFileSize

    def ReadFfsAlignment(self, FfsHeader):
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

    def IsVtfFile(self, FfsHeader):
        if not FfsHeader.Name.__cmp__(EFI_FFS_VOLUME_TOP_FILE_GUID):
            return True
        return False

    def UpdateRiscvResetVectorIfNeeded(self):
        # Find the Sec Core
        SecPe32Off = self.FindCorePeSection(self.FvImage,
                                            EFI_FV_FILETYPE_SECURITY_CORE)
        if not SecPe32Off:
            EdkLogger.info("skip because Secutiry Core not found\n")
            return

        EdkLogger.info("Update SEC core in FV Header")
        SecHeader = self.GetCommonSectionByBuffer(self.FvImage[SecPe32Off:])
        MachineType = self.GetCoreMachineType(
            self.FvImage[SecPe32Off:SecPe32Off + SecHeader.SECTION_SIZE],
            SecHeader)
        if MachineType != IMAGE_FILE_MACHINE_RISCV64:
            EdkLogger.error(None, 0,
                            "Could not update SEC core because Machine type is not RiscV.")

        SecCoreEntryAddress = self.GetCoreEntryPointAddress(SecPe32Off)
        EdkLogger.info(
            "SecCore entry point Address = 0x%X" % SecCoreEntryAddress)
        EdkLogger.info("BaseAddress = 0x%X" % self.FvDataInfo.BaseAddress)
        bSecCore = SecCoreEntryAddress - self.FvDataInfo.BaseAddress
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

        self.FvImage[:4] = self.FvImage[bSecCore:bSecCore + 4]

    def UpdateLoongArchResetVectorIfNeeded(self):
        # Locate an SEC Core instance and if found extract the machine type and entry point address
        SecPe32Off = self.FindCorePeSection(self.FvImage,
                                            EFI_FV_FILETYPE_SECURITY_CORE)
        if SecPe32Off:
            SecHeader = self.GetCommonSectionByBuffer(self.FvImage[SecPe32Off:])
            MachineType = self.GetCoreMachineType(
                self.FvImage[SecPe32Off:SecHeader.SECTION_SIZE], SecHeader)
            SecCoreEntryAddress = self.GetCoreEntryPointAddress(SecPe32Off)
            UpdateVectorSec = True
            if not UpdateVectorSec:
                return

            if MachineType == IMAGE_FILE_MACHINE_LOONGARCH64:
                ResetVecotr = [0]
                if UpdateVectorSec:
                    EdkLogger.info(
                        "UpdateLoongArchResetVectorIfNeeded updating LOONGARCH64 SEC vector")
                    ResetVecotr[0] = ((
                                          SecCoreEntryAddress - self.FvDataInfo.BaseAddress) & 0x3FFFFFF) >> 2
                    ResetVecotr[0] = ((ResetVecotr[0] & 0x0FFFF) << 16) | (
                        (ResetVecotr[0] >> 16) & 0x3FF)
                    ResetVecotr[0] = 0x50000000
                # Copy to the beginning of the FV
                self.FvImage[:8] = b''.join(
                    [i.to_bytes(4, 'little') for i in ResetVecotr])
            else:
                EdkLogger.error(None, 0, "Unknown machine type")

    def UpdateArmResetVectorIfNeeded(self):
        UpdateVectorSec = False
        MachineType = 0
        UpdateVectorPei = False
        SecCoreEntryAddress = 0
        PeiCoreEntryAddress = 0

        # Locate an SEC Core instance and if found extract the machine type and entry point address
        SecPe32Off = self.FindCorePeSection(self.FvImage,
                                            EFI_FV_FILETYPE_SECURITY_CORE)
        if SecPe32Off:
            SecPe32SectionHeader = self.GetCommonSectionByBuffer(
                self.FvImage[SecPe32Off:])
            MachineType = self.GetCoreMachineType(self.FvImage[SecPe32Off:],
                                                  SecPe32SectionHeader)

            SecCoreEntryAddress = self.GetCoreEntryPointAddress(SecPe32Off)
            EdkLogger.info(
                "UpdateArmResetVectorIfNeeded found SEC core entry at 0x%x" % SecCoreEntryAddress)
            UpdateVectorSec = True

        # Locate a PEI Core instance and if found extract the machine type and entry point address
        PeiPe32Off = self.FindCorePeSection(self.FvImage,
                                            EFI_FV_FILETYPE_PEI_CORE)
        if PeiPe32Off:
            PeiSectionHeader = self.GetCommonSectionByBuffer(
                self.FvImage[PeiPe32Off:])
            PeiMachineType = self.GetCoreMachineType(self.FvImage[PeiPe32Off:],
                                                     PeiSectionHeader)

            PeiCoreEntryAddress = self.GetCoreEntryPointAddress(PeiPe32Off)
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
            return

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
                EntryOffset = SecCoreEntryAddress - self.FvDataInfo.BaseAddress
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
            self.FvImage[:32] = b''.join(
                [i.to_bytes(4, 'little') for i in ResetVector])
        elif MachineType == IMAGE_FILE_MACHINE_ARM64:
            ResetVector = [0 for i in range(2)]
            if UpdateVectorSec:
                EdkLogger.info(
                    "UpdateArmResetVectorIfNeeded updating AArch64 SEC vector")
                ResetVector[0] = (
                                     SecCoreEntryAddress - self.FvDataInfo.BaseAddress) >> 2
                if ResetVector[0] > 0x03FFFFFF:
                    EdkLogger.error(None, 0,
                                    "SEC Entry point must be within 128MB of the start of the FV")
                ResetVector[0] |= ARM64_UNCONDITIONAL_JUMP_INSTRUCTION
            if UpdateVectorPei:
                EdkLogger.info(
                    "UpdateArmResetVectorIfNeeded updating AArch64 PEI address")
                ResetVector[1] = PeiCoreEntryAddress
                self.FvImage[:16] = b''.join(
                    [i.to_bytes(8, 'little') for i in ResetVector])
        else:
            EdkLogger.error(None, 0, "Unknown machine type")

    def GetCoreEntryPointAddress(self, SecPe32):
        SecHdrSize = self.GetCommonSectionByBuffer(
            self.FvImage[SecPe32:]).HeaderLength
        Res = self.GetPe32Info(self.FvImage[SecPe32 + SecHdrSize:])
        if not Res:
            EdkLogger.error(None, 0,
                            "Could not get the PE32 entry point for the core.")
        EntryPoint = Res[0]
        # Physical address is FV base + offset of PE32 + offset of the entry point
        EntryPhysicalAddress = self.FvDataInfo.BaseAddress
        EntryPhysicalAddress += SecPe32 + SecHdrSize + EntryPoint
        # Set value starting of FV
        self.FvImage[0] = EntryPhysicalAddress

        return EntryPhysicalAddress

    def UpdateResetVector(self):
        # Initialize FV library
        FvLib = FvLibrary(self.FvImage)
        # Verify VTF file
        FvLib.VerifyFfsFile(FvImage[self.VtfFileImageAddress:])

        if (self.VtfFileImageAddress >= IA32_X64_VTF_SIGNATURE_OFFSET) and (
            self.VtfFileImageAddress - IA32_X64_VTF_SIGNATURE_OFFSET == IA32_X64_VTF0_SIGNATURE):
            Vtf0Detected = True
        else:
            Vtf0Detected = False
        #
        # Find the Sec Core
        #
        SecCoreFileOff = FvLib.GetFileByType(EFI_FV_FILETYPE_SECURITY_CORE, 1)
        if not SecCoreFileOff:
            if Vtf0Detected:
                return
            EdkLogger.error(None, 0,
                            "Could not find the SEC core file in the FV.")
        SecCoreFileBuffer = FvLib.FvBuffer[SecCoreFileOff:]
        # Sec Core found, now find PE32 section
        Pe32SectionOff = GetSectionByType(SecCoreFileBuffer, EFI_SECTION_PE32,
                                          1)
        if not Pe32SectionOff:
            Pe32SectionOff = GetSectionByType(SecCoreFileBuffer, EFI_SECTION_TE,
                                              1)
        if not Pe32SectionOff:
            EdkLogger.error(None, 0,
                            "Could not find a PE32 seciton in the SEC core file.")

        SecHeaderSize = self.GetCommonSectionByBuffer(
            SecCoreFileBuffer[Pe32SectionOff:]).Common_Header_Size
        EntryPoint, BaseOfCode, MachineType = self.GetPe32Info(
            SecCoreFileBuffer[Pe32SectionOff + SecHeaderSize:])

        if Vtf0Detected and (
            MachineType == IMAGE_FILE_MACHINE_I386 or MachineType == IMAGE_FILE_MACHINE_X64):
            return
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
            Pe32SectionOff = GetSectionByType(PeiCoreFileBuffer,
                                              EFI_SECTION_PE32,
                                              1)
            if not Pe32SectionOff:
                Pe32SectionOff = GetSectionByType(PeiCoreFileBuffer,
                                                  EFI_SECTION_TE,
                                                  1)
            if not Pe32SectionOff:
                EdkLogger.error(None, 0,
                                "Could not find either a PE32 or a Te section in PET core file.")

            SecHeaderSize = self.GetCommonSectionByBuffer(
                PeiCoreFileBuffer[Pe32SectionOff:]).Common_Header_Size
            EntryPoint, BaseOfCode, MachineType = self.GetPe32Info(
                PeiCoreFileBuffer[Pe32SectionOff + SecHeaderSize:])

            # Physical address is FV base + offset of PE32 + offset of the entry point
            PeiCorePhysicalAddress = self.FvDataInfo.BaseAddress + Pe32SectionOff + SecHeaderSize + EntryPoint
            EdkLogger.info(
                "PeiCore physical entry point address, Address = 0x%X" % PeiCorePhysicalAddress)

        if MachineType == IMAGE_FILE_MACHINE_I386 or MachineType == IMAGE_FILE_MACHINE_X64:
            if PeiCorePhysicalAddress != 0:
                # Get the location to update
                # Write lower 32 bits of physical address for Pei Core entry
                self.FvImage[
                    self.VtfFileImageAddress - IA32_PEI_CORE_ENTRY_OFFSET] = PeiCorePhysicalAddress
            # Write SecCore Entry point relative address into the jmp instruction in reset vector.
            Ia32SecEntryOffset = SecCorePhysicalAddress - (
                FV_IMAGES_TOP_ADDRESS - IA32_SEC_CORE_ENTRY_OFFSET + 2)
            if Ia32SecEntryOffset <= (-65536):
                EdkLogger.error(None, 0,
                                "The SEC EXE file size is too large, it must be less than 64K.")
            self.FvImage[
                self.VtfFileImageAddress - IA32_SEC_CORE_ENTRY_OFFSET] = Ia32SecEntryOffset

            # Update the BFV base address
            self.FvImage[
                self.VtfFileImageAddress - 4] = self.FvDataInfo.BaseAddress
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
        VtfFile = self.GetFfsHeader(self.FvImage[self.VtfFileImageAddress:])
        if not VtfFile:
            return
        SavedState = VtfFile.State
        VtfFile.IntegrityCheck.Checksum.File = 0
        VtfFile.State = 0
        if VtfFile.Attributes & FFS_ATTRIB_CHECKSUM:
            VtfFile.IntegrityCheck.Checksum.File = CalculateChecksum8(
                self.FvImage[
                self.VtfFileImageAddress + VtfFile.HeaderLenth:self.VtfFileImageAddress + VtfFile.FFS_FILE_SIZE])
        else:
            VtfFile.IntegrityCheck.Checksum.File = FFS_FIXED_CHECKSUM

        VtfFile.State = SavedState
        VtfFileBuffer = struct2stream(VtfFile) + self.FvImage[
                                                 self.VtfFileImageAddress + VtfFile.HeaderLenth:]
        self.FvImage[
        self.VtfFileImageAddress:self.VtfFileImageAddress + VtfFile.FFS_FILE_SIZE] = VtfFileBuffer

    def GetPe32Info(self, Pe32: bytes) -> tuple:
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

    def PadFvImage(self, FvImageSize: int):
        # If there is no VTF or the VTF naturally follows the previous file without a
        # pad file, then there's nothing to do
        if self.VtfFileImageAddress == self.FvImagePointer or self.VtfFileImageAddress == FvImageSize:
            return

        if self.VtfFileImageAddress < self.FvImagePointer:
            EdkLogger.error(None, 0,
                            "FV space is full, cannot add pad file between the last file and the VTF file.")

        # Pad file starts at beginning of free space
        PadFile = EFI_FFS_FILE_HEADER()
        # write PadFile FFS header with PadType, don't need to set PAD file guid in its header.
        PadFile.Type = EFI_FV_FILETYPE_FFS_PAD
        PadFile.Attributes = 0
        # FileSize includes the EFI_FFS_FILE_HEADER
        FileSize = self.VtfFileImageAddress - self.FvImagePointer
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
        PadFile = self.UpdateFfsFileState(PadFile,
                                          Refine_FV_Header(
                                              self.NumOfBlocks + 1).from_buffer_copy(
                                              FvImage))
        self.FvImage[self.FvImagePointer:FvImageSize] = struct2stream(PadFile)
        # Update the current FV pointer
        self.FvImagePointer = FvImageSize

    def AddFile(self, Index):
        # Verify input parameters.
        if not self.FvImage or not self.FvDataInfo or not \
            self.FvDataInfo.FvFiles[
                0] or not self.VtfFileImageAddress:
            EdkLogger.error(None, PARAMETER_INVALID,
                            gErrorMessage[PARAMETER_INVALID])

        # Read the file to add
        try:
            with open(LongFilePath(self.FvDataInfo.FvFiles[Index]),
                      'rb') as file:
                NewFileBuffer = bytearray(file.read())
                NewFileSize = len(NewFileBuffer)
        except Exception as X:
            EdkLogger.error("GenFv", FILE_OPEN_FAILURE,
                            "Error reading file: %s" % self.FvDataInfo.FvFiles[
                                Index])

        # For None PI Ffs file, directly add them into FvImage.
        if not self.FvDataInfo.IsPiFvImage:
            self.FvImage[
            self.FvImagePointer: self.FvImagePointer + NewFileSize] = NewFileBuffer
            if self.FvDataInfo.SizeOfFvFiles[Index] > NewFileSize:
                self.FvImagePointer += self.FvDataInfo.SizeOfFvFiles[Index]
            else:
                self.FvImagePointer += NewFileSize
            return

        # Init FV library
        # FvHeader = EFI_FIRMWARE_VOLUME_HEADER.from_buffer_copy(FvImage)
        Fvlib = FvLibrary(self.FvImage)
        # Verify Ffs file
        Fvlib.VerifyFfsFile(NewFileBuffer)

        # Verify space exists to add the file
        if NewFileSize > (self.VtfFileImageAddress - self.FvImagePointer):
            EdkLogger.error(None, RESOURCE_FULL,
                            "Resource, FV space is full, not enough room to add file %s" %
                            self.FvDataInfo.FvFiles[Index])

        # Verify the input file is the duplicated file in this Fv image
        FfsHeader = EFI_FFS_FILE_HEADER.from_buffer_copy(NewFileBuffer)
        if FfsHeader.Name in mFileGuidArray:
            EdkLogger.error(None, PARAMETER_INVALID,
                            "Invalid parameter, the %s file have the same GUID." % FfsHeader.Name)
        mFileGuidArray.append(FfsHeader.Name)

        # Update the file statue based on polarity of the FV.
        FfsHeader = self.UpdateFfsFileState(FfsHeader,
                                            EFI_FIRMWARE_VOLUME_HEADER.from_buffer_copy(
                                                self.FvImage))
        # Update FfsHeader in New FFS image
        NewFileBuffer[:FfsHeader.HeaderLength] = struct2stream(FfsHeader)
        # Check if alignment is required
        FfsAlignment = self.ReadFfsAlignment(FfsHeader)
        # Find the largest alignment of all the FFS files in the FV
        if FfsAlignment > self.MaxFfsAlignment:
            self.MaxFfsAlignment = FfsAlignment
        # if we have a VTF file, add it at the top
        if self.IsVtfFile(FfsHeader):
            if self.VtfFileImageAddress == len(self.FvImage):
                # No previous VTF, add this one.
                self.VtfFileImageAddress = self.FvDataInfo.Size - NewFileSize
                # Sanity check, The file MUST align appropriately
                if (self.VtfFileImageAddress + FfsHeader.HeaderLength) % (
                    1 << FfsAlignment):
                    EdkLogger.error(None, FORMAT_INVALID,
                                    "Invalid, VTF file cannot be aligned on a %u-byte boundary." % (
                                        1 << FfsAlignment))
                # Rebase the PE or TE image in FileBuffer of FFS file for XIP
                # Rebase for the debug genfvmap tool
                VtfImage = self.FfsRebase(self.FvDataInfo.FvFiles[Index],
                                          NewFileBuffer,
                                          self.VtfFileImageAddress)
                if not VtfImage:
                    EdkLogger.error(None, 0,
                                    "Could not rebase %s." %
                                    self.FvDataInfo.FvFiles[
                                        Index])

                # Copy VTF file To FV image
                self.FvImage[self.VtfFileImageAddress:] = VtfImage

                FileGuidToString = PrintGuidToBuffer(FfsHeader.Name, True)
                with open(self.FvReportName, 'w') as FRF:
                    FRF.write("0x%08X %s\n" % (
                        self.VtfFileImageAddress, FileGuidToString))
                EdkLogger.info("Add VTF FFS file in FV image.")
                return
            else:
                EdkLogger.error(None, 0,
                                "Invalid, multiple VTF files are not permitted within a single FV.")

        # Add pad file if necessary
        Flag, NewFileBuffer = self.AdjustInternalFfsPadding(NewFileBuffer,
                                                            1 << FfsAlignment,
                                                            NewFileSize)
        NewFileSize = len(NewFileBuffer)
        if Flag == False:
            self.AddPadFile(1 << FfsAlignment, len(NewFileBuffer))

        # Add file
        if self.FvImagePointer + NewFileSize <= self.VtfFileImageAddress:
            NewFileBuffer = self.FfsRebase(self.FvDataInfo.FvFiles[Index],
                                           NewFileBuffer,
                                           self.FvImagePointer)

            # Copy the file
            self.FvImage[self.FvImagePointer:self.FvImagePointer + len(
                NewFileBuffer)] = bytes(
                NewFileBuffer)

            FileGuidString = PrintGuidToBuffer(
                EFI_FFS_FILE_HEADER.from_buffer_copy(NewFileBuffer).Name, True)
            with open(self.FvReportName, 'a') as Fp:
                Fp.write("0x%08X %s\n" % (self.FvImagePointer, FileGuidString))
            self.FvImagePointer += NewFileSize
        else:
            EdkLogger.error(None, 0,
                            "FV space is full, cannot add file %s" %
                            FvInfo.FvFiles[
                                Index])

        # Make next file start at QWord Boundary
        while self.FvImagePointer & (EFI_FFS_FILE_HEADER_ALIGNMENT - 1) != 0:
            self.FvImagePointer += 1

        return

    def GetFfsHeader(self, FfsBuffer: bytes):
        if len(FfsBuffer) == 0:
            return
        FfsHeader = EFI_FFS_FILE_HEADER.from_buffer_copy(FfsBuffer)
        if FfsHeader.Attributes & FFS_ATTRIB_LARGE_FILE:
            FfsHeader = EFI_FFS_FILE_HEADER2.from_buffer_copy(FfsBuffer)
        return FfsHeader

    def AdjustInternalFfsPadding(self, FfsBuffer: bytes, Alignment: int,
                                 FileSize: int):
        # Figure out the misalignment: all FFS sections are aligned relative to the
        # start of the FFS payload, so use that as the base of the misalignment computation.
        FfsHeader = GetFfsHeader(FfsBuffer)
        FfsHeaderLength = FfsHeader.HeaderLength
        # TODO: Check
        Misalignment = self.FvImagePointer - FfsHeaderLength
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
        CommonSecHdr = self.GetCommonSectionByBuffer(
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
            PadSection) + FfsBuffer[
                          PadSectionOff + sizeof(CommonSecHdr) + sizeof(
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

    def FfsRebase(self, FfsFile: str, FfsBuffer: bytes,
                  XipOffset: int) -> bytes:
        NewFfsFileBuffer = bytearray(FfsBuffer)

        # Don't need to relocate image when BaseAddress is zero and no ForceRebase Flag specified.
        if self.FvDataInfo.BaseAddress == 0 and self.FvDataInfo.ForceRebase == -1:
            return bytes(NewFfsFileBuffer)

        # If ForceRebase Flag specified to FALSE, will always not take rebase action.
        if self.FvDataInfo.ForceRebase == 0:
            return bytes(NewFfsFileBuffer)

        XipBase = self.FvDataInfo.BaseAddress + XipOffset
        FfsHeader = EFI_FFS_FILE_HEADER.from_buffer_copy(FfsBuffer)
        # We only process files potentially containing PE32 sections.
        if FfsHeader.Type == EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE:
            self.GetChildFvFromFfs(FfsBuffer, XipOffset)
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

            CurSecHdr = self.GetCommonSectionByBuffer(
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
                EdkLogger.warn(
                    "Invalid, The file %s no .reloc section." % FfsFile)
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
            NewFfsHeader = EFI_FFS_FILE_HEADER.from_buffer_copy(
                NewFfsFileBuffer)
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

            self.WriteMapFile(self.MapFileName, PdbPointer, NewFfsHeader,
                              NewPe32BaseAddress,
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
            TeSection = GetSectionByType(FfsBuffer, EFI_SECTION_TE, Index)
            if not TeSection:
                break

            TeSecHdr = self.GetCommonSectionByBuffer(
                FfsBuffer[TeSection:])
            TeSecHdrSize = TeSecHdr.Common_Header_Size()
            TeSecLength = TeSecHdr.SECTION_SIZE

            TeHeader = self.GetCommonSectionByBuffer(
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

            NewTeImage, ImageContext = PeCoffLoaderLoadImage(ImageContext,
                                                             TeImage)
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

            self.WriteMapFile(self.MapFileName, PdbPointer, FfsHeader,
                              NewPe32BaseAddress,
                              OrigImageContext, NewFfsFileBuffer)

        return bytes(NewFfsFileBuffer)

    def WriteMapFile(self, FvMapFile: str, FfsFileName: str,
                     FfsFile: EFI_FFS_FILE_HEADER,
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
        PeMapFileName = os.path.normpath(
            os.path.splitext(FfsFileName)[0] + '.map')

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
            ModuleContent += "BaseAddress=0x%010x, " % (
                ImageBaseAddress + Offset)

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
                    match = re.match(
                        r'\s*\S+\s+\w+\s+[a-zA-Z0-9]+\s+[a-zA-Z]{1}\b',
                        line)
                    if match:
                        matchObjlst = [i for i in match.group().split(' ') if i]
                        FunctionName = matchObjlst[1].strip()
                        FunctionAddress = int(matchObjlst[2].strip(), 16)
                        FunctionTypeName = matchObjlst[3].strip()
                        if FunctionTypeName[0] == 'f' or FunctionTypeName[
                            0] == 'F':
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

    def GetChildFvFromFfs(self, FfsBuffer: bytes, XipOffset: int):
        Index = 1
        while True:
            SubFvSectionPointer, SubFvSection = GetSectionByType(FfsBuffer,
                                                                 EFI_SECTION_FIRMWARE_VOLUME_IMAGE,
                                                                 Index)

            SubFvImagePointer = SubFvSectionPointer + SubFvSection.SECTION_SIZE

            #  See if there's an SEC core in the child FV
            CorePe32 = self.FindCorePeSection(FfsBuffer[SubFvImagePointer:],
                                              EFI_FV_FILETYPE_SECURITY_CORE)
            if not CorePe32:
                CorePe32 = self.FindCorePeSection(FfsBuffer[SubFvImagePointer:],
                                                  EFI_FV_FILETYPE_PEI_CORE)

            if CorePe32:
                CommonHeader = self.GetCommonSectionByBuffer(
                    FfsBuffer[CorePe32:])
                MachineType = self.GetCoreMachineType(FfsBuffer[CorePe32:],
                                                      CommonHeader)

            if MachineType == IMAGE_FILE_MACHINE_ARMTHUMB_MIXED or MachineType == IMAGE_FILE_MACHINE_ARM64:
                EdkLogger.info("Located ARM/AArch64 SEC/PEI core in child FV")
                mArm = True

            if MachineType == IMAGE_FILE_MACHINE_LOONGARCH64:
                EdkLogger.info("Located LoongArch64 SEC core in child FV")
                mLoongArch = True

            # Rebase on Flash
            SubFvBaseAddress = self.FvDataInfo.BaseAddress + SubFvImagePointer + XipOffset
            mFvBaseAddress.append(SubFvBaseAddress)

    def GetCommonSectionByBuffer(self, Buffer: bytes):
        CommonHeader = EFI_COMMON_SECTION_HEADER.from_buffer_copy(Buffer)
        if CommonHeader.SECTION_SIZE == 0xffffff:
            CommonHeader = EFI_COMMON_SECTION_HEADER2.from_buffer_copy(Buffer)

        return CommonHeader

    def GetCoreMachineType(self, Pe32Section: bytes, CorePe32SectionHeader):
        res = GetPe32Info(Pe32Section[sizeof(CorePe32SectionHeader):])
        if not res:
            EdkLogger.error(None, 0,
                            "Could not get the PE32 machine type for the core.")
        MachineType = res[2]
        return MachineType

    def FindCorePeSection(self, ImageBuffer: bytes, FileType: int):
        # Initialize FV library, saving previous values
        Fvlib = FvLibrary(ImageBuffer)
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
                EncapFvSection = GetSectionByType(
                    ImageBuffer[FvImageFileOff:],
                    EFI_SECTION_FIRMWARE_VOLUME_IMAGE,
                    EncapFvSectionCount)
                if not EncapFvSectionCount:
                    break
                EncapsulatedFvOff = EncapFvSection
                CommonHeader = EFI_COMMON_SECTION_HEADER.from_buffer_copy(
                    ImageBuffer[EncapsulatedFvOff:])
                if CommonHeader.SECTION_SIZE == 0xffffff:
                    CommonHeader = EFI_COMMON_SECTION_HEADER2.from_buffer_copy(
                        ImageBuffer[EncapsulatedFvOff:])
                if CommonHeader.Type == EFI_SECTION_COMPRESSION:
                    EncapsulatedFvHeaderLength = CommonHeader.Common_Header_Size + sizeof(
                        EFI_SECTION_COMPRESSION)
                if CommonHeader.Type == EFI_SECTION_GUID_DEFINED:
                    EncapsulatedFvHeaderLength = CommonHeader.Common_Header_Size + sizeof(
                        EFI_SECTION_GUID_DEFINED)
                Pe32Section = FindCorePeSection(ImageBuffer[
                                                EncapsulatedFvOff + EncapsulatedFvHeaderLength:],
                                                FileType)

                if Pe32Section:
                    return Pe32Section

        return

    def UpdateFfsFileState(self, FfsFile, FvHeader):
        if FvHeader.Attributes & EFI_FVB2_ERASE_POLARITY:
            FfsFile.State = GetReverseCode(FfsFile.State)
        return FfsFile

    def AddPadFile(self, DataAlignment: int, NextFfsSize: int, FvExtHeader=None,
                   FvExtBuffer=None):
        FvHeader = Refine_FV_Header(self.NumOfBlocks + 1).from_buffer_copy(
            self.FvImage)
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
            if (self.FvImagePointer + NextFfsHeaderSize) % DataAlignment == 0:
                return

            PadFileSize = self.FvImagePointer + sizeof(
                PadFileHeader) + NextFfsHeaderSize
            # Add whatever it takes to get to the next aligned address
            while PadFileSize % DataAlignment != 0:
                PadFileSize += 1
            # Subtract the next file header size
            PadFileSize -= NextFfsHeaderSize
            # Subtract the starting offset to get size
            PadFileSize -= self.FvImagePointer
        # Verify that we have enough space for the file header
        if self.FvImagePointer + PadFileSize > self.VtfFileImageAddress:
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
        self.FvImage[
        self.FvImagePointer + 16:self.FvImagePointer + CurFfsHeaderSize] = struct2stream(
            PadFileHeader)[16:]
        PadFilePointer = self.FvImagePointer
        self.FvImagePointer += PadFileSize

        if FvExtHeader != None:
            ExtFileBuffer = bytearray(FvExtBuffer)
            # Copy Fv Extension Header and Set Fv Extension header offset
            if FvExtHeader.ExtHeaderSize > sizeof(
                EFI_FIRMWARE_VOLUME_EXT_HEADER):
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
            self.FvImage[
            PadFilePointer + CurFfsHeaderSize:PadFilePointer + CurFfsHeaderSize + FvExtHeader.ExtHeaderSize] = ExtFileBuffer

            FvHeader.ExtHeaderOffset = PadFilePointer + CurFfsHeaderSize
            # Update Fv header image
            self.FvImage[:FvHeader.HeaderLength] = struct2stream(FvHeader)
            while self.FvImagePointer & (
                EFI_FFS_FILE_HEADER_ALIGNMENT - 1) != 0:
                self.FvImagePointer += 1

        return

    def WriteFile(self):
        with open(LongFilePath(self.OutFileName), 'wb') as file:
            file.write(self.FvImage)


def main():
    EdkLogger.Initialize()
    GenFvApi()


if __name__ == '__main__':
    exit(main())
