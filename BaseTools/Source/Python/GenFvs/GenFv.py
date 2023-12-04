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

UTILITY_NAME = "GenFvs"
versionNumber = "1.0" + ' ' + gBUILD_VERSION
__version__ = "%prog Version " + versionNumber
__copyright__ = "Copyright (c) 2007 - 2018, Intel Corporation  All rights reserved."

logger = logging.getLogger(UTILITY_NAME)
STATUS_ERROR = -1


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


def main():
    EdkLogger.Initialize()
    # Init var
    AddrFileName = None
    InfFileName = None
    InfFileImage = None
    OutFileName = None
    CapsuleFlag = False
    DumpCapsule = False
    Index = 0
    # Set the default FvGuid
    mFvDataInfo.FvFileSystemGuid = mEfiFirmwareFileSystem2Guid
    mFvDataInfo.ForceRebase = -1
    # Parse command line
    args = MyOptionsParser()

    if args.InFileName:
        InFileName = args.InFileName

    if args.OutFileName:
        OutFileName = args.OutFileName

    if args.AddressFile:
        AddrFileName = args.AddressFile

    if args.Address:
        # 1. Ascii string to c_uint64
        TempNumber = args.Address
        # 2.
        mFvDataInfo.BaseAddress = TempNumber
        mFvDataInfo.BaseAddressSet = True

    if args.BlockSize:
        if args.BlockSize == 0:
            EdkLogger.error(UTILITY_NAME, 0,
                            "Invalid option value, Fv block size can't be set to zero.")

        mFvDataInfo.FvBlocks[0].Length = args.BlockSize
        EdkLogger.info(
            "FV Block Size, %s = %s" % (EFI_BLOCK_SIZE_STRING, args.BlockSize))

    if args.NumberBlock:
        # 1. Ascii string to c_uint64
        if args.NumberBlock == 0:
            EdkLogger.error(UTILITY_NAME, 0,
                            "Invalid option value, Fv block size can't be set to zero.")

        mFvDataInfo.FvBlocks[0].NumBlocks = args.NumberBlock
        EdkLogger.info("FV Number Block %s = %s" % (
            EFI_NUM_BLOCKS_STRING, args.NumberBlock))

    if args.FfsFile and args.FileTakeSize:
        if len(args.FfsFile) > (MAX_LONG_FILE_PATH - 1):
            EdkLogger.error(UTILITY_NAME, 0,
                            "Invalid option value, Input Ffsfile name %s is too long!: %s" % args.FfsFile)

        if not os.path.exists(args.FfsFile):
            EdkLogger.error(UTILITY_NAME, 0,
                            "Invalid option value, Input Ffsfile not exist.")

        mFvDataInfo.FvFiles[Index] = args.FfsFile
        mFvDataInfo.SizeofFvFiles[Index] = args.FileTakeSize

    # else:
    #     logger.error(
    #         "Invalid option, It must be specified together with -f option to specify the file size.")
    #     return STATUS_ERROR

    if args.capsule:
        CapsuleFlag = True

    if args.ForceRebase:
        if args.ForceRebase == "TRUE":
            mFvDataInfo.ForceRebase = 1
        elif args.ForceRebase == "FALSE":
            mFvDataInfo.ForceRebase = 0
        else:
            EdkLogger.error(UTILITY_NAME, 0,
                            "Invalid option value, froce rebase flag value must be TRUE or FALSE")

    if args.CapHeadSize:
        mCapDataInfo.HeaderSize = args.CapHeadSize
        EdkLogger.info("Capsule Header size, %s = %s" % (
            EFI_CAPSULE_HEADER_SIZE_STRING, args.CapHeadSize))

    if args.CapFlag:
        if args.CapFlag == "PopulateSystemTable":
            mCapDataInfo.Flags |= CAPSULE_FLAGS_PERSIST_ACROSS_RESET | CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE
        elif args.CapFlag == "PersistAcrossReset":
            mCapDataInfo.Flags |= CAPSULE_FLAGS_PERSIST_ACROSS_RESET
        elif args.CapFlags == "InitiateReset":
            mCapDataInfo.Flags |= CAPSULE_FLAGS_PERSIST_ACROSS_RESET | CAPSULE_FLAGS_INITIATE_RESET
        else:
            EdkLogger.error(UTILITY_NAME, 0,
                            "Invalid option value, %s = %s" % (
                                "CapFlag", args.CapFlag))

    if args.CapOEMFlag:
        # 1. Ascii string to c_uint64
        # 2.
        if args.CapOEMFlag > 0xffff:
            EdkLogger.error(UTILITY_NAME, 0,
                            "Invalid option value, Capsule OEM flag value must be integer value between 0x000 and 0xfffff")

    if args.CapGUid:
        mCapDataInfo.CapGuid = ModifyGuidFormat(args.CapGuid)
        EdkLogger.info(
            "Capsule Guid, %s = %s " % (EFI_CAPSULE_GUID_STRING, args.CapGuid))

    if args.Guid:
        mCapDataInfo.CapGuid = ModifyGuidFormat(args.CapGuid)
        mFvDataInfo.FvFileSystemGuid = ModifyGuidFormat(args.CapGuid)
        EdkLogger.info(
            "Capsule Guid: %s = %s" % (EFI_CAPSULE_GUID_STRING, args.CapGuid))
        EdkLogger.info(
            "FV Guid: %s = %s" % (EFI_FV_FILESYSTEMGUID_STRING, args.CapGuid))

    if args.FvNameGuid:
        mFvDataInfo.FvNameGuid = ModifyGuidFormat(args.FvNameGuid)
        mFvDataInfo.FvNameGuidSet = True
        EdkLogger.info(
            "FV Name Guid: %s = %s" % (EFI_FV_NAMEGUID_STRING, args.FvNameGuid))

    if args.dump:
        DumpCapsule = True

    if args.Map:
        MapFileName = args.Map

    if args.verbose:
        pass

    if args.quiet:
        pass

    if args.debug:
        pass

    EdkLogger.info("%s tool start." % UTILITY_NAME)

    #
    # check input parameter, InfFileName can be NULL
    #
    if not os.path.exists(InFileName) and DumpCapsule:
        EdkLogger.error(UTILITY_NAME, 0, "Missing option, Input Capsule Image.")

    if not DumpCapsule and OutFileName == None:
        EdkLogger.error(UTILITY_NAME, 0, "Missing option, Output file.")

    #
    # Read the INF file image
    #
    try:
        with open(LongFilePath(InFileName), 'rb') as file:
            InFileImage = file.read()
            InFileSize = len(InFileImage)

        if DumpCapsule:
            EdkLogger.info(
                "Dump the capsule header information for the input capsule image %s" % InFileName)
            #
            # Dump Capsule Image Header Information
            #
            CapsuleHeader = EFI_CAPSULE_HEADER.from_buffer_copy(InFileImage)

            if OutFileName == None:
                FpFile = sys.stdout
            else:
                FpFile = open(LongFilePath(OutFileName), 'w')

            if FpFile != None:
                FpFile.write(
                    "Capsule %s Image Header Information\n" % InfFileName)
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

        elif CapsuleFlag:
            EdkLogger.info("Create capsule image")
            mCapDataInfo.CapFiles = mFvDataInfo.FvFiles
            #
            # Call the GenerateFvImage to generate Fv Image
            #
            GenerateCapImage(InfFileImage, OutFileName)

        else:
            EdkLogger.info("Create Fv image and its map file.")
            #
            # Will take rebase action at below situation:
            # 1. ForceRebase Flag specified to TRUE;
            # 2. ForceRebase Flag not specified, BaseAddress greater than zero.
            #
            if (
                mFvDataInfo.BaseAddress > 0 and mFvDataInfo.ForceRebase == -1) or mFvDataInfo.ForceRebase == 1:
                EdkLogger.info(
                    "FvImage Rebase Address is 0x%s" % mFvDataInfo.BaseAddress)

            #
            # Call the GenerateFvImage to Generate Fv Image
            #
            GenerateFvImage(InFileImage, OutFileName)

        # update boot driver address and runtime driver address in address file
        if AddrFileName and len(mFvBaseAddress) > 0:
            FpFile = open(LongFilePath(AddrFileName), "w")
            FpFile.write(FV_BASE_ADDRESS_STRING)
            FpFile.write("\n")
            for Index in range(len(mFvBaseAddress)):
                FpFile.write("0x%x\n" % mFvBaseAddress[Index])
            FpFile.close()

        EdkLogger.info("The Total Fv Size, %s = %s" % (
            EFI_FV_TOTAL_SIZE_STRING, mFvTotalSize))
        EdkLogger.info("The used Fv Size, %s = %s" % (
            EFI_FV_TAKEN_SIZE_STRING, mFvTakenSize))
        EdkLogger.info("The space Fv Size, %s = %s" % (
            EFI_FV_SPACE_SIZE_STRING, mFvTotalSize - mFvTakenSize))

        return 0
    except Exception as e:
        EdkLogger.error(UTILITY_NAME, 0, e)


if __name__ == '__main__':
    r = main()
    ## 0-127 is a safe return range, and 1 is a standard default error
    if r < 0 or r > 127:
        r = 1
    exit(r)
