# @file
# This file contains functions required to generate a Firmware File System file.
# Copyright (c) 2004 - 2018, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent


import os.path
import sys

sys.path.append('..')

from FirmwareStorageFormat.SectionHeader import *
from FirmwareStorageFormat.FfsFileHeader import *
from FirmwareStorageFormat.Common import *
from PeCoff import *
import logging

UTILITY_NAME = 'GenFfs'
UTILITY_MAJOR_VERSION = 0
UTILITY_MINOR_VERSION = 1

mFfsFileType = [
    "EFI_FV_FILETYPE_ALL",  # 0x00
    "EFI_FV_FILETYPE_RAW",  # 0x01
    "EFI_FV_FILETYPE_FREEFORM",  # 0x02
    "EFI_FV_FILETYPE_SECURITY_CORE",  # 0x03
    "EFI_FV_FILETYPE_PEI_CORE",  # 0x04
    "EFI_FV_FILETYPE_DXE_CORE",  # 0x05
    "EFI_FV_FILETYPE_PEIM",  # 0x06
    "EFI_FV_FILETYPE_DRIVER",  # 0x07
    "EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER",  # 0x08
    "EFI_FV_FILETYPE_APPLICATION",  # 0x09
    "EFI_FV_FILETYPE_SMM",  # 0x0A
    "EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE",  # 0x0B
    "EFI_FV_FILETYPE_COMBINED_SMM_DXE",  # 0x0C
    "EFI_FV_FILETYPE_SMM_CORE",  # 0x0D
    "EFI_FV_FILETYPE_MM_STANDALONE",  # 0x0E
    "EFI_FV_FILETYPE_MM_CORE_STANDALONE"  # 0x0F
]

mAlignName = ["1", "2", "4", "8", "16", "32", "64", "128", "256", "512",
              "1K", "2K", "4K", "8K", "16K", "32K", "64K", "128K", "256K",
              "512K", "1M", "2M", "4M", "8M", "16M"]

mFfsValidAlignName = ["8", "16", "128", "512", "1K", "4K", "32K", "64K", "128K", "256K",
                      "512K", "1M", "2M", "4M", "8M", "16M"]

mFfsValidAlign = [0, 8, 16, 128, 512, 1024, 4096, 32768, 65536, 131072, 262144,
                  524288, 1048576, 2097152, 4194304, 8388608, 16777216]

mEfiFfsSectionAlignmentPaddingGuid = (0x04132C8D, 0x0A22, 0x4FA8, (0x82, 0x6E, 0x8B, 0xBF, 0xEF, 0xDB, 0x83, 0x6C))

MAX_FFS_SIZE = 0x1000000
MAXIMUM_INPUT_FILE_NUM = 10
FFS_FIXED_CHECKSUM = 0xAA

# FFS File Attributes.
FFS_ATTRIB_LARGE_FILE = 0x01
FFS_ATTRIB_DATA_ALIGNMENT2 = 0x02
FFS_ATTRIB_FIXED = 0x04
FFS_ATTRIB_CHECKSUM = 0x40

# File Types Definitions
EFI_FV_FILETYPE_ALL = 0x00
EFI_FV_FILETYPE_SECURITY_CORE = 0x03
EFI_FV_FILETYPE_PEI_CORE = 0x04
EFI_FV_FILETYPE_DXE_CORE = 0x05
EFI_FV_FILETYPE_PEIM = 0x06
EFI_FV_FILETYPE_DRIVER = 0x07
EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER = 0x08
EFI_FV_FILETYPE_APPLICATION = 0x09

# FFS File State Bits.
EFI_FILE_HEADER_CONSTRUCTION = 0x01
EFI_FILE_HEADER_VALID = 0x02
EFI_FILE_DATA_VALID = 0x04

#
# Set log config.
#
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s: %(message)s, line %(lineno)s in %(filename)s')
logger = logging.getLogger('GenFfs')


def Version():
    print("%s Version %s.%s \n" % (UTILITY_NAME, UTILITY_MINOR_VERSION, UTILITY_MINOR_VERSION))


def Usage():
    print("\nUsage: %s [options]\n" % UTILITY_NAME)
    print("Copyright (c) 2007 - 2018, Intel Corporation. All rights reserved.\n")
    print("Options:\n")
    print("  -o FileName, --outputfile FileName\n\
                        File is FFS file to be created.")
    print("  -t Type, --filetype Type\n\
                        Type is one FV file type defined in PI spec, which is\n\
                        EFI_FV_FILETYPE_RAW, EFI_FV_FILETYPE_FREEFORM,\n\
                        EFI_FV_FILETYPE_SECURITY_CORE, EFI_FV_FILETYPE_PEIM,\n\
                        EFI_FV_FILETYPE_PEI_CORE, EFI_FV_FILETYPE_DXE_CORE,\n\
                        EFI_FV_FILETYPE_DRIVER, EFI_FV_FILETYPE_APPLICATION,\n\
                        EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER,\n\
                        EFI_FV_FILETYPE_SMM, EFI_FV_FILETYPE_SMM_CORE,\n\
                        EFI_FV_FILETYPE_MM_STANDALONE,\n\
                        EFI_FV_FILETYPE_MM_CORE_STANDALONE,\n\
                        EFI_FV_FILETYPE_COMBINED_SMM_DXE, \n\
                        EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE.")
    print("  -g FileGuid --fileguid FileGuid\n\
                        FileGuid is one module guid.\n\
                        Its format is xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
    print("  -x, --fixed  Indicates that the file may not be moved\n\
                        from its present location.")
    print("  -a FileAlign, --align FileAlign\n\
                        FileAlign points to file alignment, which only support\n\
                        the following align: 1,2,4,8,16,128,512,1K,4K,32K,64K\n\
                        128K,256K,512K,1M,2M,4M,8M,16M")
    print("  -i SectionFile, --sectionfile SectionFile\n\
                        Section file will be contained in this FFS file.")
    print("  -oi SectionFile, --optionalsectionfile SectionFile\n\
                        If the Section file exists, it will be contained in this FFS file, otherwise, it will be ignored.")
    print("  -n SectionAlign, --sectionalign SectionAlign\n\
                        SectionAlign points to section alignment, which support\n\
                        the alignment scope 0~16M. If SectionAlign is specified\n\
                        as 0, tool get alignment value from SectionFile. It is\n\
                        specified together with sectionfile to point its\n\
                        alignment in FFS file.")
    print("  -v, --verbose         Turn on verbose output with informational messages.")
    print("  -q, --quiet           Disable all messages except key message and fatal error")
    print("  -d, --debug level     Enable debug messages, at input debug level.")
    print("  --version             Show program's version number and exit.")
    print("  -h, --help            Show this help message and exit.")


#
# Converts a string to an EFI_GUID.
#
def StringToGuid(AsciiGuidBuffer: str):
    GuidBuffer = ModifyGuidFormat(AsciiGuidBuffer)
    return GuidBuffer


#
# Converts Align String to align value (1~16M).
#
def StringtoAlignment(AlignBuffer: str):
    # Check AlignBuffer
    if not AlignBuffer:
        return EFI_INVALID_PARAMETER

    for ch in mAlignName:
        if AlignBuffer == ch:
            AlignNumber = 1 << mAlignName.index(ch)
            Status = EFI_SUCCESS
            return Status, AlignNumber
    return EFI_INVALID_PARAMETER


# Converts File Type String to value.  EFI_FV_FILETYPE_ALL indicates that an
# unrecognized file type was specified.
def StringToType(String: str):
    for index in range(len(mFfsFileType)):
        if mFfsFileType[index] == String:
            return index
    return EFI_FV_FILETYPE_ALL


# Get the contents of all section files specified in InputFileName into FileBuffer
def GetSectionContents(InputFileNum: c_uint32, FfsAttrib: c_uint8,
                       InputFileName, InputFileAlign):
    Size = 0
    MaxEncounteredAlignment = 1
    Status = EFI_SUCCESS
    FileBuffer = b''
    PESectionNum = 0

    # Go through array of file names and copy their contents
    for Index in range(InputFileNum):
        # Make sure section ends on a DWORD boundary
        while Size & 0x03 != 0:
            # if FileBuffer != None and Size < BufferLength:
            FileBuffer += bytes(1)
            Size += 1

        # Open file and read contents
        try:
            with open(InputFileName[Index], 'rb') as InFile:
                Data = InFile.read()
            FileSize = len(Data)
        except Exception as e:
            logger.error("Error open file: %s" % InputFileName[Index])
            return EFI_ABORTED

        # Check this section is Te/Pe section, and Calculate the numbers of Te/Pe section.
        TeOffset = 0
        if FileSize >= MAX_FFS_SIZE:
            HeaderSize = sizeof(EFI_COMMON_SECTION_HEADER2)
        else:
            HeaderSize = sizeof(EFI_COMMON_SECTION_HEADER)

        TempSectHeader = EFI_COMMON_SECTION_HEADER2.from_buffer_copy(
            CheckLengthOfBuffer(Data, sizeof(EFI_COMMON_SECTION_HEADER2)))
        if TempSectHeader.Type == EFI_SECTION_TE:
            PESectionNum += 1
            # TeHeaderSize = sizeof(EFI_TE_IMAGE_HEADER)
            TeHeader = EFI_TE_IMAGE_HEADER.from_buffer_copy(Data[HeaderSize:])
            if TeHeader.Signature == EFI_TE_IMAGE_HEADER_SIGNATURE:
                TeOffset = TeHeader.StrippedSize - sizeof(TeHeader)

        elif TempSectHeader.Type == EFI_SECTION_PE32:
            PESectionNum += 1

        elif TempSectHeader.Type == EFI_SECTION_GUID_DEFINED:
            # if FileSize >= MAX_SECTION_SIZE:
                # EFI_GUID_DEFINED_SECTION2
            #     GuidSectHeader2 = EFI_GUID_DEFINED_SECTION.from_buffer_copy(Data)
            #     if (GuidSectHeader2.Attributes & EFI_GUIDED_SECTION_PROCESSING_REQUIRED) == 0:
            #         HeaderSize = GuidSectHeader2.DataOffset
            # else:
            #     GuidSectHeader = EFI_GUID_DEFINED_SECTION.from_buffer_copy(Data)
            #     if (GuidSectHeader.Attributes & EFI_GUIDED_SECTION_PROCESSING_REQUIRED) == 0:
            #         HeaderSize = GuidSectHeader.DataOffset
            GuidSectionHeader = EFI_GUID_DEFINED_SECTION.from_buffer_copy(Data[HeaderSize:])
            if (GuidSectionHeader.Attributes & EFI_GUIDED_SECTION_PROCESSING_REQUIRED) == 0:
                HeaderSize = GuidSectionHeader.DataOffset
            PESectionNum += 1

        elif TempSectHeader.Type == EFI_SECTION_COMPRESSION or TempSectHeader.Type == EFI_SECTION_FIRMWARE_VOLUME_IMAGE:
            # for the encapsulated section, assume it contains Pe/Te section
            PESectionNum += 1

        # Revert TeOffset to the converse value relative to Alignment
        # This is to assure the original PeImage Header at Alignment.
        if TeOffset != 0 and InputFileAlign[Index] != 0:
            TeOffset = InputFileAlign[Index] - (TeOffset % InputFileAlign[Index])
            TeOffset = TeOffset % InputFileAlign[Index]

        # Make sure section data meet its alignment requirement by adding one raw pad section.
        if (InputFileAlign[Index] != 0 and (Size + HeaderSize + TeOffset) % InputFileAlign[Index]) != 0:
            Offset = (Size + sizeof(EFI_COMMON_SECTION_HEADER) + HeaderSize + TeOffset + InputFileAlign[Index] - 1) & (
                ~(InputFileAlign[Index] - 1))

            Offset = Offset - Size - HeaderSize - TeOffset

            # The maximal alignment is 64K, the raw section size must be less than 0xffffff
            SubGuidSectHeader = EFI_FREEFORM_SUBTYPE_GUID_SECTION()
            CommonHeader = EFI_COMMON_SECTION_HEADER()
            CommonHeader.SET_SECTION_SIZE(Offset)
            # FileBuffer = struct2stream(SectHeader)

            if (FfsAttrib & FFS_ATTRIB_FIXED) != 0 and MaxEncounteredAlignment <= 1 and Offset >= (sizeof(
                    EFI_FREEFORM_SUBTYPE_GUID_SECTION) + CommonHeader.Common_Header_Size()):
                CommonHeader.Type = EFI_SECTION_FREEFORM_SUBTYPE_GUID
                SubGuidSectHeader.SubTypeGuid = mEfiFfsSectionAlignmentPaddingGuid
            else:
                CommonHeader.Type = EFI_SECTION_RAW

            FileBuffer += struct2stream(CommonHeader) + bytes(
                    Offset - sizeof(EFI_COMMON_SECTION_HEADER))

            Size += Offset

        # Get the Max alignment of all input file datas
        if MaxEncounteredAlignment < InputFileAlign[Index]:
            MaxEncounteredAlignment = InputFileAlign[Index]

        #
        # Now read the contents of the file into the buffer
        #
        if FileSize > 0:
            FileBuffer += Data

        Size += FileSize

    # MaxAlignment = MaxEncounteredAlignment

    # Set the real required buffer size.
    BufferLength = Size
    Status = EFI_SUCCESS
    return Status, FileBuffer, BufferLength, MaxEncounteredAlignment, PESectionNum


#
# InFile is input file for getting alignment
# return the alignment
#
def GetAlignmentFromFile(InFile: str):
    try:
        with open(InFile, 'rb') as InFileHandle:
            Data = InFileHandle.read()
    except Exception as exe:
        logger.error("Error opening file: %s" % InFile)
        return EFI_ABORTED

    PeFileBuffer = Data

    CommonHeader = EFI_COMMON_SECTION_HEADER.from_buffer_copy(
        CheckLengthOfBuffer(PeFileBuffer, sizeof(EFI_COMMON_SECTION_HEADER)))
    CurSecHdrSize = sizeof(CommonHeader)

    ImageContext = PE_COFF_LOADER_IMAGE_CONTEXT()
    # ImageContext.Handle =  PeFileBuffer[CurSecHdrSize:CurSecHdrSize + sizeof(c_uint64)]
    ImageContext.Handle = PeFileBuffer[CurSecHdrSize:]

    # For future use in PeCoffLoaderGetImageInfo like EfiCompress
    Status = PeCoffLoaderGetImageInfo(ImageContext)
    if EFI_ERROR(Status):
        logger.error("Invalid PeImage,he input file is %s and return status is %x" % (InFile, Status))
        return Status

    Alignment = ImageContext.SectionAlignment
    Status = EFI_SUCCESS
    return Status, Alignment


# This function calculates the value needed for a valid UINT8 checksum
def CalculateSum8(Size: int, Buffer=b''):
    Sum = 0
    # Perform the byte sum for buffer
    for Index in range(Size):
        Sum = Sum + Buffer[Index]
    return Sum


# This function calculates the UINT8 sum for the requested region.
def CalculateChecksum8(Size: int, Buffer=b''):
    return 0x100 - CalculateSum8(Size, Buffer)


# Main function
def main():
    Status = EFI_SUCCESS
    FileGuid = GUID()
    InputFileNum = 0
    Alignment = 0
    InputFileName = []
    InputFileAlign = []
    OutputFileName = ''
    FileSize = 0
    FfsAttrib = 0
    FfsAlign = 0
    MaxAlignment = 1
    FileBuffer = b''
    FfsFiletype = EFI_FV_FILETYPE_ALL
    PeSectionNum = 0
    Index = 0

    # TODO: Need manual parser command line, because args: -n vaild only of one file.
    # args = parser.parse_args()

    #
    # Parser command line
    #
    args = sys.argv
    argc = len(sys.argv)

    if argc == 1:
        logger.error("Missing options, no options input")
        Usage()
        return STATUS_ERROR
    arg_index = 1
    argc -= 1

    if args[arg_index] == "-h" or args[arg_index] == "--help":
        Version()
        Usage()
        return EFI_SUCCESS

    if args[arg_index] == "--version":
        Version()
        return EFI_SUCCESS

    while argc > 0:
        if args[arg_index] == "-t" or args[arg_index] == "--filetype":
            if args[arg_index + 1] == None or args[arg_index + 1] == "-":
                logger.error("Invalid options value, file type is missing for -t option")
                return STATUS_ERROR
            FfsFiletype = StringToType(args[arg_index + 1])
            if FfsFiletype == EFI_FV_FILETYPE_ALL:
                logger.error("Invalid option value, %s is not a valid file type" % args[arg_index + 1])
                return STATUS_ERROR
            argc -= 2
            arg_index += 2
            continue

        if args[arg_index] == "-o" or args[arg_index] == "--outputfile":
            if args[arg_index + 1] == None or args[arg_index + 1] == "-":
                logger.error("Invalid options value, file type is missing for -o option")
                return STATUS_ERROR

            OutputFileName = args[arg_index + 1]
            argc -= 2
            arg_index += 2
            continue

        if args[arg_index] == "-g" or args[arg_index] == "fileguid":
            FileGuid = StringToGuid(args[arg_index + 1])
            argc -= 2
            arg_index += 2
            continue

        if args[arg_index] == "-x" or args[arg_index] == "--fixed":
            FfsAttrib = FfsAttrib | FFS_ATTRIB_FIXED
            argc -= 1
            arg_index += 1
            continue

        if args[arg_index] == "-s" or args[arg_index] == "--checksum":
            FfsAttrib = FfsAttrib | FFS_ATTRIB_CHECKSUM
            argc -= 1
            arg_index += 1
            continue

        if args[arg_index] == "-a" or args[arg_index] == "--align":
            if args[arg_index + 1] == None or args[arg_index + 1] == '-':
                logger.error("Invalid option value, Align value is missing for -a option")
                return STATUS_ERROR
            for index in range(len(mFfsValidAlignName)):
                if args[arg_index + 1] in mFfsValidAlignName:
                    Index = mFfsValidAlignName.index(args[arg_index + 1])
                    break
            else:
                if args[arg_index + 1] == "1" or args[arg_index + 1] == "2" or args[arg_index + 1] == "4":
                    # 1, 2, 4 byte alignment same to 8 byte alignment
                    Index = 0
                else:
                    logger.error("Invaild options value, %s = %s" % (args[arg_index], args[arg_index + 1]))
                    return STATUS_ERROR
            FfsAlign = Index
            argc -= 2
            arg_index += 2
            continue

        if args[arg_index] == "-oi" or args[arg_index] == "--optionalsectionfile" or args[arg_index] == "-i" or args[
            arg_index] == "--sectionfile":
            # Get Input file name and its alignment
            if args[arg_index + 1] == None or args[arg_index + 1] == "-":
                logger.error("Invalid option value, input section file is missing for -i option")
                return STATUS_ERROR
            if not os.path.exists(args[arg_index + 1]):
                logger.warning("File is not found.", args[arg_index + 1])
                argc -= 2
                arg_index += 2
                continue

            InputFileAlign.append(0)
            InputFileName.append(args[arg_index + 1])
            argc -= 2
            arg_index += 2

            if argc <= 0:
                InputFileNum += 1
                break

            # Section File alignment requirement
            if args[arg_index] == "-n" or args[arg_index] == "--sectionalign":
                if args[arg_index + 1] != None and args[arg_index + 1] == "0":
                    Status, Alignment = GetAlignmentFromFile(InputFileName[InputFileNum])
                    if EFI_ERROR(Status):
                        logger.error("Fail to get Alignment from %s" % InputFileName[InputFileNum])
                        return STATUS_ERROR
                    if Alignment < 0x400:
                        AlignmentBuffer = str(Alignment)
                    elif Alignment >= 0x100000:
                        AlignmentBuffer = str(Alignment // 0x100000) + "M"
                    else:
                        AlignmentBuffer = str(Alignment // 0x400) + "K"
                    res = StringtoAlignment(AlignmentBuffer)
                    if isinstance(res, int):
                        Status = res
                    else:
                        Status = res[0]
                        InputFileAlign[InputFileNum] = res[1]
                else:
                    res = StringtoAlignment(args[arg_index + 1])
                    if isinstance(res, int):
                        Status = res
                    else:
                        Status = res[0]
                        InputFileAlign[InputFileNum] = res[1]
                if EFI_ERROR(Status):
                    logger.error("Invalid option value, %s = %s" % (args[arg_index], args[arg_index + 1]))
                    return STATUS_ERROR
                argc -= 2
                arg_index += 2
            InputFileNum += 1
            continue

        if args[arg_index] == "-n" or args[arg_index] == "--sectionalign":
            logger.error("Unknown option, SectionAlign option must be specified with section file.")
            return STATUS_ERROR

        if args[arg_index] == "-v" or args[arg_index] == "--verbose":
            pass

        if args[arg_index] == "-q" or args[arg_index] == "--quiet":
            pass

        if args[arg_index] == "-d" or args[arg_index] == "--debug":
            pass

        logger.error("Unknown option, %s" % args[arg_index])

    #
    # Check the complete input parameters.
    #
    # TODO: GUID().__cmp__(guid:GUID)
    if GUID().__cmp__(FileGuid):
        logger.error("Missing option, fileguid")
        return STATUS_ERROR

    if InputFileNum == 0:
        logger.error("Missing option, Input files")
        return STATUS_ERROR

    #
    # Minimum alignment is 1 byte.
    #
    for index in range(len(InputFileAlign)):
        if InputFileAlign[index] == 0:
            InputFileAlign[index] = 1

    #
    # read all input file contents into a buffer
    #
    res = GetSectionContents(InputFileNum, FfsAttrib, InputFileName,
                             InputFileAlign)
    if isinstance(res, int):
        Status = res
    else:
        Status = res[0]
        FileBuffer = res[1]
        FileSize = res[2]
        MaxAlignment = res[3]
        PeSectionNum = res[4]

    if (FfsFiletype == EFI_FV_FILETYPE_SECURITY_CORE or FfsFiletype == EFI_FV_FILETYPE_PEI_CORE or
        FfsFiletype == EFI_FV_FILETYPE_DXE_CORE) and (PeSectionNum != 1):
        logger.error(
            "Invalid parameter, Fv File type %s must have one and only one Pe or Te section, but %u Pe/Te section are input" % (
                mFfsFileType[FfsFiletype], PeSectionNum))
        return STATUS_ERROR

    if (FfsFiletype == EFI_FV_FILETYPE_PEIM or FfsFiletype == EFI_FV_FILETYPE_DRIVER or
        FfsFiletype == EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER or FfsFiletype == EFI_FV_FILETYPE_APPLICATION) and \
            (PeSectionNum < 1):
        logger.error(
            "Invalid parameter, Fv File type %s must have at least one Pe or Te section, but no Pe/Te section is input" %
            mFfsFileType[FfsFiletype])

        return STATUS_ERROR

    # if Status == EFI_BUFFER_TOO_SMALL:

    if EFI_ERROR(Status):
        return STATUS_ERROR

    #
    # Create Ffs file header.
    #
    # Update FFS Alignment based on the max alignment required by input section files
    for index in range(len(mFfsValidAlign)):
        if MaxAlignment > mFfsValidAlign[index] and MaxAlignment <= mFfsValidAlign[index + 1]:
            Index = index
            break
    if FfsAlign < Index:
        FfsAlign = Index

    #
    # Now FileSize includes the EFI_FFS_FILE_HEADER
    #
    if FileSize + sizeof(EFI_FFS_FILE_HEADER) >= MAX_FFS_SIZE:
        FfsFileHeader = EFI_FFS_FILE_HEADER2()
        FfsFileHeader.Name = FileGuid
        FfsFileHeader.Type = FfsFiletype

        HeaderSize = sizeof(EFI_FFS_FILE_HEADER2)
        FileSize += HeaderSize
        FfsFileHeader.ExtendedSize = FileSize
        FfsFileHeader.Size[0] = 0
        FfsFileHeader.Size[1] = 0
        FfsFileHeader.Size[2] = 0
        FfsAttrib |= FFS_ATTRIB_LARGE_FILE
    else:
        FfsFileHeader = EFI_FFS_FILE_HEADER()
        FfsFileHeader.Name = FileGuid
        FfsFileHeader.Type = FfsFiletype

        HeaderSize = sizeof(EFI_FFS_FILE_HEADER)
        FileSize += HeaderSize
        FfsFileHeader.Size[0] = FileSize & 0xFF
        FfsFileHeader.Size[1] = (FileSize & 0xFF00) >> 8
        FfsFileHeader.Size[2] = (FileSize & 0xFF0000) >> 16

    #
    # FfsAlign larger than 7,set FFS_ATTRIB_DATA_ALIGNMENT2
    #
    if FfsAlign < 8:
        FfsFileHeader.Attributes = FfsAttrib | (FfsAlign << 3)
    else:
        FfsFileHeader.Attributes = FfsAttrib | ((FfsAlign & 0x7) << 3) | FFS_ATTRIB_DATA_ALIGNMENT2

    #
    # Fill in checksums and state,these must be zero for checksumming
    #
    FfsFileHeader.IntegrityCheck.Checksum.Header = CalculateChecksum8(HeaderSize, struct2stream(FfsFileHeader))

    if FfsFileHeader.Attributes & FFS_ATTRIB_CHECKSUM:
        # Ffs header checksum = zero, so only need to calculate ffs body.
        FfsFileHeader.IntegrityCheck.Checksum.File = CalculateChecksum8(FileSize - HeaderSize, FileBuffer)
    else:
        FfsFileHeader.IntegrityCheck.Checksum.File = FFS_FIXED_CHECKSUM

    FfsFileHeader.State = EFI_FILE_HEADER_CONSTRUCTION | EFI_FILE_HEADER_VALID | EFI_FILE_DATA_VALID

    #
    # Open output file to write ffs data
    #
    try:
        with open(OutputFileName, "wb") as FfsFile:
            FfsFile.write(struct2stream(FfsFileHeader))
            if len(FileBuffer) != 0:
                FfsFile.write(FileBuffer)
    except OSError as exe:
        logger.error("Error opening file:%s" % OutputFileName)
        Status = STATUS_ERROR
        return Status


if __name__ == "__main__":
    exit(main())
    # Usage()
