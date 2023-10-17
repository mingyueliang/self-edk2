# @file
# The tool dumps the contents of a firmware volume
#
# Copyright (c) 1999 - 2018, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

# Import Modules
#
import argparse
import logging
import os
import re
import struct
import sys
import uuid
from GuidTools import *
from copy import copy

from ctypes import *
from struct import *

from FvHeader import *
from FfsFileHeader import *
from PI.SectionHeader import *
from Decompress import *
from Compress import *
from PeImage import *
sys.path.append(r"Z:\GitHub_edk2\edk2\BaseTools\Source\Python")
from Common.BuildToolError import *

#
# Global Variable
#
mGuidBasenameList = None
status_error = 1
status_success = 0
offset = 0
EnableHash = None

#
# define fv variable
#
FvSize = None
FvHeaderSize = None
FvAttributes = None
ErasePolarity = False

mParsedGuidedSectionTools = None
PeerFilename = ''

logger = logging.getLogger('Volinfo')
lh = logging.StreamHandler(sys.stdout)
lf = logging.Formatter("%(levelname)-8s: %(message)s")
lh.setFormatter(lf)
logger.addHandler(lh)


class GUID_TO_BASENAME_NODE(object):
    def __init__(self, guid, basename):
        self.Guid = guid
        self.BaseName = basename
        self.Next = None


class SectionTypeFunc(object):
    """
    Section type funcation
    """
    EFI_DEP_BEFORE = 0x00
    EFI_DEP_AFTER = 0x01
    EFI_DEP_PUSH = 0x02
    EFI_DEP_AND = 0x03
    EFI_DEP_OR = 0x04
    EFI_DEP_NOT = 0x05
    EFI_DEP_TRUE = 0x06
    EFI_DEP_FALSE = 0x07
    EFI_DEP_END = 0x08
    EFI_DEP_SOR = 0x09

    EFI_NOT_COMPRESSED = 0x00
    EFI_STANDARD_COMPRESSION = 0x01

    def __init__(self, Type, Commonheader, ExtHeader, Buffer):
        self.SectionType = Type
        self.CommonHeader = Commonheader
        self.ExtHeader = ExtHeader
        self.Buffer = Buffer
        self.SectionLength = self.CommonHeader.SECTION_SIZE
        self.HeaderLength = self.CommonHeader.Common_Header_Size()
        if self.ExtHeader:
            self.HeaderLength = self.CommonHeader.Common_Header_Size() + self.ExtHeader.ExtHeaderSize()

    def EFI_COMPRESSION_SECTION(self):
        UncompressedBuffer = b""
        UncompressedLength = self.ExtHeader.UncompressedLength
        CompressionType = self.ExtHeader.CompressionType
        CompressedLength = self.SectionLength - self.HeaderLength
        print("  Uncompressed Length: 0x{:0>8X}".format(UncompressedLength))
        if CompressionType == self.EFI_NOT_COMPRESSED:
            print("  Compression Type:    EFI_NOT_COMPRESSED")
            if CompressedLength != UncompressedLength:
                logger.error("file is not compressed, but the compressed length does not match the uncompressed length")
                return
            UncompressedBuffer = self.Buffer[self.HeaderLength:]

        elif CompressionType == self.EFI_STANDARD_COMPRESSION:
            print("  Compression Type:    EFI_STANDARD_COMPRESSION")
            CompressedBuffer = self.Buffer[self.HeaderLength:]
            DstSize = EfiGetInfo(CompressedBuffer, CompressedLength)
            if not DstSize:
                logger.error("error getting compression info from compression section")
                return
            if DstSize != UncompressedLength:
                logger.error("compression error in the compression section")
                return

            # parse CompressBuffer content.
            # UncompressedBuffer = decompress(CompressedBuffer, 'output.bin')
            # ParseSection(UncompressedBuffer, UncompressedLength)
            pass


        else:
            logger.error("unrecognized compression type, type: %s" % hex(CompressionType))
            return

        # ParseSection(UncompressedBuffer, UncompressedLength)

    def EFI_GUID_DEFINED_SECTION(self):
        EfiGUid = uuid.UUID(bytes_le=struct2stream(self.ExtHeader.SectionDefinitionGuid))
        DataOffset = self.ExtHeader.DataOffset
        Attributes = self.ExtHeader.Attributes
        print("  SectionDefinitionGuid: ".ljust(20), EfiGUid)
        print("  DataOffset: ".ljust(20), DataOffset)
        print("  Attributes: ".ljust(20), Attributes)

        ExtGuidTool = ParseGuidedSectionToolsFile(EfiGUid)

        DecompressBuffer = ExtGuidTool.unpack(self.Buffer[self.HeaderLength:])

        ParseSection(DecompressBuffer, len(DecompressBuffer))


    def EFI_SECTION_DISPOSABLE(self):
        pass


    def EFI_SECTION_PE32(self):
        if EnableHash:
            ToolInputFileName = "edk2Temp_InputEfi.tmp"
            ToolOutputFileName = "edk2Temp_OutputHash.tmp"
            self.RebaseImage(ToolOutputFileName, self.Buffer[self.HeaderLength:], 0)

        pass

    def EFI_SECTION_PIC(self):
        pass

    def EFI_SECTION_TE(self):
        pass

    def EFI_SECTION_DXE_DEPEX(self):
        self.DumpDepexSection()

    def EFI_SECTION_VERSION(self):
        print("  Build Number: %s" % hex(self.ExtHeader.BuildNumber))
        print("  Version Strg: %s" % self.ExtHeader.GetVersionString())

    def EFI_SECTION_USER_INTERFACE(self):
        print("  String: ", self.ExtHeader.GetUiString())

    def EFI_SECTION_COMPATIBILITY16(self):
        pass

    def EFI_SECTION_FIRMWARE_VOLUME_IMAGE(self):
        PrintFvInfo(self.Buffer[self.HeaderLength:])

    def EFI_FREEFORM_SUBTYPE_GUID_SECTION(self):
        #
        # Section does not contain any further header information.
        #
        pass

    def EFI_SECTION_RAW(self):
        pass

    def EFI_SECTION_PEI_DEPEX(self):
        self.DumpDepexSection()

    def EFI_SECTION_SMM_DEPEX(self):
        self.DumpDepexSection()

    def DEFAULT(self):
        # logger.error("unrecognized section type found!")
        pass

    def SECTION_TYPE_CASE(self):
        getattr(self, self.SectionType, self.DEFAULT)()

    def DumpDepexSection(self):
        SectionData = self.Buffer[self.HeaderLength:]
        SecDataLength = self.SectionLength - self.HeaderLength
        SecDataOffset = 0
        while SecDataLength > 0:
            print("      ", end='')
            if SectionData[SecDataOffset] == self.EFI_DEP_BEFORE:
                print("BEFORE")
                SecDataLength -= 1
                SecDataOffset += 1
            elif SectionData[SecDataOffset] == self.EFI_DEP_AFTER:
                print("AFTER")
                SecDataLength -= 1
                SecDataOffset += 1
            elif SectionData[SecDataOffset] == self.EFI_DEP_PUSH:
                print("PUSH")
                GuidName = uuid.UUID(bytes_le=struct2stream(GUID.from_buffer_copy(SectionData[1:])))
                print("      %s" % str(GuidName).upper())
                SecDataLength -= 17
                SecDataOffset += 17
            elif SectionData[SecDataOffset] == self.EFI_DEP_AND:
                print("AND")
                SecDataLength -= 1
                SecDataOffset += 1

            elif SectionData[SecDataOffset] == self.EFI_DEP_OR:
                print("OR")
                SecDataLength -= 1
                SecDataOffset += 1

            elif SectionData[SecDataOffset] == self.EFI_DEP_NOT:
                print("NOT")
                SecDataLength -= 1
                SecDataOffset += 1

            elif SectionData[SecDataOffset] == self.EFI_DEP_TRUE:
                print("TRUE")
                SecDataLength -= 1
                SecDataOffset += 1

            elif SectionData[SecDataOffset] == self.EFI_DEP_FALSE:
                print("FALSE")
                SecDataLength -= 1
                SecDataOffset += 1

            elif SectionData[SecDataOffset] == self.EFI_DEP_END:
                print("END DEPEX")
                SecDataLength -= 1
                SecDataOffset += 1

            elif SectionData[SecDataOffset] == self.EFI_DEP_SOR:
                print("SOR")
                SecDataLength -= 1
                SecDataOffset += 1
            else:
                logger.error("Unrecognized byte in depex: %s" % SectionData[
                    SecDataOffset])
                return
        return

    def RebaseImage(self, FileName, FileBuffer, NewPe32BaseAddress):
        """
        Routine Description:

          Set new base address into PeImage, and fix up PeImage based on new address.

        Arguments:

          FileName           - Name of file
          FileBuffer         - Pointer to PeImage.
          NewPe32BaseAddress - New Base Address for PE image.
        """

        ImageContext = PE_COFF_LOADER_IMAGE_CONTEXT()
        ImageContext.Handle = FileBuffer
        # ImageContext.ImageRead = self.RebaseImageRead
        self.PeCoffLoaderGetImageInfo(ImageContext)

        if ImageContext.RelocationsStripped:
            raise Exception("Invalid, The input PeImage %s has no relocation to be fixed up" % FileName)

        ImgHdr = EFI_IMAGE_OPTIONAL_HEADER_UNION.from_buffer_copy(ImageContext.Handle[ImageContext.PeCoffHeaderOffset:])
        #
        # Load and Relocate Image Data
        #
        ImageContext.DestinationAddress = NewPe32BaseAddress
        self.PeCoffLoaderRelocateImage(ImageContext)

        #
        # Copy Relocated data to raw iamge file.
        #
        SectionHeader = EFI_IMAGE_SECTION_HEADER.from_buffer_copy(
            ImageContext.Handle[ImageContext.PeCoffHeaderOffset + 4
            + EFI_IMAGE_FILE_HEADER().Size + ImgHdr.Pe32.FileHeader.SizeOfOptionalHeader:])

        for Index in range(ImgHdr.Pe32.FileHeader.NumberOfSections):
            pass


    def PeCoffLoaderRelocateImage(self, ImageContext):
        pass


    def PeCoffLoaderLoadImage(self, ImageContext):
        PeHdr = None
        TeHdr = None
        OptionHeader = EFI_IMAGE_OPTIONAL_HEADER_POINTER()
        OptionHeader.Header = None
        ImageContext.ImageError = IMAGE_ERROR_SUCCESS
        #
        # Copy the provided context info into our local version, get what we
        # can from the original image, and then use that to make sure everything
        # is legit.
        #
        CheckContext = copy(ImageContext)  # TODO
        self.PeCoffLoaderGetImageInfo(CheckContext)
        #
        # Make sure there is enough allocated space for the image being loaded
        #
        if ImageContext.ImageSize < CheckContext.ImageSize:
            ImageContext.ImageError = IMAGE_ERROR_INVALID_IMAGE_SIZE
            raise Exception("Buffer too small!")

        if CheckContext.RelocationsStripped:
            if CheckContext.ImageAddress != ImageContext.ImageAddress:
                ImageContext.ImageError = IMAGE_ERROR_INVALID_IMAGE_ADDRESS
                raise Exception("Invalid parameter!")

        if not ImageContext.IsTeImage:
            if (ImageContext.ImageAddress & (CheckContext.SectionAlignment - ) != 0):
                ImageContext.ImageError = IMAGE_ERROR_INVALID_SECTION_ALIGNMENT
                raise Exception("Invalid parameter!")

        #
        # Read the entire PE/COFF or TE header into memory
        #
        NumberOfSections = 0
        FirstSection = None
        MaxEnd = None
        if not ImageContext.IsTeImage:
            ImageContext.ImageAddress = ImageContext.Handle[:ImageContext.SizeOfHeaders]

            HdrUnion = EFI_IMAGE_OPTIONAL_HEADER_UNION.from_buffer_copy(ImageContext.Handle[ImageContext.PeCoffHeaderOffset:ImageContext.SizeOfHeaders])
            OptionHeader.Header = HdrUnion.Pe32.OptionHeader

            FirstSection = EFI_IMAGE_SECTION_HEADER.from_buffer_copy(ImageContext.Handle[
                                    ImageContext.SizeOfHeaders + ImageContext.PeCoffHeaderOffset +
                                    4 + EFI_IMAGE_FILE_HEADER().Size + HdrUnion.Pe32.FileHeader.SizeOfOptionalHeader
                                                                     :])
            NumberOfSection = HdrUnion.Pe32.FileHeader.NumberOfSections
        else:
            ImageContext.ImageAddress = ImageContext.Handle[:ImageContext.SizeOfHeaders]

            TeHdr = EFI_TE_IMAGE_HEADER.from_buffer_copy(ImageContext.Handle[:ImageContext.SizeOfHeaders])
            FirstSection = EFI_IMAGE_SECTION_HEADER.from_buffer_copy(ImageContext.Handle[EFI_TE_IMAGE_HEADER().Size:ImageContext.SizeOfHeaders])
            NumberOfSections = TeHdr.NumberOfSections

        #
        # Load each section of the image
        #
        Section = FirstSection
        for Index in range(NumberOfSections):
            Base = self.PeCoffLoaderImageAddress(ImageContext, Section.VirtualAddress)
            End = self.PeCoffLoaderImageAddress(ImageContext, Section.VirtualAddress + Section.Misc.VirtualSize - 1)
            if Base == 0 or End == 0:
                ImageContext.ImageError = IMAGE_ERROR_SECTION_NOT_LOADED
                raise Exception("Load Error")

            if ImageContext.IsTeImage:
                Base = Base + EFI_TE_IMAGE_HEADER().Size + TeHdr.StrippedSize
                End = End + EFI_TE_IMAGE_HEADER().Size + TeHdr.StrippedSize

            if End > MaxEnd:
                pass

            #
            # Read the section
            #
            Size = Section.Misc.VirtualSize
            if Size == 0 or Size > Section.SizeOfRawData:
                Size = Section.SizeOfRawData

            if Section.SizeOfRawData:
                if not ImageContext.IsTeImage:
                    BaseData = ImageContext.Handle[Section.PointerToRawData:Size]
                else:
                    BaseData = ImageContext.Handle[Section.pointerToRawData + EFI_TE_IMAGE_HEADER().Size - TeHdr.StrippedSize:Size]
            if not BaseData:
                ImageContext.ImageError = IMAGE_ERROR_IMAGE_READ

            #
            # If raw size is less then virt size, zero fill the remaining
            #
            # bytes replace


        #
        # Get image's entry point
        #
        if not ImageContext.IsTeImage:
            if HdrUnion.Pe32.OptionHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC:
                # Use PE32 offset
                ImageContext.EntryPoint = self.PeCoffLoaderImageAddress(ImageContext, HdrUnion.Pe32.OptionHeader.AddressOfEntrypoint)
            else:
                # Use PE32+ offset
                ImageContext.EntryPoint = self.PeCoffLoaderImageAddress(ImageContext, HdrUnion.Pe32Plus.OptionHeader.AddressOfEntryPoint)
        else:
            ImageContext.EntryPoint = self.PeCoffLoaderImageAddress(ImageContext, HdrUnion.Te.AddressOfEntryPoint, TeStrippedOffset)  # TODO

        """
        
        """
        if not ImageContext.IsTeImagef:
            if HdrUnion.Pe32.OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC:
                # Use Pe32
                NumberOfRvaAndSizes = HdrUnion.Pe32.OptionalHeader.NumberOfRvaAndSizes
                DirectoryEntry = HdrUnion.Pe32.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC]
            else:
                # Use Pe32+
                NumberOfRvaAndSizes = HdrUnion.Pe32Plus.OptionalHeader.NumberOfRvaAndSizes
                DirectoryEntry = HdrUnion.Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC]

            #
            # Must use UINT64 here, because there might a case that 32bit loader to load 64bit image.
            #
            if NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC:
                ImageContext.FixupDataSize = DirectoryEntry.Size / 2 * 8
            else:
                ImageContext.FixipDataSize = 0
        else:
            DirectoryEntry = HdrUnion.Te.DataDirectory[0]
            ImageContext.FixupDataSize = DirectoryEntry.Size / 2 * 8

        #
        # Consumer must allocate a buffer for the relocation fixup log.
        # Only used for runtime drivers
        #
        ImageContext.FixupData = None

        #
        # Load the Codeview infomation if present
        #
        if ImageContext.DebugDirectoryEntryRva != 0:
            DebugEntry = self.PeCoffLoaderImageAddress(ImageContext, ImageContext.DebugDirectoryEntryRva, TestrippedOffset)
            if DebugEntry == None:
                ImageContext.ImageError = IMAGE_ERROR_FAILED_RELOCATION
                raise Exception("Load Error...")
            TempDebugEntryRva = DebugEntry.RVA
            if DebugEntry.RVA == 0 and DebugEntry.FileOffset != 0:
                pass # TODO
                if Section.SizeOfRawData < Section.Misc.VirtualSize:
                    TempDebugEntryRva = Section.VirtualAddress + Section.Misc.VirtualSize
                else:
                    TempDebugEntryRva = Section.VirtualAddress + Section.SizeOfRawData
            if TempDebugEntryRva != 0:
                CodeViewSize = self.PeCoffLoaderImageAddress(ImageContext, TempDebugEntryRva, TeStrippedOffset)
                if CodeViewSize == None:
                    ImageContext.ImageError = IMAGE_ERROR_FAILED_RELOCATION
                    raise Exception("Load Error...")

                if DebugEntry.RVA == 0:
                    Size = DebugEntry.SizeOfData
                    ImageContext.CodeView = ImageContext.Handle[DebugEntry.FileOffset - TeStrippedOffset:Size]
                    if not ImageContext.CodeView:
                        ImageContext.ImageError = IMAGE_ERROR_IMAGE_READ
                        raise Exception("Load Error...")
                    DebugEntry.RVA = TempDebugEntryRva

            if ImageContext.CodeView == CODEVIEW_SIGNATURE_NB10:
                if DebugEntry.SizeOfData < EFI_IMAGE_DEBUG_CODEVIEW_NB10_ENTRY().Size:
                    ImageContext.ImageError = IMAGE_ERROR_UNSUPPORTED
                    raise Exception("Unsupported")
                ImageContext.PbdPointer = CodeViewSize + EFI_IMAGE_DEBUG_CODEVIEW_NB10_ENTRY().Size
            elif ImageContext.CodeView == CODEVIEW_SIGNATURE_RSDS:
                if DebugEntry.SizeOfData < EFI_IMAGE_DEBUG_CODEVIEW_RSDS_ENTRY().Size:
                    ImageContext.ImageError = IMAGE_ERROR_UNSUPPORTED
                    raise Exception("Unsupported")
                ImageContext.PbdPointer = CodeViewSize + EFI_IMAGE_DEBUG_CODEVIEW_RSDS_ENTRY().Size

            elif ImageContext.CodeView == CODEVIEW_SIGNATURE_MTOC:
                if DebugEntry.SizeOfData < EFI_IMAGE_DEBUG_CODEVIEW_MTOC_ENTRY().Size:
                    ImageContext.ImageError = IMAGE_ERROR_UNSUPPORTED
                    raise Exception("Unsupported")
                ImageContext.PbdPointer = CodeViewSize + EFI_IMAGE_DEBUG_CODEVIEW_MTOC_ENTRY().Size
            else:
                pass;



    def PeCoffLoaderImageAddress(self, ImageContext, Address):
        if Address >= ImageContext.ImageSize:
            ImageContext.ImageError = IMAGE_ERROR_INVALID_IMAGE_ADDRESS
            # raise Exception("the address can not be converted, otherwise, the converted address")
            return 0
        return ImageContext.ImageAddress + Address


    def RebaseImageRead(self, FileHandle, FileOffset):
        pass

    def PeCoffLoaderGetImageInfo(self, ImageContext):
        if not ImageContext.Handle:
            raise Exception(PARAMETER_INVALID)
        # Initialize Pe and Te header
        PeHdr = None
        TeHdr = None
        DebugDirectoryEntry = None
        DebugDirectoryEntryRva = 0
        #
        # Assume success
        #
        ImageContext.ImageError = IMAGE_ERROR_SUCCESS
        PeHdr, TeHdr = self.PeCoffLoaderGetPeHeader(ImageContext.Handle, PeHdr, TeHdr)
        # Verify machine type
        self.PeCoffLoaderCheckImageType(ImageContext, PeHdr, TeHdr)
        OptionHeader = EFI_IMAGE_OPTIONAL_HEADER_POINTER()
        OptionHeader.Header = PeHdr.OptionalHeader
        #
        # Retrieve the base address of the image
        #
        if not ImageContext.IsTeImage:
            if PeHdr.OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC:
                ImageContext.ImageAddress = OptionHeader.Optional32.ImageBase
            else:
                ImageContext.ImageAddress = OptionHeader.Optional63.ImageBase
        else:
            ImageContext.ImageAddress = TeHdr.ImageBase + TeHdr.StrippedSize - EFI_TE_IMAGE_HEADER().Size

        #
        # Initialize the alternate destination address to 0 indicating that it should not be used.
        #
        ImageContext.DestinationAddress = 0
        # Initialize the codeview.
        ImageContext.CodeView = None
        ImageContext.Pdbpointer = None

        #
        # Three cases with regards to relocations:
        # - Image has base relocs, RELOCS_STRIPPED==0    => image is relocatable
        # - Image has no base relocs, RELOCS_STRIPPED==1 => Image is not relocatable
        # - Image has no base relocs, RELOCS_STRIPPED==0 => Image is relocatable but
        #   has no base relocs to apply
        # Obviously having base relocations with RELOCS_STRIPPED==1 is invalid.
        #
        # Look at the file header to determine if relocations have been stripped, and
        # save this info in the image context for later use.
        #
        if not ImageContext.IsTeImage and (PeHdr.FileHeader.Characteristics & EFI_IMAGE_FILE_RELOCS_STRIPPED != 0):
            ImageContext.RelocationsStripped = True
        elif ImageContext.IsTeImage and TeHdr.DataDirectory[0].Size == 0 and TeHdr.DataDirectory[0].VirtualAddress == 0:
            ImageContext.RelocationsStripped = True
        else:
            ImageContext.RelocationsStripped = False

        SectionHeaderOffset = ImageContext.PeCoffHeaderOffset + 4 + \
                              EFI_IMAGE_FILE_HEADER().Size + \
                              PeHdr.FileHeader.SizeOfOptionalHeader

        if not ImageContext.IsTeImage:
            if PeHdr.OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC:
                ImageContext.ImageSize = OptionHeader.Optional32.SizeOfImage
                ImageContext.SectionAlignment = OptionHeader.Optional32.SectionAlignment
                ImageContext.SizeOfHeaders = OptionHeader.Optional322.SizeOfHeders
                #
                # Modify ImageSize to contain .PDB file name if required and initialize
                #  PdbRVA field...
                #
                if OptionHeader.Optional32.NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_DEBUG:
                    DebugDirectoryEntry = OptionHeader.Optionaal32.DataDirectory
                    DebugDirectoryEntryRva = DebugDirectoryEntry.VirtualAddress
                else:
                    ImageContext.ImageSize = OptionHeader.Optional64.SizeOfImage
                    ImageContext.SectionAlignment = OptionHeader.Optional64.SectionAlignment
                    ImageContext.SeizeOfHeaders = OptionHeader.Optional64.SizeOfHeaders
                    #
                    if OptionHeader.Optional64.NumberOfRvAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_DEBUG:
                        DebugDirectoryEntry = OptionHeader.Optional64.DataDirectory
                        DebugDirectoryEntryRva = DebugDirectoryEntry.VirtualAddress
                if DebugDirectoryEntryRva != 0:
                    #
                    # Determine the file offset of the debug directory...  This means we walk
                    # the sections to find which section contains the RVA of the debug
                    # directory
                    #
                    DebugDirectoryEntryFileOffset = 0
                    for section in range(PeHdr.FileHeader.NumberOfSections):
                        SectionHeader = EFI_IMAGE_FILE_HEADER.from_buffer_copy(ImageContext.Handle
                                                               [SectionHeaderOffset:])
                        if DebugDirectoryEntryRva >= SectionHeader.CirtualAddress \
                            and DebugDirectoryEntryRva < SectionHeader.VirtualAddress + SectionHeader.Misc.VirtualSize:
                            DebugDirectoryEntryRva = DebugDirectoryEntryRva - \
                                                     SectionHeader.VirtualAddress \
                                                     + SectionHeader.PointerToRawData
                            break
                        SectionHeaderOffset += EFI_IMAGE_FILE_HEADER().Size

                    if DebugDirectoryEntryFileOffset != 0:
                        for Index in range(0, DebugDirectoryEntry.Size, EFI_IMAGE_DEBUG_DIRECTORY_ENTRY().Size):
                            DebugEntry = EFI_IMAGE_DEBUG_DIRECTORY_ENTRY.from_buffer_fopy(ImageContext.Handle[DebugDirectoryEntryFileOffset + Index:])  # TODO
                            if DebugEntry.Type == EFI_IMAGE_DEBUG_TYPE_CODEVIEW:
                                ImageContext.DebugDirectoryEntryRva = DebugDirectoryEntryRva + Index
                                if DebugEntry.Rva == 0 and DebugEntry.FileOffset != 0:
                                    ImageContext.ImageSize += DebugEntry.SizeOfData
        else:
            ImageContext.ImageSize = 0
            ImageContext.SectionAlignment = 4096
            ImageContext.SizeOfHeaders = EFI_TE_IMAGE_HEADER().Size + TeHdr.BaseOfCode - TeHdr.StrippedSize
            DebugDirectoryEntry = TeHdr.DataDirectory[1]  # TODO
            DebugDirectoryEntryRva = DebugDirectoryEntry.VirtualAddress  # TODO
            SectionHeaderOffset = 0

            for Index in range(TeHdr.NumberOfSections):
                #
                # Read section header from file
                #
                SectionHeader = EFI_IMAGE_SECTION_HEADER.from_buffer_copy(ImageContext.Handle[SectionHeaderOffset:])  # TODO
                if DebugDirectoryEntryRva >= SectionHeader.VirtualAddress and DebugDirectoryEntryRva < \
                    SectionHeader.VirtualAddress + SectionHeader.Misc.VirtualSize:
                    DebugDirectoryEntryFileOffset = DebugDirectoryEntryRva - \
                        SectionHeader.VirtualAddress + SectionHeader.PointerToRawData + \
                        EFI_TE_IMAGE_HEADER().Size - TeHdr.StrippedSize
                    #
                    # File offset of the debug directory was found, if this is not the last
                    # section, then skip to the last section for calculating the image size.
                    #
                    if Index < TeHdr.NumberOfSections - 1:
                        SectionHeaderOffset += (TeHdr.NumberOfSections - 1 - Index) * EFI_IMAGE_SECTION_HEADER().Size
                        Index = TeHdr.NumberOfSections - 1
                        continue
                #
                # In Te image header there is not a field to describe the ImageSize.
                # Actually, the ImageSize equals the RVA plus the VirtualSize of
                # the last section mapped into memory (Must be rounded up to
                # a multiple of Section Alignment). Per the PE/COFF specification, the
                # section headers in the Section Table must appear in order of the RVA
                # values for the corresponding sections. So the ImageSize can be determined
                # by the RVA and the VirtualSize of the last section header in the
                # Section Table.
                #
                Index += 1
                if Index == TeHdr.NumberOfSections:
                    ImageContext.ImageSize = (SectionHeader.VirtualAddress +
                                              SectionHeader.Misc.VirtualSize +
                                              ImageContext.SectionAlignment - 1) & \
                                              ~(ImageContext.SectionAlignment - 1)
                    SectionHeaderOffset += EFI_IMAGE_SECTION_HEADER().Size

            if DebugDirectoryEntryFileOffset != 0:
                for Index in range(0, DebugDirectoryEntry.Size, EFI_IMAGE_DEBUG_DIRECTORY_ENTRY().Size):
                    DebugEntry = EFI_IMAGE_DEBUG_DIRECTORY_ENTRY.from_buffer_copy(ImageContext.Handle[DebugDirectoryEntryFileOffset:])  # TODO

                    if DebugEntry.Type == EFI_IMAGE_DEBUG_TYPE_CODEVIEW:
                        ImageContext.DebugDirectoryEntryRva = DebugDirectoryEntryRva + Index

    def PeCoffLoaderGetPeHeader(self, ImageContext, PeHdr, TeHdr):
        DosHdr = None
        ImageContext.IsTeImage = False
        #
        # Read the DOS image headers
        #
        DosHdr = EFI_IMAGE_DOS_HEADER.from_buffer_copy(ImageContext.Handle)
        if not DosHdr:
            ImageContext.ImageError = IMAGE_ERROR_IMAGE_READ
        ImageContext.PeCoffHeaderOffset = 0
        if DosHdr.e_magic == EFI_IMAGE_DOS_SIGNATURE:
            #
            # DOS image header is present, so read the PE header after the DOS image header
            #
            ImageContext.PeCoffHeaderOffset = DosHdr.Pe_signature_offset
        #
        # Get the PE/COFF Header
        #
        HdrUnion = EFI_IMAGE_OPTIONAL_HEADER_UNION.from_buffer_copy(ImageContext.Handle[ImageContext.PeCoffHeaderOffset:])
        if HdrUnion.Pe32.Signature != EFI_IMAGE_NT_SIGNATURE:
            #
            # Check the PE/COFF Header Signature. If not, then try to get a TE header
            #
            # TeHdr = EFI_TE_IMAGE_HEADER.from_buffer_copy(ImageContext.Handle[ImageContext.PeCoffHeaderOffset:])
            if HdrUnion.Te.Signature != EFI_TE_IMAGE_HEADER_SIGNATURE:
                raise Exception("Unsupported signature!")
            ImageContext.IsTeImage = True
            TeHdr = HdrUnion.Te
            return PeHdr, TeHdr

        return HdrUnion.Pe32, TeHdr

    def PeCoffLoaderCheckImageType(self, ImageContext, PeHdr, TeHdr):
        if ImageContext.IsTeImage:
            ImageContext.Machine = TeHdr.Machine
        else:
            ImageContext.Machine = PeHdr.FileHeader.Machine

        if (ImageContext.Machine != EFI_IMAGE_MACHINE_IA32 and
            ImageContext.Machine != EFI_IMAGE_MACHINE_X64  and
            ImageContext.Machine != EFI_IMAGE_MACHINE_ARMT and
            ImageContext.Machine != EFI_IMAGE_MACHINE_EBC  and
            ImageContext.Machine != EFI_IMAGE_MACHINE_AARCH64 and
            ImageContext.Machine != EFI_IMAGE_MACHINE_RISCV64):
            if ImageContext.Machine ==  IMAGE_FILE_MACHINE_ARM:
                ImageContext.Machine = IMAGE_FILE_MACHINE_ARMT
                if not ImageContext.IsTeImage:
                    PeHdr.FileHeader.Machine = ImageContext.Machine
                else:
                    TeHdr.Machine = ImageContext.Machine
            else:
                raise Exception("Not support machine type.")

        if not ImageContext.IsTeImage:
            ImageContext.ImageType = PeHdr.OptionalHeader.Subsystem
        else:
            ImageContext.ImageType = TeHdr.Subsystem

        if (ImageContext.ImageType != EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION and
            ImageContext.ImageType != EFI_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER and
            ImageContext.ImageType != EFI_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER and
            ImageContext.ImageType != EFI_IMAGE_SUBSYSTEM_SAL_RUNTIME_DRIVER):
            raise Exception("unsupported PeImage subsystem type")


def options():
    parser = argparse.ArgumentParser(prog="Volinfo",
                                     description='''Display Tiano Firmware Volume FFS image information''')
    parser.add_argument("--version", action="version",
                        version="%(prog)s Version 1.0",
                        help="Show program's version number and exit")
    parser.add_argument("-f", "--filename", required=True,
                        help="The file containing the FV")
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Output DEBUG statements, where DEBUG_LEVEL is 0 (min) - 9 (max)")
    parser.add_argument("-s", "--silent", help="Returns only the exit code; informational and error\
                messages are not displayed")
    parser.add_argument("-x", "--xref",
                        help="Parse the basename to file-guid cross reference file(s)")
    parser.add_argument("--offset", help="The offset from the start of the input file to start \
                processing an FV")
    parser.add_argument("--hash", action="store_true",
                        help="Generate HASH value of the entire PE image")
    parser.add_argument("--sfo", action="store_true",
                        help="Reserved for future use")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-v", "--verbose", action="store_true",
                       help="Print informational statements.")
    group.add_argument("-q", "--quiet", action="store_true",
                       help="Returns the exit code, error messages will be displayed")
    return parser.parse_args()


def LoadGuidedSectionToolsTxt(mUtilityFilename):
    global PeerFilename
    PeerFilename = os.path.join(os.path.split(mUtilityFilename)[0],
                                "GuidedSectionTools.txt")

def ParseGuidedSectionToolsFile(efi_guid):

    ExtGuidTool = GUIDTools(PeerFilename).__getitem__(efi_guid)
    return ExtGuidTool

# Routine Description:
#
#   GC_TODO: Add function description
#
# Arguments:
#
#   FileName  - GC_TODO: add argument description
#
# Returns:
#
# status 0, 1
def ParseGuidBaseNameFile(FileName):
    # get file real path
    global mGuidBasenameList
    FileName = os.path.abspath(FileName)
    try:
        with open(FileName, 'r') as file:
            guidBasenameList = file.readlines()
        # create link list
        for item in guidBasenameList:
            guid, basename = item.split(" ")
            guidBasenameNode = GUID_TO_BASENAME_NODE(guid, basename)
            guidBasenameNode.Next = mGuidBasenameList
            mGuidBasenameList = guidBasenameNode
    except FileNotFoundError as e:
        logging.error("Error failed to open file")
        return 1
    except Exception as e:
        logging.error(e)
        return 1


def ParseSection(SectionBuffer, BufferLength):
    BytesRead = 0
    while BytesRead < BufferLength:
        CommonHeader = EFI_COMMON_SECTION_HEADER.from_buffer_copy(
            SectionBuffer[BytesRead:])
        SectionLength = CommonHeader.SECTION_SIZE & 0xffffff
        if SectionLength == 0xffffff and CommonHeader.Type == 0xff:
            BytesRead += 4
            continue
        if SectionLength == 0xffffff:
            CommonHeader = EFI_COMMON_SECTION_HEADER2.from_buffer_copy(
                SectionBuffer[BytesRead:])

        TypeName = SectionType.get(CommonHeader.Type)
        ExdHeader = None
        # HeaderLength = CommonHeader.Common_Header_Size()
        if CommonHeader.Type in ExtHeaderType:
            ExdHeader = GetExdHeader(
                CommonHeader.Type,
                SectionBuffer[BytesRead + CommonHeader.Common_Header_Size():],
                CommonHeader.SECTION_SIZE - CommonHeader.Common_Header_Size()
            )
            # HeaderLength = CommonHeader.Common_Header_Size() + ExdHeader.ExtHeaderSize()

        if TypeName is not None:
            print(
                "------------------------------------------------------------")
            print("  Type: ".ljust(10), TypeName)
            # print("  Size: ".ljust(10), hex(CommonHeader.SECTION_SIZE))
            print("  Size: ".ljust(10), "0x{:0>8X}".format(CommonHeader.SECTION_SIZE))

            SectionTypeFunc(
                TypeName,
                CommonHeader,
                ExdHeader,
                SectionBuffer[BytesRead:]
            ).SECTION_TYPE_CASE()
        else:
            logger.error("unrecognized section type found: %s" % TypeName)
            return
        BytesRead += GetOccupiedSize(CommonHeader.SECTION_SIZE, 4)


def ReadHeader(Buffer):
    try:
        VolumeHeader = EFI_FIRMWARE_VOLUME_HEADER.from_buffer_copy(Buffer)
        map_num = (VolumeHeader.HeaderLength - 56) // 8
        VolumeHeader = Refine_FV_Header(map_num).from_buffer_copy(Buffer)
        global FvSize, FvHeaderSize, FvAttributes
        FvHeaderSize = VolumeHeader.HeaderLength
        FvSize = VolumeHeader.FvLength
        FvAttributes = VolumeHeader.Attributes
        #
        # Print FV header information
        #
        if VolumeHeader.Signature == 1213613663:
            print("Signature: ".ljust(20),
                  "%s (%s)" % (SIGNATURE_32, hex(VolumeHeader.Signature)[2:]))
        print("Attributes: ".ljust(20),
              "%s" % hex(VolumeHeader.Attributes)[2:].upper())

        if VolumeHeader.Attributes & EFI_FVB2_READ_DISABLED_CAP:
            print("      EFI_FVB2_READ_DISABLED_CAP")

        if VolumeHeader.Attributes & EFI_FVB2_READ_ENABLED_CAP:
            print("      EFI_FVB2_READ_ENABLED_CAP")

        if VolumeHeader.Attributes & EFI_FVB2_READ_STATUS:
            print("      EFI_FVB2_READ_STATUS")

        if VolumeHeader.Attributes & EFI_FVB2_WRITE_DISABLED_CAP:
            print("      EFI_FVB2_WRITE_DISABLED_CAP")

        if VolumeHeader.Attributes & EFI_FVB2_WRITE_ENABLED_CAP:
            print("      EFI_FVB2_WRITE_ENABLED_CAP")

        if VolumeHeader.Attributes & EFI_FVB2_WRITE_STATUS:
            print("      EFI_FVB2_WRITE_STATUS")

        if VolumeHeader.Attributes & EFI_FVB2_LOCK_CAP:
            print("      EFI_FVB2_LOCK_CAP")

        if VolumeHeader.Attributes & EFI_FVB2_LOCK_STATUS:
            print("      EFI_FVB2_LOCK_STATUS")

        if VolumeHeader.Attributes & EFI_FVB2_STICKY_WRITE:
            print("      EFI_FVB2_STICKY_WRITE")

        if VolumeHeader.Attributes & EFI_FVB2_MEMORY_MAPPED:
            print("      EFI_FVB2_MEMORY_MAPPED")

        if VolumeHeader.Attributes & EFI_FVB2_ERASE_POLARITY:
            # global ErasePolarity
            # ErasePolarity = True
            print("      EFI_FVB2_ERASE_POLARITY")

        #
        # PI_SPECIFICATION_VERSION
        #
        if PI_SPECIFICATION_VERSION < 0x00010000:
            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT:
                print("       EFI_FVB2_ALIGNMENT")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_2:
                print("       EFI_FVB2_ALIGNMENT_2")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_4:
                print("       EFI_FVB2_ALIGNMENT_4")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_8:
                print("       EFI_FVB2_ALIGNMENT_8")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_16:
                print("       EFI_FVB2_ALIGNMENT_16")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_32:
                print("       EFI_FVB2_ALIGNMENT_32")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_64:
                print("       EFI_FVB2_ALIGNMENT_64")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_128:
                print("       EFI_FVB2_ALIGNMENT_128")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_256:
                print("       EFI_FVB2_ALIGNMENT_256")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_512:
                print("       EFI_FVB2_ALIGNMENT_512")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_1K:
                print("       EFI_FVB2_ALIGNMENT_1K")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_2K:
                print("       EFI_FVB2_ALIGNMENT_2K")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_4K:
                print("       EFI_FVB2_ALIGNMENT_4K")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_8K:
                print("       EFI_FVB2_ALIGNMENT_8K")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_16K:
                print("       EFI_FVB2_ALIGNMENT_16K")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_32K:
                print("       EFI_FVB2_ALIGNMENT_32K")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_64K:
                print("       EFI_FVB2_ALIGNMENT_64K")

        else:
            if VolumeHeader.Attributes & EFI_FVB2_READ_LOCK_CAP:
                print("      EFI_FVB2_READ_LOCK_CAP")

            if VolumeHeader.Attributes & EFI_FVB2_READ_LOCK_STATUS:
                print("      EFI_FVB2_READ_LOCK_STATUS")

            if VolumeHeader.Attributes & EFI_FVB2_WRITE_LOCK_CAP:
                print("      EFI_FVB2_WRITE_LOCK_CAP")

            if VolumeHeader.Attributes & EFI_FVB2_WRITE_LOCK_STATUS:
                print("      EFI_FVB2_WRITE_LOCK_STATUS")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_1:
                print("       EFI_FVB2_ALIGNMENT_1")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_2:
                print("       EFI_FVB2_ALIGNMENT_2")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_4:
                print("       EFI_FVB2_ALIGNMENT_4")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_8:
                print("       EFI_FVB2_ALIGNMENT_8")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_16:
                print("       EFI_FVB2_ALIGNMENT_16")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_32:
                print("       EFI_FVB2_ALIGNMENT_32")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_64:
                print("       EFI_FVB2_ALIGNMENT_64")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_128:
                print("       EFI_FVB2_ALIGNMENT_128")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_256:
                print("       EFI_FVB2_ALIGNMENT_256")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_512:
                print("       EFI_FVB2_ALIGNMENT_512")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_1K:
                print("       EFI_FVB2_ALIGNMENT_1K")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_2K:
                print("       EFI_FVB2_ALIGNMENT_2K")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_4K:
                print("       EFI_FVB2_ALIGNMENT_4K")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_8K:
                print("       EFI_FVB2_ALIGNMENT_8K")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_16K:
                print("       EFI_FVB2_ALIGNMENT_16K")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_32K:
                print("       EFI_FVB2_ALIGNMENT_32K")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_64K:
                print("       EFI_FVB2_ALIGNMENT_64K")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_128K:
                print("       EFI_FVB2_ALIGNMENT_128K")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_256K:
                print("       EFI_FVB2_ALIGNMENT_256K")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_512K:
                print("       EFI_FVB2_ALIGNMENT_512K")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_1M:
                print("       EFI_FVB2_ALIGNMENT_1M")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_2M:
                print("       EFI_FVB2_ALIGNMENT_2M")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_4M:
                print("       EFI_FVB2_ALIGNMENT_4M")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_8M:
                print("       EFI_FVB2_ALIGNMENT_8M")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_16M:
                print("       EFI_FVB2_ALIGNMENT_16M")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_32M:
                print("       EFI_FVB2_ALIGNMENT_32M")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_64M:
                print("       EFI_FVB2_ALIGNMENT_64M")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_128M:
                print("       EFI_FVB2_ALIGNMENT_128M")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_256M:
                print("       EFI_FVB2_ALIGNMENT_256M")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_512M:
                print("       EFI_FVB2_ALIGNMENT_512M")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_1G:
                print("       EFI_FVB2_ALIGNMENT_1G")

            if VolumeHeader.Attributes & EFI_FVB2_ALIGNMENT_2G:
                print("       EFI_FVB2_ALIGNMENT_2G")

        # print("Header Length: ".ljust(20), hex(VolumeHeader.HeaderLength))
        print("Header Length: ".ljust(20), "0x{:0>8X}".format(VolumeHeader.HeaderLength))
        print("File System ID: ".ljust(20),
              uuid.UUID(bytes_le=struct2stream(VolumeHeader.FileSystemGuid)))
        # print("Revision: ".ljust(20), hex(VolumeHeader.Revision))
        print("Revision: ".ljust(20), "0x{:0>4X}".format(VolumeHeader.Revision))
        Size = 0
        for block in VolumeHeader.BlockMap:
            if not (block.NumBlocks == 0 & block.Length == 0):
                print("Number of Blocks: ".ljust(20), "0x{:0>8X}".format(block.NumBlocks))
                print("Block Length: ".ljust(20), "0x{:0>8X}".format(block.Length))
                Size = Size + block.NumBlocks * block.Length
                # If size is greater than 1GB, then assume it is corrupted
                if Size > 0x40000000:
                    logger.error(
                        "If size is greater than 1GB, then assume it is corrupted")
                    return status_error
        # If size is 0, then assume the volume is corrupted
        if Size == 0:
            logger.error("If size is 0, then assume the volume is corrupted")
            return status_error
        if FvSize != Size:
            logger.error("ERROR: Volume Size not consistent with Block Maps!")

        print("Total Volume Size: ".ljust(20), "0x{:0>8X}".format(VolumeHeader.FvLength))
    except Exception as e:
        logger.error(e)
        return status_error
    return status_success


def GetOccupiedSize(Size, alignment):
    if Size % alignment == 0:
        return Size
    else:
        return Size + alignment - (Size % alignment)


def GetFileState(FileState, ErasePolarity):
    if ErasePolarity:
        FileState = ~FileState
    HighestBit = 0x80
    while HighestBit != 0 and HighestBit & FileState != 0:
        HighestBit >>= 1
    return HighestBit


def CalculateSum8(buffer, byteorder='little'):
    length = len(buffer)
    checksum = 0
    for i in range(0, length):
        checksum += int.from_bytes(buffer[i:i + 1], byteorder, signed=False)
        checksum &= 0xFF

    return checksum

    # checksum = 0
    # for i in buffer:
    #     checksum += i
    #
    # return checksum


def EfiTestFfsAttributesBit(FvAttributes, FfsState, FfsStateType):
    if (FvAttributes & EFI_FVB2_ERASE_POLARITY):
        return ((~FfsState) & FfsStateType == FfsStateType)
    else:
        return (FfsState & FfsStateType == FfsStateType)

def ParseFfs(FfsBuffer, offset):
    pass
def PrintFvInfo(FvBuffer, IsChildFv=False):
    #
    # Get FV header
    #
    FvHeader = EFI_FIRMWARE_VOLUME_HEADER.from_buffer_copy(FvBuffer)
    num = (FvHeader.HeaderLength - 56) // 8
    FvHeader = Refine_FV_Header(num).from_buffer_copy(FvBuffer)
    if FvHeader.ExtHeaderOffset:
        ExtHeader = EFI_FIRMWARE_VOLUME_EXT_HEADER.from_buffer_copy(FvBuffer[FvHeader.ExtHeaderOffset:])

    NumberOfFiles = 0
    BytesRead = FvHeader.HeaderLength
    if BytesRead:
        while BytesRead < FvSize:
            FfsHeader = EFI_FFS_FILE_HEADER.from_buffer_copy(
                FvBuffer[BytesRead:])
            if FfsHeader.Attributes & FFS_ATTRIB_LARGE_FILE:
                FfsHeader = EFI_FFS_FILE_HEADER2.from_buffer_copy(
                    FvBuffer[BytesRead:])
            #
            # Check Ffs attributes bit
            #
            # if (not EfiTestFfsAttributesBit(FvAttributes, FfsHeader.State, EFI_FILE_HEADER_VALID)) or \
            #     EfiTestFfsAttributesBit(FvAttributes, FfsHeader.State, EFI_FILE_HEADER_INVALID):
            #     BytesRead += GetOccupiedSize(1, 8)
            #     continue
            # elif EfiTestFfsAttributesBit(FvAttributes, FfsHeader.State, EFI_FILE_MARKED_FOR_UPDATE) or \
            #     EfiTestFfsAttributesBit(FvAttributes, FfsHeader.State, EFI_FILE_DELETED):
            #     BytesRead += GetOccupiedSize(FfsHeader.FFS_FILE_SIZE, 8)
            #     continue
            # elif EfiTestFfsAttributesBit(FvAttributes, FfsHeader.State, EFI_FILE_DATA_VALID):
            #     # BytesRead += GetOccupiedSize(FfsHeader.FFS_FILE_SIZE, 8)
            #     pass

            #
            # Judge whether the current FFS is valid?
            #
            if uuid.UUID(bytes_le=struct2stream(FfsHeader.Name)) == uuid.UUID(
                    "ffffffff-ffff-ffff-ffff-ffffffffffff") and FfsHeader.Type != 0xf0:
                break

            #
            # Print file infomation
            #
            print(
                "============================================================")
            print("File Name: ".ljust(20),
                  str(uuid.UUID(bytes_le=struct2stream(FfsHeader.Name))).upper())
            print("File Offset: ".ljust(20), "0x{:0>8X}".format(BytesRead))
            print("File Length: ".ljust(20), "0x{:0>8X}".format(FfsHeader.FFS_FILE_SIZE))
            print("File Attributes: ".ljust(20), "0x{:0>2X}".format(FfsHeader.Attributes))
            print("File State: ".ljust(20), "0x{:0>2X}".format(FfsHeader.State))

            #
            # Print file state
            #
            FileState = FfsFileState.get(GetFileState(FfsHeader.State, ErasePolarity))
            if FileState is not None:
                print("     %s" % FileState)
            else:
                logger.error("File state not found: %s" % FileState)
                return status_error

            if FileState == "EFI_FILE_HEADER_CONSTRUCTION":
                pass

            elif FileState == "EFI_FILE_HEADER_VALID":
                CheckSum = CalculateSum8(FvBuffer[BytesRead:BytesRead+FfsHeader.HeaderLength])
                CheckSum = CheckSum - FfsHeader.IntegrityCheck.Checksum.File
                # CheckSum = CheckSum - FfsHeader.State
                if CheckSum != 0:
                    logger.error("ERROR: Header checksum invalid.")
                    return
                pass
            elif FileState == "EFI_FILE_DATA_VALID":
                #
                # Calculate header checksum
                #
                CheckSum = CalculateSum8(FvBuffer[BytesRead:BytesRead+FfsHeader.HeaderLength-1])
                CheckSum = CheckSum - FfsHeader.IntegrityCheck.Checksum.File
                # CheckSum = CheckSum - FfsHeader.State
                if CheckSum != 0:
                    logger.error("error parsing FFS file, FFS file with Guid %s has invalid header checksum." %
                                 uuid.UUID(bytes_le=struct2stream(FfsHeader.Name)))
                    return
                #
                # Calculate file checksum
                #
                if FfsHeader.Attributes & FFS_ATTRIB_CHECKSUM:
                    CheckSum = CalculateSum8(FvBuffer[BytesRead + FfsHeader.HeaderLength:BytesRead+FfsHeader.HeaderLengthFfsHeader.FFS_FILE_SIZE])
                    if CheckSum - FfsHeader.IntegrityCheck.Checksum.File != 0:
                        logger.error("error parsing FFS file, FFS file with Guid %s has invalid file checksum" %
                                     uuid.UUID(bytes_le=struct2stream(FfsHeader.Name)))
                        return
                else:
                    if FfsHeader.IntegrityCheck.Checksum.File != FFS_FIXED_CHECKSUM:
                        logger.error("error parsing FFS file, FFS file with Guid %s has invalid header checksum -- not set to fixed value of 0xAA" %
                                     uuid.UUID(bytes_le=struct2stream(FfsHeader.Name)))
                        return

            elif FileState == "EFI_FILE_MARKED_FOR_UPDATE":
                pass

            elif FileState == "EFI_FILE_DELETED":
                pass

            elif FileState == "EFI_FILE_HEADER_INVALID":
                pass

            else:
                pass
                # logger.error(
                #     "error parsing FFS file, FFS file with Guid %s has the invalid/unrecognized file state bits" % uuid.UUID(
                #         bytes_le=struct2stream(FfsHeader.Name)))
                # return NumberOfFiles
            #
            # Parse file section
            #
            FileType = FfsFileType.get(FfsHeader.Type)
            if FileType is not None:
                NumberOfFiles += 1
                print("File Type: ".ljust(20), "0x{:0>2X}".format(FfsHeader.Type), FileType)
                if FileType != 'EFI_FV_FILETYPE_FFS_PAD' and FileType != 'EFI_FV_FILETYPE_ALL' and FileType != 'EFI_FV_FILETYPE_RAW':
                    SectionBuffer = FvBuffer[
                                    BytesRead + FfsHeader.HeaderLength:BytesRead +
                                                                       FfsHeader.FFS_FILE_SIZE]
                    BufferLength = FfsHeader.FFS_FILE_SIZE - FfsHeader.HeaderLength
                    ParseSection(SectionBuffer, BufferLength)
            else:
                logger.error("ERROR: Unrecognized file type!")
                return status_error
            BytesRead += GetOccupiedSize(FfsHeader.FFS_FILE_SIZE, 8)
    #
    # Print file counts of current FV
    #
    if IsChildFv:
        print("There are a total of %d files in the child FV" % NumberOfFiles)
    else:
        print("There are a total of %d files in the FV" % NumberOfFiles)
    return status_success


# Routine Description:
#
#   GC_TODO: Add function description
#
# Arguments:
#
#   argc  - GC_TODO: add argument description
#   ]     - GC_TODO: add argument description
#
# Returns:
#
#   GC_TODO: add return values
def main():
    args = options()
    print(args)

    if args.quiet:
        logger.setLevel(logging.CRITICAL)
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    if args.debug:
        logger.setLevel(logging.DEBUG)

    try:
        if args.xref:
            status = ParseGuidBaseNameFile(args.xref)
            print("ParseGuidBaseNameFile: %s\n" % args.xref)
            if status != 0:
                return status
        global offset
        if args.offset:
            # judge or hex?
            if args.offset.startswith("0x"):
                if not re.search('\b0x[0-9a-fA-F]+\b', args.offset):
                    logger.error(
                        "Invalid option value offset = %s" % args.offset)
                    return status_error
                offset = int(args.offset, 16)
            else:
                offset = int(args.offset)
                if not offset:
                    logger.error(
                        "Invalid option value offset = %s" % args.offset)
                    return status_error
                if args.offset.endswith("K"):
                    offset = int(''.join(args.offset[:-1])) * 1024

        if args.hash:
            global EnableHash
            EnableHash = args.hash
            OpenSslCommand = "openssl"
            OpenSslEnv = os.getenv("OPENSSL_PATH")
            if OpenSslEnv == None:
                OpenSslPath = OpenSslCommand
            else:
                # We add quotes to the Openssl Path in case it has space characters
                OpenSslPath = os.path.join(OpenSslEnv, OpenSslCommand)
            if not OpenSslPath:
                logger.error(
                    "Open SSL command not available.  Please verify PATH or set OPENSSL_PATH.")
                return status_error

        # parser inputfile
        if args.filename:
            try:
                file = open(args.filename, 'rb')
                file.seek(offset)
                # Read the header
                Buffer = file.read()
            except Exception as e:
                logging.error(e)
                return status_error
            finally:
                file.close()

            # Determine size of FV
            status = ReadHeader(Buffer[offset:])
            # Allocate a buffer for the FV image
            # LoadGuidedSectionToolsTxt(args.filename)
            # print FV infomations
            status = PrintFvInfo(Buffer[offset:])
        else:
            logger.error("Missing option, Input files are not specified")
            return status_error
    except Exception as e:
        logger.error(e)
        return status_error

    return status


if __name__ == '__main__':
    res = main()
    ## 0-127 is a safe return range, and 1 is a standard default error
    if res < 0 or res > 127: res = 1
    sys.exit(res)
