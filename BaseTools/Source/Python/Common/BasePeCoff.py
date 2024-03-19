# @file
# Creates output file that is a properly formed section per the PI spec.

# Copyright (c) 2004 - 2018, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent

from ctypes import *

from FirmwareStorageFormat.PeImageHeader import *
from FirmwareStorageFormat.Common import *
from Common import EdkLogger
from Common.PeCoffLoader import *
from GenFvs.common import *


def PeCoffLoaderGetPeHeader(ImageContext: PE_COFF_LOADER_IMAGE_CONTEXT,
                            ImageBuffer: bytes):
    """
    Retrieves the PE or TE Header from a PE/COFF or TE image
    @param ImageContext: The context of the image being loaded
    @return: ImageContext, PE and TE Header
    """
    # PeHdr = EFI_IMAGE_OPTIONAL_HEADER_UNION()
    TeHdr = EFI_TE_IMAGE_HEADER()
    ImageContext.IsTeImage = False

    # Read the DOS image headers
    try:
        DosHeader = EFI_IMAGE_DOS_HEADER.from_buffer_copy(ImageBuffer)
    except Exception as E:
        ImageContext.ImageError = IMAGE_ERROR_IMAGE_READ
        return

    ImageContext.PeCoffHeaderOffset = 0
    if DosHeader.e_magic == EFI_IMAGE_DOS_SIGNATURE:
        # DOS image header is present, so read the PE header after the DOS image header
        ImageContext.PeCoffHeaderOffset = DosHeader.e_lfanew

    # Get the PE/COFF Header pointer
    PeHdr = EFI_IMAGE_OPTIONAL_HEADER_UNION.from_buffer_copy(
        ImageBuffer[ImageContext.PeCoffHeaderOffset:])
    if PeHdr.Pe32.Signature != EFI_IMAGE_NT_SIGNATURE:
        # Check the PE/COFF Header Signature. If not, then try to get a TE header
        TeHdr = EFI_TE_IMAGE_HEADER.from_buffer_copy(
            ImageBuffer[ImageContext.PeCoffHeaderOffset:])
        if TeHdr.Signature != EFI_TE_IMAGE_HEADER_SIGNATURE:
            return
        ImageContext.IsTeImage = True

    return ImageContext, PeHdr, TeHdr


def PeCoffLoaderCheckImageType(ImageContext: PE_COFF_LOADER_IMAGE_CONTEXT,
                               PeHdr, TeHdr):
    """

    @param ImageContext:
    @param Header:
    @return:
    """
    #
    # See if the machine type is supported.
    # We support a native machine type (IA-32/Itanium-based)
    #
    if ImageContext.IsTeImage == False:
        ImageContext.Machine = PeHdr.Pe32.FileHeader.Machine
    else:
        ImageContext.Machine = TeHdr.Machine

    if ImageContext.Machine != IMAGE_FILE_MACHINE_I386 and \
        ImageContext.Machine != IMAGE_FILE_MACHINE_X64 and \
        ImageContext.Machine != IMAGE_FILE_MACHINE_ARMTHUMB_MIXED and \
        ImageContext.Machine != IMAGE_FILE_MACHINE_EBC and \
        ImageContext.Machine != IMAGE_FILE_MACHINE_ARM64 and \
        ImageContext.Machine != IMAGE_FILE_MACHINE_RISCV64 and \
        ImageContext.Machine != IMAGE_FILE_MACHINE_LOONGARCH64:
        # unsupported PeImage machine type
        return

    #
    # See if the image type is supported.  We support EFI Applications,
    # EFI Boot Service Drivers, EFI Runtime Drivers and EFI SAL Drivers.
    #
    if ImageContext.IsTeImage == False:
        ImageContext.ImageType = PeHdr.Pe32.OptionalHeader.Subsystem
    else:
        ImageContext.ImageType = TeHdr.Subsystem

    if ImageContext.ImageType != EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION and \
        ImageContext.ImageType != EFI_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER and \
        ImageContext.ImageType != EFI_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER and \
        ImageContext.ImageType != EFI_IMAGE_SUBSYSTEM_SAL_RUNTIME_DRIVER:
        # unsupported PeImage subsystem type
        return

    return ImageContext


def PeCoffLoaderGetImageInfo(ImageContext: PE_COFF_LOADER_IMAGE_CONTEXT,
                             ImageBuffer: bytes):
    # OptionHeader = EFI_IMAGE_OPTIONAL_HEADER_POINTER()
    DebugDirectoryEntryRva = 0
    # Assume success
    ImageContext.ImageError = IMAGE_ERROR_SUCCESS

    Res = PeCoffLoaderGetPeHeader(ImageContext, ImageBuffer)
    if not Res:
        return
    ImageContext = Res[0]
    PeHdr = Res[1]
    TeHdr = Res[2]
    # Verify machine type
    ImageContext = PeCoffLoaderCheckImageType(ImageContext, PeHdr, TeHdr)
    if not ImageContext:
        return
    OptionHeader = EFI_IMAGE_OPTIONAL_HEADER_POINTER.from_buffer_copy(
        ImageBuffer[ImageContext.PeCoffHeaderOffset + sizeof(c_uint32) + sizeof(
            EFI_IMAGE_FILE_HEADER):])

    # Retrieve the base address of the image
    if not ImageContext.IsTeImage:
        if PeHdr.Pe32.OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            ImageContext.ImageAddress = OptionHeader.Optional32.ImageBase
        else:
            ImageContext.ImageAddress = OptionHeader.Optional64.ImageBase
    else:
        ImageContext.ImageAddress = TeHdr.ImageBase + TeHdr.StrippedSize - sizeof(
            EFI_TE_IMAGE_HEADER)

    # Initialize the codeview pointer.
    ImageContext.CodeView = None
    ImageContext.PdbPointer = None

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
    if (not ImageContext.IsTeImage) and (
        PeHdr.Pe32.FileHeader.Characteristics & EFI_IMAGE_FILE_RELOCS_STRIPPED != 0):
        ImageContext.RelocationsStripped = True
    elif ImageContext.IsTeImage and TeHdr.DataDirectory[0].Size == 0 and \
        TeHdr.DataDirectory[
            0].VirtualAddress == 0:
        ImageContext.RelocationsStripped = True
    else:
        ImageContext.RelocationsStripped = False

    if not ImageContext.IsTeImage:
        if PeHdr.Pe32.OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            ImageContext.ImageSize = OptionHeader.Optional32.SizeOfImage
            ImageContext.SectionAlignment = OptionHeader.Optional32.SectionAlignment
            ImageContext.SizeOfHeaders = OptionHeader.Optional32.SizeOfHeaders

            # Modify ImageSize to contain .PDB file name if required and initialize
            # PdbRVA field...
            if OptionHeader.Optional32.NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_DEBUG:
                DebugDirectoryEntry = OptionHeader.Optional32.DataDirectory[
                    EFI_IMAGE_DIRECTORY_ENTRY_DEBUG]
                DebugDirectoryEntryRva = DebugDirectoryEntry.VirtualAddress
        else:
            ImageContext.ImageSize = OptionHeader.Optional64.SizeOfImage
            ImageContext.SectionAlignment = OptionHeader.Optional64.SectionAlignment
            ImageContext.SizeOfHeaders = OptionHeader.Optional64.SizeOfHeaders

            if OptionHeader.Optional64.NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_DEBUG:
                DebugDirectoryEntry = OptionHeader.Optional64.DataDirectory[
                    EFI_IMAGE_DIRECTORY_ENTRY_DEBUG]
                DebugDirectoryEntryRva = DebugDirectoryEntry.VirtualAddress

        if DebugDirectoryEntryRva != 0:
            # Determine the file offset of the debug directory...  This means we walk
            # the sections to find which section contains the RVA of the debug directory

            DebugDirectoryEntryFileOffset = 0
            SectionHeaderOffset = ImageContext.PeCoffHeaderOffset + \
                                  sizeof(c_uint32) + \
                                  sizeof(EFI_IMAGE_FILE_HEADER) + \
                                  PeHdr.Pe32.FileHeader.SizeOfOptionalHeader

            for Index in range(PeHdr.Pe32.FileHeader.NumberOfSections):
                # Read section header from file
                SectionHeader = EFI_IMAGE_SECTION_HEADER.from_buffer_copy(
                    ImageBuffer[SectionHeaderOffset:])

                if DebugDirectoryEntryRva >= SectionHeader.VirtualAddress and DebugDirectoryEntryRva < SectionHeader.VirtualAddress + SectionHeader.Misc.VirtualSize:
                    DebugDirectoryEntryFileOffset = DebugDirectoryEntryRva - SectionHeader.VirtualAddress + SectionHeader.PointerToRawData
                    break
                SectionHeaderOffset += sizeof(EFI_IMAGE_SECTION_HEADER)

            if DebugDirectoryEntryFileOffset != 0:
                Size = 0
                while Size < DebugDirectoryEntry.Size:
                    # Read next debug directory entry
                    DebugEntry = EFI_IMAGE_DEBUG_DIRECTORY_ENTRY.from_buffer_copy(
                        ImageBuffer[
                        DebugDirectoryEntryFileOffset + Size:])

                    if DebugEntry.Type == EFI_IMAGE_DEBUG_TYPE_CODEVIEW:
                        ImageContext.DebugDirectoryEntryRva = DebugDirectoryEntryRva + Size
                        if DebugEntry.RVA == 0 and DebugEntry.FileOffset != 0:
                            ImageContext.ImageSize += DebugEntry.SizeOfData
                        return ImageContext
                    Size += sizeof(EFI_IMAGE_DEBUG_DIRECTORY_ENTRY)
    else:
        ImageContext.ImageSize = 0
        ImageContext.SectionAlignment = 4096
        ImageContext.SizeOfHeaders = sizeof(
            EFI_TE_IMAGE_HEADER) + TeHdr.BaseOfCode - TeHdr.StrippedSize

        DebugDirectoryEntry = TeHdr.DataDirectory[1]
        DebugDirectoryEntryRva = DebugDirectoryEntry.VirtualAddress
        SectionHeaderOffset = sizeof(EFI_TE_IMAGE_HEADER)

        DebugDirectoryEntryFileOffset = 0
        Index = 0
        while Index < TeHdr.NumberOfSections:
            SectionHeader = EFI_IMAGE_SECTION_HEADER.from_buffer_copy(
                ImageBuffer[SectionHeaderOffset:])
            if DebugDirectoryEntryRva >= SectionHeader.VirtualAddress and DebugDirectoryEntryRva < SectionHeader.VirtualAddress + SectionHeader.Misc.VirtualSize:
                DebugDirectoryEntryFileOffset = DebugDirectoryEntryRva - \
                                                SectionHeader.VirtualAddress + SectionHeader.PointerToRawData \
                                                + sizeof(
                    EFI_TE_IMAGE_HEADER) - TeHdr.StrippedSize

                # File offset of the debug directory was found, if this is not the last
                # section,then skip to the last section for calculating the image size
                if Index < TeHdr.NumberOfSections - 1:
                    SectionHeaderOffset += (
                                               TeHdr.NumberOfSections - 1 - Index) * sizeof(
                        EFI_IMAGE_SECTION_HEADER)
                    Index = TeHdr.NumberOfSections - 1
                    continue

            Index += 1
            if Index == TeHdr.NumberOfSections:
                ImageContext.ImageSize = SectionHeader.VirtualAddress + SectionHeader.Misc.VirtualSize + \
                                         ImageContext.SectionAlignment - 1 & ~ (
                    ImageContext.SectionAlignment - 1)
            SectionHeaderOffset += sizeof(EFI_IMAGE_SECTION_HEADER)

        if DebugDirectoryEntryFileOffset != 0:
            index = 0
            while index < DebugDirectoryEntry.Size:
                DebugEntry = EFI_IMAGE_DEBUG_DIRECTORY_ENTRY.from_buffer_copy(
                    ImageBuffer[DebugDirectoryEntryFileOffset + index:])

                if DebugEntry.Type == EFI_IMAGE_DEBUG_TYPE_CODEVIEW:
                    ImageContext.DebugDirectoryEntryRva = c_uint32(
                        DebugDirectoryEntryRva + index).value
                    return ImageContext
                index += sizeof(EFI_IMAGE_DEBUG_DIRECTORY_ENTRY)
    return ImageContext


def PeCoffLoaderGetPdbPointer(Pe32Data: bytes):
    """
    Returns a pointer to the PDB file name for a raw PE/COFF image that is not
    loaded into system memory with the PE/COFF Loader Library functions.

    Returns the PDB file name for the PE/COFF image specified by Pe32Data.  If
    the PE/COFF image specified by Pe32Data is not a valid, then NULL is
    returned.  If the PE/COFF image specified by Pe32Data does not contain a
    debug directory entry, then NULL is returned.  If the debug directory entry
    in the PE/COFF image specified by Pe32Data does not contain a PDB file name,
    then NULL is returned.
    If Pe32Data is NULL, then return NULL.
    :param Pe32Data: Pe32 section image
    :return:         Pdb pointer
    """
    # Hdr = EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION()

    if len(Pe32Data) == 0:
        return

    TEImageAdjust = 0
    DirectoryEntry = None
    DebugEntry = None
    NumberOfRvaAndSizes = 0
    NumOfSections = 0
    SectionHeaderOff = 0

    DosHdr = EFI_IMAGE_DOS_HEADER.from_buffer_copy(
        AddBytesToBuffer(Pe32Data, sizeof(EFI_IMAGE_DOS_HEADER)))
    PeHeaderOff = 0
    if DosHdr.e_magic == EFI_IMAGE_DOS_SIGNATURE:
        Hdr = EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION.from_buffer_copy(
            Pe32Data[(DosHdr.e_lfanew & 0x0ffff):])
        PeHeaderOff = DosHdr.e_lfanew & 0x0ffff
    else:
        Hdr = EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION.from_buffer_copy(
            AddBytesToBuffer(Pe32Data,
                             sizeof(EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION)))

    if Hdr.Te.Signature == EFI_TE_IMAGE_HEADER_SIGNATURE:
        if Hdr.Te.DataDirectory[
            EFI_TE_IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress != 0:
            DirectoryEntry = Hdr.Te.DataDirectory[
                EFI_TE_IMAGE_DIRECTORY_ENTRY_DEBUG]
            TEImageAdjust = sizeof(EFI_TE_IMAGE_HEADER) - Hdr.Te.StrippedSize

            # Get the DebugEntry offset in the raw data image.
            NumOfSections = Hdr.Te.NumberOfSections
            # SectionHeaderOff = PeHeaderOff + sizeof(Hdr.Te)
            SectionOff = PeHeaderOff + sizeof(Hdr.Te)
            # TODO SectionHeader[Index] ？
            for Index in range(NumOfSections):
                SectionHeader = EFI_IMAGE_SECTION_HEADER.from_buffer_copy(
                    Pe32Data[SectionOff:])
                if DirectoryEntry.VirtualAddress >= SectionHeader.VirtualAddress and DirectoryEntry.VirtualAddress < SectionHeader.VirtualAddress + SectionHeader.Misc.VirtualSize:
                    DebugEntryOff = PeHeaderOff + DirectoryEntry.VirtualAddress - SectionHeader.VirtualAddress + SectionHeader.PointerToRawData + TEImageAdjust
                    DebugEntry = EFI_IMAGE_DEBUG_DIRECTORY_ENTRY.from_buffer_copy(
                        Pe32Data[DebugEntryOff:])
                    break

                SectionOff += sizeof(EFI_IMAGE_SECTION_HEADER)

    elif Hdr.Pe32.Signature == EFI_IMAGE_NT_SIGNATURE:
        Magic = Hdr.Pe32.OptionalHeader.Magic
        if Hdr.Pe32.FileHeader.Machine == IMAGE_FILE_MACHINE_ARMT or \
            Hdr.Pe32.FileHeader.Machine == IMAGE_FILE_MACHINE_I386:
            Magic = EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC
        elif Hdr.Pe32.FileHeader.Machine == IMAGE_FILE_MACHINE_X64:
            Magic = EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC
        # elif Hdr.Pe32.FileHeader.Machine == IMAGE_FILE_MACHINE_I386:
        #     pass

        SectionHeaderOff = PeHeaderOff + sizeof(c_uint32) + sizeof(
            EFI_IMAGE_SECTION_HEADER) + Hdr.Pe32.FileHeader.SizeOfOptionalHeader
        SectionOff = PeHeaderOff + sizeof(c_uint32) + sizeof(
            EFI_IMAGE_SECTION_HEADER) + Hdr.Pe32.FileHeader.SizeOfOptionalHeader
        NumOfSections = Hdr.Pe32.FileHeader.NumberOfSections

        if Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            # Use PE32 offset get Debug Directory Entry
            NumberOfRvaAndSizes = Hdr.Pe32.OptionalHeader.NumberOfRvaAndSizes
            DirectoryEntry = Hdr.Pe32.OptionalHeader.DataDirectory[
                EFI_IMAGE_DIRECTORY_ENTRY_DEBUG]
        elif Hdr.Pe32.OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            # Use PE32+ offset get Debug Directory Entry
            NumberOfRvaAndSizes = Hdr.Pe32Plus.OptionalHeader.NumberOfRvaAndSizes
            DirectoryEntry = Hdr.Pe32Plus.OptionalHeader.DataDirestory[
                EFI_IMAGE_DIRECTORY_ENTRY_DEBUG]

        # DirectoryEntry = EFI_IMAGE_DATA_DIRECTORY.from_buffer_copy(
        #     Pe32Data[DirectoryEntry:])
        if NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_DEBUG or DirectoryEntry.VirtualAddress == 0:
            DirectoryEntry = None
            DebugEntry = None
        else:
            # Get the DebugEntry offset in the raw data image.
            for Index in range(NumOfSections):
                SectionHeader = EFI_IMAGE_SECTION_HEADER.from_buffer_copy(
                    Pe32Data[SectionOff:])
                if DirectoryEntry.VirtualAddress >= SectionHeader.VirtualAddress and DirectoryEntry.VirtualAddress < (
                    SectionHeader.VirtualAddress + SectionHeader.Misc.VirtualSize):
                    DebugEntry = DirectoryEntry.VirtualAddress - SectionHeader.VirtualAddress + SectionHeader.PointerToRawData
                    break
                SectionOff += sizeof(EFI_IMAGE_SECTION_HEADER)
    else:
        return

    if DebugEntry == None or DirectoryEntry == None:
        return

    # Scan the directory to find the debug entry.
    # DebugEntry = EFI_IMAGE_DEBUG_DIRECTORY_ENTRY.from_buffer_copy(
    #     Pe32Data[DebugEntryOff:])
    DirCount = 0
    while DirCount < DirectoryEntry.Size:
        if DebugEntry.Type == EFI_IMAGE_DEBUG_TYPE_CODEVIEW:
            if DebugEntry.SizeOfData > 0:
                # Get the DebugEntry offset in the raw data image.
                CodeViewEntryPointer = 0
                Index = 0
                SectionOff = PeHeaderOff + sizeof(Hdr.Te)
                for Index in range(NumOfSections):
                    SectionHeader = EFI_IMAGE_SECTION_HEADER.from_buffer_copy(
                        Pe32Data[SectionOff:])
                    if DebugEntry.RVA >= SectionHeader.VirtualAddress and DirectoryEntry.VirtualAddress < (
                        SectionHeader.VirtualAddress + SectionHeader.Misc.VirtualSize):
                        CodeViewEntryPointer = DebugEntry.RVA - SectionHeader.VirtualAddress + SectionHeader.PointerToRawData + TEImageAdjust
                        CodeViewEvtryValue = int.from_bytes(Pe32Data[CodeViewEntryPointer:CodeViewEntryPointer+4], 'little')
                        break
                    SectionOff += sizeof(EFI_IMAGE_SECTION_HEADER)
                if Index > NumOfSections:
                    continue

                if CodeViewEvtryValue == CODEVIEW_SIGNATURE_NB10:
                    return CodeViewEntryPointer + sizeof(
                        EFI_IMAGE_DEBUG_CODEVIEW_NB10_ENTRY)
                elif CodeViewEvtryValue == CODEVIEW_SIGNATURE_RSDS:
                    return CodeViewEntryPointer + sizeof(EFI_IMAGE_DEBUG_CODEVIEW_RSDS_ENTRY)
                elif CodeViewEvtryValue == CODEVIEW_SIGNATURE_MTOC:
                    return CodeViewEntryPointer + sizeof(
                        EFI_IMAGE_DEBUG_CODEVIEW_MTOC_ENTRY)
                else:
                    break
            DirCount += sizeof(EFI_IMAGE_DEBUG_DIRECTORY_ENTRY)
    return


def PeCoffLoaderLoadImage(ImageContext: PE_COFF_LOADER_IMAGE_CONTEXT,
                          ImageBuffer: bytes):
    """
    Loads a PE/COFF image into memory
    @param ImageContext: Contains information on image to load into memory
    @return:
    """
    PeHdr = None
    TeHdr = None
    OptionHeader = None

    CheckContext = PE_COFF_LOADER_IMAGE_CONTEXT.from_buffer_copy(
        struct2stream(ImageContext))
    CheckContext = PeCoffLoaderGetImageInfo(CheckContext, ImageBuffer)
    if not CheckContext:
        return

    # Make sure there is enough allocated space for the image being loaded
    if ImageContext.ImageSize < CheckContext.ImageSize:
        ImageContext.ImageError = IMAGE_ERROR_INVALID_IMAGE_SIZE
        # return RESOURCE_OVERFLOW
        return
    # If there's no relocations, then make sure it's not a runtime driver,
    # and that it's being loaded at the linked address.
    if CheckContext.RelocationsStripped:
        # If the image does not contain relocations and it is a runtime driver
        # then return an error.
        if CheckContext.ImageType == EFI_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
            ImageContext.ImageError = IMAGE_ERROR_INVALID_SUBSYSTEM
            return

        if CheckContext.ImageAddress != ImageContext.ImageAddress:
            ImageContext.ImageError = IMAGE_ERROR_INVALID_IMAGE_ADDRESS
            return

    # Make sure the allocated space has the proper section alignment
    # if not ImageContext.IsTeImage:
    #     if ImageContext.ImageAddress & (
    #         CheckContext.SectionAlignment - 1) != 0:
    #         ImageContext.ImageError = IMAGE_ERROR_INVALID_SECTION_ALIGNMENT
    #         return
    Image = bytearray((ImageContext.ImageSize + ImageContext.SectionAlignment + ImageContext.SectionAlignment - 1) & (
                ~(ImageContext.SectionAlignment - 1)))
    # Read the entire PE/COFF or TE header into memory
    # HeadersBuffer = ImageBuffer[:ImageContext.SizeOfHeaders]
    if not ImageContext.IsTeImage:
        Image[:ImageContext.SizeOfHeaders] = ImageBuffer[:ImageContext.SizeOfHeaders]
        PeHdr = EFI_IMAGE_OPTIONAL_HEADER_UNION.from_buffer_copy(
            Image[ImageContext.PeCoffHeaderOffset:])
        OptionHeader = EFI_IMAGE_OPTIONAL_HEADER_POINTER.from_buffer_copy(
            Image[
            ImageContext.PeCoffHeaderOffset + sizeof(c_uint32) + sizeof(
                EFI_IMAGE_FILE_HEADER):])

        FirstSectionOff = ImageContext.PeCoffHeaderOffset + sizeof(
            c_uint32) + sizeof(
            EFI_IMAGE_FILE_HEADER) + PeHdr.Pe32.FileHeader.SizeOfOptionalHeader

        NumOfSections = PeHdr.Pe32.FileHeader.NumberOfSections
    else:
        Image[:ImageContext.SizeOfHeaders] = ImageBuffer[:ImageContext.SizeOfHeaders]
        TeHdr = EFI_TE_IMAGE_HEADER.from_buffer_copy(
            Image)
        FirstSectionOff = sizeof(EFI_TE_IMAGE_HEADER)
        NumOfSections = TeHdr.NumberOfSections

    # Load each section of the image
    for Index in range(NumOfSections):
        Section = EFI_IMAGE_SECTION_HEADER.from_buffer_copy(
            ImageBuffer[
            FirstSectionOff:FirstSectionOff + sizeof(EFI_IMAGE_SECTION_HEADER)])

        Base = Section.VirtualAddress
        End = Section.VirtualAddress + Section.Misc.VirtualSize - 1

        if ImageContext.IsTeImage:
            Base = Base + sizeof(EFI_TE_IMAGE_HEADER) - TeHdr.StrippedSize
            End = End + sizeof(EFI_TE_IMAGE_HEADER) - TeHdr.StrippedSize

        # Read the section
        Size = Section.Misc.VirtualSize
        if Size == 0 or Size > Section.SizeOfRawData:
            Size = Section.SizeOfRawData
        if Section.SizeOfRawData:
            if not ImageContext.IsTeImage:
                Image[Base:Base+Size] = ImageBuffer[
                                        Section.PointerToRawData:Section.PointerToRawData + Size]
            else:
                Image[Base:Base+Size] = ImageBuffer[
                                        Section.PointerToRawData + sizeof(
                                            EFI_TE_IMAGE_HEADER) - TeHdr.StrippedSize:Section.PointerToRawData + sizeof(
                                            EFI_TE_IMAGE_HEADER) - TeHdr.StrippedSize + Size]

        # If raw size is less than virtual size, zero fill the remaining
        if Size < Section.Misc.VirtualSize:
            Image[Base + Size:Base + Size + (
                Section.Misc.VirtualSize - Size)] = bytes(
                Section.Misc.VirtualSize - Size)

        # Next Section
        FirstSectionOff += sizeof(Section)

    # Get image's entry point
    if not ImageContext.IsTeImage:
        ImageContext.EntryPoint = ImageContext.ImageAddress + PeHdr.Pe32.OptionalHeader.AddressOfEntryPoint
    else:
        ImageContext.EntryPoint = ImageContext.ImageAddress + TeHdr.AddressOfEntryPoint + sizeof(
            EFI_TE_IMAGE_HEADER) - TeHdr.StrippedSize

    # Determine the size of the fixup data
    #
    # Per the PE/COFF spec, you can't assume that a given data directory
    # is present in the image. You have to check the NumberOfRvaAndSizes in
    # the optional header to verify a desired directory entry is there.
    if not ImageContext.IsTeImage:
        if PeHdr.Pe32.OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            if OptionHeader.Optional32.NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC:
                DirectoryEntry = OptionHeader.Optional32.DataDirectory[
                    EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC]
                ImageContext.FixupDataSize = DirectoryEntry.Size // sizeof(
                    c_uint16) * sizeof(c_uint)
            else:
                ImageContext.FixupDataSize = 0
        else:
            if OptionHeader.Optional64.NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC:
                DirectoryEntry = OptionHeader.Optional64.DataDirectory[
                    EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC]
                ImageContext.FixupDataSize = DirectoryEntry.Size // sizeof(
                    c_uint16) * sizeof(c_uint)
            else:
                ImageContext.FixupDataSize = 0
    else:
        DirectoryEntry = TeHdr.DataDirectory[0]
        ImageContext.FixupDataSize = DirectoryEntry.Size // sizeof(
            c_uint16) * sizeof(c_uint)

    # Consumer must allocate a buffer for the relocation fixup log.
    # Only used for runtime drivers.
    ImageContext.FixupData = None
    # Load the Codeview info if present
    if ImageContext.DebugDirectoryEntryRva != 0:
        if not ImageContext.IsTeImage:
            DebugEntry = EFI_IMAGE_DEBUG_DIRECTORY_ENTRY.from_buffer_copy(
                Image[PeCoffLoaderImageAddress(ImageContext,
                                                     ImageContext.DebugDirectoryEntryRva):])
        else:
            DebugEntry = EFI_IMAGE_DEBUG_DIRECTORY_ENTRY.from_buffer_copy(
                Image[ImageContext.DebugDirectoryEntryRva + sizeof(
                    EFI_TE_IMAGE_HEADER) - TeHdr.StrippedSize:])

        if DebugEntry != None:
            TempDebugEntryRva = DebugEntry.RVA
            if DebugEntry.RVA == 0 and DebugEntry.FileOffset != 0:
                FirstSectionOff -= sizeof(EFI_IMAGE_SECTION_HEADER)
                Section = EFI_IMAGE_SECTION_HEADER.from_buffer_copy(ImageBuffer[
                                                                    FirstSectionOff - sizeof(
                                                                        EFI_IMAGE_SECTION_HEADER):FirstSectionOff])
                if Section.SizeOfRawData < Section.Misc.VirtualSize:
                    TempDebugEntryRva = Section.VirtualAddress + Section.Misc.VirtualSize
                else:
                    TempDebugEntryRva = Section.VirtualAddress + Section.SizeOfRawData
            if TempDebugEntryRva != 0:
                if not ImageContext.IsTeImage:
                    ImageContext.CodeView = PeCoffLoaderImageAddress(
                        ImageContext, TempDebugEntryRva)
                else:
                    ImageContext.CodeView = TempDebugEntryRva + sizeof(
                        EFI_TE_IMAGE_HEADER) - TeHdr.StrippedSize
                if ImageContext.CodeView == 0:
                    ImageContext.ImageError = IMAGE_ERROR_IMAGE_READ
                    EdkLogger.error(None, 0, "Load CodeView error.")

                if DebugEntry.RVA == 0:
                    Size = DebugEntry.SizeOfData
                    if not ImageContext.IsTeImage:
                        Image[
                        ImageContext.CodeView:ImageContext.CodeView + Size] = ImageBuffer[
                                                                              DebugEntry.FileOffset:DebugEntry.FileOffset + Size]
                    else:
                        Image[
                        ImageContext.CodeView:ImageContext.CodeView + Size] = ImageBuffer[
                                                                              DebugEntry.FileOffset + sizeof(
                                                                                  EFI_TE_IMAGE_HEADER) - TeHdr.StrippedSize:DebugEntry.FileOffset + sizeof(
                                                                                  EFI_TE_IMAGE_HEADER) - TeHdr.StrippedSize + Size]
                    DebugEntry.RVA = TempDebugEntryRva
                CodeView = int.from_bytes(Image[
                                          ImageContext.CodeView:ImageContext.CodeView + 4],
                                          "little")
                if CodeView == CODEVIEW_SIGNATURE_NB10:
                    ImageContext.PdbPointer = ImageContext.CodeView + sizeof(
                        EFI_IMAGE_DEBUG_CODEVIEW_NB10_ENTRY)
                elif CodeView == CODEVIEW_SIGNATURE_RSDS:
                    ImageContext.PdbPointer = ImageContext.CodeView + sizeof(
                        EFI_IMAGE_DEBUG_CODEVIEW_RSDS_ENTRY)
                elif CodeView == CODEVIEW_SIGNATURE_MTOC:
                    ImageContext.PdbPointer = ImageContext.CodeView + sizeof(
                        EFI_IMAGE_DEBUG_CODEVIEW_MTOC_ENTRY)

    return Image, ImageContext


def PeCoffLoaderImageAddress(ImageContext, Address):
    if Address >= ImageContext.ImageSize:
        ImageContext.ImageError = IMAGE_ERROR_INVALID_IMAGE_ADDRESS
        EdkLogger.error(None, 0, "Invalid image address.")
        # return

    return ImageContext.ImageAddress + Address


def PeCoffLoaderRelocateImage(ImageContext: PE_COFF_LOADER_IMAGE_CONTEXT,
                              SectionImage: bytes):
    TeHdr = None
    # bytes -> bytearray
    SectionImage = bytearray(SectionImage)
    ImageContext.ImageError = IMAGE_ERROR_SUCCESS

    # If there are not relocation entries, then we return done
    if ImageContext.RelocationsStripped:
        return SectionImage, ImageContext

    # Use DestinationAddress field of ImageContext as the relocation address even if it is 0.
    BaseAddress = ImageContext.DestinationAddress

    if not ImageContext.IsTeImage:
        PeHdr = EFI_IMAGE_OPTIONAL_HEADER_UNION.from_buffer_copy(
            SectionImage[ImageContext.PeCoffHeaderOffset:])

        OptionHeader = EFI_IMAGE_OPTIONAL_HEADER_POINTER.from_buffer_copy(
            SectionImage[
            ImageContext.PeCoffHeaderOffset + sizeof(c_uint32) + sizeof(
                EFI_IMAGE_FILE_HEADER):])

        if PeHdr.Pe32.OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            Adjust = BaseAddress - OptionHeader.Optional32.ImageBase
            OptionHeader.Optional32.ImageBase = BaseAddress
            SectionImage[
            ImageContext.PeCoffHeaderOffset + sizeof(c_uint32) + sizeof(
                EFI_IMAGE_FILE_HEADER):ImageContext.PeCoffHeaderOffset + sizeof(
                c_uint32) + sizeof(EFI_IMAGE_FILE_HEADER) + sizeof(
                EFI_IMAGE_OPTIONAL_HEADER32)] = struct2stream(
                OptionHeader.Optional32)
            MachineType = ImageContext.Machine

            # Find the relocation block
            # Per the PE/COFF spec, you can't assume that a given data directory
            # is present in the image. You have to check the NumberOfRvaAndSizes in
            # the optional header to verify a desired directory entry is there.
            if OptionHeader.Optional32.NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC:
                RelocDir = OptionHeader.Optional32.DataDirectory[
                    EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC]
                if RelocDir != None and RelocDir.Size > 0:
                    RelocBase = RelocDir.VirtualAddress
                    RelocBaseEnd = RelocDir.VirtualAddress + RelocDir.Size - 1
                    if RelocBaseEnd < RelocBase:
                        ImageContext.ImageError = IMAGE_ERROR_FAILED_RELOCATION
                        EdkLogger.error(None, 0,
                                        "Invalid, LocateImage() call failed on rebase of Current ffs file")
                else:
                    # Set base and end to bypass processing below.
                    RelocBase = RelocBaseEnd = 0
            else:
                RelocBase = RelocBaseEnd = 0

        else:
            Adjust = BaseAddress + OptionHeader.Optional64.ImageBase
            OptionHeader.Optional64.ImageBase = BaseAddress
            SectionImage[
            ImageContext.PeCoffHeaderOffset + sizeof(c_uint32) + sizeof(
                EFI_IMAGE_FILE_HEADER):ImageContext.PeCoffHeaderOffset + sizeof(
                c_uint32) + sizeof(EFI_IMAGE_FILE_HEADER) + sizeof(
                EFI_IMAGE_OPTIONAL_HEADER64)] = struct2stream(
                OptionHeader.Optional64)
            MachineType = ImageContext.Machine
            # Find the relocation block
            # Per the PE/COFF spec, you can't assume that a given data directory
            # is present in the image. You have to check the NumberOfRvaAndSizes in
            # the optional header to verify a desired directory entry is there.
            if OptionHeader.Optional64.NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC:
                RelocDir = OptionHeader.Optional64.DataDirectory[
                    EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC]
                if RelocDir != None and RelocDir.Size > 0:
                    RelocBase = RelocDir.VirtualAddress
                    RelocBaseEnd = RelocDir.VirtualAddress + RelocDir.Size - 1
                else:
                    RelocBase = RelocBaseEnd = 0
            else:
                RelocBase = RelocBaseEnd = 0
    else:
        TeHdr = EFI_TE_IMAGE_HEADER.from_buffer_copy(SectionImage)
        Adjust = BaseAddress - TeHdr.ImageBase
        TeHdr.ImageBase = BaseAddress
        SectionImage[:sizeof(EFI_TE_IMAGE_HEADER)] = struct2stream(TeHdr)
        MachineType = TeHdr.Machine
        # Find the relocation block
        RelocDir = TeHdr.DataDirectory[0]
        RelocBase = RelocDir.VirtualAddress + sizeof(
            EFI_TE_IMAGE_HEADER) - TeHdr.StrippedSize
        RelocBaseEnd = RelocBase + RelocDir.Size - 1

    # Run the relocation information and apply the fixups
    FixupData = ImageContext.FixupData
    while RelocBase < RelocBaseEnd:
        RelocBaseStruct = EFI_IMAGE_BASE_RELOCATION.from_buffer_copy(
            SectionImage[RelocBase:])
        Reloc = RelocBase + sizeof(EFI_IMAGE_BASE_RELOCATION)
        RelocEnd = RelocBase + RelocBaseStruct.SizeOfBlock
        if not ImageContext.IsTeImage:
            FixupBase = PeCoffLoaderImageAddress(ImageContext,
                                                 RelocBaseStruct.VirtualAddress)
        else:
            FixupBase = ImageContext.ImageAddress + RelocBaseStruct.VirtualAddress + sizeof(
                EFI_TE_IMAGE_HEADER) - TeHdr.StrippedSize

        # if RelocEnd < ImageContext.ImageAddress or RelocEnd > ImageContext.ImageAddress + ImageContext.ImageSize:
        #     ImageContext.ImageError = IMAGE_ERROR_FAILED_RELOCATION
        #     EdkLogger.error(None,0, "Invalid, LocateImage() call failed on rebase of Current ffs file")
        if RelocEnd < Reloc or RelocEnd > ImageContext.ImageSize:
            EdkLogger.error(None, 0, "Relocation infomation failed.")

        # Run this relocation record
        while Reloc < RelocEnd:
            # First value
            FirstValue = int.from_bytes(SectionImage[Reloc:Reloc + 2], 'little')
            # Low 12 bit: offset
            Fixup = FixupBase + (FirstValue & 0xFFF)
            # High 4 bit
            FixupType = FirstValue >> 12
            if FixupType == EFI_IMAGE_REL_BASED_ABSOLUTE:
                pass
            elif FixupType == EFI_IMAGE_REL_BASED_HIGH:
                SectionImage[Fixup:Fixup + 2] = (
                    int.from_bytes(SectionImage[Fixup:Fixup + 2],
                                   'little') + (
                            Adjust & 0xffffffff) >> 16).to_bytes(2,
                                                                 "little")
                if FixupData != None:
                    FixupData = Fixup
                    FixupData = FixupData + sizeof(c_uint16)

            elif FixupType == EFI_IMAGE_REL_BASED_LOW:
                SectionImage[Fixup:Fixup + 2] = (
                    int.from_bytes(SectionImage[Fixup:Fixup + 2],
                                   'little') + (Adjust & 0xffff)).to_bytes(2,
                                                                           'little')
                if FixupData != None:
                    FixupData = Fixup
                    FixupData = FixupData + sizeof(c_uint16)

            elif FixupType == EFI_IMAGE_REL_BASED_HIGHLOW:
                SectionImage[Fixup:Fixup + 4] = ((
                                                     int.from_bytes(
                                                         SectionImage[
                                                         Fixup:Fixup + 4],
                                                         'little') + Adjust) & 0xffffffff).to_bytes(
                    4, 'little')
                if FixupData != None:
                    FixupData = ALIGN_POINTER(FixupData, sizeof(
                        c_uint32))
                    FixupData = FixupData + sizeof(c_uint32)

            elif FixupType == EFI_IMAGE_REL_BASED_DIR64:
                SectionImage[Fixup:Fixup + 8] = (
                    int.from_bytes(SectionImage[Fixup:Fixup + 8],
                                   "little") + (
                            Adjust & 0xffffffffffffffff)).to_bytes(8, 'little')
                if FixupData != None:
                    FixupData = ALIGN_POINTER(FixupData, sizeof(
                        c_uint64)) + sizeof(c_uint64)

            elif FixupType == EFI_IMAGE_REL_BASED_HIGHADJ:
                ImageContext.ImageError = IMAGE_ERROR_FAILED_RELOCATION
                EdkLogger.error(None, 0, "Unsupport Fixup type.")
            else:
                Res = None
                if MachineType == IMAGE_FILE_MACHINE_I386:
                    Res = PeCoffLoaderRelocateIa32Image(Reloc, Fixup, FixupData,
                                                        Adjust)
                elif MachineType == IMAGE_FILE_MACHINE_ARMTHUMB_MIXED:
                    Res = PeCoffLoaderRelocateArmImage(
                        Reloc, Fixup, FixupData, Adjust, SectionImage)
                elif MachineType == IMAGE_FILE_MACHINE_RISCV64:
                    Res = PeCoffLoaderRelocateRiscVImage(Reloc, Fixup,
                                                         FixupData, Adjust)
                elif MachineType == IMAGE_FILE_MACHINE_LOONGARCH64:
                    Res = PeCoffLoaderRelocateLoongArch64Image(Reloc, Fixup,
                                                               FixupData,
                                                               Adjust)
                else:
                    EdkLogger.error(None, 0, "Unsupported machine type.")

                if not Res:
                    ImageContext.ImageError = IMAGE_ERROR_FAILED_RELOCATION
                    EdkLogger.error(None, 0, "Load Fix data failed.")
                Fixup = Res[0]
                FixupData = Res[1]
                SectionImage = Res[2]
                ImageContext.FixupData = FixupData

            Reloc += 2

        RelocBase = RelocEnd

    return ImageContext, SectionImage
