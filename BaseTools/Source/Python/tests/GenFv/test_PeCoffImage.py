import pytest
import os.path
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from Common.LongFilePathSupport import LongFilePath
from Common.BasePeCoff import *
from FirmwareStorageFormat.PeImageHeader import *
from FirmwareStorageFormat.SectionHeader import *


def GetCommonHeader(PeSectionImage):
    CommonHeader = EFI_COMMON_SECTION_HEADER.from_buffer_copy(PeSectionImage)
    if CommonHeader.SECTION_SIZE == 0xffffff:
        CommonHeader = EFI_COMMON_SECTION_HEADER2.from_buffer_copy(
            PeSectionImage)

    return CommonHeader


class TestPeCoff:
    def setup_class(self):
        with open(
            LongFilePath(r"PeAndTeFiles/BCAF98C9-22B0-3B4F-9CBD-C8A6B4DBCEE9SEC1.1.pe32"),
            "rb") as PeFile:
            PeSecImage = PeFile.read()
        PeSection = GetCommonHeader(PeSecImage)
        self.PeImage = PeSecImage[PeSection.Common_Header_Size():]


        with open(LongFilePath(r"PeAndTeFiles/0D244DF9-6CE3-4133-A1CF-53200AB663ACSEC2.1.te"),
                  'rb') as TeFile:
            TeSecImage = TeFile.read()
        TeSection = GetCommonHeader(TeSecImage)
        self.TeImage = TeSecImage[TeSection.Common_Header_Size():]


    def test_PeCoffLoaderGetPeHeader(self):
        # Input = [] ## Input: Pe32 Image and Te Image
        Output = [EFI_IMAGE_NT_SIGNATURE, EFI_TE_IMAGE_HEADER_SIGNATURE]
        # Test Pe Image Header
        ImageContext = PE_COFF_LOADER_IMAGE_CONTEXT()
        Res = PeCoffLoaderGetPeHeader(ImageContext,
                                      self.PeImage)
        if Res:
            PeHeader = Res[1]
            assert PeHeader.Pe32.Signature == Output[0]
        # Test Te Image Header
        Res1 = PeCoffLoaderGetPeHeader(ImageContext,
                                       self.TeImage)
        if Res1:
            TeHdr = Res1[2]
            assert TeHdr.Signature == Output[1]

    def test_PeCoffLoaderCheckImageType(self):
        Output = [
            EFI_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER,
            EFI_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER
        ]
        # Pe image
        ImageContext = PE_COFF_LOADER_IMAGE_CONTEXT()
        ImageContext.IsTeImage = False
        DosHeader = EFI_IMAGE_DOS_HEADER.from_buffer_copy(self.PeImage)
        PeOffset = 0
        if DosHeader.e_magic == EFI_IMAGE_DOS_SIGNATURE:
            PeOffset = DosHeader.e_lfanew
        PeHdr = EFI_IMAGE_OPTIONAL_HEADER_UNION.from_buffer_copy(
            self.PeImage[PeOffset:])
        TeHdr = None
        if PeHdr.Pe32.Signature != EFI_IMAGE_NT_SIGNATURE:
            # Check the PE/COFF Header Signature. If not, then try to get a TE header
            TeHdr = EFI_TE_IMAGE_HEADER.from_buffer_copy(
                self.PeImage[ImageContext.PeCoffHeaderOffset:])
            if TeHdr.Signature != EFI_TE_IMAGE_HEADER_SIGNATURE:
                return
            ImageContext.IsTeImage = True

        ImageContext = PeCoffLoaderCheckImageType(ImageContext, PeHdr, TeHdr)

        assert ImageContext.ImageType == Output[0]

        # Te image
        ImageContext = PE_COFF_LOADER_IMAGE_CONTEXT()
        ImageContext.IsTeImage = False
        DosHeader = EFI_IMAGE_DOS_HEADER.from_buffer_copy(self.TeImage)
        PeOffset = 0
        if DosHeader.e_magic == EFI_IMAGE_DOS_SIGNATURE:
            PeOffset = DosHeader.e_lfanew
        PeHdr = EFI_IMAGE_OPTIONAL_HEADER_UNION.from_buffer_copy(
            self.TeImage[PeOffset:])

        if PeHdr.Pe32.Signature != EFI_IMAGE_NT_SIGNATURE:
            # Check the PE/COFF Header Signature. If not, then try to get a TE header
            TeHdr = EFI_TE_IMAGE_HEADER.from_buffer_copy(
                self.TeImage[ImageContext.PeCoffHeaderOffset:])
            if TeHdr.Signature != EFI_TE_IMAGE_HEADER_SIGNATURE:
                return
            ImageContext.IsTeImage = True
        ImageContext = PeCoffLoaderCheckImageType(ImageContext, PeHdr, TeHdr)
        assert ImageContext.ImageType == Output[1]

    def test_PeCoffLoaderGetImageInfo(self):
        Output = [
            {'CodeView': None, 'DebugDirectoryEntryRva': 19552,
             'ImageAddress': 65536, 'ImageType': 11, 'ImageSize': 32768,
             'Machine': 332, 'PeCoffHeaderOffset': 200},
            {'CodeView': None, 'DebugDirectoryEntryRva': 0,
             'ImageAddress': 408, 'ImageType': 11, 'ImageSize': 0,
             'Machine': 332, 'PeCoffHeaderOffset': 0},

        ]
        # Pe image
        ImageContext = PE_COFF_LOADER_IMAGE_CONTEXT()
        ImageContext = PeCoffLoaderGetImageInfo(ImageContext, self.PeImage)
        assert ImageContext.CodeView == Output[0].get('CodeView')
        assert ImageContext.DebugDirectoryEntryRva == Output[0].get(
            'DebugDirectoryEntryRva')
        assert ImageContext.ImageAddress == Output[0].get('ImageAddress')
        assert ImageContext.ImageType == Output[0].get('ImageType')
        assert ImageContext.ImageSize == Output[0].get('ImageSize')
        assert ImageContext.Machine == Output[0].get('Machine')
        assert ImageContext.PeCoffHeaderOffset == Output[0].get(
            'PeCoffHeaderOffset')
        # Te image
        ImageContext = PE_COFF_LOADER_IMAGE_CONTEXT()
        ImageContext = PeCoffLoaderGetImageInfo(ImageContext, self.TeImage)
        assert ImageContext.CodeView == Output[1].get('CodeView')
        assert ImageContext.DebugDirectoryEntryRva == Output[1].get(
            'DebugDirectoryEntryRva')
        assert ImageContext.ImageAddress == Output[1].get('ImageAddress')
        assert ImageContext.ImageType == Output[1].get('ImageType')
        assert ImageContext.ImageSize == Output[1].get('ImageSize')
        assert ImageContext.Machine == Output[1].get('Machine')
        assert ImageContext.PeCoffHeaderOffset == Output[1].get(
            'PeCoffHeaderOffset')

    def test_PeCoffLoaderGetPdbPointer(self):
        Output = []
        PdbPointer = PeCoffLoaderGetPdbPointer(self.PeImage)
        PdbPointer = PeCoffLoaderGetPdbPointer(self.TeImage)
        pass

    def test_PeCoffLoaderLoadImage(self):
        pass

    def test_PeCoffLoaderRelocateImage(self):
        pass


if __name__ == '__main__':
    pytest.main(['-v', '-s', 'test_PeCoffImage.py'])
