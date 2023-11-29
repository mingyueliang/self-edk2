from Common.BuildToolError import *
from FirmwareStorageFormat.FvHeader import *
from FirmwareStorageFormat.FfsFileHeader import *
from FirmwareStorageFormat.SectionHeader import *
from Common import EdkLogger
from Common.BuildToolError import *
from Common.LongFilePathSupport import LongFilePath

from GenFv.common import *


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
        self.FvHeader = EFI_FIRMWARE_VOLUME_HEADER.from_buffer_copy(
            self.FvBuffer)
        self.FvLength = self.FvHeader.FvLength

    def VerifyFfsFile(self, FfsFileBuffer: bytearray):
        FfsHeader = EFI_FFS_FILE_HEADER.from_buffer_copy(FfsFileBuffer)
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
            CurrentFileSize = EFI_FFS_FILE_HEADER.from_buffer_copy(
                self.FvBuffer[CurrentFileOff:]).FFS_FILE_SIZE
            if CurrentFileOff + CurrentFileSize > self.FvLength:
                NextFileOff = None
            else:
                NextFileOff = CurrentFileOff + CurrentFileSize

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
        CurrentFile = EFI_FFS_FILE_HEADER.from_buffer_copy(
            self.FvBuffer[CurrentFileOff:])
        while CurrentFileOff:
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
    FfsHeader = EFI_FFS_FILE_HEADER.from_buffer_copy(FfsBuffer)

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
                                                                    CurrentSectionOff + CurrentCommonSection.Common_Header_Size:])
            GuidSecAttr = GuidSection.Attributes
            GuidDataOffset = GuidSection.DataOffset

        if SectionType != EFI_SECTION_GUID_DEFINED and CurrentCommonSection.Type == EFI_SECTION_GUID_DEFINED and not (
            GuidSecAttr & EFI_GUIDED_SECTION_PROCESSING_REQUIRED):
            InnerCommonSectionOff = FirstSectionOff + CurrentCommonSection.Common_Header_Size + GuidDataOffset

            SearchSectionByType(InnerCommonSectionOff, FfsBuffer, SectionType,
                                StartIndex, Instance)

        # Find next section (including compensating for alignment issues.
        SectionSize = CurrentCommonSection.SECTION_SIZE
        CurrentSectionOff += (SectionSize + 0x03) & (~ 3)

    # EdkLogger.warn(None, 0, "%s not found in this FFS file." % SectionType)
    return
