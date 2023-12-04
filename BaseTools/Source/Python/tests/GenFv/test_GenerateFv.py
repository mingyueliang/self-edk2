import pytest
import os.path
import sys
import filecmp
import shutil

from argparse import Namespace

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from GenFvs.GenerateFv import GenerateFvFile
from GenFvs.ParseInf import ParseInf
from GenFvs.FvInternalLib import *
from FirmwareStorageFormat.PeImageHeader import *

from FirmwareStorageFormat.FfsFileHeader import *


class TestGenFv:
    def setup_class(self):
        self.Options = Namespace(Address=None,
                                 AddressFile="FV/FVRECOVERY_a.inf",
                                 BlockSize=None,
                                 CapFlag=None,
                                 CapGUid=None, CapHeadSize=None,
                                 CapOEMFlag=None,
                                 FfsFile=None,
                                 FileTakeSize=None, ForceRebase=None,
                                 FvNameGuid=None,
                                 Guid=None, InFileName='FV/FVRECOVERY_i.inf',
                                 Map=None,
                                 NumberBlock=None,
                                 OutFileName='FV/FVRECOVERY_test.FV',
                                 capsule=False,
                                 debug=None, dump=False, quiet=False,
                                 verbose=False,
                                 version=False)
        self.GenFv = GenerateFvFile(self.Options)

    def GenerateFvObject(self, Options):
        return GenerateFvFile(Options)

    def test_GenerateFvImage(self):

        InfFiles = [
            Namespace(Address=None, AddressFile="FV/FVRECOVERY_a.inf",
                      BlockSize=None,
                      CapFlag=None,
                      CapGUid=None, CapHeadSize=None, CapOEMFlag=None,
                      FfsFile=None,
                      FileTakeSize=None, ForceRebase=None, FvNameGuid=None,
                      Guid=None, InFileName='FV/FVRECOVERY_i.inf', Map=None,
                      NumberBlock=None, OutFileName='FV/FVRECOVERY_test.FV',
                      capsule=False,
                      debug=None, dump=False, quiet=False, verbose=False,
                      version=False),
            Namespace(Address=None, AddressFile=None, BlockSize=None,
                      CapFlag=None,
                      CapGUid=None, CapHeadSize=None, CapOEMFlag=None,
                      FfsFile=None,
                      FileTakeSize=None, ForceRebase=None, FvNameGuid=None,
                      Guid=None, InFileName='FV/ACM_FV.inf', Map=None,
                      NumberBlock=None, OutFileName='FV/ACM_FV_test.FV',
                      capsule=False,
                      debug=None, dump=False, quiet=False, verbose=False,
                      version=False),
            Namespace(Address=None, AddressFile=None, BlockSize=None,
                      CapFlag=None,
                      CapGUid=None, CapHeadSize=None, CapOEMFlag=None,
                      FfsFile=None,
                      FileTakeSize=None, ForceRebase=None, FvNameGuid=None,
                      Guid=None, InFileName='FV/FVBIN.inf', Map=None,
                      NumberBlock=None, OutFileName='FV/FVBIN_test.FV',
                      capsule=False,
                      debug=None, dump=False, quiet=False, verbose=False,
                      version=False),

        ]
        OutFiles = [
            ["FV/FVRECOCERY1.FV", "FV/FVRECOCERY1.map", "FV/FVRECOCERY1.txt"],
            ["FV/ACM_FV.Fv", "FV/ACM_FV.Fv.map", "FV/ACM_FV.Fv.txt"],
            ["FV/FVBIN.Fv", "FV/FVBIN.Fv.map", "FV/FVBIN.Fv.txt"],
        ]
        for index in range(len(InfFiles)):
            Options = InfFiles[index]
            GenFv = GenerateFvFile(Options)
            GenFv.ParseMyOptions()
            GenFv.GenerateFvImage()
            if os.path.exists(GenFv.OutFileName):
                assert filecmp.cmp(GenFv.OutFileName, OutFiles[index][0])
                os.remove(GenFv.OutFileName)
            if os.path.exists(GenFv.MapFileName):
                assert filecmp.cmp(GenFv.MapFileName, OutFiles[index][1])
                os.remove(GenFv.MapFileName)

            if os.path.exists(GenFv.FvReportName):
                assert filecmp.cmp(GenFv.FvReportName, OutFiles[index][2])
                os.remove(GenFv.FvReportName)

            if os.path.exists(GenFv.AddrFileName):
                os.remove(GenFv.AddrFileName)

    def test_GenerateCapImage(self):
        pass

    def test_ParseInf(self):
        InfFiles = [
            "FVRECOVERY_i.inf",
        ]
        Output = [
            {
                'options': {
                    "EFI_BASE_ADDRESS": 0x102000000,
                    "EFI_BLOCK_SIZE": 0x10000,
                    "EFI_NUM_BLOCKS": 0x58
                },
                'attributes': {
                    'EFI_ERASE_POLARITY': '1',
                    'EFI_FVB2_ALIGNMENT_16': 'TRUE',
                    'EFI_FV_EXT_HEADER_FILE_NAME': r'c:\users\mliang2x\workspace\mingyueliang_edk2\self-edk2\Build\EmulatorIA32\DEBUG_VS2015x86\FV\FVRECOVERY.ext'
                },
                'NumOfFiles': 77
            },

        ]
        for Index in range(len(InfFiles)):
            with open(InfFiles[Index], 'rb') as file:
                InfStreams = file.read()
            Inf = ParseInf(InfStreams)
            Options = Inf.InfDict.get('options')
            assert Output[Index]['options']['EFI_BASE_ADDRESS'] == int(
                Options.get("EFI_BASE_ADDRESS")[0], 16)
            assert Output[Index]['options']['EFI_BLOCK_SIZE'] == int(
                Options.get("EFI_BLOCK_SIZE")[0], 16)
            assert Output[Index]['options']['EFI_NUM_BLOCKS'] == int(
                Options.get("EFI_NUM_BLOCKS")[0], 16)
            Attributes = Inf.InfDict.get('attributes')
            assert Output[Index]['attributes']['EFI_ERASE_POLARITY'] == \
                   Attributes.get('EFI_ERASE_POLARITY')[0]
            assert Output[Index]['attributes']['EFI_FVB2_ALIGNMENT_16'] == \
                   Attributes.get('EFI_FVB2_ALIGNMENT_16')[0]
            assert Output[Index]['attributes']['EFI_FV_EXT_HEADER_FILE_NAME'] == \
                   Attributes.get('EFI_FV_EXT_HEADER_FILE_NAME')[0]
            FfsFiles = Inf.InfDict.get('files').get(
                EFI_FILE_NAME_STRING)
            assert Output[Index]['NumOfFiles'] == len(FfsFiles)

    def test_CalculateFvSize(self):
        InfFiles = [
            Namespace(Address=None,
                      AddressFile="FV/FVRECOVERY_a.inf",
                      BlockSize=None,
                      CapFlag=None,
                      CapGUid=None, CapHeadSize=None,
                      CapOEMFlag=None,
                      FfsFile=None,
                      FileTakeSize=None, ForceRebase=None,
                      FvNameGuid=None,
                      Guid=None, InFileName='FV/FVRECOVERY_i.inf',
                      Map=None,
                      NumberBlock=None,
                      OutFileName='FV/FVRECOVERY_test.FV',
                      capsule=False,
                      debug=None, dump=False, quiet=False,
                      verbose=False,
                      version=False),
            Namespace(Address=None,
                      AddressFile="",
                      BlockSize=None,
                      CapFlag=None,
                      CapGUid=None, CapHeadSize=None,
                      CapOEMFlag=None,
                      FfsFile=None,
                      FileTakeSize=None, ForceRebase=None,
                      FvNameGuid=None,
                      Guid=None, InFileName='FV/ACM_FV.inf',
                      Map=None,
                      NumberBlock=None,
                      OutFileName='FV/ACM_FV_test.FV',
                      capsule=False,
                      debug=None, dump=False, quiet=False,
                      verbose=False,
                      version=False),

        ]
        Output = [
            [0x580000, 0x27BA60, 0x3045a0],
            [0x80000, 0x40090, 0x3ff70],
        ]

        for index in range(len(InfFiles)):
            # Create Fv object
            FvObject = GenerateFvFile(InfFiles[index])
            # Parse Options
            FvObject.ParseMyOptions()
            # parse Inf file
            FvObject.ParseFvInf()
            if FvObject.FvDataInfo.FvFileSystemGuid.__cmp__(
                mEfiFirmwareFileSystem2Guid) or FvObject.FvDataInfo.FvFileSystemGuid.__cmp__(
                mEfiFirmwareFileSystem3Guid):
                FvObject.FvDataInfo.IsPiFvImage = True
            # Calculate Fv size
            FvObject.CalculateFvSize()
            # Fv total size
            assert Output[index][0] == FvObject.FvTotalSize
            # Fv taken size
            assert Output[index][1] == FvObject.FvTakenSize
            # Fv space size
            assert Output[index][2] == FvObject.FvTotalSize - FvObject.FvTakenSize



    def test_ReadFfsAlignment(self):
        IntputFfs = [
            # r"FfsFile/BCAF98C9-22B0-3B4F-9CBD-C8A6B4DBCEE9EmuSec/BCAF98C9-22B0-3B4F-9CBD-C8A6B4DBCEE9.ffs"
            r'FfsFile/0A66E322-3740-4cce-AD62-BD172CECCA35.ffs',
            r'FfsFile/1A7E4468-2F55-4a56-903C-01265EB7622B.ffs',
            r'FfsFile/1B45CC0A-156A-428A-AF62-49864DA0E6E6FVRECOVERY.Ffs',
            r'FfsFile/9D225237-FA01-464C-A949-BAABC02D31D0.ffs',
            # r'FfsFile\BAC1001B-ECCC-40C6-990D-E8C19A8E477AFVBIN\BAC1001B-ECCC-40C6-990D-E8C19A8E477A.ffs',
            # r'FfsFile\517F51C5-E353-4556-9F65-C28472DD8C8CFVBIN\517F51C5-E353-4556-9F65-C28472DD8C8C.ffs',
            # r'FfsFile\F065674E-7C9E-44B9-8B5F-48A38177AD7FFVBIN\F065674E-7C9E-44B9-8B5F-48A38177AD7F.ffs',
            # r'FfsFile\A1F436EA-A127-4EF8-957C-8048606FF670FVBIN\A1F436EA-A127-4EF8-957C-8048606FF670.ffs',
            # r'FfsFile\02A6DE33-3EA9-4C17-8EA2-5681CC7AFDEDFVBIN\02A6DE33-3EA9-4C17-8EA2-5681CC7AFDED.ffs',
            # r'FfsFile\EFE92A04-F5D0-4E44-8757-25B3AFA3BFFFFVBIN\EFE92A04-F5D0-4E44-8757-25B3AFA3BFFF.ffs',
            # r'FfsFile\17BE8C65-84E8-4EBD-B2EE-3532B9FE502CFVBIN\17BE8C65-84E8-4EBD-B2EE-3532B9FE502C.ffs',
            # r'FfsFile\F79D1D66-1B16-43BD-A080-25086FC4B6ACFVBIN\F79D1D66-1B16-43BD-A080-25086FC4B6AC.ffs',
            # r'FfsFile\6001976E-449E-4397-AEDE-944F28CF6351FVBIN\6001976E-449E-4397-AEDE-944F28CF6351.ffs',
            # r'FfsFile\65776FCD-67CB-401A-96C5-B114EE1975E1FVBIN\65776FCD-67CB-401A-96C5-B114EE1975E1.ffs',
            # r'FfsFile\5DFC34D8-F7EE-4A11-A17D-05B51451DC8BFVBIN\5DFC34D8-F7EE-4A11-A17D-05B51451DC8B.ffs',
            # r'FfsFile\B51E4169-7E9F-47F4-8006-A65C6D51DC95FVBIN\B51E4169-7E9F-47F4-8006-A65C6D51DC95.ffs',
            # r'FfsFile\37662712-DF76-4C86-A9EB-78058E9EA9B4FVBIN\37662712-DF76-4C86-A9EB-78058E9EA9B4.ffs',
        ]
        OutAlignment = [
            0,
            0,
            0,
            12,
        ]
        for index in range(len(IntputFfs)):
            with open(IntputFfs[index], 'rb') as file:
                FfsBuffer = file.read()
            FfsHeader = GenerateFvFile.GetFfsHeader(FfsBuffer)
            alignment = GenerateFvFile.ReadFfsAlignment(FfsHeader)
            # print(alignment)
            assert OutAlignment[index] == alignment

    def test_GetCoreMachineType(self):
        PeFiles = [
            r"PeAndTeFiles/BCAF98C9-22B0-3B4F-9CBD-C8A6B4DBCEE9SEC1.1.pe32",
            r"PeAndTeFiles/0D244DF9-6CE3-4133-A1CF-53200AB663ACSEC2.1.te",
            r"FfsFile\0A66E322-3740-4cce-AD62-BD172CECCA35ScsiDisk\0A66E322-3740-4cce-AD62-BD172CECCA35SEC2.1.1.1.pe32",
            r"FfsFile/1A7E4468-2F55-4a56-903C-01265EB7622BTcpDxe/1A7E4468-2F55-4a56-903C-01265EB7622BSEC2.1.1.1.pe32",
            r"FfsFile/1FA1F39E-FEFF-4aae-BD7B-38A070A3B609PartitionDxe/1FA1F39E-FEFF-4aae-BD7B-38A070A3B609SEC2.1.1.1.pe32",
            r"FfsFile/1FA1F39E-FEFF-4aae-BD7B-38A070A3B609PartitionDxe/1FA1F39E-FEFF-4aae-BD7B-38A070A3B609SEC2.1.1.1.pe32",
        ]
        OuputMachines = [
            IMAGE_FILE_MACHINE_I386,
            IMAGE_FILE_MACHINE_I386,
            IMAGE_FILE_MACHINE_I386,
            IMAGE_FILE_MACHINE_I386,
            IMAGE_FILE_MACHINE_I386,
        ]
        for index in range(len(PeFiles)):
            with open(PeFiles[index], 'rb') as file:
                SectionImage = file.read()
            SectionHeader = GenerateFvFile.GetCommonSectionByBuffer(
                SectionImage)
            MachineType = self.GenFv.GetCoreMachineType(SectionImage,
                                                        SectionHeader)
            assert MachineType == OuputMachines[index]

    def test_FindCorePeSection(self):
        FvFiles = [
            "FV/FVRECOCERY1.FV",
        ]
        Pe32Section = [
            4116,
        ]
        for index in range(len(FvFiles)):
            with open(FvFiles[index], 'rb') as file:
                FvBuffer = file.read()
            SecPe32Off = self.GenFv.FindCorePeSection(FvBuffer, EFI_FV_FILETYPE_SECURITY_CORE)
            assert Pe32Section[index] == SecPe32Off


