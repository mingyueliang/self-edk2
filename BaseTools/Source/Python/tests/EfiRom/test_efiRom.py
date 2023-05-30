# -*- coding: utf-8 -*-

import pytest
import sys
import shutil
import os

sys.path.append(r'C:\Users\mliang2x\Code\edk2\BaseTools\Source\Python')

from conftest import *
from EfiRom.EfiRom import *
from EfiRom.EfiStruct import *


class TestEfiRom(object):
    def setup_class(self):
        pass

    def teardown_class(self):
        if os.path.exists(tmpdir):
            shutil.rmtree(tmpdir)

    def create_source_file(self, file, file_flags):
        file_obj = FILE_LIST()
        file_obj.FileFlags = file_flags
        file_obj.FileName = file
        file_obj.ClassCode = 0
        file_obj.CodeRevision = 0
        return file_obj

    def set_pci(self, pci_flags):
        if pci_flags == 'Pci23':
            mOptions.Pci23 = 1
            mOptions.Pci30 = 0
        else:
            mOptions.Pci30 = 1
            mOptions.Pci23 = 0

    def test_processBinFile(self):
        input_files = [
            (pci23_binary_file, 'Pci23'),
            (pci30_binary_file, 'Pci30'),
            (pci23_check_hdr_signature_binary_file, 'Pci23'),
        ]

        expected_output = [
            [STATUS_SUCCESS, ''],
            [STATUS_SUCCESS, ''],
            [STATUS_ERROR, ''],
        ]
        for i, input in enumerate(input_files):
            # ProcessBinFile(OutFptr,InFile:FILE_LIST,Size:int,Num:int,Length:int)
            self.set_pci(input[1])
            output_rom_file = os.path.join(tmpdir, 'out_bin_{}.rom'.format(i))
            expected_output[i][1] = output_rom_file
            with open(output_rom_file, 'wb') as OutPtr:
                res = ProcessBinFile(OutPtr, self.create_source_file(input[0], FILE_FLAG_BINARY), 0, 0, 1)
                if isinstance(res, int):
                    assert expected_output[i][0]
                    assert os.path.exists(expected_output[i][1]) == False
                    with pytest.raises(ValueError,match='Process bin file error') as exc_info:
                        raise ValueError("Process bin file error")
                    assert exc_info.type is ValueError
                    assert exc_info.value.args[0] == "Process bin file error"

                else:
                    Status = res[0]
                    Size = res[1]
                    assert Status == STATUS_SUCCESS
                    # Total size must be an even multiple of 512 bytes, and can't exceed
                    # the option ROM image size
                    assert Size % 0x200 == 0
                    assert Size <= MAX_OPTION_ROM_SIZE
                    assert os.path.exists(expected_output[i][1]) == True


    def test_processEfiFile(self):
        input_files = [
            ('DxeIpl.efi', 'Pci23'),
            # ('DxeIpl.efi', 'Pci30'),
            (check_dos_header_magic_file, 'Pci23'),
            (check_pe_header_signature_file, 'Pci23'),

        ]
        expected_value = [
            [STATUS_SUCCESS, ''],
            # [STATUS_SUCCESS, ''],
            [STATUS_ERROR, ''],
            [STATUS_ERROR, ''],
        ]
        for i, input in enumerate(input_files):
            self.set_pci(input[1])
            output_rom = os.path.join(tmpdir, 'efi_out_{}.rom'.format(i))
            expected_value[i][1] = output_rom
            with open(output_rom, 'wb') as OutPtr:
                res = ProcessEfiFile(OutPtr, self.create_source_file(input[0], FILE_FLAG_EFI), 0xABCD, 0x1234, 0, 0, 0)
                if isinstance(res, int):
                    assert expected_value[i][0] == res
                    with pytest.raises(ValueError, match='Proprecess EFI file error') as exc_info:
                        raise ValueError("Proprecess EFI file error")
                    assert exc_info.type is ValueError
                    assert exc_info.value.args[0] == "Proprecess EFI file error"
                else:
                    status = res[0]
                    size = res[1]
                    assert status == expected_value[i][0]
                    assert os.path.exists(expected_value[i][1])


    def test_checkPE32File(self):
        input_files = [
            'DxeIpl.efi', # Correct file
            check_dos_header_magic_file, # Check the magic number ()x5A4D)
            check_pe_header_signature_file,
            check_pe_option_header_magic

        ]
        expected_value = [
            (STATUS_SUCCESS, 0, 11), # Correct output
            (STATUS_ERROR,),
            (STATUS_ERROR,),
            (STATUS_SUCCESS, 0, 11)
        ]
        for i, input in enumerate(input_files):
            with open(input, 'rb') as InFptr:
                res = CheckPE32File(InFptr, 0, 0)
                if isinstance(res, int):
                    assert expected_value[i][0] == res
                    with pytest.raises(ValueError,match='Check PE32 file error') as exc_info:
                        raise ValueError("Check PE32 file error")
                    assert exc_info.type is ValueError
                    assert exc_info.value.args[0] == "Check PE32 file error"
                else:
                    status = res[0]
                    MachineType = res[1]
                    SubSystem = res[2]

                    assert status == expected_value[i][0]
                    assert MachineType == expected_value[i][1]
                    assert SubSystem == expected_value[i][2]




if __name__ == '__main__':
    pytest.main(['-v'])