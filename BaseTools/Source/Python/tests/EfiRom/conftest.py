import pytest
import tempfile
import os
from ctypes import *

import struct as st

from EfiRom.EfiStruct import *
from EfiRom.EfiRom import *
from EfiRom.FirmwareStorageFormat.Common import *



tmpdir = tempfile.mkdtemp()
pci23_binary_file = os.path.join(tmpdir, 'pci23_Binary.bin')
pci30_binary_file = os.path.join(tmpdir, 'pci30_Binary.bin')
pci23_check_hdr_signature_binary_file = os.path.join(tmpdir, 'pci23_hdr_sign_Binary.bin')
check_dos_header_magic_file = os.path.join(tmpdir, 'out.efi')
check_pe_header_signature_file = os.path.join(tmpdir, 'pe32.efi')
check_pe_option_header_magic = os.path.join(tmpdir, 'pe32_magic.efi')

# Auto call
@pytest.fixture(name="GenBin_and_Efi_file", autouse=True)
def GenSourceFiles():
    # Genarate binary file to check - Pci23
    with open(pci23_binary_file, "wb") as fout:
        Pci_Rom_Header = PCI_EXPANSION_ROM_HEADER()
        Pci_Rom_Header.Signature = 0xaa55
        Pci_Rom_Header.PcirOffset = sizeof(Pci_Rom_Header)
        # Write RomHeader to output file
        fout.write(struct2stream(Pci_Rom_Header))

        pci_data = PCI_DATA_STRUCTURE()
        pci_data.Signature = PCI_DATA_STRUCTURE_SIGNATURE
        pci_data.Length = sizeof(pci_data)
        pci_data.CodeType = 0x03
        pci_data.ImageLength = 5000

        fout.write(struct2stream(pci_data))

        fout.write(bytes(512*5))
    # Genarate binary file to check RomHeader signature - Pci23
    with open(pci23_check_hdr_signature_binary_file, "wb") as fout:
        Pci_Rom_Header = PCI_EXPANSION_ROM_HEADER()
        Pci_Rom_Header.Signature = 0xaa54
        Pci_Rom_Header.PcirOffset = sizeof(Pci_Rom_Header)
        # Write RomHeader to output file
        fout.write(struct2stream(Pci_Rom_Header))

        pci_data = PCI_DATA_STRUCTURE()
        pci_data.Signature = PCI_DATA_STRUCTURE_SIGNATURE
        pci_data.Length = sizeof(pci_data)
        pci_data.CodeType = 0x03
        pci_data.ImageLength = 5000

        fout.write(struct2stream(pci_data))

        fout.write(bytes(512*5))
    # Genarate binary file to check - Pci30
    with open(pci30_binary_file, "wb") as fout:
        Pci_Rom_Header = PCI_EXPANSION_ROM_HEADER()
        Pci_Rom_Header.Signature = 0xaa55
        Pci_Rom_Header.PcirOffset = sizeof(Pci_Rom_Header)
        # Write RomHeader to output file
        fout.write(struct2stream(Pci_Rom_Header))

        pci30_data = PCI_3_0_DATA_STRUCTURE()
        pci30_data.Signature = PCI_DATA_STRUCTURE_SIGNATURE
        pci30_data.Length = sizeof(pci30_data)
        pci30_data.CodeType = 0x03
        pci30_data.ImageLength = 5000

        fout.write(struct2stream(pci30_data))

        fout.write(bytes(512*5))

    # Generate an efi file to check the DosHeader magic
    with open(check_dos_header_magic_file, 'wb') as OutPtr:
        with open('DxeIpl.efi', 'rb') as InPtr:
            in_buffer = InPtr.read()
            DosHeader = EFI_IMAGE_DOS_HEADER.from_buffer_copy(in_buffer)
            # Change dos header magic number
            DosHeader.e_magic = 0x5A4C
            OutPtr.write(struct2stream(DosHeader))
            OutPtr.write(in_buffer[sizeof(DosHeader):])

    # Generate an efi file to check the PeHeader signature
    with open(check_pe_header_signature_file, 'wb') as OutPtr:
        with open('DxeIpl.efi', 'rb') as InPtr:
            in_buffer = InPtr.read()
            DosHeader = EFI_IMAGE_DOS_HEADER.from_buffer_copy(in_buffer)
            OutPtr.write(struct2stream(DosHeader))
            OutPtr.write(bytes(DosHeader.e_lfanew - sizeof(DosHeader)))

            PeHeader = EFI_IMAGE_OPTIONAL_HEADER_UNION.from_buffer_copy(in_buffer[DosHeader.e_lfanew:])
            PeHeader.Pe32.Signature = 17743
            OutPtr.write(struct2stream(PeHeader))
            OutPtr.write(in_buffer[(DosHeader.e_lfanew + sizeof(PeHeader)):])

    # Genarate an efi file to check the PeHdr.Pe32Plus.OptionalHeader.Magic
    with open(check_pe_option_header_magic, 'wb') as OutPtr:
        with open('DxeIpl.efi', 'rb') as InPtr:
            in_buffer = InPtr.read()
            DosHeader = EFI_IMAGE_DOS_HEADER.from_buffer_copy(in_buffer)
            OutPtr.write(struct2stream(DosHeader))
            OutPtr.write(bytes(DosHeader.e_lfanew - sizeof(DosHeader)))

            PeHeader = EFI_IMAGE_OPTIONAL_HEADER_UNION.from_buffer_copy(in_buffer[DosHeader.e_lfanew:])
            PeHeader.Pe32Plus.OptionalHeader.Magic = 523
            OutPtr.write(struct2stream(PeHeader))
            OutPtr.write(in_buffer[(DosHeader.e_lfanew + sizeof(PeHeader)):])





@pytest.fixture()
def create_bin_file_obj():
    bin_file_obj = FILE_LIST()
    bin_file_obj.FileFlags = FILE_FLAG_BINARY
    bin_file_obj.FileName = ''
    bin_file_obj.ClassCode = 0
    bin_file_obj.CodeRevision = 0

    return bin_file_obj

@pytest.fixture()
def create_efi_file_obj():
    bin_file_obj = FILE_LIST()
    bin_file_obj.FileFlags = FILE_FLAG_EFI
    bin_file_obj.FileName = ''
    bin_file_obj.ClassCode = 0
    bin_file_obj.CodeRevision = 0

    return bin_file_obj
