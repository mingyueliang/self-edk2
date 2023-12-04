from Common import EdkLogger
from GenFvs.common import GetReverseCode
from FirmwareStorageFormat.PeImageHeader import *

from ctypes import *

# C->BaseType.h
BIT11 = 0x00000800
BIT26 = 0x04000000


def ThumbMovwMovtImmediateAddress(Instructions, ImageBuffer):
    """
    Pass in a pointer to an ARM MOVW/MOVT instruction pair and
    return the immediate data encoded in the two` instruction
    :param Instructions: Pointer to ARM MOVW/MOVT instruction pair
    :return: Immediate address encoded in the instructions
    """
    Word = Instructions
    Top = Word + 2 * 2
    return ThumbMovtImmediateAddress(Top,
                                     ImageBuffer) << 16 + ThumbMovtImmediateAddress(
        Word, ImageBuffer)


def ThumbMovtImmediateAddress(Instruction, ImageBuffer):
    """
    Pass in a pointer to an ARM MOVT or MOVW immediate instruction and
    return the immediate data encoded in the instruction
    :param Instruction: Pointer to ARM MOVT or MOVW immediate instruction
    :return: Immediate address encoded in the instruction
    """
    Movt = (int.from_bytes(ImageBuffer[Instruction: Instruction + 2],
                           'little') << 16) | (
               int.from_bytes(ImageBuffer[Instruction + 2:Instruction + 4],
                              'little'))
    Address = (Movt & 0xff) & 0xffff
    Address |= ((Movt >> 4) & 0xf700) & 0xffff
    Address |= BIT11 if (Movt & BIT26 != 0) else 0
    return Address


def ThumbMovwMovtImmediatePatch(Instructions, Address, ImageBuffer):
    """
    Update an ARM MOVW/MOVT immediate instruction instruction pair.
    :param Instructions: Pointer to ARM MOVW/MOVT instruction pair
    :param Address:      New address to patch into the instructions
    :return:
    """
    Word = Instructions  # MOVW
    Top = Word + 2  # MOVT
    ImageBuffer = ThumbMovtImmediatePatch(Word, Address & 0xffff, ImageBuffer)
    ImageBuffer = ThumbMovtImmediatePatch(Top, Address >> 16, ImageBuffer)
    return Instructions, ImageBuffer


def ThumbMovtImmediatePatch(Instructions, Address, ImageBuffer):
    """
    Update an ARM MOVT or MOVW immediate instruction immediate data.
    :param Instructions:
    :param Address:
    :return:
    """
    # First 16-bit chunk of instruction
    Patch = (Address >> 12) & 0xf
    Patch |= BIT10 if (Address & BIT11) else 0
    ImageBuffer[Instructions:Instructions + 2] = ((int.from_bytes(
        ImageBuffer[Instructions:Instructions + 2],
        'little') & 0x70ff) | Patch).to_bytes(2, 'little')
    # Second 16-bit chunk of instruction
    Patch = Address & 0xff
    Patch |= (Address << 4) & 0x7000
    Instructions += 2
    ImageBuffer[Instructions:Instructions + 2] = ((int.from_bytes(
        ImageBuffer[Instructions:Instructions + 2],
        'little') & 0x70ff) | Patch).to_bytes(2, 'little')
    return ImageBuffer


def PeCoffLoaderRelocateIa32Image(Reloc, Fixup, FixupData, Adjust):
    """
    Performs an IA-32 specific relocation fixup
    """
    EdkLogger.warn("Unsupported now")
    return


def PeCoffLoaderRelocateArmImage(Reloc: int, Fixup: int, FixupData, Adjust: int,
                                 ImageBuffer: bytes):
    """
    Performs an ARM-based specific relocation fixup and is a no-op on other
    instruction sets.
    :param Reloc: Pointer to the relocation record.(c_uint16)
    :param Fixup: Pointer to the address to fix up.(c_uint8)
    :param FixupData: Pointer to a buffer to log the fixups.(c_uint8)
    :param Adjust: The offset to adjust the fixup.
    :return:
    """
    Fixup16 = Fixup & 0xFF
    if int.from_bytes(ImageBuffer[Reloc:Reloc + 2],
                      'little') >> 12 == EFI_IMAGE_REL_BASED_ARM_MOV32T:
        FixupVal = ThumbMovwMovtImmediateAddress(Fixup16,
                                                 ImageBuffer) + (Adjust & 0xffffffff)

        Fixup16, ImageBuffer = ThumbMovwMovtImmediatePatch(Fixup16, FixupVal,
                                                           ImageBuffer)
        if ImageBuffer[FixupData] != None:
            FixupData = ALIGN_POINTER(ImageBuffer[FixupData], sizeof(c_uint64))
            ImageBuffer[FixupData] = ImageBuffer[Fixup16]
            FixupData = FixupData + sizeof(c_uint64)


    elif ImageBuffer[Reloc] >> 12 == EFI_IMAGE_REL_BASED_ARM_MOV32A:
        pass
    else:
        EdkLogger.warn("Unspport")

    return Fixup, FixupData, ImageBuffer


# 4 byte
RiscVHi20Fixup = None


def PeCoffLoaderRelocateRiscVImage(Reloc, Fixup, FixupData, Adjust,
                                   ImageBuffer: bytearray):
    """
    Performs an RISC-V specific relocation fixup
    :param Reloc: Pointer to the relocation record
    :param Fixup: Pointer to the address to fix up
    :param FixupData: Pointer to a buffer to log the fixups
    :param Adjust: The offset to adjust the fixup
    :return:
    """
    global RiscVHi20Fixup
    RelocValue = int.from_bytes(ImageBuffer[Reloc:Reloc + 2], 'little')
    if RelocValue >> 12 == EFI_IMAGE_REL_BASED_RISCV_HI20:
        RiscVHi20Fixup = Fixup
    elif RelocValue >> 12 == EFI_IMAGE_REL_BASED_RISCV_LOW12I:
        if RiscVHi20Fixup != None:
            Value = RV_X(
                int.from_bytes(ImageBuffer[RiscVHi20Fixup:RiscVHi20Fixup + 4],
                               'little'), 12, 20) << 12
            Value2 = RV_X(
                int.from_bytes(ImageBuffer[Fixup:Fixup + 4], 'little'), 20, 12)
            if Value2 & (RISCV_IMM_REACH // 2):
                Value2 |= GetReverseCode(RISCV_IMM_REACH - 1)
            Value += Value2
            Value += (Adjust & 0xffffffff)
            Value2 = RISCV_CONST_HIGH_PART(Value)
            ImageBuffer[RiscVHi20Fixup:RiscVHi20Fixup + 4] = (
                    RV_X(Value2, 12, 20) | RV_X(
                    int.from_bytes(
                        ImageBuffer[RiscVHi20Fixup:RiscVHi20Fixup + 4],
                        'little'), 0, 12)).to_bytes(4, 'little')
            ImageBuffer[Fixup:Fixup + 4] = ((RV_X(Value2, 0, 12) << 20) | RV_X(
                int.from_bytes(ImageBuffer[Fixup:Fixup + 4], 'little'), 0,
                20)).to_bytes(4, 'little')
        RiscVHi20Fixup = None
    elif RelocValue >> 12 == EFI_IMAGE_REL_BASED_RISCV_LOW12S:
        if RiscVHi20Fixup != None:
            Value = RV_X(
                int.from_bytes(ImageBuffer[RiscVHi20Fixup:RiscVHi20Fixup + 4],
                               'little'), 12, 20)
            Value2 = RV_X(
                int.from_bytes(ImageBuffer[Fixup:Fixup + 4], 'little'), 7,
                5) | (
                         RV_X(int.from_bytes(ImageBuffer[Fixup:Fixup + 4],
                                             'little'), 25, 7) << 5)
            if Value2 & (RISCV_IMM_REACH // 2):
                Value2 |= GetReverseCode(RISCV_IMM_REACH - 1)
            Value += Value2
            Value += (Adjust & 0xffffffff)
            Value2 = RISCV_CONST_HIGH_PART(Value)
            ImageBuffer[RiscVHi20Fixup:RiscVHi20Fixup + 4] = (
                    (RV_X(Value2, 12, 20) << 12) | RV_X(
                    int.from_bytes(
                        ImageBuffer[RiscVHi20Fixup:RiscVHi20Fixup + 4],
                        'little'), 0, 12)).to_bytes(4, 'little')
            Value2 = int.from_bytes(ImageBuffer[Fixup:Fixup + 4],
                                    'little') & 0x01fff07f
            Value &= RISCV_IMM_REACH - 1
            ImageBuffer[Fixup:Fixup + 4] = (
                    Value2 | (RV_X(Value2, 0, 5) << 7) | (
                    RV_X(Value, 5, 7) << 25)).to_bytes(4, 'little')
            RiscVHi20Fixup = None
    else:
        return
    return Fixup, FixupData, ImageBuffer


def PeCoffLoaderRelocateLoongArch64Image(Reloc, Fixup, FixupData, Adjust,
                                         ImageBuffer):
    """
    Performs a LoongArch specific relocation fixup.
    :param Reloc:
    :param Fixup:
    :param FixupData:
    :param Adjust:
    :param ImageBuffer:
    :return:
    """
    RelocValue = int.from_bytes(ImageBuffer[Reloc:Reloc + 2], 'little')
    RelocType = RelocValue >> 12
    if RelocType == EFI_IMAGE_REL_BASED_LOONGARCH64_MARK_LA:
        Value = ((int.from_bytes(ImageBuffer[Fixup:Fixup + 4],
                                 'little') & 0x1ffffe0) << 7) | \
                (((int.from_bytes(ImageBuffer[Fixup:Fixup + 4],
                                  'little') + 1) & 0x3ffc00) >> 10)
        Tmp1 = (int.from_bytes(ImageBuffer[Fixup:Fixup + 4],
                               'little') + 2) & 0x1ffffe0
        Tmp2 = (int.from_bytes(ImageBuffer[Fixup:Fixup + 4],
                               'little') + 3) & 0x3ffc00
        Value = Value | (Tmp1 << 27) | (Tmp2 << 42)
        Value += Adjust

        ImageBuffer[Fixup:Fixup + 4] = ((int.from_bytes(
            ImageBuffer[Fixup:Fixup + 4], 'little') & GetReverseCode(0x1ffffe0)) \
                                        | (((
                                                    Value >> 12) & 0xfffff) << 5)).to_bytes(
            4, 'little')
        if FixupData != None:
            FixupData = ALIGN_POINTER(FixupData, sizeof(c_uint32))
            FixupData = FixupData + sizeof(c_uint32)

        Fixup += sizeof(c_uint32)
        ImageBuffer[Fixup:Fixup + 4] = ((int.from_bytes(
            ImageBuffer[Fixup:Fixup + 4], 'little') & GetReverseCode(
            0x3ffc00)) | (((Value >> 12) & 0xfffff) << 5)).to_bytes(4, 'little')

        if FixupData != None:
            FixupData = ALIGN_POINTER(FixupData, sizeof(c_uint32))
            FixupData = FixupData + sizeof(c_uint32)

        Fixup += sizeof(c_uint32)
        ImageBuffer[Fixup:Fixup + 4] = ((int.from_bytes(
            ImageBuffer[Fixup:Fixup + 4], 'little') & GetReverseCode(
            0x3ffc00)) | (((Value >> 52) & 0xfff) << 10)).to_bytes(4, 'little')
        if FixupData != None:
            FixupData = ALIGN_POINTER(FixupData, sizeof(c_uint32))
            FixupData = FixupData + sizeof(c_uint32)
    else:
        EdkLogger.errror(None, 0,
                         "PeCoffLoaderRelocateLoongArch64Image: Fixup[0x%x] Adjust[0x%x] *Reloc[0x%x], type[0x%x]." % (
                             int.from_bytes(ImageBuffer[Fixup:Fixup + 4],
                                            'little'),
                             Adjust,
                             int.from_bytes(ImageBuffer[Reloc:Reloc + 2],
                                            'little'),
                             RelocType))

    return Fixup, FixupData, ImageBuffer
