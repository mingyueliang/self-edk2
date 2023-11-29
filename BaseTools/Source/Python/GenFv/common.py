import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from FirmwareStorageFormat.Common import *
from FirmwareStorageFormat.FvHeader import *
from Common import EdkLogger
from Common.BuildToolError import *


def GetReverseCode(Sum: int):
    twoRes = bin(Sum)[2:]
    if len(twoRes) < 16:
        twoRes = '0' * (16 -len(twoRes)) + twoRes

    ReverseCode = '0b'
    for b in twoRes:
        if b == '1':
            ReverseCode += '0'
        else:
            ReverseCode += '1'
    return int(ReverseCode, 2)

def CalculateChecksum16(Buffer: bytes):
    Buffer += bytes(len(Buffer) % 2)
    Size = len(Buffer) // 2
    Sum = 0
    for i in range(Size):
        Sum =(Sum + int.from_bytes(Buffer[i*2:i*2+2], byteorder='little')) & 0xffff
    # # Add the high 16bits and the low 16bits
    # Sum  = (Sum >> 16) + (Sum & 0xffff)
    # # Get reverse code
    # CheckSum = GetReverseCode(Sum)
    return 0x10000 - Sum

def CheckSum16(Buffer: bytes):
    Buffer += bytes(len(Buffer) % 2)
    Size = len(Buffer) // 2
    Sum = 0
    for i in range(Size):
        Sum =(Sum + int.from_bytes(Buffer[i*2:i*2+2], byteorder='little')) & 0xffff
    return Sum

def CalculateChecksum8(Buffer:bytes):
    Sum = CalculateSum8(Buffer)
    # Get reverse code
    CheckSum = GetReverseCode(Sum)
    CheckSum += 1
    return CheckSum

def CalculateSum8(Buffer: bytes):
    Sum = 0
    for b in Buffer:
        Sum = (Sum + b) & 0xff
    return Sum

def PrintGuidToBuffer(Guid: GUID, UpperCase: False):
    if Guid == None:
        EdkLogger.error(None, PARAMETER_INVALID, "Invalid parameter, PrintGuidToBuffer() called with a NULL value")

    if UpperCase:
        FileGuidString = "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X" % (
            Guid.Guid1,
            Guid.Guid2,
            Guid.Guid3,
            Guid.Guid4[0],
            Guid.Guid4[1],
            Guid.Guid4[2],
            Guid.Guid4[3],
            Guid.Guid4[4],
            Guid.Guid4[5],
            Guid.Guid4[6],
            Guid.Guid4[7]
        )
    else:
        FileGuidString = "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" % (
            Guid.Guid1,
            Guid.Guid2,
            Guid.Guid3,
            Guid.Guid4[0],
            Guid.Guid4[1],
            Guid.Guid4[2],
            Guid.Guid4[3],
            Guid.Guid4[4],
            Guid.Guid4[5],
            Guid.Guid4[6],
            Guid.Guid4[7]
        )

    return FileGuidString



def AddBytesToBuffer(Buffer: bytes, Size):
    while len(Buffer) < Size:
        Buffer += bytes(1)

    return Buffer

if __name__ == '__main__':


    with open('FVRECOCERY.FV', 'rb') as file:
        Buff = file.read()
    FvHeader = Refine_FV_Header(2).from_buffer_copy(Buff)
    SavedCheckSum = FvHeader.Checksum
    FvHeader.Checksum = 0

    CheckSum = CalculateChecksum16(struct2stream(FvHeader))
    pass
