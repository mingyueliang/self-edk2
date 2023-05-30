# @file
#  Utility program to create an EFI option ROM image from binary and EFI PE32 files.
#
#  Copyright (c) 2021, Intel Corporation. All rights reserved.<BR>
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#
##


#Import modules
import os
import sys
import argparse
import logging
from EfiRom.EfiStruct import *
from EfiRom.EfiCompress import *
from EfiRom.ParseInf import *
from EfiRom.FirmwareStorageFormat.SectionHeader import *

STATUS_SUCCESS = 0
STATUS_ERROR = 2
FILE_FLAG_BINARY = 0x01
FILE_FLAG_EFI = 0x02
FILE_FLAG_COMPRESS = 0x04
DebugLevel = 0

UTILITY_NAME = "EfiRom"
UTILITY_MAJOR_VERSION = 0
UTILITY_MINOR_VERSION = 1
mOptions = OPTIONS()

parser = argparse.ArgumentParser(description='''
Utility program to create an EFI option ROM image from binary and EFI PE32 files.
''')
parser.add_argument("input",help = "Input Filename.")  #似乎不需要单独列出来输入的文件
parser.add_argument("-o","--output",dest ="outputfile",help = "Output Filename.File will be created to store the output content.")
parser.add_argument("-e",dest = "EfiFileName",help = "EFI PE32 image files.")
parser.add_argument("-ec",dest = "EfiFileName_Compress",help = "EFI PE32 image files and will be compressed.")
parser.add_argument("-b",dest = "BinFileName",help = "Legacy binary files.")
parser.add_argument("-l",dest = "ClassCode",help = "Hex ClassCode in the PCI data structure header.")
parser.add_argument("-r",dest = "Rev",help = "Hex Revision in the PCI data structure header.")
parser.add_argument("-n",dest = "not_auto",help = "Not to automatically set the LAST bit in the last file.")
parser.add_argument("-f",dest = "VendorId",help = "Hex PCI Vendor ID for the device OpROM, must be specified")
parser.add_argument("-i",dest = "DeviceId",nargs = '+',help = "One or more hex PCI Device IDs for the device OpROM, must be specified")
parser.add_argument("-p","--pci23",dest = "pci_layout",help = " Default layout meets PCI 3.0 specifications,specifying this flag will for a PCI 2.3 layout.")
parser.add_argument("-d","--dump",dest = "dumpimage",help = "Dump the headers of an existing option ROM image.")
parser.add_argument("-v","--verbose",dest="verbose",help="Turn on verbose output with informational messages.")
parser.add_argument("-q","--quiet",dest="quiet",help="Disable all messages except key message and fatal error")
parser.add_argument("--debug",dest="debug_level",help="Enable debug messages, at input debug level.")
parser.add_argument("--version", action="version", version='%s Version %d.%d' %(UTILITY_NAME,UTILITY_MAJOR_VERSION,UTILITY_MINOR_VERSION),
                    help="Show program's version number and exit.")

logger=logging.getLogger('EfiRom')


#Process a binary input file
def ProcessBinFile(OutFptr,InFile:FILE_LIST,Size:int,Num:int,Length:int) -> int:
    
    Status = STATUS_SUCCESS
    #Try to open the input file
    with open(InFile.FileName,"rb") as InFptr:
        if InFptr == None:
            logger.error("Error opening file : %s" %InFile.FileName)
            return STATUS_ERROR
        Data = InFptr.read()
        FileSize = len(Data)
    Buffer = Data
    if len(Buffer) == 0:
        logger.error("Invalid, Failed to read all bytes from input file.")
        return STATUS_ERROR
    
    #Total size must be an even multiple of 512 bytes, and can't exceed
    #the option ROM image size.
    TotalSize = FileSize
    if TotalSize & 0x1FF:
        TotalSize = (TotalSize + 0x200) &~0x1ff
        
    if TotalSize > MAX_OPTION_ROM_SIZE:
        logger.error("Invalid parameter, Option ROM image size exceeds limit of 0x%X bytes.",MAX_OPTION_ROM_SIZE)
        return STATUS_ERROR
    
    #Return the size to the caller so they can keep track of the running total.
    Size = TotalSize
    
    #Crude check to make sure it's a legitimate ROM image
    RomHdr = PCI_EXPANSION_ROM_HEADER.from_buffer_copy(Buffer[0:sizeof(PCI_EXPANSION_ROM_HEADER)])
    if RomHdr.Signature != PCI_EXPANSION_ROM_HEADER_SIGNATURE:
        logger.error("Invalid parameter, ROM image file has an invalid ROM signature.")
        return STATUS_ERROR
    
    #Make sure the pointer to the PCI data structure is within the size of the image.
    #Then check it for valid signature
    if RomHdr.PcirOffset > FileSize or RomHdr.PcirOffset == 0:
        logger.error("Invalid parameter, Invalid PCI data structure offset.")
        return STATUS_ERROR
    
    #Check the header is conform to PCI2.3 or PCI3.0
    if mOptions.Pci23 == 1:
        PciDs23 = PCI_DATA_STRUCTURE.from_buffer_copy(Buffer[RomHdr.PcirOffset:])
        if PciDs23.Signature != PCI_DATA_STRUCTURE_SIGNATURE:
            logger.error("Invalid parameter, PCI data structure has an invalid signature.")
            return STATUS_ERROR
    else:
        #Default setting is PCI3.0 header
        PciDs30 = PCI_3_0_DATA_STRUCTURE.from_buffer_copy(Buffer[RomHdr.PcirOffset:])
        if PciDs30.Signature != PCI_DATA_STRUCTURE_SIGNATURE:
            logger.error("Invalid parameter, PCI data structure has an invalid signature.")
            return STATUS_ERROR
    
    #ReSet Option Rom size
    if mOptions.Pci23 == 1:
        PciDs23.ImageLength = c_uint16(int(TotalSize / 512))
        CodeType = PciDs23.CodeType
    else:
        PciDs23.ImageLength = c_uint16(int(TotalSize / 512))
        CodeType = PciDs30.CodeType
        
    #If this is the last image, then set the LAST bit unless requested not
    #to via the command-line -n argument. Otherwise, make sure you clear it.
    if Num == Length - 1 and mOptions.NoLast == 0:
        if mOptions.Pci23 == 1:
            PciDs23.Indicator = INDICATOR_LAST
        else:
            PciDs30.Indicator = INDICATOR_LAST
    else:
        if mOptions.Pci23 == 1:
            PciDs23.Indicator = 0
        else:
            PciDs30.Indicator = 0
            
    if CodeType != PCI_CODE_TYPE_EFI_IMAGE:
        ByteCheckSum = 0
        for Index in range(FileSize - 1):
            ByteCheckSum = ByteCheckSum + Buffer[Index]
        Temp = ~ByteCheckSum + 1
        #Buffer = Buffer.replace(Buffer[FileSize - 1] , Temp.to_bytes(1,byteorder= 'little'))
        Buffer = Buffer.replace(Buffer[FileSize - 1: FileSize] , Temp.to_bytes(1,byteorder= 'little'))
        
    #Now copy the input file contents out to the output file
    OutFptr.write(Buffer)
    if OutFptr == None:
        logger.error("Failed to write all file bytes to output file.")
        return STATUS_ERROR
    
    TotalSize -= FileSize
    #Pad the rest of the image to make it a multiple of 512 bytes
    while TotalSize > 0:
        # putc (~0, OutFptr)
        a = ~0
        OutFptr.write(a.to_bytes(1,byteorder= 'little',signed=True))
        TotalSize -= 1
    return Status,Size


#Process a PE32 EFI file.
def ProcessEfiFile(OutFptr,InFile:FILE_LIST,VendId:c_uint16,DevId:c_uint16,Size:c_uint32,Num:int,Length:int):

    Status = STATUS_SUCCESS
    MachineType = 0
    SubSystem = 0
    RomHdr = EFI_PCI_EXPANSION_ROM_HEADER()
    PciDs23 = PCI_DATA_STRUCTURE()
    PciDs30 = PCI_3_0_DATA_STRUCTURE()
    
    #Try to open the input file
    with open(InFile.FileName,"rb") as InFptr:
        if InFptr == None:
            logger.error("Error opening file : %s" %InFile.FileName)
            return STATUS_ERROR

        #Double-check the file to make sure it's what we expect it to be.
        res = CheckPE32File(InFptr, MachineType, SubSystem)
        if type(res) == 'int':
            Status = res
        else:
            Status = res[0]
            MachineType = res[1]
            SubSystem = res[2]
        
        if Status != STATUS_SUCCESS:
            logger.error("Error parsing, Error parsing file: %s" %InFile.FileName)
            return Status
        #Seek to the end of the input file and get the file size
        # The read function is used in function CheckPE32File, and the file pointer
        # points to the end. The file pointer needs to be readjusted
        InFptr.seek(0,0)
        Data = InFptr.read()
        FileSize = len(Data)

    #Get the size of the headers we're going to put in front of the image. The
    #EFI header must be aligned on a 4-byte boundary, so pad accordingly.
    if sizeof(RomHdr) & 0x03:
        HeaderPadBytes = 4 - (sizeof (RomHdr) & 0x03)
    else:
        HeaderPadBytes = 0
        
    #For Pci3.0 to use the different data structure.
    if mOptions.Pci23 == 1:
        HeaderSize = sizeof (PCI_DATA_STRUCTURE) + HeaderPadBytes + sizeof (EFI_PCI_EXPANSION_ROM_HEADER)
    else:
        if mOptions.DevIdCount > 1:
            #Write device ID list when more than one device ID is specified.
            #Leave space for list plus terminator.
            DevIdListSize = (mOptions.DevIdCount + 1) * sizeof (c_uint16)
        else:
            DevIdListSize = 0
        HeaderSize = sizeof (PCI_3_0_DATA_STRUCTURE) + HeaderPadBytes + DevIdListSize + sizeof (EFI_PCI_EXPANSION_ROM_HEADER)
    
    Buffer = Data
    if len(Buffer) == 0:
        logger.error( "Error reading file, File %s" %InFile.FileName)
    
    if InFile.FileFlags & FILE_FLAG_COMPRESS != 0:
        CompressedBuffer = b''
        CompressedFileSize = FileSize
        res = EfiCompress(FileSize, CompressedFileSize,Buffer,CompressedBuffer)
        if type(res) == 'int':
            Status = res
        else:
            Status = res[0]
            CompressedBuffer = res[1]
            CompressedFileSize =res[2]
            
        if Status != STATUS_SUCCESS:
            logger.error("Error compressing file!")
            return Status
        
        #Now compute the size ,then swap buffer pointers.
        TotalSize         = CompressedFileSize + HeaderSize
        FileSize          = CompressedFileSize
        TempBufferPtr     = Buffer
        Buffer            = CompressedBuffer
        CompressedBuffer  = TempBufferPtr
    else:
        TotalSize = FileSize + HeaderSize
        
    #Total size must be an even multiple of 512 bytes
    if TotalSize & 0x1FF:
        TotalSize = (TotalSize + 0x200) &~0x1ff
    
    #If compressed, put the pad bytes after the image,
    #else put the pad bytes before the image.
    if InFile.FileFlags & FILE_FLAG_COMPRESS != 0:
        PadBytesBeforeImage = 0
        PadBytesAfterImage = TotalSize - (FileSize + HeaderSize)
    else:
        PadBytesBeforeImage = TotalSize - (FileSize + HeaderSize)
        PadBytesAfterImage = 0
        
    #Check size
    if TotalSize > MAX_OPTION_ROM_SIZE:
        logger.error("Invalid, Option ROM image %s size exceeds limit of 0x%x bytes." %InFile.FileName %MAX_OPTION_ROM_SIZE)
        Status = STATUS_ERROR
        return Status
    
    #Return the size to the caller so they can keep track of the running total.
    Size = TotalSize
    
    #Now fill in the ROM header. These values come from chapter 18 of the
    #EFI 1.02 specification.
    RomHdr.Signature            = PCI_EXPANSION_ROM_HEADER_SIGNATURE
    RomHdr.InitializationSize   = c_uint16(TotalSize // 512)
    RomHdr.EfiSignature         = EFI_PCI_EXPANSION_ROM_HEADER_EFISIGNATURE
    RomHdr.EfiSubsystem         = SubSystem
    RomHdr.EfiMachineType       = MachineType
    RomHdr.EfiImageHeaderOffset = HeaderSize + PadBytesBeforeImage
    RomHdr.PcirOffset           = sizeof (RomHdr) + HeaderPadBytes
    
    #Set image as compressed or not
    if InFile.FileFlags & FILE_FLAG_COMPRESS:
        RomHdr.CompressionType = EFI_PCI_EXPANSION_ROM_HEADER_COMPRESSED
    
    #Fill in the PCI data structure
    if mOptions.Pci23 == 1:
        PciDs23.Signature = PCI_DATA_STRUCTURE_SIGNATURE
        PciDs23.VendorId  = VendId
        PciDs23.DeviceId  = DevId
        PciDs23.Length    = sizeof (PCI_DATA_STRUCTURE)
        PciDs23.Revision  = 0
        
        PciDs23.ClassCode[0]  = InFile.ClassCode
        PciDs23.ClassCode[1]  = InFile.ClassCode >> 8
        PciDs23.ClassCode[2]  = InFile.ClassCode >> 16
        PciDs23.ImageLength   = RomHdr.InitializationSize
        PciDs23.CodeRevision  = InFile.CodeRevision
        PciDs23.CodeType      = PCI_CODE_TYPE_EFI_IMAGE
    else:
        PciDs30.Signature = PCI_DATA_STRUCTURE_SIGNATURE
        PciDs30.VendorId  = VendId
        PciDs30.DeviceId  = DevId
        if mOptions.DevIdCount > 1:
            #Place device list immediately after PCI structure
            PciDs30.DeviceListOffset = sizeof (PCI_3_0_DATA_STRUCTURE)
        else:
            PciDs30.DeviceListOffset = 0
        PciDs30.Length    = sizeof (PCI_3_0_DATA_STRUCTURE)
        PciDs30.Revision  = 0x3
        
        #Class code and code revision from the command line (optional)
        PciDs30.ClassCode[0]  = InFile.ClassCode
        PciDs30.ClassCode[1]  = InFile.from_addressClassCode >> 8
        PciDs30.ClassCode[2]  = InFile.ClassCode >> 16
        PciDs30.ImageLength   = RomHdr.InitializationSize
        PciDs30.CodeRevision  = InFile.CodeRevision
        PciDs30.CodeType      = PCI_CODE_TYPE_EFI_IMAGE
        PciDs30.MaxRuntimeImageLength = 0; #to be fixed
        PciDs30.ConfigUtilityCodeHeaderOffset = 0; # to be fixed
        PciDs30.DMTFCLPEntryPointOffset = 0; # to be fixed
        
    #If this is the last image, then set the LAST bit unless requested not
    #to via the command-line -n argument.
    if Num == Length - 1 and mOptions.NoLast == 0:
        if mOptions.Pci23 == 1:
            PciDs23.Indicator = INDICATOR_LAST
        else:
            PciDs30.Indicator = INDICATOR_LAST
    else:
        if mOptions.Pci23 == 1:
            PciDs23.Indicator = 0
        else:
            PciDs30.Indicator = 0
    
    #Write the ROM header to the output file
    OutFptr.write(struct2stream(RomHdr))
    if len(struct2stream(RomHdr)) == 0:
        logger.error("Failed to write ROM header to output file!")
        Status = STATUS_ERROR
        return Status
    
    #Write pad bytes to align the PciDs
    while HeaderPadBytes > 0:
        OutFptr.write(b'\0')
        if OutFptr.tell() == os.SEEK_END:
            logger.error("Failed to write PCI ROM header to output file!")
            Status = STATUS_ERROR
            return Status
        HeaderPadBytes -= 1
    
    #Write the PCI data structure header to the output file
    if mOptions.Pci23 == 1:
        OutFptr.write(struct2stream(PciDs23))
        if len(struct2stream(PciDs23)) == 0:
            logger.error("Failed to write PCI ROM header to output file!")
            Status = STATUS_ERROR
            return Status
    else:
        OutFptr.write(struct2stream(PciDs30))
        if len(struct2stream(PciDs30)) == 0:
            logger.error("Failed to write PCI ROM header to output file!")
            Status = STATUS_ERROR
            return Status
    
    #Write the Device ID list to the output file
    if mOptions.DevIdCount > 1:
        for item in mOptions.DevIdList[0:mOptions.DevIdCount]:
            OutFptr.write(item.to_bytes(2,byteorder='little'))
        if OutFptr.read() == None:
            logger.error("Failed to write PCI ROM header to output file!")
            Status = STATUS_ERROR
            return Status
        
        #Write two-byte terminating 0 at the end of the device list
        OutFptr.write(b'\0')
        OutFptr.write(b'\0')
        if OutFptr.tell() == os.SEEK_END:
            logger.error("Failed to write PCI ROM header to output file!")
            Status = STATUS_ERROR
            return Status
        
    #Pad head to make it a multiple of 512 bytes
    while PadBytesBeforeImage > 0:
        a = -1
        OutFptr.write(a.to_bytes(1,byteorder='little',signed = True))
        if OutFptr.tell() == os.SEEK_END:
            logger.error("Failed to write trailing pad bytes output file!")
            Status = STATUS_ERROR
            return Status
        PadBytesBeforeImage -= 1
        
    #Now dump the input file's contents to the output file
    OutFptr.write(Buffer)
    if len(Buffer) == 0:
        logger.error("Failed to write all file bytes to output file!")
        Status = STATUS_ERROR
        return Status
    
    #Pad the rest of the image to make it a multiple of 512 bytes
    while PadBytesAfterImage > 0:
        b = -1
        OutFptr.write(b.to_bytes(1,byteorder='little',signed = True))
        if OutFptr.tell() == os.SEEK_END:
            logger.error("Failed to write trailing pad bytes output file!")
            Status = STATUS_ERROR
            return Status
        PadBytesAfterImage -= 1
         
    return Status,Size


#Given a file pointer to a supposed PE32 image file, verify that it is indeed a
#PE32 image file, and then return the machine type in the supplied pointer.
def CheckPE32File(Fptr,MachineType:c_uint16,SubSystem:c_uint16):
    
    #Read the DOS header
    Data = Fptr.read()
    DosHeader = EFI_IMAGE_DOS_HEADER.from_buffer_copy(Data)
    if sizeof(DosHeader) == 0:
        logger.error("Failed to read the DOS stub from the input file!")
        Status = STATUS_ERROR
        return Status
    
    #Check the magic number (0x5A4D)
    if DosHeader.e_magic != EFI_IMAGE_DOS_SIGNATURE:
        logger.error("Failed to read the DOS stub from the input file!")
        Status = STATUS_ERROR
        return Status
    
    #Read PE headers
    PeHdr = EFI_IMAGE_OPTIONAL_HEADER_UNION.from_buffer_copy(Data[DosHeader.e_lfanew:])
    if sizeof(PeHdr) == 0:
        logger.error("Failed to read PE/COFF headers from input file!")
        Status = STATUS_ERROR
        return Status
    
    #Check the PE signature in the header "PE\0\0"
    if PeHdr.Pe32.Signature != EFI_IMAGE_NT_SIGNATURE:
        logger.error("Invalid parameter, Input file does not appear to be a PE32 image (signature)!")
        Status = STATUS_ERROR
        return Status

    if PeHdr.Pe32.OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        SubSystem = PeHdr.Pe32.OptionalHeader.Subsystem
    elif PeHdr.Pe32Plus.OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        SubSystem = PeHdr.Pe32Plus.OptionalHeader.Subsystem
    else:
        logger.error("Failed to read PE/COFF headers from input file!")
        Status = STATUS_ERROR
        return Status
    
    #File was successfully identified as a PE32
    Status = STATUS_SUCCESS
    return Status,MachineType,SubSystem


#Status processing,no need this function
def Done(ReturnStatus:int):
    return ReturnStatus


def BailOut(Status:int,if_error:bool):
    # if Status == STATUS_SUCCESS:
    #     #Clean up file list
    #     while mOptions.FileList != None:
    #         FList = mOptions.FileList.Next
    #         mOptions.FileList = FList

    if if_error:
        Status = STATUS_ERROR
    return Status
    

#Parse the command-line options and check their validity.
#This is the specific command line parsing function
def ParseCommandLine(Options:OPTIONS,FileLists=[]):
    FileList = FILE_LIST()
    # PrevFileList = FILE_LIST()
    #FileList = []
    
    ReturnStatus = 0
    FileFlags = 0
    EfiRomFlag = False
    # FileList = PrevFileList = None
    Options.DevIdCount = 0
    ClassCode = 0
    CodeRevision = 0
    TempValue = 0
    
    args = parser.parse_args()
    argc = len(sys.argv)
    
    if argc == 1 or 0:
        parser.print_help()
        logger.error("Missing options")
        return STATUS_ERROR
    
    #Start to parse command line arguments
    #First parse the optional arguments
    if args.VendorId:
        #Make sure there's another parameter
        res = AsciiStringToUint64(args.VendorId,False,TempValue)
        if type(res) == 'int':
            Status = res
        else:
            Status = res[0]
            TempValue = res[1]
            
        if EFI_ERROR (Status):
            logger.error("Invalid option value.")
            ReturnStatus = 1
            Done(ReturnStatus)
        if TempValue >= 0x10000:
            logger.error("Invalid option value, Vendor Id %s out of range!" %args.VendorId)
            ReturnStatus = 1
            Done(ReturnStatus)
            
        Options.VendId = TempValue
        Options.VendIdValid = 1
        
    if args.DeviceId:
        OptionName = '-i'
        #Device IDs specified with -i
        #Make sure there's at least one more parameter
        if argc == 1:
            ReturnStatus = 1
            Done(ReturnStatus)
            
        #Process until another dash-argument parameter or the end of the list
        #Because -i maybe have one or more arguments
        for arg in args.DeviceId:
            res = AsciiStringToUint64(arg, False, TempValue)
            if type(int) == 'int':
                Status = res
            else:
                Status = res[0]
                TempValue = res[1]
            if EFI_ERROR (Status):
                logger.error("Invalid option value, %s = %s" %(OptionName,arg))
                ReturnStatus = 1
                Done(ReturnStatus)
            #Dont allow deveice IDs greater than 16 bits
            #Dont allow 0,since it is used as a list terminator
            if TempValue >= 0x10000 or TempValue == 0:
                logger.error("Invalid option value, Device Id %s out of range!" %arg)
                ReturnStatus = 1
                Done(ReturnStatus)
            
            Options.DevIdList[Options.DevIdCount] = TempValue
            Options.DevIdCount += 1
            
    if args.outputfile:
        #Output filename specified with -o
        #Make sure there's another parameter
        if args.outputfile == None or args.outputfile[0] == '-':
            logger.error("Invalid parameter, Missing output file name with %s option!" %'-o')
            ReturnStatus = 1
            Done(ReturnStatus)
            
        if len(args.outputfile) >= MAX_PATH - 1:
            logger.error("Invalid parameter, Output file name %s is too long!" %args.outputfile)
            ReturnStatus = 1
            Done(ReturnStatus) 
        Options.OutFileName = args.outputfile[0: MAX_PATH - 1]
            
    if args.BinFileName:
        if args.BinFileName == None:
            logger.error("Missing Binary files!")
            ReturnStatus = STATUS_ERROR
            Done(ReturnStatus)
        # FileList = FILE_LIST()
        FileFlags = FILE_FLAG_BINARY
        
        FileList.FileName = args.BinFileName
        FileList.FileFlags     = FileFlags
        FileList.ClassCode     = ClassCode
        FileList.CodeRevision  = CodeRevision
        ClassCode               = 0
        CodeRevision            = 0
        #Options.FileList = FileList
        FileLists.append(FileList)

    if args.EfiFileName or args.EfiFileName_Compress:
        if args.BinFileName == None:
            logger.error("Missing Binary files!")
            ReturnStatus = STATUS_ERROR
            Done(ReturnStatus)
        
        #Specify EFI files with -e. Specify EFI-compressed with -c.
        FileFlags = FILE_FLAG_EFI
        if args.EfiFileName_Compress:
            FileFlags |= FILE_FLAG_COMPRESS
            
        FileList.FileName = args.EfiFileName
        FileList.FileFlags     = FileFlags
        FileList.ClassCode     = ClassCode
        FileList.CodeRevision  = CodeRevision
        ClassCode               = 0
        CodeRevision            = 0
        #Options.FileList = FileList
        FileLists.append(FileList)
        EfiRomFlag = True
    
        if EfiRomFlag:
            if Options.VendIdValid == None:
                logger.error("Missing Vendor ID in command line")
                ReturnStatus = STATUS_ERROR
                Done(ReturnStatus)
            
            if Options.DevIdCount == None:
                logger.error("Missing Device ID in command line")
                ReturnStatus = STATUS_ERROR
                Done(ReturnStatus)
        
        if Options.DevIdCount > 1 and Options.Pci23:
            logger.error("Invalid parameter, PCI 3.0 is required when specifying multiple Device IDs")
            ReturnStatus = STATUS_ERROR
            Done(ReturnStatus)
        
        
    #Specify not to set the LAST bit in the last file with -n
    if args.not_auto:
        Options.NoLast = 1
    
    #-v for verbose
    if args.verbose:
        Options.verbose = 1
    
    if args.debug_level:
        res = AsciiStringToUint64(args.debug_leve, False, DebugLevel)
        if type(res) == 'int':
            Status = res
        else:
            Status = res[0]
            DebugLevel = res[1]
        if EFI_ERROR(Status):
            logger.error("Invalid option value, %s = %s" %('--debug',args.debug_level))
            ReturnStatus = 1
            Done(ReturnStatus)        
        if DebugLevel > 9:
            logger.error("Invalid option value,Debug Level range is 0-9, current input level is %d" %args.debug_level)
            ReturnStatus = 1
            Done(ReturnStatus)
        if DebugLevel >= 5 and DebugLevel <= 9:
            Options.Debug = True
        else:
            Options.Debug = False
        
    if args.quiet:
        Options.Quiet = True
    
    if args.dumpimage:
        #-dump for dumping a ROM image. In this case, say that the device id
        #and vendor id are valid so we don't have to specify bogus ones on the
        #command line.
        Options.DumpOption   = 1
        Options.VendIdValid  = 1
        Options.DevIdCount   = 1
        FileFlags = FILE_FLAG_BINARY
        
    if args.ClassCode:
        #Class code value for the next file in the list.
        #Make sure there's another parameter
        res = AsciiStringToUint64(args.ClassCode, False, TempValue)
        if type(res) == 'int':
            Status = res
        else:
            Status = res[0]
            TempValue = res[1]
        if EFI_ERROR(Status):
            logger.error("Invalid option value", "%s = %s" %('--class-code',args.ClassCode))
            ReturnStatus = 1
            Done(ReturnStatus)
            
        ClassCode = TempValue
        if ClassCode & 0xFF000000:
            logger.error("Invalid parameter", "Class code %s out of range!" %args.ClassCod)
            ReturnStatus = STATUS_ERROR
            Done(ReturnStatus)
        if FileList != None and FileList.ClassCode == 0:
            FileList.ClassCode = ClassCode
            
    if args.Rev:
        #Code revision in the PCI data structure. The value is for the next
        #file in the list.
        #Make sure there's another parameter
        res = AsciiStringToUint64(args.Rev,False,TempValue)
        if type(res) == 'int':
            Status = res
        else:
            Status =res[0]
            TempValue = res[1]
        
        if EFI_ERROR(Status):
            logger.error("Invalid option value", "%s = %s" %('--Revision',args.Rev))
            ReturnStatus = 1
            Done(ReturnStatus)
            
        CodeRevision = TempValue
        if CodeRevision & 0xFFFF0000:
            logger.error("Invalid parameter", "Code revision %s out of range!" %args.Rev)
            ReturnStatus = 1
            Done(ReturnStatus)
            
        if FileList != None and FileList.CodeRevision == 0:
            FileList.CodeRevision = CodeRevision
    
    if args.pci_layout:
        #Default layout meets PCI 3.0 specifications, specifying this flag will for a PCI 2.3 layout.
        mOptions.Pci23 = 1
    
    else:#No arguments to be parsed, maybe should be put at the end of the parsing part
        logger.error("Invalid parameter", "Invalid option specified: %s" %sys.argv[0])
        ReturnStatus = STATUS_ERROR
        Done(ReturnStatus)
    
    #Must have specified some files
    if Options.FileList == None:
        logger.error("Invalid parameter, Missing input file name!")
        #No memory allocation,return directly
        return STATUS_ERROR
    
    #For EFI OptionRom image, Make sure a device ID and Vendoe ID are both specified
    if EfiRomFlag:
        if Options.VendIdValid == 0:
            logger.error("Missing Vendor ID in command line")
            ReturnStatus = STATUS_ERROR
            Done(ReturnStatus)
            
        if Options.DevIdCount == 0:
            logger.error("Missing Device ID in command line")
            ReturnStatus = STATUS_ERROR
            Done(ReturnStatus)
        
    if Options.DevIdCount > 1 and Options.Pci23:
        logger.error("Invalid parameter, PCI 3.0 is required when specifying multiple Device IDs")
        ReturnStatus = STATUS_ERROR
        Done(ReturnStatus)



#GC_TODO: Add function description
def GetMachineTypeStr(MachineType:str) -> str:
    Index = 0
    while mMachineTypes[Index].Name != None:
        if mMachineTypes[Index].Value == MachineType:
            return mMachineTypes[Index].Name
        Index += 1
    
    return "unknown"


#GC_TODO: Add function description
def GetSubsystemTypeStr(SubsystemType) -> str:
    Index = 0
    while mSubsystemTypes[Index].Name != None:
        if mSubsystemTypes[Index].Value == SubsystemType:
            return mSubsystemTypes[Index].Name
        Index += 1
    
    return "unknown"

#Dump the headers of an existing option ROM image
def DumpImage(InFile:FILE_LIST):
    
    DevId = 0
    
    #Open the input file
    InFptr = open(InFile.FileName)
    Data = InFptr.read()
    if len(Data) == 0:
        logger.error("Error opening file")
        return
        
        
    #Go through the image and dump the header stuff for each
    ImageCount = 0
    while True:
        #Save our position in the file, since offsets in the headers
        #are relative to the particular image.
        ImageStart = InFptr.tell()
        ImageCount += 1
        
        #Read the option ROM header. Have to assume a raw binary image for now.
        PciRomHdr = PCI_EXPANSION_ROM_HEADER.from_buffer_copy(Data)
        if sizeof(PciRomHdr) == 0:
            logger.error("Not supported, Failed to read PCI ROM header from file!")
            InFptr.close()
            
        #Dump the contents of the header
        print("Image %u -- Offset 0x%x\n" %(ImageCount, ImageStart))
        print("ROM header contents\n")
        print("    Signature              0x%04x\n" %PciRomHdr.Signature)
        print("    PCIR offset            0x%04x\n" %PciRomHdr.PcirOffset)
        
        #Find PCI data structure
        if InFptr.seek(ImageStart + PciRomHdr.PcirOffset,os.SEEK_SET) == -1:
            logger.error("Not supported, Failed to read PCI data from file!")
            InFptr.close()
            
        #Read and dump the PCI data structure
        if mOptions.Pci23 == 1:
            PciDs23 = PCI_DATA_STRUCTURE.from_buffer_copy(InFptr.read())
            if sizeof(PciDs23) == 0:
                logger.error("Not supported, Failed to read PCI data from file {}!".format(InFile.FileName))
                InFptr.close()
        else:
            PciDs30 = PCI_DATA_STRUCTURE.from_buffer_copy(InFptr.read())
            if sizeof(PciDs30) == 0:
                logger.error("Not supported, Failed to read PCI data from file {}!".format(InFile.FileName))
                InFptr.close()

        if mOptions.Pci23 == 1:
            print("    Signature              {%c}{%c}{%c}{%c}".format(
                  PciDs23.Signature,
                  PciDs23.Signature >> 8,
                  PciDs23.Signature >> 16,
                  PciDs23.Signature >> 24))
            print("    Vendor ID              0x{:0>4}\n".format(PciDs23.VendorId))
            print("    Device ID              0x{:0>4}\n".format(PciDs23.DeviceId))
            print("    Length                 0x{:0>4}\n".format(PciDs23.Length))
            print("    Revision               0x{:0>4}\n".format(PciDs23.Revision))
            print("    Class Code             0x{:0>6}\n".format(PciDs23.ClassCode[0] | (PciDs23.ClassCode[1] << 8) | (PciDs23.ClassCode[2] << 16)))
            print("    Image size             0x%{}\n".format(PciDs23.ImageLength * 512))
            print("    Code revision:         0x{:0>4}\n".format(PciDs23.CodeRevision))
            print("    Indicator              0x{:0>2}".format(PciDs23.Indicator))
        else:
            print("    Signature              {%c}{%c}{%c}{%c}".format(
                  PciDs30.Signature,
                  PciDs30.Signature >> 8,
                  PciDs30.Signature >> 16,
                  PciDs30.Signature >> 24))
            print("    Vendor ID              0x{:0>4}\n".format(PciDs30.VendorId))
            print("    Device ID              0x{:0>4}\n".format(PciDs30.DeviceId))
            print("    Length                 0x{:0>4}\n".format(PciDs30.Length))
            print("    Revision               0x{:0>4}\n".format(PciDs30.Revision))
            print("    DeviceListOffset       0x{:0>2}\n".format(PciDs30.DeviceListOffset))
            if PciDs30.DeviceListOffset:
                #Print device ID list
                print("    Device list contents\n")
                if InFptr.seek(ImageStart + PciRomHdr.PcirOffset + PciDs30.DeviceListOffset, os.SEEK_SET) == -1:
                    logger.error("Not supported, Failed to seek to PCI device ID list!")
                    InFptr.close()
                    
                #Loop until terminating 0
                
                DevId = int.from_bytes(Data[ImageStart + PciRomHdr.PcirOffset + PciDs30.DeviceListOffset : ImageStart + PciRomHdr.PcirOffset + PciDs30.DeviceListOffset + c_uint16],byteorder='little',signed=False)
                if sizeof(DevId) == 0:
                    logger.error("Not supported, Failed to PCI device ID list from file {}".format(InFile.FileName))
                    InFptr.close()
                if DevId:
                    print("      0x{:0>4}\n".format(DevId))
                i = 0 
                while(DevId):
                    DevId = int.from_bytes(Data[ImageStart + PciRomHdr.PcirOffset + PciDs30.DeviceListOffset + i : ImageStart + PciRomHdr.PcirOffset + PciDs30.DeviceListOffset + c_uint16] + i,byteorder='little',signed=False)
                    if sizeof(DevId) == 0:
                        logger.error("Not supported, Failed to PCI device ID list from file {}".format(InFile.FileName))
                        InFptr.close()
                    if DevId:
                        print("      0x{:0>4}\n".format(DevId))
                        i += 2
            print("    Image size              0x{}\n".format(PciDs30.ImageLength * 512))   
            print("    Code revision:          0x{:0>4}\n".format(PciDs30.CodeRevision))   
            print("    MaxRuntimeImageLength   0x{:0>2}\n".format(PciDs30.MaxRuntimeImageLength))   
            print("    ConfigUtilityCodeHeaderOffset 0x%{:0>2}\n".format(PciDs30.ConfigUtilityCodeHeaderOffset))   
            print("    DMTFCLPEntryPointOffset 0x{:0>2}\n".format(PciDs30.DMTFCLPEntryPointOffset))   
            print("    Indicator               0x{:0>2}".format(PciDs30.Indicator))
        
        #Print the indicator, used to flag the last image
        if PciDs23.Indicator == INDICATOR_LAST or PciDs30.Indicator == INDICATOR_LAST:
            print("   (last image)\n")
        else:
            print("\n")
            
        #Print the code type. If EFI code, then we can provide more info.
        if mOptions.Pci23 == 1:
            print("    Code type              0x{:0>2}".format(PciDs23.CodeType))
        else:
            print("    Code type              0x{:0>2}".format(PciDs30.CodeType))
        if PciDs23.CodeType == PCI_CODE_TYPE_EFI_IMAGE or PciDs30.CodeType == PCI_CODE_TYPE_EFI_IMAGE:
            print("   (EFI image)\n")
            #Re-read the header as an EFI ROM header, then dump more info
            print("  EFI ROM header contents\n")
            if InFptr.seek(ImageStart, os.SEEK_SET) == -1:
                logger.error("Failed to re-seek to ROM header structure!")
                InFptr.close()
                
            EfiRomHdr = EFI_PCI_EXPANSION_ROM_HEADER.from_buffer_copy(InFptr.read())
            if len(EfiRomHdr) == 0:
                logger.error("Failed to read EFI PCI ROM header from file!")
                InFptr.close()
                
            #Now dump more info
            print("    EFI Signature          0x%04x\n" %(EfiRomHdr.EfiSignature))
            print("    Compression Type       0x%04x " %(EfiRomHdr.CompressionType))
            if EfiRomHdr.CompressionType == EFI_PCI_EXPANSION_ROM_HEADER_COMPRESSED:
                print("(compressed)\n")
            else:
                print("(not compressed)\n")
            
            print("    Machine type           0x%04x (%s)\n" %(EfiRomHdr.EfiMachineType,GetMachineTypeStr (EfiRomHdr.EfiMachineType)) )
            print("    Subsystem              0x%04x (%s)\n" %(EfiRomHdr.EfiSubsystem,GetSubsystemTypeStr (EfiRomHdr.EfiSubsystem)) )
            print("    EFI image offset       0x%04x (@0x%x)\n" %(EfiRomHdr.EfiImageHeaderOffset,EfiRomHdr.EfiImageHeaderOffset + ImageStart))
        else:
            #Not an EFI image
            print("\n")
            
        #If code type is EFI image, then dump it as well?
        #if (PciDs.CodeType == PCI_CODE_TYPE_EFI_IMAGE) {
        #   }
        #If last image, then we're done
        if PciDs23.Indicator == INDICATOR_LAST or PciDs30.Indicator == INDICATOR_LAST:
            InFptr.close()

        if mOptions.Pci23 == 1:
            if InFptr.seek( ImageStart + (PciDs23.ImageLength * 512), os.SEEK_SET) == -1:
                logger.error("Not supported, Failed to seek to next image!")
                InFptr.close()
        else:
            if InFptr.seek(ImageStart + (PciDs30.ImageLength * 512), os.SEEK_SET) == -1:
                logger.error("Not supported, Failed to seek to next image!")
                InFptr.close()
            
                    


#Given an EFI image filename, create a ROM-able image by creating an option
#ROM header and PCI data structure, filling them in, and then writing the
#option ROM header + PCI data structure + EFI image out to the output file.
def main():
    #FList = FILE_LIST()
    Status  = STATUS_SUCCESS
    if_error = False
    FileLists = []
    #Parse the command line arguments
    if ParseCommandLine (mOptions,FileLists):
        return STATUS_ERROR
    
    mOptions.FileList = FileLists[0]
    #If dumping an image, then do that and quit
    if mOptions.DumpOption == 1:
        if mOptions.FileList != None:
            if mOptions.FileList.FileName.find(DEFAULT_OUTPUT_EXTENSION) != -1:
                DumpImage(mOptions.FileList)
                BailOut(Status,if_error)
            else:
                logger.error("No PciRom input file, No *.rom input file")
                if_error = True
                BailOut(Status,if_error)
    
    #Determine the output filename. Either what they specified on
    #the command line, or the first input filename with a different extension.
    if mOptions.OutFileName == None:
        if mOptions.FileList != None:
            if len(mOptions.FileList.FileName) >= MAX_PATH:
                Status = STATUS_ERROR
                logger.error("Invalid parameter, Input file name is too long - %s." %mOptions.FileList.FileName)
                if_error = True
                BailOut(Status,if_error)
                
            mOptions.OutFileName = mOptions.FileList.FileName  
            mOptions.OutFileName += '/0'   #以/0结尾
            
            #Find the last . on the line and replace the filename extension with
            #the default
            Ext = mOptions.OutFileName
            ExtAdd = len (mOptions.OutFileName) - 1
            #Ext = mOptions.OutFileName[ExtAdd:]
            while ExtAdd >= 0:
                if (Ext[ExtAdd] == '.') or (Ext[ExtAdd] == '\\'):
                    break
                ExtAdd -= 1
                
            #If dot here,then insert extension here, otherwise append
            if (Ext[ExtAdd] != '.'):
                # ExtAdd = len (mOptions.OutFileName)
                Ext = Ext + DEFAULT_OUTPUT_EXTENSION
            Ext = Ext.replace(Ext[ExtAdd:],DEFAULT_OUTPUT_EXTENSION)
            #Ext[ExtAdd:] = DEFAULT_OUTPUT_EXTENSION
            
    #Make sure we don't have the same filename for input and output files
    #FList = mOptions.FileList
    for FList in FileLists:
        if mOptions.OutFileName == FList.FileName:
            Status = STATUS_ERROR
            logger.error("Invalid input parameter, Input and output file names must be different - %s = %s." %(FList.FileName, mOptions.OutFileName))
            if_error = True
            BailOut(Status,if_error)

    #Now open our output file
    with open(mOptions.OutFileName,"wb") as FptrOut:
        Data = FptrOut.read()
        if len(Data) == 0:
            logger.error("Error opening file, Error opening file %s" %mOptions.OutFileName)
            if_error = True
            BailOut(Status,if_error)

    #Process all our files
    i = 0
    num = len(FileLists)
    TotalSize = 0
    for FList in FileLists:
        Size = 0
        if FList.FileFlags & FILE_FLAG_EFI != 0:
            res = ProcessEfiFile (FptrOut, FList, mOptions.VendId, mOptions.DevIdList[0], Size)
            if type(res) == 'int':
                Status = res
            else:
                Status = res[0]
                Size = res[1]
        elif FList.FileFlags & FILE_FLAG_BINARY !=0:
            res = ProcessBinFile (FptrOut, FList, Size,i,num)
            if type(res) == 'int':
                Status = res
            else:
                Status = res[0]
                Size = res[1]
        else:
            Status = STATUS_ERROR
        
        if Status != STATUS_SUCCESS:
            break
        
        TotalSize += Size
        i += 1

    #Check total size
    if TotalSize > MAX_OPTION_ROM_SIZE:
        logger.error("Invalid parameter, Option ROM image size exceeds limit of 0x%x bytes." %MAX_OPTION_ROM_SIZE)
        Status = STATUS_ERROR
    
    
if __name__ == "__main__":
    exit(main())