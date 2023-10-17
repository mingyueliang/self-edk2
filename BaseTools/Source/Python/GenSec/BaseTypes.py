# @file
#Creates output file that is a properly formed section per the PI spec.

#Copyright (c) 2004 - 2018, Intel Corporation. All rights reserved.<BR>
#SPDX-License-Identifier: BSD-2-Clause-Patent




#Attributes of EFI_GUID_DEFINED_SECTION
EFI_GUIDED_SECTION_PROCESSING_REQUIRED = 0x01
EFI_GUIDED_SECTION_AUTH_STATUS_VALID = 0x02


#CompressionType of EFI_COMPRESSION_SECTION.
EFI_NOT_COMPRESSED = 0x00
EFI_STANDARD_COMPRESSION = 0x01


EFI_SECTION_ALL = 0x00
#Encapsulation section Type values
EFI_SECTION_COMPRESSION = 0x01
EFI_SECTION_GUID_DEFINED = 0x02


#Leaf section Type values
EFI_SECTION_PE32 = 0x10
EFI_SECTION_PIC = 0x11
EFI_SECTION_TE = 0x12
EFI_SECTION_DXE_DEPEX = 0x13
EFI_SECTION_VERSION = 0x14
EFI_SECTION_USER_INTERFACE = 0x15
EFI_SECTION_COMPATIBILITY16 = 0x16
EFI_SECTION_FIRMWARE_VOLUME_IMAGE = 0x17
EFI_SECTION_FREEFORM_SUBTYPE_GUID = 0x18
EFI_SECTION_RAW = 0x19
EFI_SECTION_PEI_DEPEX = 0x1B
EFI_SECTION_SMM_DEPEX = 0x1C


EFI_TE_IMAGE_HEADER_SIGNATURE = 0x5A56
IMAGE_ERROR_SUCCESS = 0


MAX_SECTION_SIZE = 0x1000000


#Enumeration of EFI_STATUS.
RETURN_SUCCESS = EFI_SUCCESS = 0
EFI_BUFFER_TOO_SMALL = 0x8000000000000000 | (5)
EFI_ABORTED = 0x8000000000000000 | (21)
EFI_OUT_OF_RESOURCES = 0x8000000000000000 | (9)
EFI_INVALID_PARAMETER = 0x8000000000000000 | (2)
EFI_NOT_FOUND = 0x8000000000000000 | (14)
RETURN_INVALID_PARAMETER = 0x8000000000000000 | (2)
RETURN_UNSUPPORTED = 0x8000000000000000 | (3)

