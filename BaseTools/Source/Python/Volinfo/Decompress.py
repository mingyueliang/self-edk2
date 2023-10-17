# -*- coding: utf-8 -*-
# @Time : 12/21/2021 3:56 PM
# @Author : mliang2x
# @Email : mingyuex.liang@intel.com
# @File : Decompress.py
# @Project : GitHub_edk2

import logging
import zlib
import binascii
from HuffManTree import *


'''
Routine Description:

  The implementation of EFI_DECOMPRESS_PROTOCOL.EfiGetInfo().

Arguments:

  CompressBuffer      - The source buffer containing the compressed data.
  CompressLength      - The size of source buffer

Returns:

  DstSize     - The size of destination buffer.
'''
def EfiGetInfo(CompressBuffer, CompressLength):
    # If the compressed size is smaller than the size of the header, the data is invalid
    if CompressLength < 8:
        logging.error("The source data is corrupted")
        return

    CompSize = CompressBuffer[0] + (CompressBuffer[1] << 8) + (CompressBuffer[2] << 16) + (CompressBuffer[3] << 24)
    DstSize = CompressBuffer[4] + (CompressBuffer[5] << 8) + (CompressBuffer[6] << 16) + (CompressBuffer[7] << 24)
    if (CompressLength < CompSize + 8 or (CompSize + 8) < 8):
        logging.error("Invalid parameter!")
        return

    return DstSize


def EfiDecompress(str_bytes):
    """
    Uncompress buffer content.
    return: Uncompressed Buffer.
    """
    pass















