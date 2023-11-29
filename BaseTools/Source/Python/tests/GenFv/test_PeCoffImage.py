import pytest
import os.path
import re
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from Common.LongFilePathSupport import LongFilePath
from Common.BasePeCoff import *
from GenFvs.GenFvInternalLib import *
from FirmwareStorageFormat.PeImageHeader import *

class TestPeCoff:
    def setup_class(self):
        with open(LongFilePath("BCAF98C9-22B0-3B4F-9CBD-C8A6B4DBCEE9SEC1.1.pe32"), "rb") as PeFile:
            self.PeImage = PeFile.read()

        with open(LongFilePath("0D244DF9-6CE3-4133-A1CF-53200AB663ACSEC2.1.te"), 'rb') as TeFile:
            self.TeImage = TeFile.read()

    def test_PeCoffLoaderGetPeHeader(self):
        # Input = [] ##
        Output = []
        # Test Pe Image Header
        ImageContext = PE_COFF_LOADER_IMAGE_CONTEXT()
        ImageContext, PeHeader, TeHeader = PeCoffLoaderGetPeHeader(ImageContext, self.PeImage)


    def test_PeCoffLoaderCheckImageType(self):
        pass

    def test_PeCoffLoaderGetImageInfo(self):
        pass

    def test_PeCoffLoaderGetPdbPointer(self):
        pass

    def test_PeCoffLoaderLoadImage(self):
        pass

    def test_PeCoffLoaderRelocateImage(self):
        pass



