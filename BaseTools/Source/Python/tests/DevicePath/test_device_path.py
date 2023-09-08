import pytest
import sys
import os
import subprocess

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from DevicePath.DevicePathFromText import *
from DevicePath.DevicePathUtilitles import *
from DevicePath.DevicePathFromText import *
from FirmwareStorageFormat.Common import *


def ExecuteCmd(exe_path, args):
    p = subprocess.Popen([exe_path, args], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    if stderr:
        print(stderr)
        raise Exception("C Tool is failed.....")
    if stdout:
        stdout = stdout.replace(b'\r\n', b'').split(b' ')
        stdout.pop()
    return stdout


class TestDevicePath:
    def setup_class(self):
        self.input = [
            'PciRoot(0)',
            'PciRoot',
            'Pci',
            'Pci(0,0)',
            'Path(0,1,2)',
            'HardwarePath(0,1)',
            'Ata(0x0)',
            'Floppy(0x0)',
            'PciRoot(0)/Pci(0,0)',
            'PciRoot(0)/Pci(0,0)/Path(0,1,2)',
            'PciRoot(0)/Pci(0,0)/Path(0,1,2)/HardwarePath(0,1)',
            'PciRoot(0)/Pci(0,0)/Path(0,1,2)/HardwarePath(0,1)/Ata(0x0)',
            'PciRoot(0)/Pci(0,0)/Path(0,1,2)/HardwarePath(0,1)/Ata(0x0)/Floppy(0x0)',
        ]

        self.IPv6StrList = [
            '2001:db8:3333:4444:5555:6666:7777:8888',
            '2001:db8::',
            '::1234:5678',
            '2001:db8::1234:5678'
        ]
        self.IPv4StrList = [
            '1.2.3.4',
            '01.102.103.104'
        ]

    def test_device_path_sys(self):
        CTool = 'DevicePath.exe'
        for index in range(len(self.input)):
            DevicePath = UefiDevicePathLibConvertTextToDevicePath(
                self.input[index])
            sourceBytes = ExecuteCmd(CTool, self.input[index])

            for i in range(len(DevicePath)):
                assert DevicePath[i] == int(sourceBytes[i], 16)

    def test_StrToIpv4Address(self):
        for index in range(len(self.IPv4StrList)):
            res = StrToIpv4Address(self.IPv4StrList[index])[0]
            destBytes = struct2stream(res)
            for i in range(len(destBytes)):
                assert destBytes[i] == int(self.IPv4StrList[index].split('.')[i], 10)

    def test_StrToIpv6Address(self):
        for index in range(len(self.IPv6StrList)):
            res = StrToIpv6Address(self.IPv6StrList[index])[0]
            destBytes = struct2stream(res)
            source = self.IPv6StrList[index]
            if "::" in source:
                if source.startswith("::"):
                    source = source[2:].split(':')
                    offset = -1
                    offIndex = -1
                    for i in range(len(source)):
                        assert ((destBytes[offset-1] << 8) + destBytes[offset]) == int(source[offIndex], 16)
                        offset -= 2
                        offIndex -= 1
                elif source.endswith("::"):
                    source = source[:-2].split(':')
                    offset = 0
                    for i in range(len(source)):

                        assert ((destBytes[offset] << 8) + destBytes[offset+1]) == int(source[i], 16)
                        offset += 2
                else:
                    off = source.find('::')
                    preSource = source[:off].split(':')
                    EndSource = source[off+2:].split(':')
                    offset = 0
                    for i in range(len(preSource)):
                        ds1 = destBytes[offset] << 8
                        ds2 = destBytes[offset+1]
                        s1 = int(preSource[i], 16)
                        assert (((destBytes[offset] << 8) + destBytes[offset+1])) == int(preSource[i], 16)
                        offset += 2

                    offset = -1
                    offIndex = -1
                    for j in range(len(EndSource)):
                        assert ((destBytes[offset -1] << 8) + destBytes[offset]) == int(EndSource[offIndex], 16)
                        offset -= 2
                        offIndex -= 1
            else:
                source = source.split(':')
                offset = 0
                for i in range(len(source)):
                    assert ((destBytes[offset] << 8) + destBytes[offset+1]) == int(source[i], 16)
                    offset += 2


if __name__ == '__main__':
    pytest.main(['-vs', 'test_device_path.py'])
