import sys
import os
from ctypes import *
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from FirmwareStorageFormat.SectionHeader import *

# file = sys.stdout
# print("stdout: ", sys.stdout)
#
# file.write("ffff\n")
# file.write("ffff\n")
# file.write("ffff\n")
# file.write("ffff\n")
# file.write("ffff\n")
#
# file.close()



bb = bytes([0x0 for i in range(10)])
b1 = bb[5:]
pass


size = sizeof(EFI_COMMON_SECTION_HEADER())
pass


from copy import deepcopy, copy

class UN(Union):
    _pack_ = 1
    _fields_ = [
        ("a", c_uint8),
        ("b", c_uint32),
    ]

class s(Structure):
    _pack_ = 1
    _fields_ = [
        ('age', UN),
        ('name', POINTER(c_char)),
    ]


s = s()
s.age = UN(1)
s.name = POINTER(c_char)()
#
# n = deepcopy(s)
#
# s.age = UN(2)
# pass

# U = UN()
# U.a = 2
# U.b = 3
#
# N = copy(U)
#
# U.a = 1
# print(sizeof(UN))


import re

line = " 0001:00000000       __ModuleEntryPoint         00011000 f   EmuSec:Sec.obj"

match = re.match(r'\s+\S+\s+\w+\s+[a-zA-Z0-9]+\s+[a-zA-Z]+\s+', line)
print(type(match.group(0)))
#
#
by = bytearray([0xff for i in range(1000)])
with open('file.Fv', 'wb') as file:
    file.write(by)

Sum = 0x4ad1
twoRes = bin(Sum)[2:]
if len(twoRes) < 16:
    twoRes = '0' * (16 - len(twoRes)) + twoRes

s = '0b'
for b in twoRes:
    if b == '1':
        s += '0'
    else:
        s += '1'

t = hex(int(s,2))
pass


a =0
def change():
    global a
    a = 2


def change1():
    global a
    a = 3

change()
change1()

print(a)

b = b'0x2' + b'0x3'
pass
