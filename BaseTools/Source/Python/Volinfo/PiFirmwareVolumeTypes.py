



from ctypes import *
from copy import *
import sys


class A(Structure):
    _fields_ = [
        ("a", c_ulonglong),
        ("b", c_ulong),
    ]

def C():
    print(sizeof(c_uint64))
    a = A(2, 3)
    print(a.a, a.b)
    # print(id(a.a), id(a.b))
    # a.a = 67
    # B(a)
    # print(a.b)
    # b = copy(a)
    # # print(a is b)
    # # print(id(a), id(b))
    # # print(id(b.a), id(b.b))
    # # # print()
    # D(b)
    # print(a.b, b.b)
    # print(a is b)

def B(a):
    a.b = 45


def D(a):
    a.b = 67



if __name__ == '__main__':
    C()
