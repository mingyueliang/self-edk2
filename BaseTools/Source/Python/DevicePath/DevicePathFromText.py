from DevicePathFormat import *
from DevicePathUtilitles import *


# Convert text to the binary representation of a device path
def UefiDevicePathLibConvertTextToDevicePath(TextDevicePath: str) -> bytearray:
    if not TextDevicePath:
        return bytearray()

    DevicePath = EFI_DEVICE_PATH_PROTOCOL()
    DevicePath = bytearray(struct2stream(SetDevicePathEndNode(DevicePath)))
    DevicePathStr = TextDevicePath

    Str = DevicePathStr
    res = GetNextDeviceNodeStr(Str)
    if res == None:
        DeviceNodeStr = None
    else:
        DeviceNodeStr = res[0]
        Str = res[1]

    while DeviceNodeStr:
        DeviceNode = UefiDevicePathLibConvertTextToDeviceNode(DeviceNodeStr)
        DevicePath = AppendDevicePathNode(DevicePath,
                                          bytearray(struct2stream(DeviceNode)))

        res = GetNextDeviceNodeStr(Str)
        if res == None:
            DeviceNodeStr = None
        else:
            DeviceNodeStr = res[0]
            Str = res[1]
    return DevicePath


def AppendDevicePathNode(DevicePath: bytearray,
                         DevicePathNode: bytearray) -> bytearray:
    return UefiDevicePathLibAppendDevicePathNode(DevicePath, DevicePathNode)


# Fills in all the fields of a device path node that is the end of an entire device path
def SetDevicePathEndNode(Node):
    Node = mUefiDevicePathLibEndDevicePath
    return Node


# Get one device node from entire device path text
def GetNextDeviceNodeStr(DevicePath: str):
    Str = DevicePath
    if not Str:
        return None

    # Skip the leading '/','(',')' and ','
    i = 0
    for i in range(len(Str)):
        if not IS_SLASH(Str[i]) and not IS_SLASH(
                Str[i]) and not IS_LEFT_PARENTH(
                Str[i]) and not IS_RIGHT_PARENTH(Str[i]):
            break
    ReturnStr = Str[i:]
    # Scan for the separator of this device node, '/' or ','
    ParenthesesStack = 0
    i = 0
    for i in range(len(ReturnStr)):
        if (IS_COMMA(ReturnStr[i]) or IS_SLASH(
                ReturnStr[i])) and ParenthesesStack == 0:
            break
        if IS_LEFT_PARENTH(ReturnStr[i]):
            ParenthesesStack = ParenthesesStack + 1
        elif IS_RIGHT_PARENTH(ReturnStr[i]):
            ParenthesesStack = ParenthesesStack - 1

    if ParenthesesStack != 0:
        # The '(' doesn't pair with ')', invalid device path
        return None

    DevicePath = Str[i + 1:]

    return ReturnStr, DevicePath
