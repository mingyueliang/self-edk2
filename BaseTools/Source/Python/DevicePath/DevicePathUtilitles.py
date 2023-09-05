from DevicePathFormat import *
from DevicePathFromText import *
from FirmwareStorageFormat.Common import *
from DevicePath import logger


def SplitStr(List, separator):
    List = List.split(separator)
    returnStr = List[0]
    return returnStr, ','.join(List[1:])


def GetNextParamStr(List: str) -> tuple:
    # The separator is comma
    return SplitStr(List, ',')


def UefiDevicePathLibCreateDeviceNode(NodeType: int, NodeSubType: int,
                                      NodeLength: int) -> EFI_DEVICE_PATH_PROTOCOL:
    DevicePath = EFI_DEVICE_PATH_PROTOCOL()
    if NodeLength < sizeof(DevicePath):
        return None

    DevicePath.Type = NodeType
    DevicePath.SubType = NodeSubType
    DevicePath = SetDevicePathNodeLength(DevicePath, NodeLength)

    return DevicePath


def CreateDeviceNode(NodeType: int, NodeSubType: int, NodeLength: int) -> EFI_DEVICE_PATH_PROTOCOL:
    return UefiDevicePathLibCreateDeviceNode(NodeType, NodeSubType, NodeLength)


def DevPathFromTextGenericPath(Type: int, TextDeviceNode: str):
    SubtypeStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    DataStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)

    if DataStr == None:
        DataLength = 0
    else:
        DataLength = int(len(DataStr) / 2)
    Node = Get_GENERIC_PATH(DataLength)
    Node.Header = CreateDeviceNode(Type, Strtoi(SubtypeStr), sizeof(EFI_DEVICE_PATH_PROTOCOL) + DataLength)
    for Index in range(DataLength):
        if Index & BIT0 == 0:
            Node.Data[Index // 2] = InternalHexCharToUintn(DataStr[Index]) << 4
        else:
            Node.Data[Index // 2] = InternalHexCharToUintn(DataStr[Index])
    return Node


# Converts a generic text device path node to device path structure.
def DevPathFromTextPath(TextDeviceNode: str) -> EFI_DEVICE_PATH_PROTOCOL:
    TypeStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    return DevPathFromTextGenericPath(Strtoi(TypeStr), TextDeviceNode)


def DevPathFromTextHardwarePath(TextDeviceNode: str):
    return DevPathFromTextGenericPath(HARDWARE_DEVICE_PATH, TextDeviceNode)


def DevPathFromTextPci(TextDeviceNode: str) -> PCI_DEVICE_PATH:
    Pci = PCI_DEVICE_PATH()
    # TextDeviceNodeList = TextDeviceNode.split(',')
    # DeviceStr = TextDeviceNodeList[0]
    # FunctionStr = TextDeviceNodeList[1]
    DeviceStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    FunctionStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    Pci.Header = CreateDeviceNode(HARDWARE_DEVICE_PATH, HW_PCI_DP, sizeof(PCI_DEVICE_PATH))
    Pci.Function = Strtoi(FunctionStr)
    Pci.Device = Strtoi(DeviceStr)
    return Pci


def DevPathFromTextPcCard(TextDeviceNode: str):
    Pccard = PCCARD_DEVICE_PATH()
    FunctionNumberStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    Pccard.Header = CreateDeviceNode(HARDWARE_DEVICE_PATH, HW_PCCARD_DP, sizeof(PCCARD_DEVICE_PATH))
    Pccard.FunctionNumber = Strtoi(FunctionNumberStr)
    return Pccard


def DevPathFromTextMemoryMapped(TextDeviceNode: str):
    MemMap = MEMMAP_DEVICE_PATH()
    MemoryTypeStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    StartingAddressStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    EndingAddressStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    MemMap.MemoryType = Strtoi(MemoryTypeStr)
    MemMap.StartingAddress = Strtoi(StartingAddressStr)
    MemMap.EndingAddress = Strtoi(EndingAddressStr)
    return MemMap


def ConvertFromTextVendor(TextDeviceNode: str, Type: int, SubType: int) -> VENDOR_DEVICE_PATH:
    GuidStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    DataStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    Length = len(DataStr)

    # Two hex characters make up 1 buffer byte
    Length = (Length + 1) // 2
    Vendor = VENDOR_DEVICE_PATH()
    Vendor.Header = CreateDeviceNode(Type, SubType, sizeof(VENDOR_DEVICE_PATH) + Length)
    Vendor.Guid = ModifyGuidFormat(GuidStr)
    # Vendor = DataStr.encode()
    return Vendor


def DevPathFromTextVenHw(TextDeviceNode: str):
    return ConvertFromTextVendor(TextDeviceNode, HARDWARE_DEVICE_PATH, HW_VENDOR_DP)


def DevPathFromTextCtrl(TextDeviceNode: str) -> CONTROLLER_DEVICE_PATH:
    ControllerStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    Controller = CONTROLLER_DEVICE_PATH()
    Controller.Header = CreateDeviceNode(HARDWARE_DEVICE_PATH, HW_CONTROLLER_DP, sizeof(CONTROLLER_DEVICE_PATH))
    Controller.ControllerNumber = Strtoi(ControllerStr)
    return Controller


def DevPathFromTextBmc(TextDeviceNode: str) -> BMC_DEVICE_PATH:
    BmcDp = BMC_DEVICE_PATH()
    InterfaceTypeStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    BaseAddressStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    BmcDp.Header = CreateDeviceNode(HARDWARE_DEVICE_PATH, HW_BMC_DP, sizeof(BMC_DEVICE_PATH))
    BmcDp.InterfaceType = Strtoi(InterfaceTypeStr)
    BmcDp.BaseAddress = Strtoi(BaseAddressStr)
    return BmcDp


def DevPathFromTextAcpiPath(TextDeviceNode: str) -> EFI_DEVICE_PATH_PROTOCOL:
    return DevPathFromTextGenericPath(ACPI_DEVICE_PATH, TextDeviceNode)


def EisaIdFromText(Text: str) -> int:
    return (((ord(Text[0]) - ord('A') + 1) & 0x1f) << 10) + \
        (((ord(Text[1]) - ord('A') + 1) & 0x1f) << 5) \
        + (((ord(Text[2]) - ord('A') + 1) & 0x1f) << 0) \
        + Strtoi(Text[3]) << 16


def DevPathFromTextAcpi(TextDeviceNode: str) -> ACPI_HID_DEVICE_PATH:
    Acpi = ACPI_HID_DEVICE_PATH()
    HIDStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    UIDStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    Acpi.Header = CreateDeviceNode(ACPI_DEVICE_PATH, ACPI_DP, sizeof(ACPI_HID_DEVICE_PATH))
    Acpi.HID = EisaIdFromText(HIDStr)
    Acpi.UID = Strtoi(UIDStr)
    return Acpi


def ConvertFromTextAcpi(TextDeviceNode: str, PnPId: int) -> ACPI_HID_DEVICE_PATH:
    Acpi = ACPI_HID_DEVICE_PATH()
    # UIDStr = TextDeviceNode.split(",")[0]
    UIDStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    Acpi.Header = CreateDeviceNode(ACPI_DEVICE_PATH, ACPI_DP, sizeof(ACPI_HID_DEVICE_PATH))
    Acpi.HID = EFI_PNP_ID(PnPId)
    Acpi.UID = Strtoi(UIDStr)
    return Acpi


def DevPathFromTextPciRoot(TextDeviceNode: str) -> ACPI_HID_DEVICE_PATH:
    return ConvertFromTextAcpi(TextDeviceNode, 0x0a03)


def DevPathFromTextPcieRoot(TextDeviceNode: str) -> ACPI_HID_DEVICE_PATH:
    return ConvertFromTextAcpi(TextDeviceNode, 0x0a08)


def DevPathFromTextFloppy(TextDeviceNode: str) -> ACPI_HID_DEVICE_PATH:
    return ConvertFromTextAcpi(TextDeviceNode, 0x0604)


def DevPathFromTextKeyboard(TextDeviceNode: str) -> ACPI_HID_DEVICE_PATH:
    return ConvertFromTextAcpi(TextDeviceNode, 0x0301)


def DevPathFromTextSerial(TextDeviceNode: str) -> ACPI_HID_DEVICE_PATH:
    return ConvertFromTextAcpi(TextDeviceNode, 0x0501)


def DevPathFromTextParallelPort(TextDeviceNode: str) -> ACPI_HID_DEVICE_PATH:
    return ConvertFromTextAcpi(TextDeviceNode, 0x0401)


def DevPathFromTextAcpiEx(TextDeviceNode: str) -> ACPI_EXTENDED_HID_DEVICE_PATH:
    AcpiEx = ACPI_EXTENDED_HID_DEVICE_PATH()
    HIDStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    CIDStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    UIDStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    HIDSTRStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    CIDSTRStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    UIDSTRStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)

    Length = sizeof(ACPI_EXTENDED_HID_DEVICE_PATH) + len(HIDSTRStr) + 1
    Length = Length + len(UIDSTRStr) + 1
    Length = Length + len(CIDSTRStr) + 1
    AcpiEx.Header = CreateDeviceNode(ACPI_DEVICE_PATH, ACPI_EXTENDED_DP, Length)

    AcpiEx.HID = EisaIdFromText(HIDStr)
    AcpiEx.CID = EisaIdFromText(CIDStr)
    AcpiEx.UID = Strtoi(UIDStr)

    return AcpiEx


def DevPathFromTextAcpiExp(TextDeviceNode: str) -> ACPI_EXTENDED_HID_DEVICE_PATH:
    AcpiEx = ACPI_EXTENDED_HID_DEVICE_PATH()
    HIDStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    CIDStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    UIDSTRStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    Length = sizeof(ACPI_EXTENDED_HID_DEVICE_PATH) + len(UIDSTRStr) + 3
    AcpiEx.Header = CreateDeviceNode(ACPI_DEVICE_PATH, ACPI_EXTENDED_DP, Length)

    AcpiEx.HID = EisaIdFromText(HIDStr)
    if CIDStr == '0':
        AcpiEx.CID = 0
    else:
        AcpiEx.CID = EisaIdFromText(CIDStr)
    AcpiEx.UID = 0
    return AcpiEx


def DevPathFromTextAcpiAdr(TextDeviceNode: str) -> ACPI_ADR_DEVICE_PATH:
    nums = 0
    DeviceStrList = list()
    while TextDeviceNode:
        DisplayDeviceStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
        DeviceStrList.append(DisplayDeviceStr)
        nums += 1

    AcpiAdr = Get_ACPI_ADR_DEVICE_PATH(nums)
    AcpiAdr.Header = CreateDeviceNode(
        ACPI_DEVICE_PATH,
        ACPI_ADR_DP,
        sizeof(EFI_DEVICE_PATH_PROTOCOL) + 4 * nums
    )
    for i in range(nums):
        AcpiAdr.ADR[i] = DeviceStrList[i].encode()
    return AcpiAdr


def DevPathFromTextMsg(TextDeviceNode: str) -> EFI_DEVICE_PATH_PROTOCOL:
    return DevPathFromTextGenericPath(MESSAGING_DEVICE_PATH, TextDeviceNode)


def DevPathFromTextAta(TextDeviceNode: str) -> ATAPI_DEVICE_PATH:
    Atapi = ATAPI_DEVICE_PATH()
    Atapi.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_ATAPI_DP, sizeof(ATAPI_DEVICE_PATH))
    PrimarySecondaryStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    SlaveMasterStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    LunStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    if PrimarySecondaryStr == 'Primary':
        Atapi.PrimarySecondary = 0
    elif PrimarySecondaryStr == 'Secondary':
        Atapi.PrimarySecondary = 1
    else:
        Atapi.PrimarySecondary = Strtoi(PrimarySecondaryStr)

    if SlaveMasterStr == 'Master':
        Atapi.SlaveMasterStr = 0
    elif SlaveMasterStr == 'Slave':
        Atapi.SlaveMasterStr = 1
    else:
        Atapi.SlaveMasterStr = Strtoi(SlaveMasterStr)

    Atapi.Lun = Strtoi(LunStr)
    return Atapi


def DevPathFromTextScsi(TextDeviceNode: str) -> SCSI_DEVICE_PATH:
    Scsi = SCSI_DEVICE_PATH()
    PunStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    LunStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    Scsi.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_SCSI_DP, sizeof(SCSI_DEVICE_PATH))
    Scsi.Pun = Strtoi(PunStr)
    Scsi.Lun = Strtoi(LunStr)
    return Scsi


def DevPathFromTextFibre(TextDeviceNode: str) -> FIBRECHANNEL_DEVICE_PATH:
    Fibre = FIBRECHANNEL_DEVICE_PATH()
    WWNStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    LunStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    Fibre.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_FIBRECHANNEL_DP, sizeof(FIBRECHANNEL_DEVICE_PATH))

    Fibre.Reserved = 0
    Fibre.WWN = Strtoi(WWNStr)
    Fibre.Lun = Strtoi(LunStr)
    return Fibre


def DevPathFromTextFibreEx(TextDeviceNode: str) -> FIBRECHANNEL_DEVICE_PATH:
    FibreEx = FIBRECHANNEL_DEVICE_PATH()
    WWNStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    LunStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    FibreEx.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_FIBRECHANNEL_DP, sizeof(FIBRECHANNEL_DEVICE_PATH))

    FibreEx.Reserved = 0
    FibreEx.WWN = Strtoi(WWNStr)
    FibreEx.Lun = Strtoi(LunStr)
    return FibreEx


def DevPathFromText1394(TextDeviceNode: str) -> F1394_DEVICE_PATH:
    F1394DevPath = F1394_DEVICE_PATH()
    GuidStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    F1394DevPath.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_1394_DP, sizeof(F1394_DEVICE_PATH))
    F1394DevPath.Reserved = 0
    F1394DevPath.Guid = Strtoi(GuidStr)
    return F1394DevPath


def DevPathFromTextUsb(TextDeviceNode: str) -> USB_DEVICE_PATH:
    Usb = USB_DEVICE_PATH()
    PortStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    InterfaceStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    Usb.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_USB_DP, sizeof(USB_DEVICE_PATH))
    Usb.ParentPortNumber = Strtoi(PortStr)
    Usb.InterfaceNumber = Strtoi(InterfaceStr)
    return Usb


def DevPathFromTextI2O(TextDeviceNode: str) -> I2O_DEVICE_PATH:
    I2ODevPath = I2O_DEVICE_PATH()
    TIDStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    I2ODevPath.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_I2O_DP, sizeof(I2O_DEVICE_PATH))
    I2ODevPath.Tid = Strtoi(TIDStr)
    return I2ODevPath


def DevPathFromTextInfiniband(TextDeviceNode: str) -> INFINIBAND_DEVICE_PATH:
    InfiniBand = INFINIBAND_DEVICE_PATH()
    FlagsStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    GuidStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    SidStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    TidStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    DidStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    InfiniBand.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_INFINIBAND_DP, sizeof(INFINIBAND_DEVICE_PATH))
    InfiniBand.ResourceFlags = Strtoi(FlagsStr)
    InfiniBand.PortGid = ModifyGuidFormat(GuidStr)
    InfiniBand.ServiceId = Strtoi(SidStr)
    InfiniBand.TargetPortId = Strtoi(TidStr)
    InfiniBand.DeviceId = Strtoi(DidStr)
    return InfiniBand


def DevPathFromTextVenMsg(TextDeviceNode: str):
    return ConvertFromTextVendor(TextDeviceNode, MESSAGING_DEVICE_PATH, MSG_VENDOR_DP)


gEfiPcAnsiGuid = EFI_GUID(0xe0c14753, 0xf9be, 0x11d2, (0x9a, 0x0c, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d))


def DevPathFromTextVenPcAnsi(TextDeviceNode: str) -> VENDOR_DEVICE_PATH:
    Vendor = VENDOR_DEVICE_PATH()
    Vendor.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_VENDOR_DP, sizeof(VENDOR_DEVICE_PATH))
    Vendor.Guid = gEfiPcAnsiGuid
    return Vendor


gEfiVT100Guid = EFI_GUID(0xdfa66065, 0xb419, 0x11d3, (0x9a, 0x2d, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d))


def DevPathFromTextVenVt100(TextDeviceNode: str) -> VENDOR_DEVICE_PATH:
    Vendor = VENDOR_DEVICE_PATH()
    Vendor.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_VENDOR_DP, sizeof(VENDOR_DEVICE_PATH))
    Vendor.Guid = gEfiVT100Guid
    return Vendor


gEfiVT100PlusGuid = EFI_GUID(0x7baec70b, 0x57e0, 0x4c76, (0x8e, 0x87, 0x2f, 0x9e, 0x28, 0x08, 0x83, 0x43))


def DevPathFromTextVenVt100Plus(TextDeviceNode: str) -> VENDOR_DEVICE_PATH:
    Vendor = VENDOR_DEVICE_PATH()
    Vendor.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_VENDOR_DP, sizeof(VENDOR_DEVICE_PATH))
    Vendor.Guid = gEfiVT100PlusGuid
    return Vendor


gEfiVTUTF8Guid = EFI_GUID(0xad15a0d6, 0x8bec, 0x4acf, (0xa0, 0x73, 0xd0, 0x1d, 0xe7, 0x7e, 0x2d, 0x88))


def DevPathFromTextVenUtf8(TextDeviceNode: str) -> VENDOR_DEVICE_PATH:
    Vendor = VENDOR_DEVICE_PATH()
    Vendor.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_VENDOR_DP, sizeof(VENDOR_DEVICE_PATH))
    Vendor.Guid = gEfiVTUTF8Guid
    return Vendor


gEfiUartDevicePathGuid = EFI_GUID(0x37499a9d, 0x542f, 0x4c89, (0xa0, 0x26, 0x35, 0xda, 0x14, 0x20, 0x94, 0xe4))


def DevPathFromTextUartFlowCtrl(TextDeviceNode: str) -> UART_FLOW_CONTROL_DEVICE_PATH:
    UartFlowControl = UART_FLOW_CONTROL_DEVICE_PATH()
    ValueStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    UartFlowControl.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_VENDOR_DP,
                                              sizeof(UART_FLOW_CONTROL_DEVICE_PATH))
    UartFlowControl.Guid = gEfiUartDevicePathGuid
    if ValueStr == 'XonXoff':
        UartFlowControl.FlowControlMap = 2
    elif ValueStr == 'Hardware':
        UartFlowControl.FlowControlMap = 1
    else:
        UartFlowControl.FlowControlMap = 0
    return UartFlowControl


gEfiSasDevicePathGuid = EFI_GUID(0x37499a9d, 0x542f, 0x4c89, (0xa0, 0x26, 0x35, 0xda, 0x14, 0x20, 0x94, 0xe4))


def DevPathFromTextSAS(TextDeviceNode: str) -> SAS_DEVICE_PATH:
    Sas = SAS_DEVICE_PATH()
    AddressStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    LunStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    RTPStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    SASSATAStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    LocationStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    ConnectStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    DriveBayStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    ReservedStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    Sas.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_VENDOR_DP, sizeof(SAS_DEVICE_PATH))
    Sas.Guid = gEfiSasDevicePathGuid
    Sas.SasAddress = Strtoi(AddressStr)
    Sas.Lun = Strtoi(LunStr)
    Sas.RelativeTargetPort = Strtoi(RTPStr)

    if SASSATAStr == 'NoTopology':
        Info = 0x0
    elif SASSATAStr == 'SATA' or SASSATAStr == 'SAS':
        Uint16 = Strtoi(DriveBayStr)
        if Uint16 == 0:
            Info = 0x1
        else:
            Info = 0x2 | ((Uint16 - 1) << 8)

        if SASSATAStr == 'SATA':
            Info = Info | BIT4
        if LocationStr == 'External':
            Uint16 = 1
        elif LocationStr == 'Internal':
            Uint16 = 0
        else:
            Uint16 = Strtoi(LocationStr) & BIT0
        Info |= (Uint16 << 5)

        if ConnectStr == 'Expanded':
            Uint16 = 1
        elif ConnectStr == 'Direct':
            Uint16 = 0
        else:
            Uint16 = Strtoi(ConnectStr) & (BIT0 | BIT1)
        Info = Info | (Uint16 << 6)
    else:
        Info = Strtoi(SASSATAStr)
    Sas.DeviceTopology = Info
    Sas.Reserved = Strtoi(ReservedStr)
    return Sas


def DevPathFromTextSasEx(TextDeviceNode: str) -> SAS_DEVICE_PATH:
    SasEx = SAS_DEVICE_PATH()
    AddressStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    LunStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    RTPStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    SASSATAStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    LocationStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    ConnectStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    DriveBayStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)

    SasEx.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_SASEX_DP, sizeof(SAS_DEVICE_PATH))
    # SasEx.Guid = gEfiSasDevicePathGuid
    SasEx.SasAddress = Strtoi(AddressStr)
    SasEx.Lun = Strtoi(LunStr)
    SasEx.RelativeTargetPort = Strtoi(RTPStr)

    if SASSATAStr == 'NoTopology':
        Info = 0x0
    elif SASSATAStr == 'SATA' or SASSATAStr == 'SAS':
        Uint16 = Strtoi(DriveBayStr)
        if Uint16 == 0:
            Info = 0x1
        else:
            Info = 0x2 | ((Uint16 - 1) << 8)

        if SASSATAStr == 'SATA':
            Info |= BIT4

        if LocationStr == 'External':
            Uint16 = 1
        elif LocationStr == 'Internal':
            Uint16 = 0
        else:
            Uint16 = Strtoi(LocationStr) & BIT0
        Info |= (Uint16 << 5)

        if ConnectStr == 'Expanded':
            Uint16 = 1
        elif ConnectStr == 'Direct':
            Uint16 = 0
        else:
            Uint16 = Strtoi(ConnectStr) & (BIT0 | BIT1)
        Info |= (Uint16 << 6)
    else:
        Info = Strtoi(SASSATAStr)
    SasEx.DeviceTopology = Info
    return SasEx


def DevPathFromTextNVMe(TextDeviceNode: str) -> NVME_NAMESPACE_DEVICE_PATH:
    Nvme = NVME_NAMESPACE_DEVICE_PATH()
    NamespaceIdStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    NamespaceUuidStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    Nvme.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_NVME_NAMESPACE_DP, sizeof(NVME_NAMESPACE_DEVICE_PATH))
    Nvme.NamespaceId = Strtoi(NamespaceIdStr)
    Uuid = Nvme.NamespaceUuid
    Index = sizeof(Nvme.NamespaceUuid) // sizeof(c_uint8)
    while Index - 1 != 0:
        Uuid[Index], NamespaceUuidStr = SplitStr(NamespaceUuidStr, '-')
    return Nvme


def DevPathFromTextUfs(TextDeviceNode: str) -> UFS_DEVICE_PATH:
    Ufs = UFS_DEVICE_PATH()
    PunStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    LunStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    Ufs.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_UFS_DP, sizeof(UFS_DEVICE_PATH))

    Ufs.Pun = Strtoi(PunStr)
    Ufs.Lun = Strtoi(LunStr)
    return Ufs


def DevPathFromTextSd(TextDeviceNode: str) -> SD_DEVICE_PATH:
    Sd = SD_DEVICE_PATH()
    SlotNumberStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    Sd.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_SD_DP, sizeof(SD_DEVICE_PATH))
    Sd.SlotNumber = Strtoi(SlotNumberStr)
    return Sd


def DevPathFromTextEmmc(TextDeviceNode: str) -> EMMC_DEVICE_PATH:
    Emmc = EMMC_DEVICE_PATH()
    SlotNumberStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    Emmc.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_EMMC_DP, sizeof(EMMC_DEVICE_PATH))
    Emmc.SlotNumber = Strtoi(SlotNumberStr)
    return Emmc


gEfiDebugPortProtocolGuid = EFI_GUID(0xEBA4E8D2, 0x3858, 0x41EC, (0xA2, 0x81, 0x26, 0x47, 0xBA, 0x96, 0x60, 0xD0))


def DevPathFromTextDebugPort(TextDeviceNode: str) -> VENDOR_DEVICE_PATH:
    Vend = VENDOR_DEVICE_PATH()
    Vend.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_VENDOR_DP, sizeof(VENDOR_DEVICE_PATH))
    Vend.Guid = gEfiDebugPortProtocolGuid
    return Vend


def DevPathFromTextMAC(TextDeviceNode: str) -> MAC_ADDR_DEVICE_PATH:
    MACDevPath = MAC_ADDR_DEVICE_PATH()
    AddressStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    IfTypeStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    MACDevPath.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_MAC_ADDR_DP, sizeof(MAC_ADDR_DEVICE_PATH))
    MACDevPath.IfType = Strtoi(IfTypeStr)

    # Length = sizeof(EFI_MAC_ADDRESS)
    # if MACDevPath.IfType == 0x01 or MACDevPath.IfType == 0x00:
    #     Length = 6
    MACDevPath.Addr = bytes.fromhex(AddressStr)

    return MACDevPath


def StrDecimalToUint64S(Str: str, EndPointer=None):
    """
      Convert a Null-terminated Unicode decimal string to a value of type UINT64.

      This function outputs a value of type UINT64 by interpreting the contents of
      the Unicode string specified by String as a decimal number. The format of the
      input Unicode string String is:

                      [spaces] [decimal digits].

      The valid decimal digit character is in the range [0-9]. The function will
      ignore the pad space, which includes spaces or tab characters, before
      [decimal digits]. The running zero in the beginning of [decimal digits] will
      be ignored. Then, the function stops at the first character that is a not a
      valid decimal character or a Null-terminator, whichever one comes first.

      If String is NULL, then ASSERT().
      If Data is NULL, then ASSERT().
      If String is not aligned in a 16-bit boundary, then ASSERT().
      If PcdMaximumUnicodeStringLength is not zero, and String contains more than
      PcdMaximumUnicodeStringLength Unicode characters, not including the
      Null-terminator, then ASSERT().

      If String has no valid decimal digits in the above format, then 0 is stored
      at the location pointed to by Data.
      If the number represented by String exceeds the range defined by UINT64, then
      MAX_UINT64 is stored at the location pointed to by Data.

      If EndPointer is not NULL, a pointer to the character that stopped the scan
      is stored at the location pointed to by EndPointer. If String has no valid
      decimal digits right after the optional pad spaces, the value of String is
      stored at the location pointed to by EndPointer.

      @param  String                   Pointer to a Null-terminated Unicode string.
      @param  EndPointer               Pointer to character that stops scan.
      @param  Data                     Pointer to the converted value.

      @retval RETURN_SUCCESS           Value is translated from String.
      @retval RETURN_INVALID_PARAMETER If String is NULL.
                                       If Data is NULL.
                                       If PcdMaximumUnicodeStringLength is not
                                       zero, and String contains more than
                                       PcdMaximumUnicodeStringLength Unicode
                                       characters, not including the
                                       Null-terminator.
      @retval RETURN_UNSUPPORTED       If the number represented by String exceeds
                                   the range defined by UINT64.
    """
    Status = RETURN_SUCCESS
    assert (ord(Str[0]) & BIT0 == 0)
    # Neither String nor Data shall be a null pointer.
    if not Str:
        return RETURN_INVALID_PARAMETER
    # The length of String shall not be greater than RSIZE_MAX.
    if len(Str) > RSIZE_MAX:
        return RETURN_INVALID_PARAMETER
    # Ignore the pad spaces (space or tab)
    Index = 0
    if EndPointer != None:
        EndPointer = Index
    while (Str[Index] == " " or Str[Index] == "\t"):
        Index += 1
    # Ignore leading Zeros after the spaces
    while Str[Index] == '0':
        Index += 1

    Data = 0
    while InternalIsDecimalDigitCharacter(Str[Index]):
        if Data > ((MAX_UINT64 - (ord(Str[Index]) - ord('0'))) // 10):
            Data = MAX_UINT64
            if EndPointer != None:
                EndPointer = Index
            return RETURN_UNSUPPORTED
        Data = Data * 10 + (ord(Str[Index]) - ord('0'))
        Index += 1

    if EndPointer != None:
        EndPointer = Index
    return Status, Data, EndPointer


def StrHexToUint64S(Str: str, EndPointer=None):
    """
      Convert a Null-terminated Unicode hexadecimal string to a value of type
      UINT64.

      This function outputs a value of type UINT64 by interpreting the contents of
      the Unicode string specified by String as a hexadecimal number. The format of
      the input Unicode string String is:

                      [spaces][zeros][x][hexadecimal digits].

      The valid hexadecimal digit character is in the range [0-9], [a-f] and [A-F].
      The prefix "0x" is optional. Both "x" and "X" is allowed in "0x" prefix.
      If "x" appears in the input string, it must be prefixed with at least one 0.
      The function will ignore the pad space, which includes spaces or tab
      characters, before [zeros], [x] or [hexadecimal digit]. The running zero
      before [x] or [hexadecimal digit] will be ignored. Then, the decoding starts
      after [x] or the first valid hexadecimal digit. Then, the function stops at
      the first character that is a not a valid hexadecimal character or NULL,
      whichever one comes first.

      If String is NULL, then ASSERT().
      If Data is NULL, then ASSERT().
      If String is not aligned in a 16-bit boundary, then ASSERT().
      If PcdMaximumUnicodeStringLength is not zero, and String contains more than
      PcdMaximumUnicodeStringLength Unicode characters, not including the
      Null-terminator, then ASSERT().

      If String has no valid hexadecimal digits in the above format, then 0 is
      stored at the location pointed to by Data.
      If the number represented by String exceeds the range defined by UINT64, then
      MAX_UINT64 is stored at the location pointed to by Data.

      If EndPointer is not NULL, a pointer to the character that stopped the scan
      is stored at the location pointed to by EndPointer. If String has no valid
      hexadecimal digits right after the optional pad spaces, the value of String
      is stored at the location pointed to by EndPointer.

      @param  String                   Pointer to a Null-terminated Unicode string.
      @param  EndPointer               Pointer to character that stops scan.
      @param  Data                     Pointer to the converted value.

      @retval RETURN_SUCCESS           Value is translated from String.
      @retval RETURN_INVALID_PARAMETER If String is NULL.
                                       If Data is NULL.
                                       If PcdMaximumUnicodeStringLength is not
                                       zero, and String contains more than
                                       PcdMaximumUnicodeStringLength Unicode
                                       characters, not including the
                                       Null-terminator.
      @retval RETURN_UNSUPPORTED       If the number represented by String exceeds
                                   the range defined by UINT64.
    """
    Status = RETURN_SUCCESS
    assert (ord(Str[0]) & BIT0 == 0)
    # 1. Neither String nor Data shall be a null pointer.
    if not Str:
        return RETURN_UNSUPPORTED
    # 2. The length of String shall not be greater than RSIZE_MAX.
    if len(Str) > RSIZE_MAX:
        return RETURN_UNSUPPORTED

    # Ignore the pad spaces (space or tab)
    Index = 0
    if EndPointer != None:
        EndPointer = Index

    while Str[Index] == ' ' or Str[Index] == '\t':
        Index += 1

    # Ignore leading Zeros after the spaces
    while Str[Index] == '0':
        Index += 1
    Data = 0
    if Str[Index].upper() == 'X':
        if (Str[Index - 1]) != '0':
            Data = 0
            return RETURN_SUCCESS
        Index += 1
    Data = 0
    while InternalIsHexaDecimalDigitCharacter(Str[Index]):
        if Data > ((MAX_UINT64 - InternalHexCharToUintn(Str[Index])) >> 4):
            Data = MAX_UINT64
            if EndPointer != None:
                EndPointer = Index
            return RETURN_UNSUPPORTED
        Data = (Data << 4) + InternalHexCharToUintn(Str[Index])
        Index += 1

    if EndPointer != None:
        EndPointer = Index

    return Status, Data, EndPointer


def StrToIpv4Address(Str: str, PrefixLength=None):
    Addr = EFI_IPv4_ADDRESS()
    assert (ord(Str[0]) & BIT0 == 0)
    if not Str:
        # logger.error("Invalid parameter")
        raise Exception('Invalid parameter: Str is empty')
    AddressIndex = 0
    while AddressIndex < sizeof(EFI_IPv4_ADDRESS) + 1:
        if not InternalIsDecimalDigitCharacter(Str[AddressIndex]):
            break
        Uint64 = None
        res = StrDecimalToUint64S(Str[AddressIndex])
        if isinstance(res, int):
            Status = res
        else:
            Status = res[0]
            Uint64 = res[1]

        if EFI_ERROE(Status):
            raise Exception('Unsupported')

        LocalPrefixLength = None
        if AddressIndex == sizeof(EFI_IPv4_ADDRESS):
            if Uint64 > 32:
                raise Exception('Unsupported')
            LocalPrefixLength = c_uint8(Uint64).value
        else:
            if Uint64 > MAX_UINT8:
                raise Exception('Unsupported')
            Addr[AddressIndex] = c_uint8(Uint64).value
            AddressIndex += 1
        # Check the '.' or '/', depending on the AddressIndex.
        if AddressIndex == sizeof(EFI_IPv4_ADDRESS):
            if Str[AddressIndex] == '/':
                AddressIndex += 1
            else:
                break
        elif AddressIndex < sizeof(EFI_IPv4_ADDRESS):
            if Str[AddressIndex] == '.':
                AddressIndex += 1
            else:
                raise Exception('Unsupported')

        if AddressIndex < sizeof(EFI_IPv4_ADDRESS):
            raise Exception('Unsupported')

        if PrefixLength != None:
            PrefixLength = LocalPrefixLength

    return Addr


def StrToIpv6Address(Str: str, EndPointer=None, PrefixLength=None):
    Address = EFI_IPv6_ADDRESS()
    Status = RETURN_SUCCESS

    LocalPrefixLength = MAX_UINT8
    CompressStart = sizeof(EFI_IPv4_ADDRESS)
    ExpectPrefix = False

    assert (ord(Str[0]) & BIT0 == 0)
    # None of String or Guid shall be a null pointer.
    if not Str:
        raise Exception('Invalid parameter: Str is empty')

    AddressIndex = 0
    while AddressIndex < CompressStart + 1:
        if not InternalIsHexaDecimalDigitCharacter(Str[AddressIndex]):
            if Str[AddressIndex] == ':':
                raise Exception('Unsupported')

            if ExpectPrefix:
                raise Exception('Unsupported')

            if CompressStart != sizeof(EFI_IPv4_ADDRESS) or AddressIndex == sizeof(EFI_IPv4_ADDRESS):
                return RETURN_UNSUPPORTED
            else:
                CompressStart = AddressIndex
                AddressIndex += 1
                if CompressStart == 0:
                    if Str[AddressIndex] != ':':
                        raise Exception('Unsupported')
                    AddressIndex += 1
        if not InternalIsHexaDecimalDigitCharacter(Str[AddressIndex]):
            if Str[AddressIndex] == '/':
                if CompressStart != AddressIndex:
                    raise Exception('Unsupported')
            else:
                break
        else:
            if not ExpectPrefix:
                Uint64 = None
                res = StrHexToUint64S(Str[AddressIndex], EndPointer)
                if isinstance(res, int):
                    Status = res
                else:
                    Status = res[0]
                    Uint64 = res[1]
                    EndPointer = res[2]
                if EFI_ERROR(Status) or EndPointer - AddressIndex > 4:
                    raise Exception('Unsupported')

                AddressIndex = EndPointer
                # Uint64 won't exceed MAX_UINT16 if number of hexadecimal digit characters is no more than 4.
                assert (AddressIndex + 1 < sizeof(EFI_IPv6_ADDRESS))
                Address[AddressIndex] = c_uint8(c_uint16(Uint64 >> 8).value).value
                Address[AddressIndex + 1] = c_uint8(Uint64).value
                AddressIndex += 2
            else:
                Uint64 = None
                res = StrDecimalToUint64S(Str[AddressIndex], True)
                if isinstance(res, int):
                    Status = res
                else:
                    Status = res[0]
                    Uint64 = res[1]
                    EndPointer = res[2]
                if EFI_ERROR(Status) or EndPointer == AddressIndex or Uint64 > 128:
                    raise Exception('Unsupported')
                LocalPrefixLength = c_uint8(Uint64).value
                AddressIndex = EndPointer
                break

        # Skip ':' or "/"
        if Str[AddressIndex] == '/':
            ExpectPrefix = True
        elif Str[AddressIndex] == ':':
            if AddressIndex == sizeof(EFI_IPv6_ADDRESS):
                break
        else:
            break
        AddressIndex += 1

    if AddressIndex == sizeof(EFI_IPv6_ADDRESS) and CompressStart != sizeof(EFI_IPv6_ADDRESS) or (
            AddressIndex != sizeof(EFI_IPv6_ADDRESS) and CompressStart == sizeof(EFI_IPv6_ADDRESS)):
        raise Exception('Unsupported')

    # Full length of address shall not have compressing zeros.
    # Non-full length of address shall have compressing zeros.
    # Address = EFI_IPv6_ADDRESS() deafult value is zeros

    if PrefixLength != None:
        PrefixLength = LocalPrefixLength

    if EndPointer != None:
        EndPointer = AddressIndex

    return Address, EndPointer


def IS_NULL(Str: str):
    return Str == '\0'


def DevPathFromTextIPv4(TextDeviceNode: str) -> IPv4_DEVICE_PATH:
    IPv4 = IPv4_DEVICE_PATH()
    RemoteIPStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    ProtocolStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    TypeStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    LocalIPStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    GatewayIPStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    SubnetMaskStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    IPv4.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_IPv4_DP, sizeof(IPv4_DEVICE_PATH))

    res = StrToIpv4Address(RemoteIPStr)
    if isinstance(res, int):
        pass
    else:
        IPv4.RemoteIpAddress = res[1]
    IPv4.Protocol = NetworkProtocolFromText(ProtocolStr)
    if TypeStr == 'Static':
        IPv4.StaticIpAddress = True
    else:
        IPv4.StaticIpAddress = False

    res = StrToIpv4Address(LocalIPStr)
    if isinstance(res, int):
        pass
    else:
        IPv4.LocalIpAddress = res[1]
    if IS_NULL(GatewayIPStr) and IS_NULL(SubnetMaskStr):

        IPv4.GatewayIpAddress = StrToIpv4Address(GatewayIPStr)
        IPv4.SubnetMask = StrToIpv4Address(SubnetMaskStr)
    else:
        IPv4.GatewayIpAddress = StrToIpv4Address('0.0.0.0.')
        IPv4.GatewayIpAddress = StrToIpv4Address('0.0.0.0.')
    IPv4.LocalPort = 0
    IPv4.RemotePort = 0
    return IPv4


def DevPathFromTextIPv6(TextDeviceNode: str) -> IPv6_DEVICE_PATH:
    IPv6 = IPv6_DEVICE_PATH()
    RemoteIPStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    ProtocolStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    TypeStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    LocalIPStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    PrefixLengthStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    GatewayIPStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    IPv6.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_IPv6_DP, sizeof(IPv6_DEVICE_PATH))

    IPv6.RemoteIpAddress = StrToIpv6Address(RemoteIPStr)[0]
    IPv6.Protocol = NetworkProtocolFromText(ProtocolStr)
    if TypeStr == 'Static':
        IPv6.IpAddressOrigin = 0
    elif TypeStr == 'StatelessAutoConfigure':
        IPv6.IpAddressOrigin = 1
    else:
        IPv6.IpAddressOrigin = 2
    # StrToIpv6Address (LocalIPStr, NULL, &IPv6->LocalIpAddress, NULL);
    IPv6.LocalIpAddress = StrToIpv6Address(LocalIPStr)[0]
    if IS_NULL(GatewayIPStr) == 0 and IS_NULL(PrefixLengthStr) == 0:
        # StrToIpv6Address (GatewayIPStr, NULL, &IPv6->GatewayIpAddress, NULL);
        IPv6.GatewayIpAddress = StrToIpv6Address(GatewayIPStr)[0]
        IPv6.PrefixLength = StrToIpv6Address(PrefixLengthStr)[0]
    else:
        # IPv6.GatewayIpAddress = StrToIpv6Address('0.0.0.0.0.0') deafult is zeros
        IPv6.PrefixLength = 0
    IPv6.LocalPort = 0
    IPv6.RemotePort = 0
    return IPv6


def DevPathFromTextUart(TextDeviceNode: str) -> UART_DEVICE_PATH:
    Uart = UART_DEVICE_PATH()
    BaudStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    DataBitsStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    ParityStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    StopBitsStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    Uart.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_UART_DP, sizeof(UART_DEVICE_PATH))
    if BaudStr == 'DEFAULT':
        Uart.BaudRate = 115200
    else:
        Uart.BaudRate = Strtoi(BaudStr)

    Uart.DataBits = 8 if DataBitsStr == 'DEFAULT' else Strtoi(DataBitsStr)
    if ParityStr == 'D':
        Uart.Parity = 0
    elif ParityStr == 'N':
        Uart.Parity = 1
    elif ParityStr == 'E':
        Uart.Parity = 2
    elif ParityStr == 'O':
        Uart.Parity = 3
    elif ParityStr == 'M':
        Uart.Parity = 4
    elif ParityStr == 'S':
        Uart.Parity = 5
    else:
        Uart.Parity = Strtoi(ParityStr)
    if StopBitsStr == 'D':
        Uart.StopBits = 0
    elif StopBitsStr == '1':
        Uart.StopBits = 1
    elif StopBitsStr == '1.5':
        Uart.StopBits = 2
    else:
        Uart.StopBits = Strtoi(StopBitsStr)

    return Uart


def ConvertFromTextUsbClass(TextDeviceNode: str, UsbClassText: USB_CLASS_TEXT):
    UsbClass = USB_CLASS_DEVICE_PATH()
    VIDStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    PIDStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    if UsbClassText.ClassExist:
        ClassStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
        if ClassStr == '\0':
            UsbClass.DeviceClass = 0xFF
        else:
            UsbClass.DeviceClass = Strtoi(ClassStr)
    else:
        UsbClass.DeviceClass = UsbClassText.Class

    if UsbClassText.SubClassExist:
        SubClassStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
        if SubClassStr == '\0':
            UsbClass.DeviceClass = 0xFF
        else:
            UsbClass.DeviceClass = Strtoi(SubClassStr)
    else:
        UsbClass.DeviceSubClass = UsbClassText.SubClass

    ProtocolStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    if PIDStr == '\0':
        UsbClass.ProductId = 0xFFFF
    else:
        UsbClass.ProductId = Strtoi(PIDStr)
    if ProtocolStr == '\0':
        UsbClass.DeviceProtocol = 0xFF
    else:
        UsbClass.DeviceProtocol = Strtoi(ProtocolStr)
    return UsbClass


def DevPathFromTextUsbClass(TextDeviceNode: str) -> USB_CLASS_DEVICE_PATH:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist = True
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass(TextDeviceNode, UsbClassText)


def DevPathFromTextUsbAudio(TextDeviceNode: str) -> USB_CLASS_DEVICE_PATH:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist = False
    UsbClassText.Class = USB_CLASS_AUDIO
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass(TextDeviceNode, UsbClassText)


def DevPathFromTextUsbCDCControl(TextDeviceNode: str) -> USB_CLASS_DEVICE_PATH:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist = False
    UsbClassText.Class = USB_CLASS_CDCCONTROL
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass(TextDeviceNode, UsbClassText)


def DevPathFromTextUsbHID(TextDeviceNode: str) -> USB_CLASS_DEVICE_PATH:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist = False
    UsbClassText.Class = USB_CLASS_HID
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass(TextDeviceNode, UsbClassText)


def DevPathFromTextUsbImage(TextDeviceNode: str) -> USB_CLASS_DEVICE_PATH:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist = False
    UsbClassText.Class = USB_CLASS_IMAGE
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass(TextDeviceNode, UsbClassText)


def DevPathFromTextUsbPrinter(TextDeviceNode: str) -> USB_CLASS_DEVICE_PATH:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist = False
    UsbClassText.Class = USB_CLASS_PRINTER
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass(TextDeviceNode, UsbClassText)


def DevPathFromTextUsbMassStorage(TextDeviceNode: str) -> USB_CLASS_DEVICE_PATH:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist = False
    UsbClassText.Class = USB_CLASS_MASS_STORAGE
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass(TextDeviceNode, UsbClassText)


def DevPathFromTextUsbHub(TextDeviceNode: str) -> USB_CLASS_DEVICE_PATH:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist = False
    UsbClassText.Class = USB_CLASS_HUB
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass(TextDeviceNode, UsbClassText)


def DevPathFromTextUsbCDCData(TextDeviceNode: str) -> USB_CLASS_DEVICE_PATH:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist = False
    UsbClassText.Class = USB_CLASS_CDCDATA
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass(TextDeviceNode, UsbClassText)


def DevPathFromTextUsbSmartCard(TextDeviceNode: str) -> USB_CLASS_DEVICE_PATH:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist = False
    UsbClassText.Class = USB_CLASS_SMART_CARD
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass(TextDeviceNode, UsbClassText)


def DevPathFromTextUsbVideo(TextDeviceNode: str) -> USB_CLASS_DEVICE_PATH:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist = False
    UsbClassText.Class = USB_CLASS_VIDEO
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass(TextDeviceNode, UsbClassText)


def DevPathFromTextUsbDiagnostic(TextDeviceNode: str) -> USB_CLASS_DEVICE_PATH:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist = False
    UsbClassText.Class = USB_CLASS_DIAGNOSTIC
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass(TextDeviceNode, UsbClassText)


def DevPathFromTextUsbWireless(TextDeviceNode: str) -> USB_CLASS_DEVICE_PATH:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist = False
    UsbClassText.Class = USB_CLASS_WIRELESS
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass(TextDeviceNode, UsbClassText)


def DevPathFromTextUsbDeviceFirmwareUpdate(TextDeviceNode: str) -> USB_CLASS_DEVICE_PATH:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist = False
    UsbClassText.Class = USB_CLASS_RESERVE
    UsbClassText.SubClassExist = False
    UsbClassText.SubClass = USB_SUBCLASS_FW_UPDATE
    return ConvertFromTextUsbClass(TextDeviceNode, UsbClassText)


def DevPathFromTextUsbIrdaBridge(TextDeviceNode: str) -> USB_CLASS_DEVICE_PATH:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist = False
    UsbClassText.Class = USB_CLASS_RESERVE
    UsbClassText.SubClassExist = False
    UsbClassText.SubClass = USB_SUBCLASS_IRDA_BRIDGE
    return ConvertFromTextUsbClass(TextDeviceNode, UsbClassText)


def DevPathFromTextUsbTestAndMeasurement(TextDeviceNode: str) -> USB_CLASS_DEVICE_PATH:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist = False
    UsbClassText.Class = USB_CLASS_RESERVE
    UsbClassText.SubClassExist = False
    UsbClassText.SubClass = USB_SUBCLASS_TEST
    return ConvertFromTextUsbClass(TextDeviceNode, UsbClassText)


def DevPathFromTextUsbWwid(TextDeviceNode: str) -> USB_WWID_DEVICE_PATH:
    UsbWwid = USB_WWID_DEVICE_PATH()
    VIDStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    PIDStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    InterfaceNumStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    SerialNumberStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    SerialNumberStrLen = len(SerialNumberStr)
    if SerialNumberStrLen >= 2 and SerialNumberStr[0] == '\"' and SerialNumberStr[SerialNumberStrLen - 1] == '\"':
        Index = SerialNumberStrLen - 1
        SerialNumberStr[Index] = '\0'
        Index += 1
        SerialNumberStrLen -= 2
    UsbWwid.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_USB_WWID_DP,
                                      sizeof(USB_WWID_DEVICE_PATH) + SerialNumberStrLen * sizeof(c_ushort))
    UsbWwid.VendorId = Strtoi(VIDStr)
    UsbWwid.ProductId = Strtoi(PIDStr)
    UsbWwid.InterfaceNumber = Strtoi(InterfaceNumStr)
    return UsbWwid


def DevPathFromTextUnit(TextDeviceNode: str) -> DEVICE_LOGICAL_UNIT_DEVICE_PATH:
    LogicalUnit = DEVICE_LOGICAL_UNIT_DEVICE_PATH()
    LunStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    LogicalUnit.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_DEVICE_LOGICAL_UNIT_DP,
                                          sizeof(DEVICE_LOGICAL_UNIT_DEVICE_PATH))
    LogicalUnit.Lun = Strtoi(LunStr)
    return LogicalUnit


def DevPathFromTextiSCSI(TextDeviceNode: str) -> ISCSI_DEVICE_PATH_WITH_NAME:
    ISCSIDevPath = ISCSI_DEVICE_PATH_WITH_NAME()
    NameStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    PortalGroupStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    LunStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    HeaderDigestStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    DataDigestStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    AuthenticationStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    ProtocolStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    ISCSIDevPath.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_ISCSI_DP,
                                           sizeof(ISCSI_DEVICE_PATH_WITH_NAME) + len(NameStr))
    ISCSIDevPath.TargetName = NameStr
    ISCSIDevPath.TargetPortalGroupTag = Strtoi(PortalGroupStr)
    ISCSIDevPath.Lun = LunStr
    Options = 0x0000
    if HeaderDigestStr == 'CRC32C':
        Options |= 0x0002
    if DataDigestStr == 'CRC32C':
        Options |= 0x0008
    if AuthenticationStr == 'None':
        Options |= 0x0800
    if AuthenticationStr == 'CHAP_UNI':
        Options |= 0x1000
    ISCSIDevPath.LoginOption = Options

    if IS_NULL(ProtocolStr) or ProtocolStr == 'TCP':
        ISCSIDevPath.NetworkProtocol = 0
    else:
        ISCSIDevPath.NetworkProtocol = 1
    return ISCSIDevPath


def DevPathFromTextVlan(TextDeviceNode: str) -> VLAN_DEVICE_PATH:
    Vlan = VLAN_DEVICE_PATH()
    VlanStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    Vlan.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_VLAN_DP, sizeof(VLAN_DEVICE_PATH))
    Vlan.VlanId = Strtoi(VlanStr)
    return Vlan


def DevPathFromTextDns(TextDeviceNode: str) -> EFI_DEVICE_PATH_PROTOCOL:
    # DnsDeviceNode = DNS_DEVICE_PATH()
    # Count the DNS server address number.
    DeviceNodeStr = TextDeviceNode
    if not DeviceNodeStr:
        return None
    DeviceNodeStrPtr = DeviceNodeStr
    DnsServerIpCount = 0
    while DeviceNodeStrPtr:
        paramStr, DeviceNodeStrPtr = GetNextParamStr(DeviceNodeStrPtr)
        DnsServerIpCount += 1

    if DnsServerIpCount == 0:
        return None
    DnsDeviceNode = Get_DNS_DEVICE_PATH(DnsServerIpCount)

    DnsDeviceNodeLength = sizeof(EFI_DEVICE_PATH_PROTOCOL) + sizeof(c_uint8) + DnsServerIpCount * sizeof(EFI_IP_ADDRESS)
    DnsDeviceNode.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_DNS_DP, DnsDeviceNodeLength)

    # Confirm the DNS server address is IPv4 or IPv6 type.
    DeviceNodeStrPtr = TextDeviceNode
    for ch in DeviceNodeStrPtr:
        if ch == '.':
            DnsDeviceNode.IsIPv6 = 0x00
            break
        if ch == ':':
            DnsDeviceNode.IsIPv6 = 0x01
            break

    for DnsServerIpIndex in range(DnsServerIpCount):
        DnsServerIp, TextDeviceNode = GetNextParamStr(TextDeviceNode)
        if DnsDeviceNode.IsIPv6 == 0x00:
            DnsDeviceNode.DnsServerIp[DnsServerIpIndex].v4 = StrToIpv4Address(DnsServerIp)
        else:
            DnsDeviceNode.DnsServerIp[DnsServerIpIndex].v6 = StrToIpv6Address(DnsServerIp)[0]

    return DnsDeviceNode


def StrnLenS(Str: str, MaxSize=0):
    if not Str or MaxSize == 0:
        return 0
    length = len(Str)
    if length > MaxSize - 1:
        return MaxSize
    return length


def DevPathFromTextUri(TextDeviceNode: str):
    UriStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    UriLength = StrnLenS(UriStr, MAX_UINT16 - sizeof(EFI_DEVICE_PATH_PROTOCOL) * 2)
    UriNode = Get_URI_DEVICE_PATH(UriLength)
    UriNode.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_URI_DP, sizeof(EFI_DEVICE_PATH_PROTOCOL) + UriLength)
    while UriLength - 1 != 0:
        UriNode.Uri[UriLength] = UriStr[UriLength]
        UriLength -= 1
    return UriNode


def DevPathFromTextBluetooth(TextDeviceNode: str) -> BLUETOOTH_DEVICE_PATH:
    BluetoothDp = BLUETOOTH_DEVICE_PATH()
    BluetoothStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    BluetoothDp.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_BLUETOOTH_DP, sizeof(BLUETOOTH_DEVICE_PATH))
    BluetoothDp.BD_ADDR.Address = BluetoothStr.encode()
    return BluetoothDp


def DevPathFromTextWiFi(TextDeviceNode: str) -> WIFI_DEVICE_PATH:
    WiFiDp = WIFI_DEVICE_PATH()
    SSIdStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    WiFiDp.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_WIFI_DP, sizeof(WIFI_DEVICE_PATH))
    if SSIdStr:
        DataLen = len(SSIdStr)
        if len(SSIdStr) > 32:
            SSIdStr[32] = '\0'
            DataLen = 32
        SSIdStr = SSIdStr.encode()
        for i in range(DataLen):
            WiFiDp.SSId[i] = SSIdStr[i]
    return WiFiDp


def DevPathFromTextBluetoothLE(TextDeviceNode: str) -> BLUETOOTH_LE_DEVICE_PATH:
    BluetoothLeDp = BLUETOOTH_LE_DEVICE_PATH()
    BluetoothLeAddrStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    BluetoothLeAddrTypeStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    BluetoothLeDp.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_BLUETOOTH_LE_DP,
                                            sizeof(BLUETOOTH_LE_DEVICE_PATH))
    BluetoothLeDp.Address.Type = Strtoi(BluetoothLeAddrTypeStr)
    BluetoothLeAddrStr = BluetoothLeAddrStr.encode()
    for i in range(len(BluetoothLeAddrStr)):
        BluetoothLeDp.Address.Address[i] = BluetoothLeAddrStr[i]
    return BluetoothLeDp


def DevPathFromTextMediaPath(TextDeviceNode: str) -> EFI_DEVICE_PATH_PROTOCOL:
    return DevPathFromTextGenericPath(MEDIA_DEVICE_PATH, TextDeviceNode)


def DevPathFromTextHD(TextDeviceNode: str) -> HARDDRIVE_DEVICE_PATH:
    Hd = HARDDRIVE_DEVICE_PATH()
    PartitionStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    TypeStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    SignatureStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    StartStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    SizeStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    Hd.Header = CreateDeviceNode(MEDIA_DEVICE_PATH, MEDIA_HARDDRIVE_DP, sizeof(HARDDRIVE_DEVICE_PATH))
    Hd.PartitionNumber = Strtoi(PartitionStr)
    # for i in range(16):
    #     Hd.Signature[i] = 0
    Hd.MBRType = 0
    if TypeStr == 'MBR':
        Hd.SignatureType = SIGNATURE_TYPE_MBR
        Hd.MBRType = 0x01
        Signature32 = Strtoi(SignatureStr)
        # for i in range(len(SignatureStr)):
        Hd.Signature.Data1 = Signature32
    elif TypeStr == 'GPT':
        Hd.SignatureType = SIGNATURE_TYPE_GUID
        Hd.MBRType = 0x02
        Hd.Signature = ModifyGuidFormat(SignatureStr)
    else:
        Hd.SignatureType = Strtoi(TypeStr)
    Hd.PartitionStart = Strtoi(StartStr)
    Hd.PartitionSize = Strtoi(SizeStr)
    return Hd


def DevPathFromTextCDROM(TextDeviceNode: str) -> CDROM_DEVICE_PATH:
    CDROMDevPath = CDROM_DEVICE_PATH()
    EntryStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    StartStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    SizeStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    CDROMDevPath.Header = CreateDeviceNode(MEDIA_DEVICE_PATH, MEDIA_CDROM_DP, sizeof(CDROM_DEVICE_PATH))
    CDROMDevPath.BootEntry = Strtoi(EntryStr)
    CDROMDevPath.PartitionStart = Strtoi(StartStr)
    CDROMDevPath.PartitionSize = Strtoi(SizeStr)
    return CDROMDevPath


def DevPathFromTextVenMedia(TextDeviceNode: str) -> VENDOR_DEVICE_PATH:
    return ConvertFromTextVendor(TextDeviceNode, MEDIA_DEVICE_PATH, MEDIA_VENDOR_DP)


def DevPathFromTextMedia(TextDeviceNode: str) -> MEDIA_PROTOCOL_DEVICE_PATH:
    Media = MEDIA_PROTOCOL_DEVICE_PATH()
    GuidStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    Media.Header = CreateDeviceNode(MEDIA_DEVICE_PATH, MEDIA_PROTOCOL_DP, sizeof(MEDIA_PROTOCOL_DEVICE_PATH))
    Media.Protocol = ModifyGuidFormat(GuidStr)
    return Media


def DevPathFromTextFv(TextDeviceNode: str) -> MEDIA_FW_VOL_DEVICE_PATH:
    Fv = MEDIA_FW_VOL_DEVICE_PATH()
    GuidStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    Fv.Header = CreateDeviceNode(MEDIA_DEVICE_PATH, MEDIA_PIWG_FW_VOL_DP, sizeof(MEDIA_FW_VOL_DEVICE_PATH))
    Fv.FvName = ModifyGuidFormat(GuidStr)
    return Fv


def DevPathFromTextFvFile(TextDeviceNode: str) -> MEDIA_FW_VOL_FILEPATH_DEVICE_PATH:
    FvFile = MEDIA_FW_VOL_FILEPATH_DEVICE_PATH()
    GuidStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    FvFile.Header = CreateDeviceNode(MEDIA_DEVICE_PATH, MEDIA_PIWG_FW_FILE_DP, sizeof(MEDIA_FW_VOL_DEVICE_PATH))
    FvFile.FvName = ModifuGuidFormat(GuidStr)
    return FvFile


def DevPathFromTextRelativeOffsetRange(TextDeviceNode: str) -> MEDIA_RELATIVE_OFFSET_RANGE_DEVICE_PATH:
    Offset = MEDIA_RELATIVE_OFFSET_RANGE_DEVICE_PATH()
    StartingOffsetStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    EndingOffsetStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    Offset.Header = CreateDeviceNode(MEDIA_DEVICE_PATH, MEDIA_RELATIVE_OFFSET_RANGE_DP,
                                     sizeof(MEDIA_RELATIVE_OFFSET_RANGE_DEVICE_PATH))
    Offset.StartingOffset = Strtoi(StartingOffsetStr)
    Offset.EndingOffset = Strtoi(EndingOffsetStr)

    return Offset


def DevPathFromTextRamDisk(TextDeviceNode: str) -> MEDIA_RAM_DISK_DEVICE_PATH:
    RamDisk = MEDIA_RAM_DISK_DEVICE_PATH()
    StartingAddrStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    EndingAddrStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    InstanceStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    TypeGuidStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    RamDisk.Header = CreateDeviceNode(MEDIA_DEVICE_PATH, MEDIA_RAM_DISK_DP, sizeof(MEDIA_RAM_DISK_DEVICE_PATH))
    StartingAddrStr = Strtoi(StartingAddrStr)
    RamDisk.StartingAddr = StartingAddrStr
    EndingAddrStr = Strtoi(EndingAddrStr)
    RamDisk.Instance = EndingAddrStr
    RamDisk.TypeGuid = ModifyGuidFormat(TypeGuidStr)
    return RamDisk


def CreateMediaRamDiskDevicePath(TextDeviceNode: str, guid: GUID) -> MEDIA_RAM_DISK_DEVICE_PATH:
    RamDisk = MEDIA_RAM_DISK_DEVICE_PATH()
    StartingAddrStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    EndingAddrStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    InstanceStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    RamDisk.Header = CreateDeviceNode(MEDIA_DEVICE_PATH, MEDIA_RAM_DISK_DP, sizeof(MEDIA_RAM_DISK_DEVICE_PATH))
    # TODO: Three parm is list, Need review?
    RamDisk.StartingAddr = Strtoi(StartingAddrStr)
    RamDisk.EndingAddr = Strtoi(EndingAddrStr)
    RamDisk.Instance = Strtoi(InstanceStr)
    RamDisk.TypeGuid = guid
    return RamDisk


gEfiVirtualDiskGuid = GUID(0x77AB535A, 0x45FC, 0x624B, (0x55, 0x60, 0xF7, 0xB2, 0x81, 0xD1, 0xF9, 0x6E))


def DevPathFromTextVirtualDisk(TextDeviceNode: str) -> MEDIA_RAM_DISK_DEVICE_PATH:
    return CreateMediaRamDiskDevicePath(TextDeviceNode, gEfiVirtualDiskGuid)


gEfiVirtualCdGuid = GUID(0x3D5ABD30, 0x4175, 0x87CE, (0x6D, 0x64, 0xD2, 0xAD, 0xE5, 0x23, 0xC4, 0xBB))


def DevPathFromTextVirtualCd(TextDeviceNode: str) -> MEDIA_RAM_DISK_DEVICE_PATH:
    return CreateMediaRamDiskDevicePath(TextDeviceNode, gEfiVirtualCdGuid)



gEfiPersistentVirtualDiskGuid = GUID(0x5CEA02C9, 0x4D07, 0x69D3, (0x26, 0x9F, 0x44, 0x96, 0xFB, 0xE0, 0x96, 0xF9))


def DevPathFromTextPersistentVirtualDisk(TextDeviceNode: str) -> MEDIA_RAM_DISK_DEVICE_PATH:
    return CreateMediaRamDiskDevicePath(TextDeviceNode, gEfiPersistentVirtualDiskGuid)



gEfiPersistentVirtualCdGuid = GUID(0x08018188, 0x42CD, 0xBB48, (0x10, 0x0F, 0x53, 0x87, 0xD5, 0x3D, 0xED, 0x3D))


def DevPathFromTextPersistentVirtualCd(TextDeviceNode: str) -> MEDIA_RAM_DISK_DEVICE_PATH:
    return CreateMediaRamDiskDevicePath(TextDeviceNode, gEfiPersistentVirtualDiskGuid)


def DevPathFromTextBbsPath(TextDeviceNode: str) -> EFI_DEVICE_PATH_PROTOCOL:
    return DevPathFromTextGenericPath(BBS_DEVICE_PATH, TextDeviceNode)


def DevPathFromTextBBS(TextDeviceNode: str) -> BBS_BBS_DEVICE_PATH:
    Bbs = BBS_BBS_DEVICE_PATH()
    TypeStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    IdStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    FlagsStr, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    Bbs.Header = CreateDeviceNode(BBS_DEVICE_PATH, BBS_BBS_DP, sizeof(BBS_BBS_DEVICE_PATH) + len(IdStr))
    if TypeStr == 'Floppy':
        Bbs.DeviceType = BBS_TYPE_FLOPPY
    elif TypeStr == 'HD':
        Bbs.DeviceType = BBS_TYPE_HARDDRIVE
    elif TypeStr == 'CDROM':
        Bbs.DeviceType = BBS_TYPE_CDROM
    elif TypeStr == 'PCMCIA':
        Bbs.DeviceType = BBS_TYPE_PCMCIA
    elif TypeStr == 'USB':
        Bbs.DeviceType = BBS_TYPE_USB
    elif TypeStr == 'Network':
        Bbs.DeviceType = BBS_TYPE_EMBEDDED_NETWORK
    else:
        Bbs.DeviceType = Strtoi(TypeStr)
    Bbs.String[0] = IdStr
    Bbs.StatusFlag = Strtoi(TypeStr)
    return Bbs


def DevPathFromTextSata(TextDeviceNode: str) -> SATA_DEVICE_PATH:
    Sata = SATA_DEVICE_PATH()
    Param1, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    Param2, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    Param3, TextDeviceNode = GetNextParamStr(TextDeviceNode)
    Sata.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH, MSG_SATA_DP, sizeof(SATA_DEVICE_PATH))
    Sata.HBAPortNumber = Strtoi(Param1)
    if Param2 == '\0':
        Sata.PortMultiplierPortNumber = 0xFFFF
    else:
        Sata.PortMultiplierPortNumber = Strtoi(Param2)
    Sata.Lun = Strtoi(Param3)
    return Sata


mUefiDevicePathLibDevPathFromTextList = [
    ("Path", DevPathFromTextPath),
    ("HardwarePath", DevPathFromTextHardwarePath),
    ("Pci", DevPathFromTextPci),
    ("PcCard", DevPathFromTextPcCard),
    ("MemoryMapped", DevPathFromTextMemoryMapped),
    ("VenHw", DevPathFromTextVenHw),
    ("Ctrl", DevPathFromTextCtrl),
    ("BMC", DevPathFromTextBmc),

    ("AcpiPath", DevPathFromTextAcpiPath),
    ("Acpi", DevPathFromTextAcpi),
    ("PciRoot", DevPathFromTextPciRoot),
    ("PcieRoot", DevPathFromTextPcieRoot),
    ("Floppy", DevPathFromTextFloppy),
    ("Keyboard", DevPathFromTextKeyboard),
    ("Serial", DevPathFromTextSerial),
    ("ParallelPort", DevPathFromTextParallelPort),
    ("AcpiEx", DevPathFromTextAcpiEx),
    ("AcpiExp", DevPathFromTextAcpiExp),
    ("AcpiAdr", DevPathFromTextAcpiAdr),

    ("Msg", DevPathFromTextMsg),
    ("Ata", DevPathFromTextAta),
    ("Scsi", DevPathFromTextScsi),
    ("Fibre", DevPathFromTextFibre),
    ("FibreEx", DevPathFromTextFibreEx),
    ("I1394", DevPathFromText1394),
    ("USB", DevPathFromTextUsb),
    ("I2O", DevPathFromTextI2O),
    ("Infiniband", DevPathFromTextInfiniband),
    ("VenMsg", DevPathFromTextVenMsg),
    ("VenPcAnsi", DevPathFromTextVenPcAnsi),
    ("VenVt100", DevPathFromTextVenVt100),
    ("VenVt100Plus", DevPathFromTextVenVt100Plus),
    ("VenUtf8", DevPathFromTextVenUtf8),
    ("UartFlowCtrl", DevPathFromTextUartFlowCtrl),
    ("SAS", DevPathFromTextSAS),
    ("SasEx", DevPathFromTextSasEx),
    ("NVMe", DevPathFromTextNVMe),
    ("UFS", DevPathFromTextUfs),
    ("SD", DevPathFromTextSd),
    ("eMMC", DevPathFromTextEmmc),
    ("DebugPort", DevPathFromTextDebugPort),
    ("MAC", DevPathFromTextMAC),

    ("IPv4", DevPathFromTextIPv4),
    ("IPv6", DevPathFromTextIPv6),
    ("Uart", DevPathFromTextUart),
    ("UsbClass", DevPathFromTextUsbClass),
    ("UsbAudio", DevPathFromTextUsbAudio),
    ("UsbCDCControl", DevPathFromTextUsbCDCControl),
    ("UsbHID", DevPathFromTextUsbHID),
    ("UsbImage", DevPathFromTextUsbImage),
    ("UsbPrinter", DevPathFromTextUsbPrinter),
    ("UsbMassStorage", DevPathFromTextUsbMassStorage),
    ("UsbHub", DevPathFromTextUsbHub),
    ("UsbCDCData", DevPathFromTextUsbCDCData),
    ("UsbSmartCard", DevPathFromTextUsbSmartCard),
    ("UsbVideo", DevPathFromTextUsbVideo),
    ("UsbDiagnostic", DevPathFromTextUsbDiagnostic),
    ("UsbWireless", DevPathFromTextUsbWireless),
    ("UsbDeviceFirmwareUpdate", DevPathFromTextUsbDeviceFirmwareUpdate),
    ("UsbIrdaBridge", DevPathFromTextUsbIrdaBridge),
    ("UsbTestAndMeasurement", DevPathFromTextUsbTestAndMeasurement),
    ("UsbWwid", DevPathFromTextUsbWwid),
    ("Unit", DevPathFromTextUnit),
    ("iSCSI", DevPathFromTextiSCSI),
    ("Vlan", DevPathFromTextVlan),
    ("Dns", DevPathFromTextDns),
    ("Uri", DevPathFromTextUri),
    ("Bluetooth", DevPathFromTextBluetooth),
    ("Wi-Fi", DevPathFromTextWiFi),
    ("BluetoothLE", DevPathFromTextBluetoothLE),
    ("MediaPath", DevPathFromTextMediaPath),
    ("HD", DevPathFromTextHD),
    ("CDROM", DevPathFromTextCDROM),
    ("VenMedia", DevPathFromTextVenMedia),
    ("Media", DevPathFromTextMedia),
    ("Fv", DevPathFromTextFv),
    ("FvFile", DevPathFromTextFvFile),
    ("Offset", DevPathFromTextRelativeOffsetRange),
    ("RamDisk", DevPathFromTextRamDisk),
    ("VirtualDisk", DevPathFromTextVirtualDisk),
    ("VirtualCD", DevPathFromTextVirtualCd),
    ("PersistentVirtualDisk", DevPathFromTextPersistentVirtualDisk),
    ("PersistentVirtualCD", DevPathFromTextPersistentVirtualCd),

    ("BbsPath", DevPathFromTextBbsPath),
    ("BBS", DevPathFromTextBBS),
    ("Sata", DevPathFromTextSata),
    (None, None)
]

mUefiDevicePathLibDevPathFromTextTable = [DEVICE_PATH_FROM_TEXT_TABLE(i[0], i[1]) for i in
                                          mUefiDevicePathLibDevPathFromTextList]


# Convert text to the binary representation of a device node
def UefiDevicePathLibConvertTextToDeviceNode(TextDeviceNode: str) -> EFI_DEVICE_PATH_PROTOCOL:
    if not TextDeviceNode:
        return None

    ParamStr = ''
    FromText = None
    DeviceNodeStr = TextDeviceNode
    Index = 0
    while mUefiDevicePathLibDevPathFromTextTable[Index].Function:
        ParamStr = GetParamByNodeName(DeviceNodeStr, mUefiDevicePathLibDevPathFromTextTable[Index].DevicePathNodeText)
        if ParamStr:
            FromText = mUefiDevicePathLibDevPathFromTextTable[Index].Function
            break
        Index = Index + 1

    if not FromText:
        FromText = DevPathFromTextFilePath
        DeviceNode = FromText(DeviceNodeStr)
    else:
        DeviceNode = FromText(ParamStr)
    return DeviceNode


def GetParamByNodeName(Str: str, NodeName: str):
    #
    # Check whether the node name matchs
    #
    NodeNameLength = len(NodeName)
    if len(Str) <= NodeNameLength:
        return None

    if Str[0:NodeNameLength] != NodeName[0:NodeNameLength]:
        return None

    if not IS_LEFT_PARENTH(Str[NodeNameLength]):
        return None

    #
    # Skip the found '(' and find first occurrence of ')'
    #
    ParamStr = Str[NodeNameLength + 1:]
    ParameterLength = 0
    Right_flag = False
    # StrPointer = ParamStr
    while not Right_flag:
        if IS_RIGHT_PARENTH(ParamStr[ParameterLength]):
            Right_flag = True
            break
        ParameterLength += 1
    if not Right_flag:
        # ')' not found
        return None

    ParamStr = ParamStr[:ParameterLength]
    return ParamStr


# Creates a new device path by appending a second device path to a first device path.
def UefiDevicePathLibAppendDevicePath(FirstDevicePath: bytearray,
                                      SecondDevicePath: bytearray) -> bytearray:
    # If there's only 1 path, just duplicate it
    if not FirstDevicePath:
        # return DuplicateDevicePath(SecondDevicePath if SecondDevicePath != None else mUefiDevicePathLibEndDevicePath)
        return SecondDevicePath if SecondDevicePath != None else bytearray(
            struct2stream(mUefiDevicePathLibEndDevicePath))

    if not SecondDevicePath:
        return FirstDevicePath

    if not IsDevicePathValid(FirstDevicePath, 0) or not IsDevicePathValid(SecondDevicePath, 0):
        return bytearray()

    # Allocate space for the combined device path. It only has one end node of
    Size1 = GetDevicePathSize(FirstDevicePath)
    Size2 = GetDevicePathSize(SecondDevicePath)
    # Size1 = len(FirstDevicePath)
    # Size2 = len(SecondDevicePath)
    Size = Size1 + Size2 + END_DEVICE_PATH_LENGTH

    NewDevicePath = bytearray(Size)

    NewDevicePath[:Size1] = FirstDevicePath[:Size1]
    NewDevicePath[Size1:] = SecondDevicePath

    return NewDevicePath


# Returns the 16-bit Length field of a device path node.
def DevicePathNodeLength(Node: bytearray) -> int:
    Node = EFI_DEVICE_PATH_PROTOCOL.from_buffer_copy(Node)
    return Node.Length[0]


def AppendDevicePath(FirstDevicePath: bytearray, SecondDevicePath: bytearray):
    return UefiDevicePathLibAppendDevicePath(FirstDevicePath, SecondDevicePath)


# Creates a new path by appending the device node to the device path.
def UefiDevicePathLibAppendDevicePathNode(DevicePath: bytearray,
                                          DevicePathNode: bytearray) -> bytearray:
    if not DevicePathNode:
        return DevicePath if DevicePath != None else bytearray(struct2stream(mUefiDevicePathLibEndDevicePath))

    # Build a Node that has a terminator on it
    NodeLength = DevicePathNodeLength(DevicePathNode)

    TempDevicePath = bytearray(NodeLength + END_DEVICE_PATH_LENGTH)
    TempDevicePath[:NodeLength] = DevicePathNode

    TempDevicePath[NodeLength:] = bytearray(struct2stream(mUefiDevicePathLibEndDevicePath))
    NewDevicePath = AppendDevicePath(DevicePath, TempDevicePath)

    return NewDevicePath


# Determine whether a given device path is valid
def IsDevicePathValid(DevicePath: bytearray, MaxSize: int) -> bool:
    if not DevicePath or (MaxSize > 0 and MaxSize < END_DEVICE_PATH_LENGTH):
        return False

    if MaxSize == 0:
        MaxSize = MAX_UINT32

    Count = 0
    Size = 0
    while not IsDevicePathEnd(DevicePath):
        NodeLength = DevicePathNodeLength(DevicePath)
        if NodeLength < sizeof(EFI_DEVICE_PATH_PROTOCOL):
            return False

        if NodeLength > MAX_UINT32 - Size:
            return False
        Size += NodeLength

        if Size > MaxSize - END_DEVICE_PATH_LENGTH:
            return False
        Count += 1
        if Count >= MAX_DEVICE_PATH_NODE_COUNT:
            return False

        DevicePath = NextDevicePathNode(DevicePath, Size)
    #
    # Only return TRUE when the End Device Path node is valid.
    #
    return True if DevicePathNodeLength(DevicePath) == END_DEVICE_PATH_LENGTH else False


# Returns the size of a device path in bytes
def UefiDevicePathLibGetDevicePathSize(DevicePath: bytearray) -> int:
    if not DevicePath:
        return 0
    if not IsDevicePathValid(DevicePath, 0):
        return 0

    # Start = DevicePath
    Size = 0
    while not IsDevicePathEnd(DevicePath):
        Size += DevicePathNodeLength(DevicePath)
        DevicePath = NextDevicePathNode(DevicePath, Size)
    # return DevicePath - Start + DevicePathNodeLength(DevicePath)
    return Size


# Returns the size of a device path in bytes.
def GetDevicePathSize(DevicePath: bytearray) -> int:
    return UefiDevicePathLibGetDevicePathSize(DevicePath)


# Ruturns the SubType field of device path node
# Returns the SubType field of the device path node specified by Node
# If Node is None, then assert
def DevicePathType(buffer) -> int:
    Node = EFI_DEVICE_PATH_PROTOCOL.from_buffer_copy(buffer)
    return Node.Type


def IsDevicePathEndType(buffer) -> bool:
    return DevicePathType(buffer) == END_DEVICE_PATH_TYPE


def IsDevicePathEnd(Node) -> bool:
    return IsDevicePathEndType(Node) and DevicePathSubType(Node) == END_ENTIRE_DEVICE_PATH_SUBTYPE


# Returns a pointer to the next node in a device path.
def NextDevicePathNode(Node, Offset: int) -> bytearray:
    return Node[Offset:]


# Ruturns the SubType field of device path node
# Returns the SubType field of the device path node specified by Node
# If Node is None, then assert
def DevicePathSubType(buffer) -> int:
    assert (buffer != None)
    Node = EFI_DEVICE_PATH_PROTOCOL.from_buffer_copy(buffer)
    return Node.SubType
