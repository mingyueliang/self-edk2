import re
from GenFv.GenFvInternalLib import *


class ParseInf(object):
    def __init__(self, Stream):
        self.Stream = Stream
        self.InfDict = {}

        self.DealStreamToDcit()

    def FindToken(self, Line):
        if b'//' in Line:
            return None, None
        lst = Line.split(b"=")
        return re.sub(b' ', b'', lst[0]).decode('utf-8'), re.sub(b' ', b'',
                                                                 lst[1]).decode(
            'utf-8')

    def FindSection(self, Line: bytes):
        if bytes(OPTIONS_SECTION_STRING, encoding='utf-8') in Line:
            return OPTIONS_SECTION_STRING[1:-1]
        elif bytes(ATTRIBUTES_SECTION_STRING, encoding='utf-8') in Line:
            return ATTRIBUTES_SECTION_STRING[1:-1]
        elif bytes(FILES_SECTION_STRING, encoding='utf-8') in Line:
            return FILES_SECTION_STRING[1:-1]
        elif bytes(FV_BASE_ADDRESS_STRING, encoding='utf-8') in Line:
            return FV_BASE_ADDRESS_STRING[1:-1]

    def DealStreamToDcit(self):
        EndOfPattern = re.compile(b"\r\n")
        section = ""
        while self.Stream:
            # Read a line
            FirstIndex = EndOfPattern.search(self.Stream)
            Line = self.Stream[:FirstIndex.regs[0][0]]
            self.Stream = self.Stream[FirstIndex.regs[0][1]:]

            if b'[' in Line and b']' in Line:
                section = self.FindSection(Line)
                if self.InfDict.get(section) == None:
                    self.InfDict[section] = {}
            else:
                Token, Value = self.FindToken(Line)
                if Token and Value:
                    if section == "files":
                        if not self.InfDict[section].get(Token):
                            self.InfDict[section][Token] = []
                        self.InfDict[section][Token].append(Value)
                        continue
                    if not self.InfDict[section].get(Token):
                        self.InfDict[section][Token] = []
                    self.InfDict[section][Token].append(Value)


class ParseCapInf(object):
    def __init__(self, Stream: bytes):
        pass




if __name__ == '__main__':
    with open("FVRECOVERY_i.inf", 'rb') as file:
        Stream = file.read()
    FvInf = ParseFvInf(Stream)
    pass
