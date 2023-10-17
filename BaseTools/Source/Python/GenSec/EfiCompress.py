import ctypes
from ctypes import *


EFI_SUCCESS = 0
EFI_OUT_OF_RESOURCES = 0x8000000000000000 | (9)
EFI_BUFFER_TOO_SMALL = 0x8000000000000000 | (5)
WNDBIT = 13
WNDSIZ = 1 << WNDBIT
THRESHOLD = 3
UINT8_MAX = 0xff
MAX_HASH_VAL = 3 * WNDSIZ + (int(WNDSIZ / 512) + 1) * UINT8_MAX


MAXMATCH = 256
NC = UINT8_MAX + MAXMATCH + 2 - THRESHOLD
NP = WNDBIT + 1
CODE_BIT = 16
NT = CODE_BIT + 3
NPT = NT
TBIT = 5
CBIT = 9
PBIT = 4
NIL = 0
mBitCount = 0
mRemainder = 0


UINT8_BIT = 8
mSubBitBuf = None


mSrc = b''
mSrcAdd = 0
mDst = b''
mDstAdd = 0
mSrcUpperLimit = 0
mDstUpperLimit = 0
mCrc = 0
mOutputPos = 0
mOutputMask = 0


mCLen = [0]*NC
mCCode = [0]*NC
mTFreq = [0]*(2 * NT - 1)
mLen = []
mPTLen = [0]*NPT
mPTCode = [0]*NPT
mHeap = [0]*(NC + 1)
mLeft = [0]*(2 * NC - 1)
mRight = [0]*(2 * NC - 1)
mLenCnt = [0] * 17
mText = bytearray(WNDSIZ * 2 + MAXMATCH)

mBufSiz = 0
mBuf = bytearray((16 * 1024)<<2)
mMatchLen = 0
mFreq = []
mSortPtr = []
mN = 0

mCFreq = [0]*(2 * NC - 1)
mCrcTable = [0]*(UINT8_MAX + 1)
mPFreq = [0]*(2 * NP - 1)

# LZ77
mPos = 0
mMatchPos = 0
mAvail = 0
mLevel = [0]*(WNDSIZ + UINT8_MAX + 1)
mChildCount = [0]* (WNDSIZ + UINT8_MAX + 1)
mPosition = [0]*((WNDSIZ + UINT8_MAX + 1) * 2)
mParent = [0]*(WNDSIZ * 2 * 2)
mNext = [0]*((MAX_HASH_VAL + 1) * 2)
mPrev = [0]*(WNDSIZ * 2 * 2)
mHeapSize = 0

INIT_CRC = 0
CRCPOLY = 0xA001
PERC_FLAG = 0x8000


def HASH(a,b):
    return a + (b <<(WNDBIT - 9)) + WNDSIZ * 2

#TODO: Error
def EFI_ERROR(A):
    if A < 0:
        return True
    else:
        return False


#Put a dword to output stream
def PutDword(Data:int):
    global mDst, mDstAdd
    if mDstAdd < mDstUpperLimit:
        mDst = mDst + Data.to_bytes(1,byteorder='little')
        mDstAdd += 1
        
    if mDstAdd < mDstUpperLimit:
        Data = (Data >> 0x08) &0xff
        mDst = mDst + Data.to_bytes(1,byteorder='little')
        mDstAdd += 1
        
    if mDstAdd < mDstUpperLimit:
        Data = (Data >> 0x10) &0xff
        mDst = mDst + Data.to_bytes(1,byteorder='little')
        mDstAdd += 1
        
    if mDstAdd < mDstUpperLimit:
        Data = (Data >> 0x18) &0xff
        mDst = mDst + Data.to_bytes(1,byteorder='little')
        mDstAdd += 1


def MakeCrcTable():
    for i in range(UINT8_MAX + 1):
        r = i
        for j in range(UINT8_BIT):
            if r & 1:
                r = (r >> 1) ^ CRCPOLY
            else:
                r >>= 1
        # mCrcTable[i] = c_uint16(r)
        mCrcTable[i] = r


#Initialize String Info Log data structures
def InitSlide():
    global mAvail
    for i in range(WNDSIZ, WNDSIZ + UINT8_MAX,1):
        mLevel[i] = 1
        mPosition[i] = NIL
        
    for i in range(WNDSIZ, WNDSIZ * 2,1):
        mParent[i] = NIL
    mAvail = 1
    
    for i in range(1,WNDSIZ - 1,1):
        mNext[i]  = i + 1
        
    mNext[WNDSIZ - 1] = NIL
    for i in range(WNDSIZ * 2,MAX_HASH_VAL + 1,1):
        mNext[i] = NIL


#Count the number of each code length for a Huffman tree
def InitPutBits():
    global mBitCount,mSubBitBuf
    mBitCount = UINT8_BIT
    mSubBitBuf = 0


def HufEncodeStart():
    global mOutputPos,mOutputMask
    for i in range(NC):
        mCFreq[i] = 0
    
    for i in range(NP):
        mPFreq[i] = 0
        
    mOutputPos = mOutputMask = 0
    InitPutBits()
    return


def UPDATE_CRC(a):
    global mCrc
    mCrc = mCrcTable[(mCrc ^ (a)) & 0xFF] ^ (mCrc >> UINT8_BIT)
    return mCrc


#Read in source data
# def FreadCrc(n:int,p = b'') -> int:
#     i = 0
#     global mSrcAdd,mSrcUpperLimit,mOrigSize
#     mSrcAdd = 0
#     while mSrcAdd < mSrcUpperLimit and i < n:
#         p += mSrc[i:i + 1]
#         mSrcAdd += 1
#         i += 1
#     n = i
    
#     mOrigSize += n
#     j = 0
#     while i - 1 >= 0:
#         UPDATE_CRC(p[j])
#         j += 1
#     return n


#Find child node given the parent node and the edge character
def Child(q:int,c:int) ->int:
    CurrentCPos = mNext[HASH(q,c)]
    mParent[NIL] = q
    i = 0
    while mParent[CurrentCPos] != q:
        if i > 255:
            break
        # with open('file1.txt', "a") as f:
        #     f.write("%s %s %s %s\n" % (CurrentCPos, mParent[CurrentCPos], CurrentCPos, q))
        CurrentCPos = mNext[CurrentCPos]

        print(mParent[CurrentCPos], CurrentCPos, q)
    return CurrentCPos


#Create a new child for a given parent node.
def MakeChild(q:int,c:int,pos:int):
    h1 = HASH(q, c)
    h = HASH(q, c) & 0x7fff
    t = mNext[h]
    mNext[h] = pos
    mNext[pos] = t
    mPrev[t] = pos
    mPrev[pos] = h
    mParent[pos] = q
    mChildCount[q] += 1


#Split a node
def Split(Old:int):
    global mAvail,mMatchPos,mMatchLen,mPos
    
    New = mAvail
    mAvail = mNext[New]
    mChildCount[New] = 0
    t = mPrev[Old]
    mPrev[New] = t
    mNext[t] = New
    t = mNext[Old]
    mNext[New] = t
    mPrev[t] = New
    mParent[New] = mParent[Old]
    mLevel[New] = mMatchLen
    mPosition[New] = mPos
    MakeChild(New, mText[mMatchPos + mMatchLen], Old)
    MakeChild(New, mText[mPos + mMatchLen], mPos)


#Outputs rightmost n bits of x
def PutBits(n:int,x:int):
    global mBitCount,mSubBitBuf,mDstUpperLimit,mDst,mDstAdd,mCompSize
    
    if n < mBitCount:
        mBitCount -= n
        mSubBitBuf |= x << mBitCount
    else:
        n -= mBitCount
        Temp = mSubBitBuf | x >> n
        # print(Temp)

        if mDstAdd < mDstUpperLimit:
            mDst += Temp.to_bytes(4,byteorder ='little')
            #mDst = mDst.replace(mDst[mDstAdd:mDstAdd+1],Temp.to_bytes(1,byteorder ='little'))
            mDstAdd += 1
        
        mCompSize += 1
        if n < UINT8_BIT:
            mBitCount = UINT8_BIT - n
            mSubBitBuf = x << mBitCount
        else:
            Temp = int(x >> (n - UINT8_BIT))

            if mDstAdd < mDstUpperLimit:
                mDst += Temp.to_bytes(4,byteorder ='little')
                #mDst = mDst.replace(mDst[mDstAdd:mDstAdd+1],Temp.to_bytes(1,byteorder ='little'))
                mDstAdd += 1

            mCompSize += 1
            mBitCount = 2 * UINT8_BIT - n
            mSubBitBuf = x << mBitCount


def EncodeC(c:int):
    PutBits(mCLen[c], mCCode[c])
    
    
def EncodeP(p:int):
    c = 0
    q = p
    while q:
        q >>= 1
        c += 1
    PutBits(mPTLen[c], mPTCode[c])
    if c > 1:
        PutBits(c - 1, p & (0xFFFF >> (17 - c)))


#Outputs the code length array for the Extra Set or the Position Set.
def WritePTLen(n:int,nbit:int,Special:int):
    while n > 0 and mPTLen[n - 1] == 0:
        n -= 1
    PutBits(nbit, n)
    i = 0
    while i < n:
        k = mPTLen[i]
        i += 1
        if k <= 6:
            PutBits(3, k)
        else:
            PutBits(k - 3, (1 << (k - 3)) - 2)
        if i == Special:
            while i < 6 and mPTLen[i] == 0:
                i += 1
            PutBits(2, (i - 3) & 3)


#Outputs the code length array for Char&Length Set
def WriteCLen():
    n = NC
    while n > 0 and mCLen[n - 1] == 0:
        n -= 1
    PutBits(CBIT, n)
    i = 0
    while i < n:
        k = mCLen[i]
        i += 1
        if k == 0:
            Count = 1
            while i < n and mCLen[i] == 0:
                i += 1
                Count += 1
            if Count <= 2:
                for k in range(Count):
                    PutBits(mPTLen[0], mPTCode[0])
            elif Count <= 18:
                PutBits(mPTLen[1], mPTCode[1])
                PutBits(4, Count - 3)
            elif Count == 19:
                PutBits(mPTLen[0], mPTCode[0])
                PutBits(mPTLen[1], mPTCode[1])
                PutBits(4, 15)
            else:
                PutBits(mPTLen[2], mPTCode[2])
                PutBits(CBIT, Count - 20)
        else:
            PutBits(mPTLen[k + 2], mPTCode[k + 2])


#Count the frequencies for the Extra Set
def CountTFreq():
    for i in range(NT):
        mTFreq[i] = 0
    n = NC
    while n > 0 and mCLen[n - 1] == 0:
        n -= 1
    i = 0
    while i < n:
        k = mCLen[i]
        i += 1
        if k == 0:
            Count = 1
            while i < n and mCLen[i] == 0:
                i += 1
                Count += 1
            if Count <= 2:
                mTFreq[0] = mTFreq[0] + Count
            elif Count <= 18:
                mTFreq[1] += 1
            elif Count == 19:
                mTFreq[0] += 1
                mTFreq[1] += 1
            else:
                mTFreq[2] += 1
        else:
            mTFreq[k + 2] += 1


def DownHeap(i:int):
    #Priority queue: send i-th entry down heap
    global mHeapSize
    k = mHeap[i]
    j = 2 * i
    while j <= mHeapSize:
        if j < mHeapSize and mFreq[mHeap[j]] > mFreq[mHeap[j + 1]]:
            j += 1
        if mFreq[k] <= mFreq[mHeap[j]]:
            break
        mHeap[i] = mHeap[j]
        i = j
        j = 2 * i
    mHeap[i] = k


#Count the number of each code length for a Huffman tree.
def CountLen(i:int):
    if i < mN:
        mLenCnt[Depth if Depth < 16 else 16] += 1
    else:
        Depth += 1
        CountLen(mLeft [i])
        CountLen(mRight[i])
        Depth -= 1

#Create code length array for a Huffman tree
def MakeLen(Root:int):
    mSortPtrAdd = 0
    for i in range(16):
        mLenCnt[i] = 0
    CountLen(Root)

    #Adjust the length count array so that
    #no code will be generated longer than its designated length
    Cum = 0
    for i in range(15,0,-1):
        Cum += mLenCnt[i] << (16 - i)
    while Cum != (1 << 16):
        mLenCnt[16] -= 1
        for i in range(15,0,-1):
            mLenCnt[16] -= 1
            if mLenCnt[i] != 0:
                mLenCnt[i] -= 1
                mLenCnt[i+1] += 2
                break
        Cum -= 1
    for i in range(16,0,-1):
        k = mLenCnt[i]
        while ( k - 1 >= 0):
            mLen[mSortPtr[mSortPtrAdd]] = i
            mSortPtrAdd += 1


def MakeCode(n:int,Len=[],Code=[]):
    Start = []*18
    Start[1] = 0
    for i in range(17):
        Start[i + 1] = (Start[i] + mLenCnt[i]) << 1
    for i in range(n):
        Code[i] = Start[Len[i]]
        Start[Len[i]] += 1 

                
#Generates Huffman codes given a frequency distribution of symbols
def MakeTree(NParm:int,FreqParm = [],LenParm= [],CodeParm = []):
    global mN,mHeapSize,mSortPtr,mSortPtrAdd
    
    mN = NParm
    mFreq = FreqParm
    mLen = LenParm
    Avail = mN
    mHeapSize = 0
    mHeap[1] = 0
    for i in range(mN):
        mLen[i] = 0
        if mFreq[i]:
            mHeapSize += 1
            mHeap[mHeapSize] = i
    if mHeapSize < 2:
        CodeParm[mHeap[1]] = 0
        return mHeap[1]
    for i in range(mHeapSize // 2 , 0,-1):
        #Make priority queue
        DownHeap(i)
    mSortPtr = CodeParm
    mSortPtrAdd = 0
    
    
    i = mHeap[1]
    if i < mN:
        mSortPtr = i
        mSortPtr += 1
    mHeap[1] = mHeap[mHeapSize]
    mHeapSize -= 1
    DownHeap(1)
    j = mHeap[1]
    if j < mN:
        mSortPtr[mSortPtrAdd] = j
        mSortPtrAdd += 1
    k = Avail
    Avail += 1
    mFreq[k] = mFreq[i] + mFreq[j]
    mHeap[1] = k
    DownHeap(1)
    mLeft[k] = i
    mRight[k] = j
        
        
    while mHeapSize > 1:
        i = mHeap[1]
        if i < mN:
            mSortPtr = i
            mSortPtr += 1
        mHeap[1] = mHeap[mHeapSize]
        mHeapSize -= 1
        DownHeap(1)
        j = mHeap[1]
        if j < mN:
            mSortPtr[mSortPtrAdd] = j
            mSortPtrAdd += 1
        k = Avail
        Avail += 1
        mFreq[k] = (mFreq[i] + mFreq[j])
        mHeap[1] = k
        DownHeap(1)
        mLeft[k] = i
        mRight[k] = j
        
    mSortPtr = CodeParm
    mSortPtrAdd = 0
    MakeLen(k)
    MakeCode(NParm, LenParm, CodeParm)
    return k


#Huffman code the block and output it
def SendBlock():
    #global mCFreq
    Root = MakeTree(NC, mCFreq, mCLen, mCCode)
    Size = mCFreq[Root]
    PutBits(16, Size)
    if Root >= NC:
        CountTFreq()
        Root = MakeTree(NT, mTFreq, mPTLen, mPTCode)
        if Root >= NT:
            WritePTLen(NT, TBIT, 3)
        else:
            PutBits(TBIT, 0)
            PutBits(TBIT, Root)
        WriteCLen()
    else:
        PutBits(TBIT, 0)
        PutBits(TBIT, 0)
        PutBits(CBIT, 0)
        PutBits(CBIT, Root)
    Root = MakeTree(NP, mPFreq, mPTLen, mPTCode)
    if Root >= NP:
        WritePTLen(NP, PBIT, -1)
    else:
        PutBits(PBIT, 0)
        PutBits(PBIT, Root)
    Pos = 0
    for i in range(Size):
        if i % UINT8_BIT == 0:
            Flags = mBuf[Pos]
            Pos += 1
        else:
            Flags = Flags << 1
        if Flags & (1 << (UINT8_BIT - 1)):
            EncodeC(mBuf[Pos] + (1 << UINT8_BIT))
            Pos += 1
            k = mBuf[Pos] << UINT8_BIT
            Pos += 1
            k += mBuf[Pos]
            Pos += 1
            EncodeP(k)
        else:
            EncodeC(mBuf[Pos])
            Pos += 1
    for i in range(NC):
        mCFreq[i] = 0
    for i in range(NP):
        mPFreq[i] = 0
        

#Outputs an Original Character or a Pointer
def Output(c:int,p:int):
    global mOutputMask,mOutputPos,mBufSiz,mBuf
    CPos = 0
    mOutputMask >>= 1
    if mOutputMask == 0:
        mOutputMask = 1 << (UINT8_BIT - 1)
        if mOutputPos >= mBufSiz - 3 * UINT8_BIT:
            SendBlock()
            mOutputPos = 0
        CPos = mOutputPos
        mOutputPos += 1
        mBuf[CPos] = 0

    mBuf[mOutputPos] = c & 0xff
    mOutputPos += 1
    mCFreq[c] += 1
    if (c >= (1 << UINT8_BIT)):
        mBuf[CPos] |= mOutputMask
        
        mBuf[mOutputPos] = (p >> UINT8_BIT) & 0xff
        mOutputPos += 1
        
        mBuf[mOutputPos] = p & 0xff
        mOutputPos += 1
        c = 0
        while p:
            p >>= 1
            c += 1
        mPFreq[c] += 1


#Insert string info for current position into the String Info Log
def InsertNode():
    global mMatchLen,mMatchPos,mPos
    
    if mMatchLen >= 4:
        #
        # We have just got a long match, the target tree
        # can be located by MatchPos + 1. Traverse the tree
        # from bottom up to get to a proper starting point.
        # The usage of PERC_FLAG ensures proper node deletion
        # in DeleteNode() later.
        #
        mMatchLen -= 1
        r = (mMatchPos + 1) | WNDSIZ
        q = mParent[r]
        while q == NIL:
            r = mNext[r]
            q = mParent[r]
        while mLevel[q] >= mMatchLen:
            r = q
            q = mParent[q]
        t = q
        while mPosition[t] < 0:
            mPosition[t] = mPos
            t = mParent[t]
        if t < WNDSIZ:
            mPosition[t] = (mPos | PERC_FLAG)
    else:
        #Locate the target tree
        q = (mText[mPos] + WNDSIZ)
        c = mText[mPos + 1]
        r = Child(q, c)
        if r == NIL:
            MakeChild(q, c, mPos)
            mMatchLen = 1
            return
        mMatchLen = 2

    #Traverse down the tree to find a match.
    #Update Position value along the route.
    #Node split or creation is involved.
    while True:
        if r >= WNDSIZ:
            j = MAXMATCH
            mMatchPos = r
        else:
            j = mLevel[r]
            mMatchPos = (mPosition[r] & ~PERC_FLAG)
        if mMatchPos >= mPos:
            mMatchPos -= WNDSIZ
            
        index1 = mPos + mMatchLen
        index2 = mMatchPos + mMatchLen
        while mMatchLen < j:
            value1 = mText[index1]
            value2 = mText[index2]
            if mText[index1] != mText[index2]:
                Split(r)
                return
            mMatchLen += 1
            index1 += 1 
            index2 += 1
        if mMatchLen >= MAXMATCH:
            break
        mPosition[r] = mPos
        q = r
        r = Child(q, mText[index1])
        if r == NIL:
            MakeChild(q, mText[index1], mPos)
            return
        mMatchLen +=1
    t = mPrev[r]
    mPrev[mPos] = t
    mNext[t] = mPos
    t = mNext[r]
    mNext[mPos] = t
    mPrev[t] = mPos
    mParent[mPos] = q
    mParent[r] = NIL
    
    #Special usage of 'next'
    mNext[r] = mPos


#Delete outdated string info.
def DeleteNode():
    global mPos,mAvail
    if mParent[mPos] == NIL:
        return
    r = mPrev[mPos]
    s = mNext[mPos]
    mNext[r] = s
    mPrev[s] = r
    r = mParent[mPos]
    mParent[mPos] = NIL
    mChildCount[r] -= 1
    if r >= WNDSIZ or mChildCount[r] > 1:
        mChildCount[r] -= 1
        return
    
    t = (mPosition[r] & ~PERC_FLAG)
    if t >= mPos:
        t -= WNDSIZ
    s = t
    q = mParent[r]
    u = mPosition[q]
    while u & PERC_FLAG:
        u = u & ~PERC_FLAG
        if u >= mPos:
            u -= WNDSIZ
        if u > s:
            s = u
        mPosition[q] = (s | WNDSIZ)
        q = mParent[q]
        u = mPosition[q]

    if q < WNDSIZ:
        if u >= mPos:
            u -= WNDSIZ
        if u > s:
            s = u
        mPosition[q] = (s | WNDSIZ | PERC_FLAG)
    s = Child(r, mText[t + mLevel[r]])
    t = mPrev[s]
    u = mNext[s]
    mNext[t] = u
    mPrev[u] = t
    t = mPrev[r]
    mNext[t] = s
    mPrev[s] = t
    t = mNext[r]
    mPrev[t] = s
    mNext[s] = t
    mParent[s] = mParent[r]
    mParent[r] = NIL
    mNext[r] = mAvail
    mAvail = r

#Advance the current position (read in new data if needed).
#Delete outdated string info. Find a match string for current position.
def GetNextMatch():
    global mRemainder,mPos,mSrc,mSrcAdd,mSrcUpperLimit,mText,mOrigSize
    mRemainder -= 1
    mPos += 1
    if mPos == WNDSIZ * 2:
        mText[0:WNDSIZ + MAXMATCH] = mText[WNDSIZ:WNDSIZ * 2 + MAXMATCH]
        n = FreadCrc(WNDSIZ+MAXMATCH, WNDSIZ)
        mRemainder += n
        mPos = WNDSIZ
    DeleteNode()
    InsertNode()


def HufEncodeEnd():
    SendBlock()
    #Flush remaining bits
    PutBits(UINT8_BIT - 1, 0)
    return


def FreadCrc(start:int, size:int):
    global mOrigSize, mSrcAdd
    i = 0
    while mSrcAdd < mSrcUpperLimit and i < size:
        mText[start: start+1] = mSrc[mSrcAdd: mSrcAdd+1]
        mSrcAdd += 1
        start += 1
        i += 1
    n = i
    mOrigSize += n

    # Update CRC table
    Index = WNDSIZ
    while i-1 >= 0:
        UPDATE_CRC(mText[Index])
        Index += 1
        i -= 1

    return n
#The main controlling routine for compression process.
def Encode() -> int:
    
    global mBufSiz,mBuf,mRemainder,mMatchLen,mPos,mSrcAdd,mSrcUpperLimit,mText,mOrigSize
    mBufSiz = 16 * 1024

    InitSlide()
    
    HufEncodeStart()
    
    # mRemainder = FreadCrc(&mText[WNDSIZ], WNDSIZ + MAXMATCH);
    mRemainder = FreadCrc(WNDSIZ, WNDSIZ+MAXMATCH)

    # Start compress data
    # 遍历匹配链: 负责找到当前strstart的最长匹配
    # 懒匹配： 负责在连续几个strstart的最长匹配中找到匹配串长度最长的那个作为最终的最长匹配
    mMatchLen = 0
    mPos = WNDSIZ
    Text = mText[mPos:]
    value1 = Text[0]
    value2 = Text[1]
    InsertNode()
    if mMatchLen > mRemainder:
        mMatchLen = mRemainder
    while mRemainder > 0:
        LastMatchLen = mMatchLen
        LastMatchPos = mMatchPos
        # Find a match
        GetNextMatch()
        if mMatchLen > mRemainder:
            mMatchLen = mRemainder

        if mMatchLen > LastMatchLen or LastMatchLen < THRESHOLD:
            # Not enough benefits are gained by outputting a pointer,
            # so just output the original character
            Output(mText[mPos - 1], 0)
        else:
            # Outputting a pointer is beneficial enough, do it.
            Output(LastMatchLen + UINT8_MAX + 1 - THRESHOLD,(mPos - LastMatchPos - 2) & (WNDSIZ - 1))
            LastMatchLen -= 1
            while LastMatchLen > 0:
                GetNextMatch()
                LastMatchLen -= 1
            if mMatchLen > mRemainder:
                mMatchLen = mRemainder
    
    HufEncodeEnd()
    return EFI_SUCCESS


#The main compression routine.
def EfiCompress(SrcSize:int,DstSize:int,SrcBuffer = b'',DstBuffer = b''):
    
    global mSrc,mSrcAdd,mSrcUpperLimit,mDst,mDstAdd,mDstUpperLimit,mOrigSize, mCompSize
    Status = EFI_SUCCESS
    
    mSrc = SrcBuffer
    mSrcUpperLimit = mSrcAdd + SrcSize
    # print(mSrcUpperLimit)
    mDst = DstBuffer
    mDstUpperLimit = mDstAdd + DstSize

    PutDword(0)
    PutDword(0)
    
    MakeCrcTable()
    
    mOrigSize = mCompSize = 0
    mCrc = INIT_CRC
    
    #Compress it
    Status = Encode()
    if EFI_ERROR (Status):
        return EFI_OUT_OF_RESOURCES
    
    #Null terminate the compressed data
    if mDstAdd < mDstUpperLimit:
        mDst += b'\0'
        mDstAdd += 1

    
    #Fill in compressed size and original size
    mDst = DstBuffer
    PutDword(mCompSize+1)
    PutDword(mOrigSize)
    print(len(mDst))
    
    #Return
    # if mCompSize + 1 + 8 > DstSize:
    #     DstSize = mCompSize + 1 + 8
    #     Status = EFI_BUFFER_TOO_SMALL
    # else:
    DstSize = mCompSize + 1 + 8
    Status =  EFI_SUCCESS
    
    return Status,mDst,DstSize