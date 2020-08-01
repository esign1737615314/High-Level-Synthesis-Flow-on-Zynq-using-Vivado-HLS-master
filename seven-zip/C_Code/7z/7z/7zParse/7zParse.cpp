// 基础head文件
#include <stdio.h>
// 支持EXIT_SUCCESS EXIT_FAILURE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#include "7zCrc.h"
#include "7zParse.h"
#include "7zUnpack.h"


const unsigned long long cnlLzmaMethodId  = 0x00030101;
const unsigned long long cnlLzma2MethodId = 0x00000021;
const unsigned long long cnlPpmdMethodId  = 0x00030401;
const unsigned long long cnlBzip2MethodId = 0x00040202;
const unsigned long long cnlAesMethodId   = 0x06F10701;
const unsigned long long cnlBcjMethodId   = 0x03030103;

const unsigned char kMajorVersion         = 0;

unsigned char kSignature[kSignatureSize]       = {'7', 'z', 0xBC, 0xAF, 0x27, 0x1C};
unsigned char kKeySignature[kKeySignatureSize] = {'X', '.', 'Y', '.', '7', '.', 'Z'};

C7zParse::C7zParse(void)
{
    memset(_sHeader, 0, kHeaderSize);
    memset(_sSignature, 0, kSignatureSize);
    _iMajor = 0;
    _iMinor = 0;
    _iHeaderCrc = 0;
    _sTailHeader = NULL;
    _lTailHeaderCurPos = 0;
    _lTailHeaderOff = 0;
    _lTailHeaderSize = 0;
    _iTailHeaderCrc = 0;
    _iIsEncFileNames = 0;
    _ci = NULL;
    CrcGenerateTable();
}


C7zParse::~C7zParse(void)
{
    if(_sTailHeader != NULL)
    {
        free(_sTailHeader);
        _sTailHeader = NULL;
    }
}

int C7zParse::iParse7zFile(char *sFile, stCrackInfo *ci)
{
    // 读取文件头摘要
    RINOK(ci == NULL)
    RINOK(0 != access(sFile, 0))
    FILE *pf = fopen(sFile, "rb");
    RINOK(pf == NULL)
    fseek(pf, 0, SEEK_SET);
    unsigned char sSignature[kMaxSignatureSize];
    int iRdCnt = fread(sSignature, kMaxSignatureSize, 1, pf);
    if(iRdCnt != 1)
    {
        fclose(pf);
        pf = NULL;
        return EXIT_FAILURE;
    }
    fclose(pf);
    pf = NULL;

    // 比较摘要值
    if(0 == memcmp(sSignature, kSignature, kSignatureSize))
    {
        // 原始文件
        RINOK(iReadHeader(sFile, ci))
        RINOK(iReadTailHeader())
    }
    else if(0 == memcmp(sSignature, kKeySignature, kKeySignatureSize))
    {
        // 伪文件
        RINOK(iReadKeyFile(sFile, ci))
    }
    else
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int C7zParse::iReadHeader(char *sFile, stCrackInfo *ci)
{
    _ci = ci;
    FILE *pf = fopen(sFile, "rb");
    RINOK(pf == NULL)
    // 保存文件名
    RINOK(strlen(sFile) > 1024)
    memset(_sFile, 0, 1024);
    strcpy(_sFile, sFile);

    // 读取文件头摘要
    fseek(pf, 0, SEEK_SET);
    int iRdCnt = fread(_sHeader, kHeaderSize, 1, pf);
    if(iRdCnt != 1)
    {
        fclose(pf);
        pf = NULL;
        return EXIT_FAILURE;
    }

    // 检查文件头摘要
    memcpy(_sSignature, _sHeader, kSignatureSize);
    if(0 != memcmp(_sSignature, kSignature, kSignatureSize))
    {
        fclose(pf);
        pf = NULL;
        return EXIT_FAILURE;
    }

    // 检查文件主版本号是否是支持的版本
    _iMajor = _sHeader[6];
    _iMinor = _sHeader[7];
    if(_iMajor != kMajorVersion)
    {
        fclose(pf);
        pf = NULL;
        return EXIT_FAILURE;
    }

    // 读取文件头摘要的CRC值
    memcpy(&_iHeaderCrc, &_sHeader[8], 4);
    // 计算摘要头CRC
    unsigned int iCrc = CrcCalc(&_sHeader[12], 20);
    if(iCrc != _iHeaderCrc)
    {
        fclose(pf);
        pf = NULL;
        return EXIT_FAILURE;
    }

    // 读取尾文件头的偏移量
    memcpy(&_lTailHeaderOff, &_sHeader[12], 8);
    _lTailHeaderOff += 0x20;
    // 读取尾文件头的数据长度
    memcpy(&_lTailHeaderSize, &_sHeader[20], 8);
    // 读取尾文件头的CRC值
    memcpy(&_iTailHeaderCrc, &_sHeader[28], 4);
    // 读取尾文件头数据
    _sTailHeader = (unsigned char *)malloc(_lTailHeaderSize);
    fseek(pf, _lTailHeaderOff, SEEK_SET);
    iRdCnt = fread(_sTailHeader, _lTailHeaderSize, 1, pf);
    if(iRdCnt != 1)
    {
        fclose(pf);
        pf = NULL;
        return EXIT_FAILURE;
    }
    // 计算尾文件件头CRC值
    iCrc = CrcCalc(_sTailHeader, _lTailHeaderSize);
    if(iCrc != _iTailHeaderCrc)
    {
        fclose(pf);
        pf = NULL;
        return EXIT_FAILURE;
    }

    fclose(pf);
    pf = NULL;
    return EXIT_SUCCESS;
}

int C7zParse::iReadTailHeader()
{
    unsigned long long type = 0;
    RINOK(iReadNumber(type))
    RINOK(type > ((unsigned int)1 << 30))

    if(type == kEncodedHeader)
    {
        // 打包了文件头的情况
        RINOK(iReadPackHeader())
        // 是否是文件名加密的情况
        if(EXIT_SUCCESS == iCheckEncryption())
        {
            // 这是文件名加密的情况
            _iIsEncFileNames = 1;
        }
        else
        {
            if(_TailHeaderInfo.Folders[0].lstCoders.size() > 0)
            {
                RINOK(iUnpackTailHeader())
                // 进一步对解压缩出来的数据进行尾文件头的解析
                RINOK(iReadTailHeader())
                return EXIT_SUCCESS;
            }
            else
            {
                // 没有一种算法处理，这种情况应该是出错了
                return EXIT_FAILURE;
            }
        }
    }
    else if(type == kHeader)
    {
        RINOK(iReadMainStreamsInfo())
    }
    
    // 设置相关破解参数
    RINOK(iSetCrackArgs())

    return EXIT_SUCCESS;
}

int C7zParse::iReadPackHeader()
{
    // 打包的文件头，只需要解析pack段和coder段
    for(;;)
    {
        unsigned long long type = 0;
        RINOK(iReadNumber(type))
        RINOK(type > ((UInt32)1 << 30))
        switch((unsigned int)type)
        {
            case kEnd:
            {
                return EXIT_SUCCESS;
            }
            case kPackInfo:
            {
                RINOK(iReadPackInfo())
                break;
            }
            case kUnpackInfo:
            {
                RINOK(iReadUnpackInfo())
                ProcEmptyCoder();
                return EXIT_SUCCESS;
            }
            default:
            {
                return EXIT_FAILURE;
            }
        }
    }
}

int C7zParse::iReadStreamsInfo()
{
    for(;;)
    {
        unsigned long long type = 0;
        RINOK(iReadNumber(type))
        RINOK(type > ((UInt32)1 << 30))
        switch((unsigned int)type)
        {
            case kEnd:
            {
                return EXIT_SUCCESS;
            }
            case kPackInfo:
            {
                RINOK(iReadPackInfo())
                break;
            }
            case kUnpackInfo:
            {
                RINOK(iReadUnpackInfo())
                // 检测目标文件是否加密
                RINOK(iCheckEncryption())
                break;
            }
            case kSubStreamsInfo:
            {
                RINOK(iReadSubStreamsInfo())
                ProcEmptyCoder();
                return EXIT_SUCCESS;
            }
            default:
            {
                return EXIT_FAILURE;
            }
        }
    }
}

int C7zParse::iReadPackInfo()
{
    // 读取文件名加密数据的偏移量
    unsigned long long lDataOffset = 0;
    RINOK(iReadNumber(lDataOffset))
    // 从文件头开始计算，需要加上32个字节的文件头长度
    lDataOffset += 0x20;

    unsigned int iPackStreamNum = 0;
    RINOK(iReadNum(iPackStreamNum))
    RINOK(iWaitAttribute(kSize))
    for(unsigned int i = 0; i < iPackStreamNum; i++)
    {
        // 获取打包数据大小
        unsigned long long iPackSize = 0;
        RINOK(iReadNumber(iPackSize))
        // 更新打包相关信息
        stFolderInfo Folder;
        Folder.PackInfo.lPackSize = iPackSize;
        Folder.PackInfo.lDataOffset = lDataOffset;
        lDataOffset += iPackSize;
        _TailHeaderInfo.Folders.push_back(Folder);
    }

    unsigned long long lType = 0;
    for(;;)
    {
        RINOK(iReadNumber(lType))
        if(lType == kEnd)
        {
            break;
        }
        if(lType == kCRC)
        {
            unsigned int *iNeedReadCrc = (unsigned int *)malloc(sizeof(unsigned int) * iPackStreamNum);
            unsigned int *iReadCrc = (unsigned int *)malloc(sizeof(unsigned int) * iPackStreamNum);
            memset(iNeedReadCrc, 0, (sizeof(unsigned int) * iPackStreamNum));
            memset(iReadCrc, 0, (sizeof(unsigned int) * iPackStreamNum));
            if(EXIT_FAILURE == iReadHashDigests((int)iPackStreamNum, iNeedReadCrc, iReadCrc))
            {
                free(iNeedReadCrc);
                free(iReadCrc);
                iNeedReadCrc = NULL;
                iReadCrc = NULL;
                return EXIT_FAILURE;
            }
            for(unsigned int i = 0; i < iPackStreamNum; i++)
            {
                // 如果有CRC校验值，则存入对应的文件夹
                _TailHeaderInfo.Folders[i].PackInfo.iPackCRC = iReadCrc[i];
                _TailHeaderInfo.Folders[i].PackInfo.bPackCRCDefined = iNeedReadCrc[i];
            }
            free(iNeedReadCrc);
            free(iReadCrc);
            iNeedReadCrc = NULL;
            iReadCrc = NULL;
            continue;
        }
        RINOK(iSkipData())
    }

    return EXIT_SUCCESS;
}


int C7zParse::iReadUnpackInfo()
{
    RINOK(iWaitAttribute(kFolder))
    unsigned int numFolders = 0;
    RINOK(iReadNum(numFolders))

    // 检查是否有额外信息
    unsigned char external = 0;
    RINOK(iReadByte(external))
    // 有额外信息的情况暂时不支持
    RINOK(external != 0)

    // 读取coder核心信息
    vector<stFolderInfo>::iterator it = _TailHeaderInfo.Folders.begin();
    while(it != _TailHeaderInfo.Folders.end())
    {
        RINOK(iGetNextFolderItem(it))
        it++;
    }

    RINOK(iWaitAttribute(kCodersUnpackSize))

    it = _TailHeaderInfo.Folders.begin();
    while(it != _TailHeaderInfo.Folders.end())
    {
        unsigned int numOutStreams = 0;
        vector<stCoderInfo>::iterator itCoder = it->lstCoders.begin();
        while(itCoder != it->lstCoders.end())
        {
            numOutStreams += itCoder->iNumOutStreams;
            itCoder++;
        }
        for(unsigned int j = 0; j < numOutStreams; j++)
        {
            unsigned long long lReadUnpackSize = 0;
            RINOK(iReadNumber(lReadUnpackSize))
            it->lstCoders[j].lUnpackSize = lReadUnpackSize;
        }
        it++;
    }

    for(;;)
    {
        unsigned long long type = 0;
        RINOK(iReadNumber(type))
        if(type == kEnd)
        {
            break;
        }
        if(type == kCRC)
        {
            unsigned int *iNeedReadCrc = (unsigned int *)malloc(sizeof(unsigned int) * numFolders);
            unsigned int *iReadCrc = (unsigned int *)malloc(sizeof(unsigned int) * numFolders);
            memset(iNeedReadCrc, 0, (sizeof(unsigned int) * numFolders));
            memset(iReadCrc, 0, (sizeof(unsigned int) * numFolders));
            if(EXIT_FAILURE == iReadHashDigests(numFolders, iNeedReadCrc, iReadCrc))
            {
                free(iNeedReadCrc);
                free(iReadCrc);
                iNeedReadCrc = NULL;
                iReadCrc = NULL;
                return EXIT_FAILURE;
            }
            for(unsigned int i = 0; i < numFolders; i++)
            {
                // 读取文件名加密情况下的CRC值
                _TailHeaderInfo.Folders[i].bUnpackCRCDefined = iNeedReadCrc[i];
                _TailHeaderInfo.Folders[i].iUnpackCRC = iReadCrc[i];
            }
            free(iNeedReadCrc);
            free(iReadCrc);
            continue;
        }
        RINOK(iSkipData())
    }

    return EXIT_SUCCESS;
}

int C7zParse::iGetNextFolderItem(vector<stFolderInfo>::iterator itFolder)
{
    unsigned int iCodersNum = 0;
    RINOK(iReadNum(iCodersNum))
    // 没有方法的情况，直接返回失败
    RINOK(iCodersNum == 0)

    unsigned int i = 0;
    unsigned int numInStreams = 0;
    unsigned int numOutStreams = 0;
    for(i = 0; i < iCodersNum; i++)
    {
        unsigned char mainByte = 0;
        RINOK(iReadByte(mainByte))
        int idSize = (mainByte & 0xF);
        unsigned char longID[15];
        RINOK(iReadBytes(longID, idSize))
        RINOK(idSize > 8)
        unsigned long long id = 0;
        for(int j = 0; j < idSize; j++)
        {
            id |= (unsigned long long)longID[idSize - 1 - j] << (8 * j);
        }
        // 检查是否是支持的算法
        RINOK(iCheckMethod(id))

        stCoderInfo Coder;
        Coder.lMethodID = id;
        unsigned int iNumInStreams = 0;
        unsigned int iNumOutStreams = 0;
        if((mainByte & 0x10) != 0)
        {
            RINOK(iReadNum(iNumInStreams))
            RINOK(iReadNum(iNumOutStreams))
        }
        else
        {
            iNumInStreams = 1;
            iNumOutStreams = 1;
        }
        Coder.iNumInStreams = iNumInStreams;
        Coder.iNumOutStreams = iNumOutStreams;
        if((mainByte & 0x20) != 0)
        {
            unsigned int iPropsSize = 0;
            RINOK(iReadNum(iPropsSize))
            unsigned char *sProps = (unsigned char *)malloc(iPropsSize);
            RINOK(iReadBytes(sProps, iPropsSize))
            memset(Coder.sProps, 0, 16);
            if(id == cnlAesMethodId)
            {
                RINOK(iPropsSize != 10)
                memcpy(Coder.sProps, &sProps[2], 8);
                Coder.iPropsSize = 16;
            }
            else if(id == cnlLzmaMethodId ||
                    id == cnlPpmdMethodId)
            {
                RINOK(iPropsSize != 5)
                memcpy(Coder.sProps, sProps, 5);
                Coder.iPropsSize = 5;
            }
            else if(id == cnlLzma2MethodId)
            {
                RINOK(iPropsSize < 1)
                Coder.sProps[0] = sProps[0];
                Coder.iPropsSize = 1;
            }
        }
        // 添加coder算法数据到队列
        itFolder->lstCoders.push_back(Coder);
        RINOK((mainByte & 0x80) != 0)
        numInStreams += iNumInStreams;
        numOutStreams += iNumOutStreams;
    }

    unsigned int numBindPairs = numOutStreams - 1;
    for (unsigned int i = 0; i < numBindPairs; i++)
    {
        // 索引号数据
        unsigned int InIndex = 0;
        unsigned int OutIndex = 0;
        RINOK(iReadNum(InIndex))
        RINOK(iReadNum(OutIndex))
        // 更新数据
        stBindPair BindPair;
        BindPair.iInIndex = InIndex;
        BindPair.iOutIndex = OutIndex;
        itFolder->lstBindPairs.push_back(BindPair);
    }

    RINOK(numInStreams < numBindPairs)
    unsigned int numPackStreams = numInStreams - numBindPairs;
    if(numPackStreams == 1)
    {
        for (i = 0; i < numInStreams; i++)
        {
            if(itFolder->iFindBindPairForInStream(i) < 0)
            {
                itFolder->lstPackStreamsNum.push_back(i);
                break;
            }
        }
        RINOK(itFolder->lstPackStreamsNum.size() != 1)
    }
    else
    {
        for(unsigned int i = 0; i < numPackStreams; i++)
        {
            unsigned int PackStreams = 0;
            RINOK(iReadNum(PackStreams))
            itFolder->lstPackStreamsNum.push_back(PackStreams);
        }
    }
    return EXIT_SUCCESS;
}

int C7zParse::iReadHashDigests(int numItems, unsigned int *digestsDefined, unsigned int *digests)
{
    RINOK(iReadBoolVector2(numItems, digestsDefined))
    for(int i = 0; i < numItems; i++)
    {
        unsigned int crc = 0;
        if(digestsDefined[i] == 1)
        {
            RINOK(iReadUInt32(crc))
        }
        digests[i] = crc;
    }
    return EXIT_SUCCESS;
}

int C7zParse::iReadBoolVector2(int numItems, unsigned int *v)
{
    unsigned char allAreDefined = 0;
    RINOK(iReadByte(allAreDefined))
    if(allAreDefined == 0)
    {
        RINOK(iReadBoolVector(numItems, v))
        return EXIT_SUCCESS;
    }
    for(int i = 0; i < numItems; i++)
    {
        v[i] = 1;
    }
    return EXIT_SUCCESS;
}

int C7zParse::iReadBoolVector(int numItems, unsigned int *v)
{
    unsigned char b = 0;
    unsigned char mask = 0;
    for(int i = 0; i < numItems; i++)
    {
        if(mask == 0)
        {
            RINOK(iReadByte(b))
            mask = 0x80;
        }
        v[i] = ((b & mask) != 0) ? 1 : 0;
        mask >>= 1;
    }
    return EXIT_SUCCESS;
}

int C7zParse::iReadSubStreamsInfo()
{
    unsigned int iFolderNum = _TailHeaderInfo.Folders.size();
    vector<unsigned int> numUnpackStreamsInFolders;
    unsigned long long type = 0;
    for(;;)
    {
        RINOK(iReadNumber(type))
        if(type == kNumUnpackStream)
        {
            for(unsigned int i = 0; i < iFolderNum; i++)
            {
                unsigned int iUnpackStreamsInFolder = 0;
                RINOK(iReadNum(iUnpackStreamsInFolder))
                numUnpackStreamsInFolders.push_back(iUnpackStreamsInFolder);
            }
            continue;
        }
        if(type == kCRC || type == kSize)
        {
            break;
        }
        if(type == kEnd)
        {
            break;
        }
        RINOK(iSkipData())
    }

    if(numUnpackStreamsInFolders.empty() == 1)
    {
        for(unsigned int i = 0; i < iFolderNum; i++)
        {
            numUnpackStreamsInFolders.push_back(1);
        }
    }

    for(unsigned int i = 0; i < numUnpackStreamsInFolders.size(); i++)
    {
        unsigned int numSubstreams = numUnpackStreamsInFolders[i];
        if(numSubstreams == 0)
        {
            continue;
        }
        unsigned long long sum = 0;
        for(unsigned int j = 1; j < numSubstreams; j++)
        {
            if(type == kSize)
            {
                unsigned long long size = 0;
                RINOK(iReadNumber(size))
                // 获取子文件流解压缩的数据大小
                _TailHeaderInfo.Folders[i].SubStreamInfo.lstUnpackSizes.push_back(size);
                sum += size;
            }
        }
        _TailHeaderInfo.Folders[i].SubStreamInfo.lstUnpackSizes.push_back(_TailHeaderInfo.Folders[i].lGetUnpackSize() - sum);
    }

    if(type == kSize)
    {
        RINOK(iReadNumber(type))
    }

    int numDigests = 0;
    int numDigestsTotal = 0;
    for(unsigned int i = 0; i < iFolderNum; i++)
    {
        unsigned int numSubstreams = numUnpackStreamsInFolders[i];
        if(numSubstreams != 1 || !_TailHeaderInfo.Folders[i].bUnpackCRCDefined)
        {
            numDigests += numSubstreams;
        }
        numDigestsTotal += numSubstreams;
    }

    for(;;)
    {
        if(type == kCRC)
        {
            unsigned int *iNeedReadCrc = (unsigned int *)malloc(sizeof(unsigned int) * numDigests);
            unsigned int *iReadCrc = (unsigned int *)malloc(sizeof(unsigned int) * numDigests);
            memset(iNeedReadCrc, 0, (sizeof(unsigned int) * numDigests));
            memset(iReadCrc, 0, (sizeof(unsigned int) * numDigests));
            if(EXIT_FAILURE == iReadHashDigests(numDigests, iNeedReadCrc, iReadCrc))
            {
                free(iNeedReadCrc);
                free(iReadCrc);
                iNeedReadCrc = NULL;
                iReadCrc = NULL;
                return EXIT_FAILURE;
            }
            int digestIndex = 0;
            for(unsigned int i = 0; i < iFolderNum; i++)
            {
                unsigned int numSubstreams = numUnpackStreamsInFolders[i];
                if(numSubstreams == 1 && _TailHeaderInfo.Folders[i].bUnpackCRCDefined)
                {
                    _TailHeaderInfo.Folders[i].SubStreamInfo.lstUnpackCRCDefined.push_back(true);
                    _TailHeaderInfo.Folders[i].SubStreamInfo.lstUnpackCRC.push_back(_TailHeaderInfo.Folders[i].iUnpackCRC);
                }
                else
                {
                    for (unsigned int j = 0; j < numSubstreams; j++, digestIndex++)
                    {
                        _TailHeaderInfo.Folders[i].SubStreamInfo.lstUnpackCRCDefined.push_back(iNeedReadCrc[digestIndex]);
                        _TailHeaderInfo.Folders[i].SubStreamInfo.lstUnpackCRC.push_back(iReadCrc[digestIndex]);
                    }
                }
            }
            free(iNeedReadCrc);
            free(iReadCrc);
            iNeedReadCrc = NULL;
            iReadCrc = NULL;
        }
        else if(type == kEnd)
        {
            for(unsigned int i = 0; i < iFolderNum; i++)
            {
                unsigned int numSubstreams = numUnpackStreamsInFolders[i];
                for(unsigned int j = 0; j < numSubstreams; j++)
                {
                    _TailHeaderInfo.Folders[i].SubStreamInfo.lstUnpackCRCDefined.push_back(false);
                    _TailHeaderInfo.Folders[i].SubStreamInfo.lstUnpackCRC.push_back(0);
                }
            }
            break;
        }
        else
        {
            RINOK(iSkipData())
        }
        RINOK(iReadNumber(type))
    }

    return EXIT_SUCCESS;
}

int C7zParse::iReadArchiveProperties()
{
    for(;;)
    {
        unsigned long long type = 0;
        RINOK(iReadNumber(type))
        if(type == kEnd)
        {
            break;
        }
        RINOK(iSkipData())
    }
    return EXIT_SUCCESS;
}

int C7zParse::iReadMainStreamsInfo()
{
    unsigned long long type = 0;
    RINOK(iReadNumber(type))

    if(type == kArchiveProperties)
    {
        RINOK(iReadArchiveProperties())
        RINOK(iReadNumber(type))
    }

    if(type == kAdditionalStreamsInfo)
    {
        RINOK(iReadPackHeader())
        return EXIT_SUCCESS;
    }

    if(type == kMainStreamsInfo)
    {
        RINOK(iReadStreamsInfo())
        return EXIT_SUCCESS;
    }

    // 如果都不是上述类型，则目前版本暂不支持解析
    return EXIT_FAILURE;
}

int C7zParse::iCheckMethod(unsigned long long lID)
{
    if(lID == cnlAesMethodId)
        return EXIT_SUCCESS;
    else if(lID == cnlLzmaMethodId)
        return EXIT_SUCCESS;
    else if(lID == cnlLzma2MethodId)
        return EXIT_SUCCESS;
    else if(lID == cnlPpmdMethodId)
        return EXIT_SUCCESS;
    else if(lID == cnlBzip2MethodId)
        return EXIT_SUCCESS;
    else if(lID == cnlBcjMethodId)
        return EXIT_SUCCESS;
    else if(lID == 0x0)
        return EXIT_SUCCESS;
    return EXIT_FAILURE;
}

int C7zParse::iCheckEncryption()
{
    vector<stFolderInfo>::iterator it = _TailHeaderInfo.Folders.begin();
    while(it != _TailHeaderInfo.Folders.end())
    {
        vector<stCoderInfo>::iterator jt = it->lstCoders.begin();
        while(jt != it->lstCoders.end())
        {
            if(jt->lMethodID == cnlAesMethodId)
                return EXIT_SUCCESS;
            jt++;
        }
        it++;
    }
    return EXIT_FAILURE;
}

void C7zParse::ProcEmptyCoder()
{
    vector<stFolderInfo>::iterator it = _TailHeaderInfo.Folders.begin();
    for(; it != _TailHeaderInfo.Folders.end(); it++)
    {
        // 如果某个coder的id是0，那么可以把这个coder从列表中删除
        vector<stCoderInfo>::iterator jt = it->lstCoders.begin();
        for(; jt != it->lstCoders.end();)
        {
            if(jt->lMethodID == 0)
            {
                jt = it->lstCoders.erase(jt);
            }
            else
            {
                jt++;
            }
        }
    }
    return;
}

int C7zParse::iUnpackTailHeader()
{
    RINOK(_TailHeaderInfo.Folders.size() != 1)
    vector<stFolderInfo>::iterator it = _TailHeaderInfo.Folders.begin();
    // 申请解压缩的BUFFER区资源
    unsigned int iCoderBufNum = it->lstCoders.size() + 1;
    unsigned char ** sCoderBuf = (unsigned char **)malloc(iCoderBufNum * sizeof(unsigned char *));
    unsigned long long *lCoderBufSize = (unsigned long long *)malloc(iCoderBufNum * sizeof(unsigned long long));
    RINOK(lCoderBufSize == NULL)
    unsigned int j = 0;
    lCoderBufSize[j] = it->PackInfo.lPackSize;
    unsigned char * sBuf = (unsigned char *)malloc(lCoderBufSize[j]);
    RINOK(sBuf == NULL)
    sCoderBuf[j++] = sBuf;
    for(unsigned int i = 0; i < it->lstCoders.size(); i++)
    {
        lCoderBufSize[j] = it->lstCoders[i].lUnpackSize;
        sBuf = (unsigned char *)malloc(lCoderBufSize[j]);
        RINOK(sBuf == NULL)
        sCoderBuf[j++] = sBuf;
    }

    // 读取目标文件压缩数据
    FILE * pf = fopen(_sFile, "rb");
    fseek(pf, it->PackInfo.lDataOffset, SEEK_SET);
    if(1 != fread(sCoderBuf[0], it->PackInfo.lPackSize, 1, pf))
    {
        // 释放申请的BUFFER区资源
        for(j = 0; j < iCoderBufNum; j++)
        {
            free(sCoderBuf[j]);
            sCoderBuf[j] = NULL;
        }
        free(sCoderBuf);
        free(lCoderBufSize);
        fclose(pf);
        return EXIT_FAILURE;
    }
    fclose(pf);

    // 对压缩数据进行解压缩
    int iRet = EXIT_FAILURE;
    C7zUnpack *pCK = new C7zUnpack();
    unsigned char * sInData = NULL;
    unsigned char * sOutData = NULL;
    unsigned long long lInDataSize = 0;
    unsigned long long lOutDataSize = 0;
    j = 0;
    vector<stCoderInfo>::iterator jt = it->lstCoders.begin();
    while(jt != it->lstCoders.end())
    {
        lInDataSize = lCoderBufSize[j];
        sInData = sCoderBuf[j];
        j++;
        lOutDataSize = lCoderBufSize[j];
        sOutData = sCoderBuf[j];
        if(jt->lMethodID == cnlLzmaMethodId)
        {
            iRet = pCK->iLzmaUnpack(sInData, lInDataSize, jt->sProps, jt->iPropsSize,
                                    sOutData, lOutDataSize);
        }
        else if(jt->lMethodID == cnlLzma2MethodId)
        {
            iRet = pCK->iLzma2Unpack(sInData, lInDataSize, jt->sProps[0], 
                                     sOutData, lOutDataSize);
        }
        else if(jt->lMethodID == cnlPpmdMethodId)
        {
            iRet = pCK->iPpmdUnpack(sInData, lInDataSize, jt->sProps, jt->iPropsSize,
                                    sOutData, lOutDataSize);
        }
        else if(jt->lMethodID == cnlBzip2MethodId)
        {
            iRet = pCK->iBzip2Unpack(sInData, lInDataSize);
        }
        else if(jt->lMethodID == cnlBcjMethodId)
        {
            iRet = pCK->iBcjTransfor(sInData, lInDataSize);
            sOutData = sInData;
            lOutDataSize = lInDataSize;
        }
        if(iRet == EXIT_FAILURE)
        {
            // 释放申请的BUFFER区资源
            for(j = 0; j < iCoderBufNum; j++)
            {
                free(sCoderBuf[j]);
                sCoderBuf[j] = NULL;
            }
            free(sCoderBuf);
            free(lCoderBufSize);
            return EXIT_FAILURE;
        }
        jt++;
    }
    
    // 之前的验证都通过了，再验证CRC
    if(it->bUnpackCRCDefined == 1)
    {
        if(EXIT_FAILURE == pCK->iCheckCrc(sOutData, lOutDataSize, it->iUnpackCRC))
        {
            // 释放申请的BUFFER区资源
            for(j = 0; j < iCoderBufNum; j++)
            {
                free(sCoderBuf[j]);
                sCoderBuf[j] = NULL;
            }
            free(sCoderBuf);
            free(lCoderBufSize);
            return EXIT_FAILURE;
        }
    }

    // 最后一个BUFFER区不释放，
    // 作为最新的尾文件头数据
    for(j = 0; j < iCoderBufNum - 1; j++)
    {
        free(sCoderBuf[j]);
        sCoderBuf[j] = NULL;
    }
    free(sCoderBuf);
    free(lCoderBufSize);

    // 更新尾文件头数据
    if(_sTailHeader != NULL)
    {
        free(_sTailHeader);
        _sTailHeader = NULL;
    }
    // 更新尾文件头数据
    _sTailHeader = sOutData;
    _lTailHeaderSize = lOutDataSize;
    _lTailHeaderCurPos = 0;
    // 对尾文件头格式信息进行初始化
    _TailHeaderInfo.init();
    return EXIT_SUCCESS;
}

void C7zParse::SetDecoderType()
{
    unsigned int iUnpackCoderNum = 0;
    enDecoderType iUnpackCoderIdx = kAes;
    vector<stCrackCoder>::iterator it = _ci->Coders.begin();
    for(; it != _ci->Coders.end(); it++)
    {
        if(it->lMethodID == cnlLzmaMethodId)
        {
            iUnpackCoderNum++;
            iUnpackCoderIdx = kAesLzma;
        }
        if(it->lMethodID == cnlLzma2MethodId)
        {
            iUnpackCoderNum++;
            iUnpackCoderIdx = kAesLzma2;
        }
        if(it->lMethodID == cnlPpmdMethodId)
        {
            iUnpackCoderNum++;
            iUnpackCoderIdx = kAesPpmd;
        }
        if(it->lMethodID == cnlBzip2MethodId)
        {
            iUnpackCoderNum++;
            iUnpackCoderIdx = kAesBzip2;
        }
    }

    if(iUnpackCoderNum == 0)
    {
        _iDecoderType = kAes;
    }
    else if(iUnpackCoderNum == 1)
    {
        _iDecoderType = iUnpackCoderIdx;
    }
    else if(iUnpackCoderNum > 1)
    {
        _iDecoderType = kAesMulUnpack;
    }
    
    return;
}

int C7zParse::iSetCrackArgs()
{
    // 选择解压缩后数据量最小的文件以及其所在的文件夹作为目标数据
    unsigned int iTargetFolderIdx = 0;
    unsigned int iTargetStreamIdx = 0;
    // 目标数据在数据区中的偏移量
    unsigned long long lTargetStreamOffset = 0;

    // 文件名未加密情况，如果文件名加密，则只都取第一个序号
    if(_iIsEncFileNames == 0)
    {
        unsigned int i = 0;
        vector<stFolderInfo>::iterator it = _TailHeaderInfo.Folders.begin();
        unsigned long long lUnpackSize = it->SubStreamInfo.lstUnpackSizes[0];
        while(it != _TailHeaderInfo.Folders.end())
        {
            // 当前文件夹内文件解压缩后数据的偏移量
            unsigned long long lUnpackOffset = 0;
            unsigned int j = 0;
            vector<unsigned long long>::iterator jt;
            jt = it->SubStreamInfo.lstUnpackSizes.begin();
            while(jt != it->SubStreamInfo.lstUnpackSizes.end())
            {
                if(*jt < lUnpackSize)
                {
                    iTargetFolderIdx = i;
                    iTargetStreamIdx = j;
                    lTargetStreamOffset = lUnpackOffset;
                    lUnpackSize = *jt;
                }
                lUnpackOffset += *jt;
                jt++;
                j++;
            }
            it++;
            i++;
        }
    }

    // 设置档案数据
    _ci->lDataOff = _TailHeaderInfo.Folders[iTargetFolderIdx].PackInfo.lDataOffset;
    _ci->lDataSize = _TailHeaderInfo.Folders[iTargetFolderIdx].PackInfo.lPackSize;

    // 设置处理算法数据
    unsigned long long lInDataSize = _ci->lDataSize;
    vector<stCoderInfo>::iterator it;
    it = _TailHeaderInfo.Folders[iTargetFolderIdx].lstCoders.begin();
    for(; it != _TailHeaderInfo.Folders[iTargetFolderIdx].lstCoders.end(); it++)
    {
        stCrackCoder Coder;
        Coder.lMethodID = it->lMethodID;
        memcpy(Coder.sProps, it->sProps, it->iPropsSize);
        Coder.iPropsSize = it->iPropsSize;
        Coder.lInDataSize = lInDataSize;
        if(it->lMethodID == cnlAesMethodId)
        {
            Coder.lOutDataSize = Coder.lInDataSize;
        }
        else
        {
            Coder.lOutDataSize = it->lUnpackSize;
        }
        _ci->Coders.push_back(Coder);
        // 下一个coder的输入数据大小
        if(it->lMethodID == cnlAesMethodId)
        {
            lInDataSize = it->lUnpackSize;
        }
        else
        {
            lInDataSize = Coder.lOutDataSize;
        }
    }
    // 设置解密解压类型
    SetDecoderType();

    // 设置CRC验证参数
    it--;
    if(it->lMethodID == cnlBzip2MethodId)
    {
        // bzip2算法不需要验证CRC
        return EXIT_SUCCESS;
    }
    if(_iIsEncFileNames == 1)
    {
        // 文件名加密情况，都使用coder段中的crc
        _ci->bUnpackCRCDefined = _TailHeaderInfo.Folders[iTargetFolderIdx].bUnpackCRCDefined;
        _ci->iUnpackCRC        = _TailHeaderInfo.Folders[iTargetFolderIdx].iUnpackCRC;
        _ci->lUnpackCRCSize    = it->lUnpackSize;
    }
    else
    {
        _ci->bUnpackCRCDefined = _TailHeaderInfo.Folders[iTargetFolderIdx].SubStreamInfo.lstUnpackCRCDefined[iTargetStreamIdx];
        _ci->iUnpackCRC        = _TailHeaderInfo.Folders[iTargetFolderIdx].SubStreamInfo.lstUnpackCRC[iTargetStreamIdx];
        if(_TailHeaderInfo.Folders[iTargetFolderIdx].SubStreamInfo.lstUnpackSizes[iTargetStreamIdx] != 0)
        {
            _ci->lUnpackCRCSize = _TailHeaderInfo.Folders[iTargetFolderIdx].SubStreamInfo.lstUnpackSizes[iTargetStreamIdx];
        }
        else
        {
            // 使用最后一个coder处理之后的数据大小
            _ci->lUnpackCRCSize = it->lUnpackSize;
        }
    }
    _ci->lUnpackCRCOffset = lTargetStreamOffset;

    return EXIT_SUCCESS;
}

int C7zParse::iReadKeyFile(char *sFile, stCrackInfo *ci)
{
    RINOK(ci == NULL);
    _ci = ci;
    RINOK(0 != access(sFile, 0));
    FILE *pf = fopen(sFile, "rb");
    RINOK(pf == NULL);
    fseek(pf, kKeySignatureSize, SEEK_SET);
    unsigned char iIsEncFileName = 0;
    int iRdCnt = fread(&iIsEncFileName, 1, 1, pf);
    if(iRdCnt != 1)
    {
        fclose(pf);
        pf = NULL;
        return EXIT_FAILURE;
    }
    _iIsEncFileNames = (iIsEncFileName == 1) ? 1 : 0;
    stKeyFolder KeyFolder;
    iRdCnt = fread(&KeyFolder, sizeof(stKeyFolder), 1, pf);
    fclose(pf);
    pf = NULL;
    // 设置破解参数
    _ci->lDataOff = (unsigned long long)KeyFolder.iPackDataPos;
    _ci->lDataSize = (unsigned long long)KeyFolder.iPackDataSize;

    // 设置Coder, AES
    if(KeyFolder.DecCoder.lMethodID != 0)
    {
        RINOK(KeyFolder.DecCoder.lMethodID != cnlAesMethodId);
        stCrackCoder Coder;
        Coder.lMethodID = cnlAesMethodId;
        Coder.lInDataSize = (unsigned long long)KeyFolder.iPackDataSize;
        Coder.lOutDataSize = (unsigned long long)KeyFolder.iPackDataSize;
        Coder.iPropsSize = 0x10;
        memcpy(Coder.sProps, &KeyFolder.DecCoder.Prop.sData[2], (Coder.iPropsSize - 2));
        _ci->Coders.push_back(Coder);
    }
    // 解压缩算法
    if(KeyFolder.UnpackCoder.lMethodID != 0)
    {
        RINOK(iCheckMethod(KeyFolder.UnpackCoder.lMethodID));
        stCrackCoder Coder;
        Coder.lMethodID = (unsigned long long)KeyFolder.UnpackCoder.lMethodID;
        Coder.lInDataSize = (unsigned long long)KeyFolder.lUnpackInDataSize;
        Coder.lOutDataSize = (unsigned long long)KeyFolder.iUnpackOutDataSize;
        Coder.iPropsSize = KeyFolder.UnpackCoder.Prop.iSize;
        memcpy(Coder.sProps, KeyFolder.UnpackCoder.Prop.sData, Coder.iPropsSize);
        _ci->Coders.push_back(Coder);
    }
    // BCJ
    if(KeyFolder.BCJCoder.lMethodID != 0)
    {
        RINOK(KeyFolder.BCJCoder.lMethodID != cnlBcjMethodId);
        stCrackCoder Coder;
        Coder.lMethodID = cnlBcjMethodId;
        Coder.lInDataSize = (unsigned long long)KeyFolder.iUnpackOutDataSize;
        Coder.lOutDataSize = (unsigned long long)KeyFolder.iUnpackOutDataSize;
        _ci->Coders.push_back(Coder);
    }
    // 设置解密解压类型
    SetDecoderType();

    // 处理子文件流CRC校验
    if(iIsEncFileName == 1)
    {
        _ci->bUnpackCRCDefined = (KeyFolder.iUnpackOutDataCRCDefined == 1) ? true: false;
        _ci->iUnpackCRC = KeyFolder.iUnpackOutDataCRC;
        _ci->lUnpackCRCOffset = 0;
        _ci->lUnpackCRCSize = KeyFolder.iUnpackOutDataSize;
    }
    else
    {
        // 非文件名加密的情况，可以取最小的文件进行CRC校验
        unsigned int iMinSizeStreamIdx = 0;
        unsigned long long iStreamSize = (unsigned long long)KeyFolder.Stream[0].iSize;
        for(unsigned int i = 0; i < 3; i++)
        {
            if(KeyFolder.Stream[i].iSize == 0)
            {
                continue;
            }
            if(iStreamSize > KeyFolder.Stream[i].iSize)
            {
                iMinSizeStreamIdx = i;
                iStreamSize = KeyFolder.Stream[i].iSize;
            }
        }
        if(KeyFolder.UnpackCoder.lMethodID != cnlBzip2MethodId)
        {
            _ci->bUnpackCRCDefined = true;
            _ci->iUnpackCRC = KeyFolder.Stream[iMinSizeStreamIdx].iCrc;
            _ci->lUnpackCRCOffset = KeyFolder.Stream[iMinSizeStreamIdx].iStartPos;
            _ci->lUnpackCRCSize = KeyFolder.Stream[iMinSizeStreamIdx].iSize;
        }
    }

    return EXIT_SUCCESS;

}


int C7zParse::iCheckTailFileHeader(unsigned char *sTail, 
    unsigned long long lTailSize)
{
    //检查参数
    if
    (
        (NULL == sTail)
        ||
        (0 == lTailSize)
    )
    {
        return EXIT_FAILURE;
    }
    
    //更新尾文件头相关参数
    if(_sTailHeader != NULL)
    {
        free(_sTailHeader);
        _sTailHeader = NULL;
    }
    _sTailHeader = (unsigned char *)malloc(lTailSize + 1);
    if(NULL == _sTailHeader)
    {
        return EXIT_FAILURE;
    }
    _sTailHeader[lTailSize] = 0;
    memcpy(_sTailHeader, sTail, lTailSize);
    _lTailHeaderSize = lTailSize;
    _lTailHeaderCurPos = 0;

    // 对尾文件头格式信息进行初始化
    _TailHeaderInfo.init();

    //检查尾文件头数据
    unsigned long long type = 0;
    if(EXIT_FAILURE == iReadNumber(type))
    {
        free(_sTailHeader);
        _sTailHeader = NULL;
        return EXIT_FAILURE;
    }
    if(type != kHeader)
    {
        //不是尾文件头，返回错误退出
        free(_sTailHeader);
        _sTailHeader = NULL;
        return EXIT_FAILURE;
    }
    if(type > ((unsigned int)1 << 30))
    {
        free(_sTailHeader);
        _sTailHeader = NULL;
        return EXIT_FAILURE;
    }

    //解析完整的尾文件头数据
    if(EXIT_FAILURE == iReadMainStreamsInfo())
    {
        free(_sTailHeader);
        _sTailHeader = NULL;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}