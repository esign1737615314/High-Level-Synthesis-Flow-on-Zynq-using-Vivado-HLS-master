// ����head�ļ�
#include <stdio.h>
// ֧��EXIT_SUCCESS EXIT_FAILURE
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
    // ��ȡ�ļ�ͷժҪ
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

    // �Ƚ�ժҪֵ
    if(0 == memcmp(sSignature, kSignature, kSignatureSize))
    {
        // ԭʼ�ļ�
        RINOK(iReadHeader(sFile, ci))
        RINOK(iReadTailHeader())
    }
    else if(0 == memcmp(sSignature, kKeySignature, kKeySignatureSize))
    {
        // α�ļ�
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
    // �����ļ���
    RINOK(strlen(sFile) > 1024)
    memset(_sFile, 0, 1024);
    strcpy(_sFile, sFile);

    // ��ȡ�ļ�ͷժҪ
    fseek(pf, 0, SEEK_SET);
    int iRdCnt = fread(_sHeader, kHeaderSize, 1, pf);
    if(iRdCnt != 1)
    {
        fclose(pf);
        pf = NULL;
        return EXIT_FAILURE;
    }

    // ����ļ�ͷժҪ
    memcpy(_sSignature, _sHeader, kSignatureSize);
    if(0 != memcmp(_sSignature, kSignature, kSignatureSize))
    {
        fclose(pf);
        pf = NULL;
        return EXIT_FAILURE;
    }

    // ����ļ����汾���Ƿ���֧�ֵİ汾
    _iMajor = _sHeader[6];
    _iMinor = _sHeader[7];
    if(_iMajor != kMajorVersion)
    {
        fclose(pf);
        pf = NULL;
        return EXIT_FAILURE;
    }

    // ��ȡ�ļ�ͷժҪ��CRCֵ
    memcpy(&_iHeaderCrc, &_sHeader[8], 4);
    // ����ժҪͷCRC
    unsigned int iCrc = CrcCalc(&_sHeader[12], 20);
    if(iCrc != _iHeaderCrc)
    {
        fclose(pf);
        pf = NULL;
        return EXIT_FAILURE;
    }

    // ��ȡβ�ļ�ͷ��ƫ����
    memcpy(&_lTailHeaderOff, &_sHeader[12], 8);
    _lTailHeaderOff += 0x20;
    // ��ȡβ�ļ�ͷ�����ݳ���
    memcpy(&_lTailHeaderSize, &_sHeader[20], 8);
    // ��ȡβ�ļ�ͷ��CRCֵ
    memcpy(&_iTailHeaderCrc, &_sHeader[28], 4);
    // ��ȡβ�ļ�ͷ����
    _sTailHeader = (unsigned char *)malloc(_lTailHeaderSize);
    fseek(pf, _lTailHeaderOff, SEEK_SET);
    iRdCnt = fread(_sTailHeader, _lTailHeaderSize, 1, pf);
    if(iRdCnt != 1)
    {
        fclose(pf);
        pf = NULL;
        return EXIT_FAILURE;
    }
    // ����β�ļ���ͷCRCֵ
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
        // ������ļ�ͷ�����
        RINOK(iReadPackHeader())
        // �Ƿ����ļ������ܵ����
        if(EXIT_SUCCESS == iCheckEncryption())
        {
            // �����ļ������ܵ����
            _iIsEncFileNames = 1;
        }
        else
        {
            if(_TailHeaderInfo.Folders[0].lstCoders.size() > 0)
            {
                RINOK(iUnpackTailHeader())
                // ��һ���Խ�ѹ�����������ݽ���β�ļ�ͷ�Ľ���
                RINOK(iReadTailHeader())
                return EXIT_SUCCESS;
            }
            else
            {
                // û��һ���㷨�����������Ӧ���ǳ�����
                return EXIT_FAILURE;
            }
        }
    }
    else if(type == kHeader)
    {
        RINOK(iReadMainStreamsInfo())
    }
    
    // ��������ƽ����
    RINOK(iSetCrackArgs())

    return EXIT_SUCCESS;
}

int C7zParse::iReadPackHeader()
{
    // ������ļ�ͷ��ֻ��Ҫ����pack�κ�coder��
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
                // ���Ŀ���ļ��Ƿ����
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
    // ��ȡ�ļ����������ݵ�ƫ����
    unsigned long long lDataOffset = 0;
    RINOK(iReadNumber(lDataOffset))
    // ���ļ�ͷ��ʼ���㣬��Ҫ����32���ֽڵ��ļ�ͷ����
    lDataOffset += 0x20;

    unsigned int iPackStreamNum = 0;
    RINOK(iReadNum(iPackStreamNum))
    RINOK(iWaitAttribute(kSize))
    for(unsigned int i = 0; i < iPackStreamNum; i++)
    {
        // ��ȡ������ݴ�С
        unsigned long long iPackSize = 0;
        RINOK(iReadNumber(iPackSize))
        // ���´�������Ϣ
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
                // �����CRCУ��ֵ��������Ӧ���ļ���
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

    // ����Ƿ��ж�����Ϣ
    unsigned char external = 0;
    RINOK(iReadByte(external))
    // �ж�����Ϣ�������ʱ��֧��
    RINOK(external != 0)

    // ��ȡcoder������Ϣ
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
                // ��ȡ�ļ�����������µ�CRCֵ
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
    // û�з����������ֱ�ӷ���ʧ��
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
        // ����Ƿ���֧�ֵ��㷨
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
        // ���coder�㷨���ݵ�����
        itFolder->lstCoders.push_back(Coder);
        RINOK((mainByte & 0x80) != 0)
        numInStreams += iNumInStreams;
        numOutStreams += iNumOutStreams;
    }

    unsigned int numBindPairs = numOutStreams - 1;
    for (unsigned int i = 0; i < numBindPairs; i++)
    {
        // ����������
        unsigned int InIndex = 0;
        unsigned int OutIndex = 0;
        RINOK(iReadNum(InIndex))
        RINOK(iReadNum(OutIndex))
        // ��������
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
                // ��ȡ���ļ�����ѹ�������ݴ�С
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

    // ����������������ͣ���Ŀǰ�汾�ݲ�֧�ֽ���
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
        // ���ĳ��coder��id��0����ô���԰����coder���б���ɾ��
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
    // �����ѹ����BUFFER����Դ
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

    // ��ȡĿ���ļ�ѹ������
    FILE * pf = fopen(_sFile, "rb");
    fseek(pf, it->PackInfo.lDataOffset, SEEK_SET);
    if(1 != fread(sCoderBuf[0], it->PackInfo.lPackSize, 1, pf))
    {
        // �ͷ������BUFFER����Դ
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

    // ��ѹ�����ݽ��н�ѹ��
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
            // �ͷ������BUFFER����Դ
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
    
    // ֮ǰ����֤��ͨ���ˣ�����֤CRC
    if(it->bUnpackCRCDefined == 1)
    {
        if(EXIT_FAILURE == pCK->iCheckCrc(sOutData, lOutDataSize, it->iUnpackCRC))
        {
            // �ͷ������BUFFER����Դ
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

    // ���һ��BUFFER�����ͷţ�
    // ��Ϊ���µ�β�ļ�ͷ����
    for(j = 0; j < iCoderBufNum - 1; j++)
    {
        free(sCoderBuf[j]);
        sCoderBuf[j] = NULL;
    }
    free(sCoderBuf);
    free(lCoderBufSize);

    // ����β�ļ�ͷ����
    if(_sTailHeader != NULL)
    {
        free(_sTailHeader);
        _sTailHeader = NULL;
    }
    // ����β�ļ�ͷ����
    _sTailHeader = sOutData;
    _lTailHeaderSize = lOutDataSize;
    _lTailHeaderCurPos = 0;
    // ��β�ļ�ͷ��ʽ��Ϣ���г�ʼ��
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
    // ѡ���ѹ������������С���ļ��Լ������ڵ��ļ�����ΪĿ������
    unsigned int iTargetFolderIdx = 0;
    unsigned int iTargetStreamIdx = 0;
    // Ŀ���������������е�ƫ����
    unsigned long long lTargetStreamOffset = 0;

    // �ļ���δ�������������ļ������ܣ���ֻ��ȡ��һ�����
    if(_iIsEncFileNames == 0)
    {
        unsigned int i = 0;
        vector<stFolderInfo>::iterator it = _TailHeaderInfo.Folders.begin();
        unsigned long long lUnpackSize = it->SubStreamInfo.lstUnpackSizes[0];
        while(it != _TailHeaderInfo.Folders.end())
        {
            // ��ǰ�ļ������ļ���ѹ�������ݵ�ƫ����
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

    // ���õ�������
    _ci->lDataOff = _TailHeaderInfo.Folders[iTargetFolderIdx].PackInfo.lDataOffset;
    _ci->lDataSize = _TailHeaderInfo.Folders[iTargetFolderIdx].PackInfo.lPackSize;

    // ���ô����㷨����
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
        // ��һ��coder���������ݴ�С
        if(it->lMethodID == cnlAesMethodId)
        {
            lInDataSize = it->lUnpackSize;
        }
        else
        {
            lInDataSize = Coder.lOutDataSize;
        }
    }
    // ���ý��ܽ�ѹ����
    SetDecoderType();

    // ����CRC��֤����
    it--;
    if(it->lMethodID == cnlBzip2MethodId)
    {
        // bzip2�㷨����Ҫ��֤CRC
        return EXIT_SUCCESS;
    }
    if(_iIsEncFileNames == 1)
    {
        // �ļ��������������ʹ��coder���е�crc
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
            // ʹ�����һ��coder����֮������ݴ�С
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
    // �����ƽ����
    _ci->lDataOff = (unsigned long long)KeyFolder.iPackDataPos;
    _ci->lDataSize = (unsigned long long)KeyFolder.iPackDataSize;

    // ����Coder, AES
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
    // ��ѹ���㷨
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
    // ���ý��ܽ�ѹ����
    SetDecoderType();

    // �������ļ���CRCУ��
    if(iIsEncFileName == 1)
    {
        _ci->bUnpackCRCDefined = (KeyFolder.iUnpackOutDataCRCDefined == 1) ? true: false;
        _ci->iUnpackCRC = KeyFolder.iUnpackOutDataCRC;
        _ci->lUnpackCRCOffset = 0;
        _ci->lUnpackCRCSize = KeyFolder.iUnpackOutDataSize;
    }
    else
    {
        // ���ļ������ܵ����������ȡ��С���ļ�����CRCУ��
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
    //������
    if
    (
        (NULL == sTail)
        ||
        (0 == lTailSize)
    )
    {
        return EXIT_FAILURE;
    }
    
    //����β�ļ�ͷ��ز���
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

    // ��β�ļ�ͷ��ʽ��Ϣ���г�ʼ��
    _TailHeaderInfo.init();

    //���β�ļ�ͷ����
    unsigned long long type = 0;
    if(EXIT_FAILURE == iReadNumber(type))
    {
        free(_sTailHeader);
        _sTailHeader = NULL;
        return EXIT_FAILURE;
    }
    if(type != kHeader)
    {
        //����β�ļ�ͷ�����ش����˳�
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

    //����������β�ļ�ͷ����
    if(EXIT_FAILURE == iReadMainStreamsInfo())
    {
        free(_sTailHeader);
        _sTailHeader = NULL;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}