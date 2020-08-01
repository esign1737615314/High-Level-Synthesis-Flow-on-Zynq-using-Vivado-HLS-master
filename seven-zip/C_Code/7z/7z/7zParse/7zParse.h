#ifndef __7ZPARSE_H_
#define __7ZPARSE_H_

#include <iterator>
#include <vector>
using namespace std;

#include "CpuArch.h"


const unsigned int kSignatureSize    = 6;
const unsigned int kKeySignatureSize = 7;
const unsigned int kMaxSignatureSize = 7;
const unsigned int kHeaderSize       = 32;
const unsigned int kNumMax           = 0x7FFFFFFF;

enum EEnum
{
    kEnd,

    kHeader,

    kArchiveProperties,
    
    kAdditionalStreamsInfo,
    kMainStreamsInfo,
    kFilesInfo,
    
    kPackInfo,
    kUnpackInfo,
    kSubStreamsInfo,

    kSize,
    kCRC,

    kFolder,

    kCodersUnpackSize,
    kNumUnpackStream,

    kEmptyStream,
    kEmptyFile,
    kAnti,

    kName,
    kCTime,
    kATime,
    kMTime,
    kWinAttributes,
    kComment,

    kEncodedHeader,

    kStartPos,
    kDummy
};


// �߽��ܱ߽�ѹ����
typedef enum ENUM_DECODERTYPE
{
    kAes          = 0,
    kAesLzma      = 1,
    kAesLzma2     = 2,
    kAesPpmd      = 3,
    kAesBzip2     = 4,
    kAesMulUnpack = 5,
}enDecoderType;




//------------crack info------------
typedef struct STUR_CRACK_CODER
{
    // �㷨ID
    unsigned long long lMethodID;
    // �㷨����ֵ�����16�ֽ�
    unsigned char      sProps[16];
    // �㷨����ֵ��С
    unsigned int       iPropsSize;
    // �㷨����֮ǰ���ݴ�С
    unsigned long long lInDataSize;
    // �㷨����֮�����ݴ�С
    unsigned long long lOutDataSize;
    STUR_CRACK_CODER()
    {
        lMethodID         = 0;
        memset(sProps, 0, 16);
        iPropsSize        = 0;
        lInDataSize       = 0;
        lOutDataSize      = 0;
        return;
    }
    ~STUR_CRACK_CODER()
    {
        return;
    }
    inline void init()
    {
        lMethodID         = 0;
        memset(sProps, 0, 16);
        iPropsSize        = 0;
        lInDataSize       = 0;
        lOutDataSize      = 0;
        return;
    }
    inline STUR_CRACK_CODER& operator=(const STUR_CRACK_CODER& v)
    {
        lMethodID         = v.lMethodID;
        memcpy(sProps, v.sProps, 16);
        iPropsSize        = v.iPropsSize;
        lInDataSize       = v.lInDataSize;
        lOutDataSize      = v.lOutDataSize;
        return *this;
    }
}stCrackCoder;

typedef struct STUR_CRACK_INFO
{
    // ��������ƫ����
    unsigned long long   lDataOff;
    // �������ݵĴ�С
    unsigned long long   lDataSize;
    // �㷨�������
    vector<stCrackCoder> Coders;
    // CRCУ��ֵ
    unsigned int         iUnpackCRC;
    // �Ƿ���Ҫ��֤CRC
    bool                 bUnpackCRCDefined;
    // ��Ҫ��֤CRC��BUFFER��ƫ����
    unsigned long long   lUnpackCRCOffset;
    // ��Ҫ��֤CRC�����ݴ�С
    unsigned long long   lUnpackCRCSize;

    STUR_CRACK_INFO()
    {
        lDataOff          = 0;
        lDataSize         = 0;
        Coders.clear();
        iUnpackCRC        = 0;
        bUnpackCRCDefined = 0;
        lUnpackCRCOffset  = 0;
        lUnpackCRCSize    = 0;
        return;
    }
    ~STUR_CRACK_INFO()
    {
        vector<stCrackCoder>::iterator it = Coders.begin();
        while(it != Coders.end())
        {
            it = Coders.erase(it);
        }
        return;
    }
    inline void init()
    {
        lDataOff          = 0;
        lDataSize         = 0;
        vector<stCrackCoder>::iterator it = Coders.begin();
        while(it != Coders.end())
        {
            it = Coders.erase(it);
        }
        Coders.clear();
        iUnpackCRC        = 0;
        bUnpackCRCDefined = 0;
        lUnpackCRCOffset  = 0;
        lUnpackCRCSize    = 0;
        return;
    }
    inline STUR_CRACK_INFO& operator=(const STUR_CRACK_INFO& v)
    {
        init();
        lDataOff          = v.lDataOff;
        lDataSize         = v.lDataSize;
        copy(Coders.begin(), Coders.end(), back_inserter(Coders));
        iUnpackCRC        = v.iUnpackCRC;
        bUnpackCRCDefined = v.bUnpackCRCDefined;
        lUnpackCRCOffset  = v.lUnpackCRCOffset;
        lUnpackCRCSize    = v.lUnpackCRCSize;
        return *this;
    }
}stCrackInfo;
//------------crack info------------









//------------pack info------------
typedef struct STUR_PACK_INFO
{
    // ������������ļ��е���ʼλ��
    unsigned long long lDataOffset;
    // ��������ݴ�С
    unsigned long long lPackSize;
    // ��������ݵ�CRCֵ
    unsigned int iPackCRC;
    // ����������Ƿ���Ҫ���CRC
    bool bPackCRCDefined;

    STUR_PACK_INFO()
    {
        lDataOffset     = 0;
        lPackSize       = 0;
        iPackCRC        = 0;
        bPackCRCDefined = false;
        return;
    }
    ~STUR_PACK_INFO()
    {
        lDataOffset     = 0;
        lPackSize       = 0;
        iPackCRC        = 0;
        bPackCRCDefined = false;
        return;
    }
    inline void init()
    {
        lDataOffset     = 0;
        lPackSize       = 0;
        iPackCRC        = 0;
        bPackCRCDefined = false;
        return;
    }
    inline STUR_PACK_INFO& operator=(const STUR_PACK_INFO& v)
    {
        lDataOffset     = v.lDataOffset;
        lPackSize       = v.lPackSize;
        iPackCRC        = v.iPackCRC;
        bPackCRCDefined = v.bPackCRCDefined;
        return *this;
    }
}stPackInfo;
//------------pack info------------





//------------sub stream info------------
typedef struct STUR_SUB_STREAM_INFO
{
    // ���ļ�����ѹ��֮������ݴ�С
    vector<unsigned long long> lstUnpackSizes;
    // ���ļ�����ѹ��֮�������CRCֵ
    vector<unsigned int> lstUnpackCRC;
    // ���ļ�����ѹ��֮��������Ƿ���Ҫ����CRC���
    vector<bool> lstUnpackCRCDefined;

    STUR_SUB_STREAM_INFO()
    {
        lstUnpackSizes.clear();
        lstUnpackCRC.clear();
        lstUnpackCRCDefined.clear();
        return;
    }
    ~STUR_SUB_STREAM_INFO()
    {
        {
            vector<unsigned long long>::iterator it = lstUnpackSizes.begin();
            while(it != lstUnpackSizes.end())
            {
                it = lstUnpackSizes.erase(it);
            }
        }
        {
            vector<unsigned int>::iterator it = lstUnpackCRC.begin();
            while(it != lstUnpackCRC.end())
            {
                it = lstUnpackCRC.erase(it);
            }
        }
        {
            vector<bool>::iterator it = lstUnpackCRCDefined.begin();
            while(it != lstUnpackCRCDefined.end())
            {
                it = lstUnpackCRCDefined.erase(it);
            }
        }
        return;
    }
    inline void init()
    {
        {
            vector<unsigned long long>::iterator it = lstUnpackSizes.begin();
            while(it != lstUnpackSizes.end())
            {
                it = lstUnpackSizes.erase(it);
            }
            lstUnpackSizes.clear();
        }
        {
            vector<unsigned int>::iterator it = lstUnpackCRC.begin();
            while(it != lstUnpackCRC.end())
            {
                it = lstUnpackCRC.erase(it);
            }
            lstUnpackCRC.clear();
        }
        {
            vector<bool>::iterator it = lstUnpackCRCDefined.begin();
            while(it != lstUnpackCRCDefined.end())
            {
                it = lstUnpackCRCDefined.erase(it);
            }
            lstUnpackCRCDefined.clear();
        }
        return;
    }
    inline STUR_SUB_STREAM_INFO& operator=(const STUR_SUB_STREAM_INFO& v)
    {
        init();
        copy(v.lstUnpackSizes.begin(), v.lstUnpackSizes.end(), back_inserter(lstUnpackSizes));
        copy(v.lstUnpackCRC.begin(), v.lstUnpackCRC.end(), back_inserter(lstUnpackCRC));
        copy(v.lstUnpackCRCDefined.begin(), v.lstUnpackCRCDefined.end(), back_inserter(lstUnpackCRCDefined));
        return *this;
    }
}stSubStreamInfo;
//------------sub stream info------------






//------------folder info------------
typedef struct STUR_CODER_INFO
{
    unsigned long long lMethodID;
    unsigned long long lUnpackSize;
    unsigned char sProps[16];
    unsigned int iPropsSize;
    unsigned int iNumInStreams;
    unsigned int iNumOutStreams;

    STUR_CODER_INFO()
    {
        lMethodID      = 0;
        lUnpackSize    = 0;
        iNumInStreams  = 0;
        iNumOutStreams = 0;
        iPropsSize     = 0;
        memset(sProps, 0, 16);
        return;
    }
    ~STUR_CODER_INFO()
    {
        lMethodID      = 0;
        lUnpackSize    = 0;
        iNumInStreams  = 0;
        iNumOutStreams = 0;
        iPropsSize     = 0;
        memset(sProps, 0, 16);
        return;
    }
    inline void init()
    {
        lMethodID      = 0;
        lUnpackSize    = 0;
        iNumInStreams  = 0;
        iNumOutStreams = 0;
        iPropsSize     = 0;
        memset(sProps, 0, 16);
        return;
    }
    inline STUR_CODER_INFO& operator=(const STUR_CODER_INFO& v)
    {
        lMethodID      = v.lMethodID;
        lUnpackSize    = v.lUnpackSize;
        iNumInStreams  = v.iNumInStreams;
        iNumOutStreams = v.iNumOutStreams;
        iPropsSize     = v.iPropsSize;
        memcpy(sProps, v.sProps, 16);
        return *this;
    }
}stCoderInfo;

typedef struct STUR_BIND_PAIR
{
    unsigned int iInIndex;
    unsigned int iOutIndex;
    STUR_BIND_PAIR()
    {
        iInIndex  = 0;
        iOutIndex = 0;
        return;
    }
    ~STUR_BIND_PAIR()
    {
        iInIndex  = 0;
        iOutIndex = 0;
        return;
    }
    inline void init()
    {
        iInIndex  = 0;
        iOutIndex = 0;
        return;
    }
    inline STUR_BIND_PAIR& operator=(const STUR_BIND_PAIR& v)
    {
        iInIndex  = v.iInIndex;
        iOutIndex = v.iOutIndex;
        return *this;
    }
}stBindPair;

typedef struct STUR_FOLDER_INFO
{
    // �ļ��д������
    stPackInfo PackInfo;
    // �ļ����а��������ļ�����Ϣ
    stSubStreamInfo SubStreamInfo;

    // ������ļ������ļ���Coders
    vector<stCoderInfo> lstCoders;
    // ������ļ����ڵ�Լ����
    vector<stBindPair> lstBindPairs;
    // �ļ����ڴ����������
    vector<unsigned int> lstPackStreamsNum;
    // ��ѹ��֮�����ݵ�CRCֵ
    unsigned int iUnpackCRC;
    // ��ѹ��֮�������Ƿ���Ҫ����CRC���
    bool bUnpackCRCDefined;

    STUR_FOLDER_INFO()
    {
        lstCoders.clear();
        lstBindPairs.clear();
        lstPackStreamsNum.clear();
        iUnpackCRC = 0;
        bUnpackCRCDefined = false;
        return;
    }
    ~STUR_FOLDER_INFO()
    {
        {
            vector<stCoderInfo>::iterator it = lstCoders.begin();
            while(it != lstCoders.end())
            {
                it = lstCoders.erase(it);
            }
        }
        {
            vector<stBindPair>::iterator it = lstBindPairs.begin();
            while(it != lstBindPairs.end())
            {
                it = lstBindPairs.erase(it);
            }
        }
        {
            vector<unsigned int>::iterator it = lstPackStreamsNum.begin();
            while(it != lstPackStreamsNum.end())
            {
                it = lstPackStreamsNum.erase(it);
            }
        }
        iUnpackCRC = 0;
        bUnpackCRCDefined = false;
        return;
    }
    inline void init()
    {
        PackInfo.init();
        SubStreamInfo.init();
        {
            vector<stCoderInfo>::iterator it = lstCoders.begin();
            while(it != lstCoders.end())
            {
                it = lstCoders.erase(it);
            }
            lstCoders.clear();
        }
        {
            vector<stBindPair>::iterator it = lstBindPairs.begin();
            while(it != lstBindPairs.end())
            {
                it = lstBindPairs.erase(it);
            }
            lstBindPairs.clear();
        }
        {
            vector<unsigned int>::iterator it = lstPackStreamsNum.begin();
            while(it != lstPackStreamsNum.end())
            {
                it = lstPackStreamsNum.erase(it);
            }
            lstPackStreamsNum.clear();
        }
        iUnpackCRC = 0;
        bUnpackCRCDefined = false;
        return;
    }
    inline STUR_FOLDER_INFO& operator=(const STUR_FOLDER_INFO& v)
    {
        init();
        PackInfo = v.PackInfo;
        SubStreamInfo = v.SubStreamInfo;
        copy(v.lstCoders.begin(), v.lstCoders.end(), back_inserter(lstCoders));
        copy(v.lstBindPairs.begin(), v.lstBindPairs.end(), back_inserter(lstBindPairs));
        copy(v.lstPackStreamsNum.begin(), v.lstPackStreamsNum.end(), back_inserter(lstPackStreamsNum));
        iUnpackCRC = v.iUnpackCRC;
        bUnpackCRCDefined = v.bUnpackCRCDefined;
        return *this;
    }

    // ��ز�������
    inline unsigned long long lGetUnpackSize()
    {
        if(lstCoders.empty() == 1)
        {
            return 0;
        }
        for(unsigned int i = lstCoders.size() - 1; i >= 0; i--)
        {
            if(iFindBindPairForOutStream(i) < 0)
            {
                return lstCoders[i].lUnpackSize;
            }
        }
        return 1;
    }
    inline int iFindBindPairForOutStream(unsigned int outStreamIndex)
    {
        for(unsigned int i = 0; i < lstBindPairs.size(); i++)
        {
            if(lstBindPairs[i].iOutIndex == outStreamIndex)
            {
                return i;
            }
        }
        return -1;
    }
    inline int iFindBindPairForInStream(unsigned int inStreamIndex)
    {
        for(unsigned int i = 0; i < lstBindPairs.size(); i++)
        {
            if(lstBindPairs[i].iInIndex == inStreamIndex)
            {
                return i;
            }
        }
        return -1;
    }

}stFolderInfo;
//------------folder info------------










//------------tail header info------------
typedef struct STUR_TAIL_HEADER_INFO
{
    // β�ļ�ͷ�������ļ���
    vector<stFolderInfo> Folders;

    STUR_TAIL_HEADER_INFO()
    {
        Folders.clear();
        return;
    }
    ~STUR_TAIL_HEADER_INFO()
    {
        vector<stFolderInfo>::iterator it = Folders.begin();
        while(it != Folders.end())
        {
            it = Folders.erase(it);
        }
        return;
    }
    inline void init()
    {
        vector<stFolderInfo>::iterator it = Folders.begin();
        while(it != Folders.end())
        {
            it = Folders.erase(it);
        }
        Folders.clear();
        return;
    }
    inline STUR_TAIL_HEADER_INFO& operator=(const STUR_TAIL_HEADER_INFO& v)
    {
        init();
        copy(Folders.begin(), Folders.end(), back_inserter(v.Folders));
        return *this;
    }
}stTailHeaderInfo;
//------------tail header info------------




//------------key file parse info------------
typedef struct STUR_CODER_PROP
{
    // coder����ֵ
    unsigned char sData[255];
    // coder����ֵ��С
    unsigned char iSize;
    STUR_CODER_PROP()
    {
        init();
        return;
    }
    ~STUR_CODER_PROP()
    {
        return;
    }
    inline void init()
    {
        memset(sData, 0, 255);
        iSize = 0;
        return;
    }
    inline STUR_CODER_PROP& operator=(const STUR_CODER_PROP& v)
    {
        init();
        memcpy(sData, v.sData, 255);
        iSize = v.iSize;
        return * this;
    }
}stCoderProp;

typedef struct STUR_KEY_CODER
{
    // ��Coder��������������
    unsigned int       iInStreamNum;
    // ��Coder�������������
    unsigned int       iOutStreamNum;
    // ��Coder�ķ���ID
    unsigned long long lMethodID;
    // ��Coder����ֵ
    stCoderProp        Prop;

    STUR_KEY_CODER()
    {
        init();
        return;
    }
    ~STUR_KEY_CODER()
    {
        return;
    }
    inline void init()
    {
        iInStreamNum  = 0;
        iOutStreamNum = 0;
        lMethodID     = 0;
        Prop.init();
        return;
    }
    inline STUR_KEY_CODER& operator=(const STUR_KEY_CODER& v)
    {
        iInStreamNum  = v.iInStreamNum;
        iOutStreamNum = v.iOutStreamNum;
        lMethodID     = v.lMethodID;
        Prop          = v.Prop;
        return * this;
    }
}stKeyCoder;

typedef struct STUR_KEY_STREAM
{
    // �ļ�����С
    unsigned int iSize;
    // �ļ���CRC
    unsigned int iCrc;
    // �ڽ�ѹ�����ļ����������е�ƫ��λ��
    unsigned int iStartPos;
    // �ļ���
    unsigned char sFileName[256];

    STUR_KEY_STREAM()
    {
        init();
        return;
    }
    ~STUR_KEY_STREAM()
    {
        return;
    }
    inline void init()
    {
        iSize     = 0;
        iCrc      = 0;
        iStartPos = 0;
        memset(sFileName, 0, 256);
        return;
    }
    inline STUR_KEY_STREAM& operator=(const STUR_KEY_STREAM& v)
    {
        init();
        iSize     = v.iSize;
        iCrc      = v.iCrc;
        iStartPos = v.iStartPos;
        memcpy(sFileName, v.sFileName, 256);
        return * this;
    }
}stKeyStream;

typedef struct STUR_KEY_FOLDER
{
    // �ļ��д������ƫ����
    unsigned int iPackDataPos;
    // �ļ��д�����ݴ�С
    unsigned int iPackDataSize;
    // ��ѹ�������ļ������ݴ�С
    unsigned long long lUnpackInDataSize;
    // ��ѹ������ļ������ݴ�С
    unsigned int iUnpackOutDataSize;
    // ��ѹ�����ļ�������CRCֵ
    unsigned int iUnpackOutDataCRC;
    // Coder������
    unsigned int iCoderNum;
    // �ļ������ļ���������
    unsigned int iStreamNum;
    // �Ƿ���ҪУ���ļ���ѹ��������CRC
    unsigned int iUnpackOutDataCRCDefined;
    // ��4���ֽ�������������������
    unsigned int iAlign;
    // ��ѹ��coder
    stKeyCoder UnpackCoder;
    // ����coder
    stKeyCoder DecCoder;
    // BCJ coder
    stKeyCoder BCJCoder;
    // �����ļ���
    stKeyStream Stream[3];

    STUR_KEY_FOLDER()
    {
        init();
        return;
    }
    ~STUR_KEY_FOLDER()
    {
        return;
    }
    inline void init()
    {
        iPackDataPos             = 0;
        iPackDataSize            = 0;
        lUnpackInDataSize        = 0;
        iUnpackOutDataSize       = 0;
        iUnpackOutDataCRC        = 0;
        iCoderNum                = 0;
        iStreamNum               = 0;
        iUnpackOutDataCRCDefined = 0;
        UnpackCoder.init();
        DecCoder.init();
        BCJCoder.init();
        for(unsigned int i = 0; i < 3; i++)
        {
            Stream[i].init();
        }
        return;
    }
    inline STUR_KEY_FOLDER& operator=(const STUR_KEY_FOLDER& v)
    {
        init();
        iPackDataPos             = v.iPackDataPos;
        iPackDataSize            = v.iPackDataSize;
        lUnpackInDataSize        = v.lUnpackInDataSize;
        iUnpackOutDataSize       = v.iUnpackOutDataSize;
        iUnpackOutDataCRC        = v.iUnpackOutDataCRC;
        iCoderNum                = v.iCoderNum;
        iStreamNum               = v.iStreamNum;
        iUnpackOutDataCRCDefined = v.iUnpackOutDataCRCDefined;
        UnpackCoder              = v.UnpackCoder;
        DecCoder                 = v.DecCoder;
        BCJCoder                 = v.BCJCoder;
        for(unsigned int i = 0; i < 3; i++)
        {
            Stream[i]            = v.Stream[i];
        }
        return * this;
    }
}stKeyFolder;
//------------key file parse info------------







class C7zParse
{
public:
    C7zParse(void);
    ~C7zParse(void);

    // ����7zĿ���ļ�
    int iParse7zFile(char * sFile, stCrackInfo *ci);
    
    // �Ƿ�����ļ���
    inline int iGetEncFileNameFlag()
    {
        return _iIsEncFileNames;
    }

    // ���ؽ��ܽ�ѹ������
    inline enDecoderType iGetDecoderType()
    {
        return _iDecoderType;
    }

    //���ܵ�β�ļ�ͷͨ�������Լ�CRC���֮��
    //����Ҫ�ٽ���β�ļ�ͷ��ʽ�ļ��
    int iCheckTailFileHeader(unsigned char *sTail, 
        unsigned long long lTailSize);

private:
    // ------���ļ���Ҫ�Ĳ�������------
    inline int iReadByte(unsigned char &iData)
    {
        if (_lTailHeaderCurPos >= _lTailHeaderSize)
        {
            return EXIT_FAILURE;
        }
        iData = _sTailHeader[_lTailHeaderCurPos++];
        return EXIT_SUCCESS;
    }
    inline int iReadBytes(unsigned char *sData, unsigned int iDataSize)
    {
        if(iDataSize > (_lTailHeaderSize - _lTailHeaderCurPos))
        {
            return EXIT_FAILURE;
        }
        else
        {
            for (unsigned int i = 0; i < iDataSize; i++)
            {
                sData[i] = _sTailHeader[_lTailHeaderCurPos++];
            }
        }
        return EXIT_SUCCESS;
    }
    inline int iSkipData(unsigned long long lSize)
    {
        if(lSize > (_lTailHeaderSize - _lTailHeaderCurPos))
        {
            return EXIT_FAILURE;
        }
        _lTailHeaderCurPos += lSize;
        return EXIT_SUCCESS;
    }
    inline int iSkipData()
    {
        unsigned long long lNumber;
        if(EXIT_FAILURE == iReadNumber(lNumber))
        {
            return EXIT_FAILURE;
        }
        iSkipData(lNumber);
        return EXIT_SUCCESS;
    }
    inline int iReadNumber(unsigned long long &lNumber)
    {
        if (_lTailHeaderCurPos >= _lTailHeaderSize)
        {
            return EXIT_FAILURE;
        }
        unsigned char firstByte = _sTailHeader[_lTailHeaderCurPos++];
        unsigned char mask = 0x80;
        unsigned long long value = 0;
        for (int i = 0; i < 8; i++)
        {
            if ((firstByte & mask) == 0)
            {
                unsigned long long highPart = firstByte & (mask - 1);
                value += (highPart << (i * 8));
                lNumber = value;
                return EXIT_SUCCESS;
            }
            if (_lTailHeaderCurPos >= _lTailHeaderSize)
            {
                return EXIT_FAILURE;
            }
            value |= ((unsigned long long)_sTailHeader[_lTailHeaderCurPos++] << (8 * i));
            mask >>= 1;
        }
        lNumber = value;
        return EXIT_SUCCESS;
    }
    inline int iReadNum(unsigned int &lNum)
    {
        unsigned long long value;
        if(EXIT_FAILURE == iReadNumber(value))
        {
            return EXIT_FAILURE;
        }
        if(value > kNumMax)
        {
            return EXIT_FAILURE;
        }
        lNum = (unsigned int)value;
        return EXIT_SUCCESS;
    }
    inline int iReadUInt32(unsigned int &iData)
    {
        if ((_lTailHeaderCurPos + 4) > _lTailHeaderSize)
        {
            return EXIT_FAILURE;
        }
        iData = GetUi32(_sTailHeader + _lTailHeaderCurPos);
        _lTailHeaderCurPos += 4;
        return EXIT_SUCCESS;
    }
    inline int iReadUInt64(unsigned long long &lData)
    {
        if ((_lTailHeaderCurPos + 8) > _lTailHeaderSize)
        {
            return EXIT_FAILURE;
        }
        lData = GetUi64(_sTailHeader + _lTailHeaderCurPos);
        _lTailHeaderCurPos += 8;
        return EXIT_SUCCESS;
    }
    inline int ReadString(unsigned char *sData)
    {
        const unsigned char *buf = _sTailHeader + _lTailHeaderCurPos;
        unsigned int rem = (_lTailHeaderSize - _lTailHeaderCurPos) / 2 * 2;
        {
            unsigned int i;
            for (i = 0; i < rem; i += 2)
            {
                if (buf[i] == 0 && buf[i + 1] == 0)
                {
                    break;
                }
            }
            if (i == rem)
            {
                return EXIT_FAILURE;
            }
            rem = i;
        }
        int len = (int)(rem / 2);
        if (len < 0 || (unsigned int)len * 2 != rem)
        {
            return EXIT_FAILURE;
        }
        int i;
        for (i = 0; i < len; i++, buf += 2)
        {
            memcpy((sData + i*2), buf, 2);
        }
        _lTailHeaderCurPos += rem + 2;
        return EXIT_SUCCESS;
    }
    inline int iWaitAttribute(unsigned long long attribute)
    {
        for (;;)
        {
            unsigned long long lType = 0;
            if(EXIT_FAILURE == iReadNumber(lType))
            {
                return EXIT_FAILURE;
            }
            if(lType == attribute)
            {
                break;
            }
            if(lType == kEnd)
            {
                return EXIT_FAILURE;
            }
            iSkipData();
        }
        return EXIT_SUCCESS;
    }

    // ------����β�ļ�ͷ------
    // ���������β�ļ�ͷ
    int iReadPackHeader();
    // ��������������(δ�����β�ļ�ͷ)
    int iReadMainStreamsInfo();
    // ������������
    int iReadStreamsInfo();
    // ����������ݶ�
    int iReadPackInfo();
    // ����������ݶ�
    int iReadUnpackInfo();
    // �����ļ����ݶ�
    int iReadSubStreamsInfo();

    int iGetNextFolderItem(vector<stFolderInfo>::iterator itFolder);
    int iReadHashDigests(int numItems, unsigned int *digestsDefined, unsigned int *digests);
    int iReadBoolVector2(int numItems, unsigned int *v);
    int iReadBoolVector(int numItems, unsigned int *v);
    int iReadArchiveProperties();

    // �����ƽ����
    int iSetCrackArgs();

    // ����㷨�Ƿ���֧�ֵ��㷨
    int iCheckMethod(unsigned long long lID);
    // ��鵵���Ƿ����
    int iCheckEncryption();
    // ��ѹ��β�ļ�ͷ
    int iUnpackTailHeader();
    // ������ڿ�ID��coder
    void ProcEmptyCoder();

    // �����ļ�ͷ
    int iReadHeader(char *sFile, stCrackInfo *ci);
    // ����β�ļ�ͷ
    int iReadTailHeader();

    // ����α�ļ�
    int iReadKeyFile(char *sFile, stCrackInfo *ci);
    // ���ý��ܽ�ѹ����
    void SetDecoderType();

private:
    // Ŀ���ļ�
    char                    _sFile[1024];

    // �ļ�ͷժҪ����
    unsigned char           _sHeader[kHeaderSize];
    unsigned char           _sSignature[kSignatureSize];
    unsigned char           _iMajor;
    unsigned char           _iMinor;
    unsigned int            _iHeaderCrc;

    // β�ļ�ͷ����
    unsigned char *         _sTailHeader;
    // β�ļ�ͷ��ƫ���������ļ�ͷ��ʼ����
    unsigned long long      _lTailHeaderOff;
    // β�ļ�ͷ��ǰ����λ��
    unsigned long long      _lTailHeaderCurPos;
    // β�ļ�ͷ�Ĵ�С
    unsigned long long      _lTailHeaderSize;
    // β�ļ�ͷ��CRCֵ
    unsigned int            _iTailHeaderCrc;
    // �Ƿ��ļ�������
    unsigned int            _iIsEncFileNames;
    // ���ܽ�ѹ������
    enDecoderType           _iDecoderType;
    // β�ļ�ͷ��ʽ��Ϣ
    stTailHeaderInfo        _TailHeaderInfo;

    // ��ɽ����󣬺����֤��Ҫ������
    stCrackInfo *           _ci;
};



#endif //__7ZPARSE_H_