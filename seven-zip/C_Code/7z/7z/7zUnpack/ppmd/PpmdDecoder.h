#ifndef __PPMDDECODER_H_
#define __PPMDDECODER_H_


#include "Ppmd7.h"

struct Ppmd7In
{
    IByteIn _ByteIn;
    unsigned char *_sInBuf;
    unsigned long long _iInSize;
    unsigned long long _iCurPos;
    bool _bIsReadOver;
    Ppmd7In()
    {
        _ByteIn.Read = NULL;
        _sInBuf = NULL;
        _iInSize = 0;
        _iCurPos = 0;
        _bIsReadOver = false;
    };
    unsigned char iReadInBuf()
    {
        if(_iCurPos < _iInSize)
        {
            return _sInBuf[_iCurPos++];
        }
        else
        {
            _bIsReadOver = true;
            return 0;
        }
    }
};

class CPpmdDecoder
{
public:
    CPpmdDecoder(void);
    ~CPpmdDecoder(void);
    inline unsigned long long lGetProcUnpackDataSize()
    {
        return _lGetProcUnpackDataSize;
    }
    inline void SetInRange(unsigned char *sPackBuf, unsigned long long iPackBufLen)
    {
        _In._sInBuf = sPackBuf;
        _In._iInSize = iPackBufLen;
        _In._iCurPos = 0;
        _In._bIsReadOver = false;
    }
    inline void SetOutRange(unsigned char *sUnpackBuf, unsigned long long iUnpackBufLen)
    {
        _Out = sUnpackBuf;
        _iOutSize = iUnpackBufLen;
    }
    inline int iSetProp(unsigned char *sProp, unsigned int iPropLen, ISzAlloc *alloc)
    {
        // 先检查压缩属性数据大小
        if(iPropLen < 5)
        {
            return EXIT_FAILURE;
        }
        _iOrder = sProp[0];
        _iMemSize = GetUi32(sProp + 1);
        _alloc = alloc;

        return EXIT_SUCCESS;
    }
    int iAlloc();
    int iInit();
    // 支持对完整的数据进行解压缩验证
    int iPpmd7Check();

private:
    CPpmd7z_RangeDec _rangeDec;
    Ppmd7In _In;
    ISzAlloc *_alloc;
    unsigned int _iMemSize;
    unsigned char _iOrder;
    unsigned char * _Out;
    unsigned long long _iOutSize;
    unsigned long long _lGetProcUnpackDataSize;
    CPpmd7 _ppmd;
};



#endif //__PPMDDECODER_H_