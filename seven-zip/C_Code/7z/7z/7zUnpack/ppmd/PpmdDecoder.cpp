// 基础head文件
#include <stdio.h>
// 支持EXIT_SUCCESS EXIT_FAILURE
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include <list>
#include <map>

#include "PpmdDecoder.h"


static Byte ReadBuf(void *pp)
{
    Ppmd7In *p = (Ppmd7In *)pp;
    return p->iReadInBuf();
}


CPpmdDecoder::CPpmdDecoder(void)
{
    _lGetProcUnpackDataSize = 0;
    _In._ByteIn.Read = ReadBuf;
    _rangeDec.Stream = (IByteIn *)&_In;
    Ppmd7z_RangeDec_CreateVTable(&_rangeDec);
    Ppmd7_Construct(&_ppmd);
}


CPpmdDecoder::~CPpmdDecoder(void)
{
    Ppmd7_Free(&_ppmd, _alloc);
}

int CPpmdDecoder::iAlloc()
{
    // 申请ppmd7解压缩的空间
    int iRet = Ppmd7_Alloc(&_ppmd, _iMemSize, _alloc);
    if(iRet == 0)
    {
        return EXIT_FAILURE;
    }
    else
    {
        return EXIT_SUCCESS;
    }
}

int CPpmdDecoder::iInit()
{
    // 初始化解压缩范围
    int iRet = Ppmd7z_RangeDec_Init(&_rangeDec);
    if(iRet == 0)
    {
        return EXIT_FAILURE;
    }
    // 初始化PPMD
    Ppmd7_Init(&_ppmd, _iOrder);
    return EXIT_SUCCESS;
}

int CPpmdDecoder::iPpmd7Check()
{
    int iSym = 0;
    unsigned long long i;
    for(i = 0; i < _iOutSize; i++)
    {
        iSym = Ppmd7_DecodeSymbol(&_ppmd, &_rangeDec.p);
        if((_In._bIsReadOver == true) || iSym < 0)
        {
            break;
        }
        _Out[i] = iSym;
    }
    if(_In._bIsReadOver == true)
    {
        return EXIT_FAILURE;
    }
    if(iSym < -1)
    {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

