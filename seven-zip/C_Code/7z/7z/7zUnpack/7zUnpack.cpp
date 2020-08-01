// 7zUnpack.cpp

// 基础head文件
#include <stdio.h>
// 支持EXIT_SUCCESS EXIT_FAILURE
#include <stdlib.h>
#include <string.h>

// AES处理头文件
#include "MyAes.h"
// 解压缩头文件
#include "LzmaDec.h"
#include "Lzma2Dec.h"
#include "PpmdDecoder.h"
#include "BZip2Decoder.h"
#include "7zCrc.h"
#include "Bra.h"
#include "7zUnpack.h"

using namespace std;

const unsigned long long cnlLzmaMethodId  = 0x00030101;
const unsigned long long cnlLzma2MethodId = 0x00000021;
const unsigned long long cnlPpmdMethodId  = 0x00030401;
const unsigned long long cnlBzip2MethodId = 0x00040202;
const unsigned long long cnlAesMethodId   = 0x06F10701;


const unsigned int cniKeyDataSize         = 32;
const unsigned int cniIvDataSize          = 16;


const unsigned int cniAesDecryptBatchSize = 128;



static void *SzAlloc(void *p, size_t size)
{
    p = p;
    return malloc(size);
}
static void SzFree(void *p, void *address)
{
    p = p;
    free(address);
}


C7zUnpack::C7zUnpack(void)
{
    _Alloc.Alloc = SzAlloc;
    _Alloc.Free = SzFree;
    CrcGenerateTable();
}


C7zUnpack::~C7zUnpack(void)
{
}


int C7zUnpack::iAesDecoder(unsigned char *sEncData, unsigned long long lEncDataLen,
                           unsigned char *sDecData, unsigned long long lDecDataLen,
                           unsigned char *sKey, unsigned int iKeyLen,
                           unsigned char *sIv, unsigned int iIvLen)
{
    // 检查key长度
    RINOK(iKeyLen != cniKeyDataSize)
    // 检查iv长度
    //RINOK(iIvLen != cniIvDataSize)
    // 检查加解密数据长度
    RINOK(lEncDataLen != lDecDataLen)
    // 检查加密数据
    RINOK(sEncData == NULL)
    // 检查解密数据
    RINOK(sDecData == NULL)

    // 实例化解密类对象
    CAesCbcCoder *pACC = new CAesCbcCoder();
    // 设置口令数据
    pACC->SetKey(sKey, iKeyLen);
    // 设置IV数据
    pACC->SetInitVector(sIv, iIvLen);
    memcpy(sDecData, sEncData, lEncDataLen);
    // 解密加密数据
    lDecDataLen = pACC->Filter(sDecData, lEncDataLen);
    // 释放相关类
    delete pACC;
    pACC = NULL;

    return (lDecDataLen == lEncDataLen) ? EXIT_SUCCESS : EXIT_FAILURE;
}

int C7zUnpack::iLzmaUnpack(unsigned char *sPackData, unsigned long long lPackDataLen,
                           unsigned char *sProps, unsigned int iPropsLen,
                           unsigned char *sUnpackData, unsigned long long lUnpackDataLen)
{
    SizeT iOutProcSize = lUnpackDataLen;
    SizeT iInProcSize = lPackDataLen;
    ELzmaStatus status;
    SRes res = LzmaDecode(sUnpackData, &iOutProcSize, sPackData, &iInProcSize, sProps, iPropsLen, LZMA_FINISH_ANY, &status, &_Alloc);
    if(res == SZ_OK && (status != LZMA_STATUS_NOT_SPECIFIED))
    {
        if((iInProcSize == lPackDataLen) && (iOutProcSize == lUnpackDataLen))
        {
            return EXIT_SUCCESS;
        }
        else
        {
            return EXIT_FAILURE;
        }
    }
    else
    {
        return EXIT_FAILURE;
    }
}

int C7zUnpack::iLzma2Unpack(unsigned char *sPackData, unsigned long long lPackDataLen,
                            unsigned char iProps,
                            unsigned char *sUnpackData, unsigned long long lUnpackDataLen)
{
    SizeT iOutProcSize = lUnpackDataLen;
    SizeT iInProcSize = lPackDataLen;
    ELzmaStatus status;
    SRes res = Lzma2Decode(sUnpackData, &iOutProcSize, sPackData, &iInProcSize, iProps, LZMA_FINISH_ANY, &status, &_Alloc);
    if(res == SZ_OK && (status != LZMA_STATUS_NOT_SPECIFIED))
    {
        if(iOutProcSize >= lUnpackDataLen)
        {
            return EXIT_SUCCESS;
        }
        if((iInProcSize == 0) && (iOutProcSize == 0))
        {
            if(status == LZMA_STATUS_FINISHED_WITH_MARK)
            {
                return EXIT_SUCCESS;
            }
            else
            {
                return EXIT_FAILURE;
            }
        }
        else
        {
            return EXIT_FAILURE;
        }
    }
    else
    {
        return EXIT_FAILURE;
    }
}

int C7zUnpack::iBzip2Unpack(unsigned char *sPackData, unsigned long long lPackDataLen)
{
    CBZip2Decoder *pBD = new CBZip2Decoder();
    int iRet = pBD->BZip2Check(sPackData, lPackDataLen);
    delete pBD;
    return iRet;
}

int C7zUnpack::iPpmdUnpack(unsigned char *sPackData, unsigned long long lPackDataLen,
                           unsigned char *sProps, unsigned int iPropsLen,
                           unsigned char *sUnpackData, unsigned long long lUnpackDataLen)
{
    CPpmdDecoder *pPD = new CPpmdDecoder();
    pPD->SetOutRange(sUnpackData, lUnpackDataLen);
    RINOK(pPD->iSetProp(sProps, iPropsLen, &_Alloc))
    RINOK(pPD->iAlloc())
    pPD->SetInRange(sPackData, lPackDataLen);
    if(EXIT_FAILURE == pPD->iInit())
    {
        delete pPD;
        return EXIT_FAILURE;
    }
    else
    {
        int iRet = pPD->iPpmd7Check();
        delete pPD;
        return iRet;
    }
}

int C7zUnpack::iCheckCrc(unsigned char *sBuf, unsigned long long lBufSize, unsigned int iCrc)
{
    unsigned int iCalcCrc = CrcCalc(sBuf, lBufSize);
    return (iCrc == iCalcCrc) ? EXIT_SUCCESS:EXIT_FAILURE;
}

int C7zUnpack::iBcjTransfor(unsigned char *sBuf, unsigned long long lBufSize)
{
    unsigned int iPrevMask = 0;
    unsigned int iRetPos = x86_Convert(sBuf, lBufSize, 0, &iPrevMask, 0);
    return (iRetPos > 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

int C7zUnpack::iLzmaCheck(unsigned char *sEncData, unsigned long long lEncDataLen,
                          unsigned char *sKey, unsigned int iKeyLen,
                          unsigned char *sIv, unsigned int iIvLen,
                          unsigned char *sProps, unsigned int iPropsLen,
                          unsigned long long lPackDataLen,
                          unsigned char *sUnpackData, unsigned long long lUnpackDataLen)
{
    // ------检查输入参数------
    // 检查加密数据
    RINOK(sEncData == NULL)
    // 检查key
    RINOK(sKey == NULL)
    RINOK(iKeyLen != cniKeyDataSize)
    // 检查iv
    RINOK(sIv == NULL)
    RINOK(iIvLen != cniIvDataSize)
    // 检查解压缩属性数据
    RINOK(sProps == NULL)
    RINOK(iPropsLen != 5)
    RINOK(sUnpackData == NULL)

    // ------解密数据------
    // 批次明文数据
    unsigned char sPTBuf[cniAesDecryptBatchSize];
    memset(sPTBuf, 0, cniAesDecryptBatchSize);
    // 当前批次解密数据大小
    unsigned long long lCurBatchAesDataSize = 0;
    // 已完成解密数据大小
    unsigned long long lAesDecDataSize = 0;

    // 初始化AES部分
    CAesCbcCoder *pACC = new CAesCbcCoder();
    // 设置口令数据
    RINOK(pACC->SetKey(sKey, iKeyLen))
    // 设置IV数据
    RINOK(pACC->SetInitVector(sIv, iIvLen))

    // 初始化解压缩部分
    CLzmaDec p;
    LzmaDec_Construct(&p);
    RINOK(LzmaDec_AllocateProbs(&p, sProps, iPropsLen, &_Alloc))
    p.dic = sUnpackData;
    p.dicBufSize = lUnpackDataLen;
    LzmaDec_Init(&p);
    ELzmaStatus status;
    SizeT inSize = 0;
    SizeT outSize = lUnpackDataLen;

    // 处理全部的批次数据
    do
    {
        lCurBatchAesDataSize = (unsigned long long)MyMin((unsigned long long )cniAesDecryptBatchSize, (lEncDataLen - lAesDecDataSize));
        // 拷贝部分密文数据到批量数据区
        memset(sPTBuf, 0, cniAesDecryptBatchSize);
        memcpy(sPTBuf, (sEncData + lAesDecDataSize), lCurBatchAesDataSize);
        // 进行AES解密
        pACC->Filter(sPTBuf, lCurBatchAesDataSize);
        // 进行LZMA解压缩
        inSize = lCurBatchAesDataSize;
        int iRet = LzmaDec_DecodeToDic(&p, outSize, sPTBuf, &inSize, LZMA_FINISH_ANY, &status);
        if(iRet == SZ_OK)
        {
            if(status == LZMA_STATUS_NOT_SPECIFIED)
            {
                // 该组数据解压缩出错，直接返回错误
                break;
            }
            else if(status == LZMA_STATUS_FINISHED_WITH_MARK || 
                    status == LZMA_STATUS_NOT_FINISHED ||
                    status == LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK)
            {
                // 这种情况下需要对解压缩的输出值进行比较
                if(p.dicPos == lUnpackDataLen && (lAesDecDataSize + inSize) == lPackDataLen)
                {
                    delete pACC;
                    p.dic = NULL;
                    LzmaDec_Free(&p, &_Alloc);
                    return EXIT_SUCCESS;
                }
                else
                {
                    // 该组数据解压缩出错，直接返回错误
                    break;
                }
            }
        }
        else
        {
            // 该组数据解压缩出错，直接返回错误
            break;
        }
        // 加载下一批
        lAesDecDataSize += lCurBatchAesDataSize;
    }while(lAesDecDataSize < lEncDataLen);

    delete pACC;
    p.dic = NULL;
    LzmaDec_Free(&p, &_Alloc);
    return EXIT_FAILURE;
}

int C7zUnpack::iLzma2Check(unsigned char *sEncData, unsigned long long lEncDataLen,
                           unsigned char *sKey, unsigned int iKeyLen,
                           unsigned char *sIv, unsigned int iIvLen,
                           unsigned char sProps,
                           unsigned long long lPackDataLen,
                           unsigned char *sUnpackData, unsigned long long lUnpackDataLen)
{
    // ------检查输入参数------
    // 检查加密数据
    RINOK(sEncData == NULL)
    // 检查key
    RINOK(sKey == NULL)
    RINOK(iKeyLen != cniKeyDataSize)
    // 检查iv
    RINOK(sIv == NULL)
    RINOK(iIvLen != cniIvDataSize)
    RINOK(sUnpackData == NULL)

    // ------解密数据------
    // 批次明文数据
    unsigned char sPTBuf[cniAesDecryptBatchSize];
    memset(sPTBuf, 0, cniAesDecryptBatchSize);
    // 当前批次解密数据大小
    unsigned long long lCurBatchAesDataSize = 0;
    // 已完成解密数据大小
    unsigned long long lAesDecDataSize = 0;

    // 初始化AES部分
    CAesCbcCoder *pACC = new CAesCbcCoder();
    // 设置口令数据
    RINOK(pACC->SetKey(sKey, iKeyLen))
    // 设置IV数据
    RINOK(pACC->SetInitVector(sIv, iIvLen))

    // 初始化解压缩部分
    CLzma2Dec decoder;
    Lzma2Dec_Construct(&decoder);
    RINOK(Lzma2Dec_AllocateProbs(&decoder, sProps, &_Alloc))
    decoder.decoder.dicPos = 0;
    decoder.decoder.dic = sUnpackData;
    decoder.decoder.dicBufSize = lUnpackDataLen;
    Lzma2Dec_Init(&decoder);
    ELzmaStatus status = LZMA_STATUS_NOT_SPECIFIED;
    SizeT inSize = 0;
    SizeT outSize = lUnpackDataLen;
    // 已经解压的数据大小
    unsigned long long lProcUnpackDataSize = 0;
    // 本批次解压的数据大小
    unsigned long long lBatchProcUnpackDataSize = 0;

    // 处理全部的批次数据
    do
    {
        lCurBatchAesDataSize = (unsigned long long)MyMin((unsigned long long )cniAesDecryptBatchSize, (lEncDataLen - lAesDecDataSize));
        // 拷贝部分密文数据到批量数据区
        memset(sPTBuf, 0, cniAesDecryptBatchSize);
        memcpy(sPTBuf, (sEncData + lAesDecDataSize), lCurBatchAesDataSize);
        // 进行AES解密
        pACC->Filter(sPTBuf, lCurBatchAesDataSize);
        // 进行LZMA2解压缩
        inSize = lCurBatchAesDataSize;
        int iRet = Lzma2Dec_DecodeToDic(&decoder, outSize, sPTBuf, &inSize, LZMA_FINISH_ANY, &status);
        lBatchProcUnpackDataSize = decoder.decoder.dicPos - lProcUnpackDataSize;
        lProcUnpackDataSize += lBatchProcUnpackDataSize;
        bool finished = (inSize == 0 && lBatchProcUnpackDataSize == 0);
        bool stopDecoding = (lProcUnpackDataSize >= lUnpackDataLen);
        if(iRet != SZ_OK || decoder.decoder.dicPos == decoder.decoder.dicBufSize || finished || stopDecoding)
        {
            if(iRet != SZ_OK)
            {
                break;
            }
            if(status == LZMA_STATUS_NOT_SPECIFIED)
            {
                break;
            }
            if(stopDecoding == true)
            {
                delete pACC;
                pACC = NULL;
                decoder.decoder.dic = NULL;
                Lzma2Dec_Free(&decoder, &_Alloc);
                return EXIT_SUCCESS;
            }
            if(finished == true)
            {
                if(status == LZMA_STATUS_FINISHED_WITH_MARK)
                {
                    delete pACC;
                    pACC = NULL;
                    decoder.decoder.dic = NULL;
                    Lzma2Dec_Free(&decoder, &_Alloc);
                    return EXIT_SUCCESS;
                }
                else
                {
                    break;
                }
            }
        }
        // 加载下一批
        lAesDecDataSize += lCurBatchAesDataSize;
        if(decoder.decoder.dicPos == decoder.decoder.dicBufSize)
        {
            decoder.decoder.dicPos = 0;
        }
    }while(lAesDecDataSize < lEncDataLen);

    delete pACC;
    pACC = NULL;
    decoder.decoder.dic = NULL;
    Lzma2Dec_Free(&decoder, &_Alloc);
    return EXIT_FAILURE;
}


int C7zUnpack::iPpmdCheck(unsigned char *sEncData, unsigned long long lEncDataLen,
                          unsigned char *sKey, unsigned int iKeyLen,
                          unsigned char *sIv, unsigned int iIvLen,
                          unsigned char *sProps, unsigned int iPropsLen,
                          unsigned long long lPackDataLen, 
                          unsigned char *sUnpackData, unsigned long long lUnpackDataLen,
                          unsigned long long lCrcBufSize, unsigned int iCrc)
{
    // ------检查输入参数------
    // 检查加密数据
    RINOK(sEncData == NULL)
    // 检查key
    RINOK(sKey == NULL)
    RINOK(iKeyLen != cniKeyDataSize)
    // 检查iv
    RINOK(sIv == NULL)
    RINOK(iIvLen != cniIvDataSize)
    // 检查解压缩属性数据
    RINOK(sProps == NULL)
    RINOK(iPropsLen != 5)
    RINOK(sUnpackData == NULL)

    // ------解密数据------
    // 批次明文数据
    unsigned char sPTBuf[cniAesDecryptBatchSize];
    memset(sPTBuf, 0, cniAesDecryptBatchSize);
    // 当前批次解密数据大小
    unsigned long long lCurBatchAesDataSize = 0;
    // 已完成解密数据大小
    unsigned long long lAesDecDataSize = 0;

    // 初始化AES部分
    CAesCbcCoder *pACC = new CAesCbcCoder();
    // 设置口令数据
    RINOK(pACC->SetKey(sKey, iKeyLen))
    // 设置IV数据
    RINOK(pACC->SetInitVector(sIv, iIvLen))

    // 初始化解压缩部分
    CPpmdDecoder *pPD = new CPpmdDecoder();
    pPD->SetOutRange(sUnpackData, lUnpackDataLen);
    RINOK(pPD->iSetProp(sProps, iPropsLen, &_Alloc))
    RINOK(pPD->iAlloc())
    bool bIsInit = false;
    unsigned long long lProcUnpackDataSize = 0;

    do
    {
        lCurBatchAesDataSize = (unsigned long long)MyMin((unsigned long long )cniAesDecryptBatchSize, (lEncDataLen - lAesDecDataSize));
        // 拷贝部分密文数据到批量数据区
        memset(sPTBuf, 0, cniAesDecryptBatchSize);
        memcpy(sPTBuf, (sEncData + lAesDecDataSize), lCurBatchAesDataSize);
        // 进行AES解密
        pACC->Filter(sPTBuf, lCurBatchAesDataSize);
        // 进行PPMD解压缩
        pPD->SetInRange(sPTBuf, lCurBatchAesDataSize);
        if(bIsInit == false)
        {
            if(EXIT_FAILURE == pPD->iInit())
            {
                break;
            }
            bIsInit = true;
        }
        if(EXIT_SUCCESS == pPD->iPpmd7Check())
        {
            // 检查是否已经达到了解压缩后大小
            lProcUnpackDataSize = pPD->lGetProcUnpackDataSize();
            if(lProcUnpackDataSize >= lUnpackDataLen)
            {
                // 进行CRC校验
                delete pACC;
                pACC = NULL;
                delete pPD;
                pPD = NULL;
                unsigned int iCalcCrc = CrcCalc(sUnpackData, lCrcBufSize);
                return (iCrc == iCalcCrc) ? EXIT_SUCCESS : EXIT_FAILURE;
            }
        }
        else
        {
            break;
        }
        // 加载下一批
        lAesDecDataSize += lCurBatchAesDataSize;
    }while(lAesDecDataSize < lEncDataLen);

    // 解压缩验证失败，退出
    delete pACC;
    pACC = NULL;
    delete pPD;
    pPD = NULL;
    return EXIT_FAILURE;
}