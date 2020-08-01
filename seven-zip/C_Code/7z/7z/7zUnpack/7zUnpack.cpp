// 7zUnpack.cpp

// ����head�ļ�
#include <stdio.h>
// ֧��EXIT_SUCCESS EXIT_FAILURE
#include <stdlib.h>
#include <string.h>

// AES����ͷ�ļ�
#include "MyAes.h"
// ��ѹ��ͷ�ļ�
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
    // ���key����
    RINOK(iKeyLen != cniKeyDataSize)
    // ���iv����
    //RINOK(iIvLen != cniIvDataSize)
    // ���ӽ������ݳ���
    RINOK(lEncDataLen != lDecDataLen)
    // ����������
    RINOK(sEncData == NULL)
    // ����������
    RINOK(sDecData == NULL)

    // ʵ�������������
    CAesCbcCoder *pACC = new CAesCbcCoder();
    // ���ÿ�������
    pACC->SetKey(sKey, iKeyLen);
    // ����IV����
    pACC->SetInitVector(sIv, iIvLen);
    memcpy(sDecData, sEncData, lEncDataLen);
    // ���ܼ�������
    lDecDataLen = pACC->Filter(sDecData, lEncDataLen);
    // �ͷ������
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
    // ------����������------
    // ����������
    RINOK(sEncData == NULL)
    // ���key
    RINOK(sKey == NULL)
    RINOK(iKeyLen != cniKeyDataSize)
    // ���iv
    RINOK(sIv == NULL)
    RINOK(iIvLen != cniIvDataSize)
    // ����ѹ����������
    RINOK(sProps == NULL)
    RINOK(iPropsLen != 5)
    RINOK(sUnpackData == NULL)

    // ------��������------
    // ������������
    unsigned char sPTBuf[cniAesDecryptBatchSize];
    memset(sPTBuf, 0, cniAesDecryptBatchSize);
    // ��ǰ���ν������ݴ�С
    unsigned long long lCurBatchAesDataSize = 0;
    // ����ɽ������ݴ�С
    unsigned long long lAesDecDataSize = 0;

    // ��ʼ��AES����
    CAesCbcCoder *pACC = new CAesCbcCoder();
    // ���ÿ�������
    RINOK(pACC->SetKey(sKey, iKeyLen))
    // ����IV����
    RINOK(pACC->SetInitVector(sIv, iIvLen))

    // ��ʼ����ѹ������
    CLzmaDec p;
    LzmaDec_Construct(&p);
    RINOK(LzmaDec_AllocateProbs(&p, sProps, iPropsLen, &_Alloc))
    p.dic = sUnpackData;
    p.dicBufSize = lUnpackDataLen;
    LzmaDec_Init(&p);
    ELzmaStatus status;
    SizeT inSize = 0;
    SizeT outSize = lUnpackDataLen;

    // ����ȫ������������
    do
    {
        lCurBatchAesDataSize = (unsigned long long)MyMin((unsigned long long )cniAesDecryptBatchSize, (lEncDataLen - lAesDecDataSize));
        // ���������������ݵ�����������
        memset(sPTBuf, 0, cniAesDecryptBatchSize);
        memcpy(sPTBuf, (sEncData + lAesDecDataSize), lCurBatchAesDataSize);
        // ����AES����
        pACC->Filter(sPTBuf, lCurBatchAesDataSize);
        // ����LZMA��ѹ��
        inSize = lCurBatchAesDataSize;
        int iRet = LzmaDec_DecodeToDic(&p, outSize, sPTBuf, &inSize, LZMA_FINISH_ANY, &status);
        if(iRet == SZ_OK)
        {
            if(status == LZMA_STATUS_NOT_SPECIFIED)
            {
                // �������ݽ�ѹ������ֱ�ӷ��ش���
                break;
            }
            else if(status == LZMA_STATUS_FINISHED_WITH_MARK || 
                    status == LZMA_STATUS_NOT_FINISHED ||
                    status == LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK)
            {
                // �����������Ҫ�Խ�ѹ�������ֵ���бȽ�
                if(p.dicPos == lUnpackDataLen && (lAesDecDataSize + inSize) == lPackDataLen)
                {
                    delete pACC;
                    p.dic = NULL;
                    LzmaDec_Free(&p, &_Alloc);
                    return EXIT_SUCCESS;
                }
                else
                {
                    // �������ݽ�ѹ������ֱ�ӷ��ش���
                    break;
                }
            }
        }
        else
        {
            // �������ݽ�ѹ������ֱ�ӷ��ش���
            break;
        }
        // ������һ��
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
    // ------����������------
    // ����������
    RINOK(sEncData == NULL)
    // ���key
    RINOK(sKey == NULL)
    RINOK(iKeyLen != cniKeyDataSize)
    // ���iv
    RINOK(sIv == NULL)
    RINOK(iIvLen != cniIvDataSize)
    RINOK(sUnpackData == NULL)

    // ------��������------
    // ������������
    unsigned char sPTBuf[cniAesDecryptBatchSize];
    memset(sPTBuf, 0, cniAesDecryptBatchSize);
    // ��ǰ���ν������ݴ�С
    unsigned long long lCurBatchAesDataSize = 0;
    // ����ɽ������ݴ�С
    unsigned long long lAesDecDataSize = 0;

    // ��ʼ��AES����
    CAesCbcCoder *pACC = new CAesCbcCoder();
    // ���ÿ�������
    RINOK(pACC->SetKey(sKey, iKeyLen))
    // ����IV����
    RINOK(pACC->SetInitVector(sIv, iIvLen))

    // ��ʼ����ѹ������
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
    // �Ѿ���ѹ�����ݴ�С
    unsigned long long lProcUnpackDataSize = 0;
    // �����ν�ѹ�����ݴ�С
    unsigned long long lBatchProcUnpackDataSize = 0;

    // ����ȫ������������
    do
    {
        lCurBatchAesDataSize = (unsigned long long)MyMin((unsigned long long )cniAesDecryptBatchSize, (lEncDataLen - lAesDecDataSize));
        // ���������������ݵ�����������
        memset(sPTBuf, 0, cniAesDecryptBatchSize);
        memcpy(sPTBuf, (sEncData + lAesDecDataSize), lCurBatchAesDataSize);
        // ����AES����
        pACC->Filter(sPTBuf, lCurBatchAesDataSize);
        // ����LZMA2��ѹ��
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
        // ������һ��
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
    // ------����������------
    // ����������
    RINOK(sEncData == NULL)
    // ���key
    RINOK(sKey == NULL)
    RINOK(iKeyLen != cniKeyDataSize)
    // ���iv
    RINOK(sIv == NULL)
    RINOK(iIvLen != cniIvDataSize)
    // ����ѹ����������
    RINOK(sProps == NULL)
    RINOK(iPropsLen != 5)
    RINOK(sUnpackData == NULL)

    // ------��������------
    // ������������
    unsigned char sPTBuf[cniAesDecryptBatchSize];
    memset(sPTBuf, 0, cniAesDecryptBatchSize);
    // ��ǰ���ν������ݴ�С
    unsigned long long lCurBatchAesDataSize = 0;
    // ����ɽ������ݴ�С
    unsigned long long lAesDecDataSize = 0;

    // ��ʼ��AES����
    CAesCbcCoder *pACC = new CAesCbcCoder();
    // ���ÿ�������
    RINOK(pACC->SetKey(sKey, iKeyLen))
    // ����IV����
    RINOK(pACC->SetInitVector(sIv, iIvLen))

    // ��ʼ����ѹ������
    CPpmdDecoder *pPD = new CPpmdDecoder();
    pPD->SetOutRange(sUnpackData, lUnpackDataLen);
    RINOK(pPD->iSetProp(sProps, iPropsLen, &_Alloc))
    RINOK(pPD->iAlloc())
    bool bIsInit = false;
    unsigned long long lProcUnpackDataSize = 0;

    do
    {
        lCurBatchAesDataSize = (unsigned long long)MyMin((unsigned long long )cniAesDecryptBatchSize, (lEncDataLen - lAesDecDataSize));
        // ���������������ݵ�����������
        memset(sPTBuf, 0, cniAesDecryptBatchSize);
        memcpy(sPTBuf, (sEncData + lAesDecDataSize), lCurBatchAesDataSize);
        // ����AES����
        pACC->Filter(sPTBuf, lCurBatchAesDataSize);
        // ����PPMD��ѹ��
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
            // ����Ƿ��Ѿ��ﵽ�˽�ѹ�����С
            lProcUnpackDataSize = pPD->lGetProcUnpackDataSize();
            if(lProcUnpackDataSize >= lUnpackDataLen)
            {
                // ����CRCУ��
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
        // ������һ��
        lAesDecDataSize += lCurBatchAesDataSize;
    }while(lAesDecDataSize < lEncDataLen);

    // ��ѹ����֤ʧ�ܣ��˳�
    delete pACC;
    pACC = NULL;
    delete pPD;
    pPD = NULL;
    return EXIT_FAILURE;
}