#pragma once
#include "ai.h"

// ���������ݳ���
const int cniMinRandDataLen = 1;

class RandData
{
public:
    ~RandData(void);
    static RandData * GetInstance();
    int iGenRandData(ByteSeq & bsRandData, const int iPwdLen);
protected:
    void GetRandByte(unsigned char &ucCh);
protected:
    RandData(void);
    static RandData * _pInst;
};

