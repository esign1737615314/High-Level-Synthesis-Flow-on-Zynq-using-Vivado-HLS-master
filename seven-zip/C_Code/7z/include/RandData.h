#pragma once
#include "ai.h"

// 最短随机数据长度
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

