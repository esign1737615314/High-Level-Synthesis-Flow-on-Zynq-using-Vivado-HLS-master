#include <stdlib.h>
#include <math.h>
#include <time.h>
#include "RandData.h"

RandData * RandData::_pInst = NULL;

RandData::RandData(void)
{
    return;
}


RandData::~RandData(void)
{
    return;
}


RandData * RandData::GetInstance()
{
    if (NULL == _pInst)
    {
        _pInst = new RandData();
    }
    return _pInst;
}
int RandData::iGenRandData(ByteSeq & bsRandData, const int iPwdLen)
{
    bsRandData.clear();
    if (iPwdLen < cniMinRandDataLen)
    {
        return EXIT_FAILURE;
    }
    
    srand((unsigned int)time(0));
    for (int i = 0; i < iPwdLen; i++)
    {
        unsigned char ucCh;
        GetRandByte(ucCh);
        bsRandData.push_back(ucCh);
    }
    return EXIT_SUCCESS;
}

void RandData::GetRandByte(unsigned char &ucCh)
{
    int iPower = sizeof(unsigned char)*8;
    ucCh = rand()%((int)pow(2.0, iPower));
    return;
}