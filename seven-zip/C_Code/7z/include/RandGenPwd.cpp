#include <stdlib.h>
#include <time.h>
#include "RandGenPwd.h"

RandGenPwd * RandGenPwd::_pInst = NULL;


RandGenPwd::RandGenPwd(void)
{
    return;
}


RandGenPwd::~RandGenPwd(void)
{
    return;
}

RandGenPwd * RandGenPwd::GetInstance()
{
    if (NULL == _pInst)
    {
        _pInst = new RandGenPwd();
    }
    return _pInst;
}

int RandGenPwd::iGenRandPwd(string & sPwd, const int & iPwdLen)
{
    if (iPwdLen < cniMinPwdLen)
    {
        return EXIT_FAILURE;
    }
    sPwd.clear();
    
    for (int i = 0; i < iPwdLen; i++)
    {
        char ch;
        GenRandChar(ch);
        sPwd += ch; 
    }
    return EXIT_SUCCESS;
}

int RandGenPwd::iGenPrintSalt(string & sSalt, const int & iSaltLen)
{
    sSalt.clear();
    
    for (int i = 0; i < iSaltLen; i++)
    {
        char ch;
        int iIndex = rand()%(cnsVisualCharExt.size());
        ch = cnsVisualCharExt[iIndex];
        sSalt += ch; 
    }
    
    return EXIT_SUCCESS;
}

void RandGenPwd::initSeed()
{
		srand((unsigned int)time(0));
}

void RandGenPwd::GenRandChar(char & ch)
{
    int iIndex = rand()%(cnsVisualChar.size());
    ch = cnsVisualChar[iIndex];
    return;
}
