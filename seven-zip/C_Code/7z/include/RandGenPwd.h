#pragma once
#include <string>
#include <string.h>

using namespace std;

// 可见字符
const string cnsVisualChar = "abcedfghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUCWXYZ0123456789`-=[]\\;',./~!@#$%^&*()_+{}|\"<>? ";
const string cnsVisualCharExt = "abcedfghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUCWXYZ0123456789";
// 最短口令长度
const int cniMinPwdLen = 1;

class RandGenPwd
{
public:
    ~RandGenPwd(void);
    static RandGenPwd * GetInstance();
    int iGenRandPwd(string & sPwd, const int & iPwdLen); // 随机产生口令
    int iGenPrintSalt(string & sSalt, const int & iSaltLen);
    void initSeed();
protected:
    void GenRandChar(char & ch);
private:
    RandGenPwd(void);
    static RandGenPwd * _pInst;
};

