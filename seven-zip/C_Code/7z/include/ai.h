///////////////////////////////////////////////////////////////////////////////
//  版权      : 版权所有 (C) 江苏微锐超算科技有限公司
//  文件名    : ai.h
//  作者      : 
//  版本      : V1.0
//  日期      : 2019-01-16
//  描述      : 
//              本文件用于算法接口函数的定义。
//  其它      : 无
///////////////////////////////////////////////////////////////////////////////

#pragma once

#include <list>
#include <vector>
#include <map>
#include <deque>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <assert.h>
#include <string>



using namespace std;


//////////////////////////////////////////////////////////////////////////
//SO接口
//////////////////////////////////////////////////////////////////////////

//字节序列
typedef vector<unsigned char>       ByteSeq;
//字节序列的序列
typedef vector<ByteSeq>             ByteSeqSeq;
//参数名<--->参数值
typedef std::map<string, ByteSeq>   MapParam2Val;

typedef struct stCaseInfo
{
    ByteSeq bsPwd;
    ByteSeq bsCaseData;
    stCaseInfo()
    {
        bsPwd.clear();
        bsCaseData.clear();
        return;
    }
    stCaseInfo(const stCaseInfo &caseInfo)
    {
        bsPwd = caseInfo.bsPwd;
        bsCaseData = caseInfo.bsCaseData;
        return;
    }
    stCaseInfo & operator = (const stCaseInfo &caseInfo)
    {
        bsPwd = caseInfo.bsPwd;
        bsCaseData = caseInfo.bsCaseData;
        return *this;
    }
    friend ostream & operator << (ostream &os, const stCaseInfo &caseInfo)
    {
        string sPwd;
        string sCaseData;
        
        if(!caseInfo.bsPwd.empty())
        {
        		copy(caseInfo.bsPwd.begin(), caseInfo.bsPwd.end(), back_inserter(sPwd));
        }
        
        if(!caseInfo.bsCaseData.empty())
        {
        		copy(caseInfo.bsCaseData.begin(), caseInfo.bsCaseData.end(), back_inserter(sCaseData));
        }
        
        os << "Pwd[" << sPwd << "], CaseData[" << sCaseData << "]" << endl;
        return os;
    }
}stCaseInfo;
typedef vector<stCaseInfo> CaseInfoSeq;
typedef map<unsigned long long, stCaseInfo> CaseInfoDict;
typedef map<string, unsigned long long> AlgName2MaxCaseID;

// 用例执行状态
typedef struct stCaseInfoStatus
{
    // 用例信息 
    stCaseInfo caseInfo;
    // 用例执行状态
    bool bExeStatus;
    // 执行失败原因
    string sErr;
    stCaseInfoStatus()
    {
        bExeStatus = false;
        sErr.clear();
        return;
    }
    stCaseInfoStatus(const stCaseInfoStatus & caseInfoStatus)
    {
        caseInfo = caseInfoStatus.caseInfo;
        bExeStatus = caseInfoStatus.bExeStatus;
        sErr = caseInfoStatus.sErr;
        return;
    }
    stCaseInfoStatus & operator = (const stCaseInfoStatus & caseInfoStatus)
    {
        caseInfo = caseInfoStatus.caseInfo;
        bExeStatus = caseInfoStatus.bExeStatus;
        sErr = caseInfoStatus.sErr;
        return *this;
    }
    friend ostream & operator << (ostream & os, const stCaseInfoStatus & caseInfoStatus)
    {
        os << "CaseInfo:" << caseInfoStatus.caseInfo;
        os << "Verified-Status[" << (caseInfoStatus.bExeStatus? "Success":"failed") << "]";
        if (!caseInfoStatus.bExeStatus)
        {
            os << "Failed Err:" << caseInfoStatus.sErr << endl;
        }
        else
        {
            os << endl;
        }
        return os;
    }
}stCaseInfoStatus;

typedef vector<stCaseInfoStatus> CaseInfoStatusSeq;


//参数一般包括： 
//  0:  盐
//  1:  IV
//  2:  用户名
//  3:  目标串0
//  4:  目标串1
//  5:  多目标串
//  6:  编码方式
//  7： ……

//so中所实现的接口函数名
const string cnsFunInitAlgSoWithFile            = "iInitAlgSoWithFile";
const string cnsFunInitAlgSoWithMap             = "iInitAlgSoWithMap";
const string cnsFunDestroyAlgSo                 = "iDestroyAlgSo";
const string cnsFunGetOutput4Pwd                = "iGetOutput4Pwd";
const string cnsFunGetOutput4Pwds               = "iGetOutput4Pwds";
const string cnsFunExeCase                      = "iExeCase";
const string cnsFunAutoGenCase                  = "iAutoGenCase";
const string cnsFunGenCase                      = "iGenCase";
const string cnsFunGenCaseByFile                = "iGenCaseByFile";



typedef enum enum_SoInfo_level
{
    SI_Debug   = 1,            //调试信息
    SI_Info    = 2,            //一般信息
    SI_Msg     = 3,            //消息
    SI_Alert   = 4,            //告警
    SI_Error   = 5,            //错误
    SI_Fatal   = 6,            //致命
}enSILevel;

//日志信息回送给管理程序的函数类型定义
typedef void (*funOutpuDebugInfo)(const int& iInfoLevel, const string& sErr);
//在so中设置日志信息回送的函数指针
typedef int (*funSetCallback4DebugInfo)(funOutpuDebugInfo fOutputDebuginfo);


//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//输出
///////////////////////////////////////////////////////////////////////////////
// 函数名称 :   funExeCase
// 当前版本 :   V1.0
// 作    者 :   
// 创建日期 :   2019-01-17
// 输入/输出参数 :
//              seqCaseInfo         ---     待执行的用例:（输入参数）
//              CaseInfoStatusSeq   ---     用例执行验证返回的状态（二进制方式出）（输出参数）
//              sErr                ---     相关错误提示（输出参数）
//              fOpDebugInfo        ---     错误信息输出到日志信息函数
//
//  返回值：
//              0                   ---     成功
//              -1                  ---     失败
//
// 功能说明 :   
//              执行用例，并返回用例执行的结果
//              
///////////////////////////////////////////////////////////////////////////////
typedef int (*funExeCase)(const CaseInfoSeq & seqCaseInfo, CaseInfoStatusSeq & seqCaseInfoStatus
    , string &sErr, funOutpuDebugInfo fOpDebugInfo);

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//输出
///////////////////////////////////////////////////////////////////////////////
// 函数名称 :   funAutoGenCase
// 当前版本 :   V1.0
// 作    者 :   
// 创建日期 :   2019-01-17
// 输入/输出参数 :
//              iCaseNum            ---     用例条数
//              seqCaseInfo         ---     生成的用例:（输出参数）
//              sErr                ---     相关错误提示（输出参数）
//              fOpDebugInfo        ---     错误信息输出到日志信息函数
//
//  返回值：
//              0                   ---     成功
//              -1                  ---     失败
//
// 功能说明 :   
//              自动产生用例并返回用例
//              
///////////////////////////////////////////////////////////////////////////////
typedef int (*funAutoGenCase)(const int & iCaseNum, const int &iPwd,CaseInfoSeq & seqCaseInfo, string & sErr, funOutpuDebugInfo fOpDebugInfo);




//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//输出
///////////////////////////////////////////////////////////////////////////////
// 函数名称 :   funGenCase
// 当前版本 :   V1.0
// 作    者 :   
// 创建日期 :   2019-01-17
// 输入/输出参数 :
//              sCaseDescInfo       ---     用例描述信息（输入参数）
//              seqCaseInfo         ---     生成的用例:（输出参数）
//              sErr                ---     相关错误提示（输出参数）
//              fOpDebugInfo        ---     错误信息输出到日志信息函数
//
//  返回值：
//              0                   ---     成功
//              -1                  ---     失败
//
// 功能说明 :   
//              通过用例描述串产生用例并返回用例
//              
///////////////////////////////////////////////////////////////////////////////
typedef int (*funGenCase)(const string & sCaseDescInfo, CaseInfoSeq & seqCaseInfo, string & sErr, funOutpuDebugInfo fOpDebugInfo);


//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//输出
///////////////////////////////////////////////////////////////////////////////
// 函数名称 :   funGenCaseByFile
// 当前版本 :   V1.0
// 作    者 :   
// 创建日期 :   2019-01-17
// 输入/输出参数 :
//              sCaseDescInfoFile   ---     用例描述信息文件名（输入参数）
//              seqCaseInfo         ---     生成的用例:（输出参数）
//              sErr                ---     相关错误提示（输出参数）
//              fOpDebugInfo        ---     错误信息输出到日志信息函数
//
//  返回值：
//              0                   ---     成功
//              -1                  ---     失败
//
// 功能说明 :   
//              通过用例描述文件产生用例并返回用例
//              
///////////////////////////////////////////////////////////////////////////////
typedef int (*funGenCaseByFile)(const string & sCaseDescInfoFile, CaseInfoSeq & seqCaseInfo, string & sErr, funOutpuDebugInfo fOpDebugInfo);

