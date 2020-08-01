///////////////////////////////////////////////////////////////////////////////
//  ��Ȩ      : ��Ȩ���� (C) ����΢����Ƽ����޹�˾
//  �ļ���    : ai.h
//  ����      : 
//  �汾      : V1.0
//  ����      : 2019-01-16
//  ����      : 
//              ���ļ������㷨�ӿں����Ķ��塣
//  ����      : ��
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
//SO�ӿ�
//////////////////////////////////////////////////////////////////////////

//�ֽ�����
typedef vector<unsigned char>       ByteSeq;
//�ֽ����е�����
typedef vector<ByteSeq>             ByteSeqSeq;
//������<--->����ֵ
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

// ����ִ��״̬
typedef struct stCaseInfoStatus
{
    // ������Ϣ 
    stCaseInfo caseInfo;
    // ����ִ��״̬
    bool bExeStatus;
    // ִ��ʧ��ԭ��
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


//����һ������� 
//  0:  ��
//  1:  IV
//  2:  �û���
//  3:  Ŀ�괮0
//  4:  Ŀ�괮1
//  5:  ��Ŀ�괮
//  6:  ���뷽ʽ
//  7�� ����

//so����ʵ�ֵĽӿں�����
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
    SI_Debug   = 1,            //������Ϣ
    SI_Info    = 2,            //һ����Ϣ
    SI_Msg     = 3,            //��Ϣ
    SI_Alert   = 4,            //�澯
    SI_Error   = 5,            //����
    SI_Fatal   = 6,            //����
}enSILevel;

//��־��Ϣ���͸��������ĺ������Ͷ���
typedef void (*funOutpuDebugInfo)(const int& iInfoLevel, const string& sErr);
//��so��������־��Ϣ���͵ĺ���ָ��
typedef int (*funSetCallback4DebugInfo)(funOutpuDebugInfo fOutputDebuginfo);


//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//���
///////////////////////////////////////////////////////////////////////////////
// �������� :   funExeCase
// ��ǰ�汾 :   V1.0
// ��    �� :   
// �������� :   2019-01-17
// ����/������� :
//              seqCaseInfo         ---     ��ִ�е�����:�����������
//              CaseInfoStatusSeq   ---     ����ִ����֤���ص�״̬�������Ʒ�ʽ���������������
//              sErr                ---     ��ش�����ʾ�����������
//              fOpDebugInfo        ---     ������Ϣ�������־��Ϣ����
//
//  ����ֵ��
//              0                   ---     �ɹ�
//              -1                  ---     ʧ��
//
// ����˵�� :   
//              ִ������������������ִ�еĽ��
//              
///////////////////////////////////////////////////////////////////////////////
typedef int (*funExeCase)(const CaseInfoSeq & seqCaseInfo, CaseInfoStatusSeq & seqCaseInfoStatus
    , string &sErr, funOutpuDebugInfo fOpDebugInfo);

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//���
///////////////////////////////////////////////////////////////////////////////
// �������� :   funAutoGenCase
// ��ǰ�汾 :   V1.0
// ��    �� :   
// �������� :   2019-01-17
// ����/������� :
//              iCaseNum            ---     ��������
//              seqCaseInfo         ---     ���ɵ�����:�����������
//              sErr                ---     ��ش�����ʾ�����������
//              fOpDebugInfo        ---     ������Ϣ�������־��Ϣ����
//
//  ����ֵ��
//              0                   ---     �ɹ�
//              -1                  ---     ʧ��
//
// ����˵�� :   
//              �Զ�������������������
//              
///////////////////////////////////////////////////////////////////////////////
typedef int (*funAutoGenCase)(const int & iCaseNum, const int &iPwd,CaseInfoSeq & seqCaseInfo, string & sErr, funOutpuDebugInfo fOpDebugInfo);




//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//���
///////////////////////////////////////////////////////////////////////////////
// �������� :   funGenCase
// ��ǰ�汾 :   V1.0
// ��    �� :   
// �������� :   2019-01-17
// ����/������� :
//              sCaseDescInfo       ---     ����������Ϣ�����������
//              seqCaseInfo         ---     ���ɵ�����:�����������
//              sErr                ---     ��ش�����ʾ�����������
//              fOpDebugInfo        ---     ������Ϣ�������־��Ϣ����
//
//  ����ֵ��
//              0                   ---     �ɹ�
//              -1                  ---     ʧ��
//
// ����˵�� :   
//              ͨ������������������������������
//              
///////////////////////////////////////////////////////////////////////////////
typedef int (*funGenCase)(const string & sCaseDescInfo, CaseInfoSeq & seqCaseInfo, string & sErr, funOutpuDebugInfo fOpDebugInfo);


//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//���
///////////////////////////////////////////////////////////////////////////////
// �������� :   funGenCaseByFile
// ��ǰ�汾 :   V1.0
// ��    �� :   
// �������� :   2019-01-17
// ����/������� :
//              sCaseDescInfoFile   ---     ����������Ϣ�ļ��������������
//              seqCaseInfo         ---     ���ɵ�����:�����������
//              sErr                ---     ��ش�����ʾ�����������
//              fOpDebugInfo        ---     ������Ϣ�������־��Ϣ����
//
//  ����ֵ��
//              0                   ---     �ɹ�
//              -1                  ---     ʧ��
//
// ����˵�� :   
//              ͨ�����������ļ�������������������
//              
///////////////////////////////////////////////////////////////////////////////
typedef int (*funGenCaseByFile)(const string & sCaseDescInfoFile, CaseInfoSeq & seqCaseInfo, string & sErr, funOutpuDebugInfo fOpDebugInfo);

