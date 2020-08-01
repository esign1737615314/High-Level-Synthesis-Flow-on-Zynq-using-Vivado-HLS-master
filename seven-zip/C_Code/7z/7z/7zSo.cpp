#include <fstream>
#include <istream>
#include "7z.h"
#include "7zSo.h"
#include "RandData.h"
#include "RandGenPwd.h"
using namespace std;

// Salt关键字
const string cnsSaltKey = "Salt";

const string cnsIV  = "IV";
const string cnsIVLen = "IVLen";
const string cnsCRC = "CRC";
const string cnsCoderAttr = "CoderAttr";
const string cnsCipherLen = "CipherLen";
const string cnsUnpackCipherLen = "UnpackCipherLen";
// 密文关键字
const string cnsEncryptedDataKey = "EncryptedData";
// Rar参数个数
const int cni7zParamNum = 10;
// Rar前缀
const string cns7zPrefix = "$7z$";
// 口令与用例描述串分割符
const char cncPwdCaseDescStrSeperator = '$';
// 用例描述串组成部分数
const int cniCaseDescComponetNum = 11;
// UserString数据长度
const int cniSaltLen = 8;
// OwnerString数据的长度
const int cniEncryptedLen = 16;

// 解析算法参数
int iParseAlgParam(const string & sInputParam, MapParam2Val& param2Val, string & sErr);

// PDF5的hashcat串
int iParseCaseParam(const string & sInputParam, MapParam2Val & param2Val, string & sErr);

// 用例执行
int iExeCase(const ByteSeq& bsPwd, const MapParam2Val& param2Val, string & sErr);

int iParseAlgParam(const string & sInputParam, MapParam2Val & param2Val, string & sErr)
{
    if (sInputParam.empty())
    {
        sErr = "Err: InputParam is empty";
        return EXIT_FAILURE;
    }
    vector<string> paramItem;
    if (EXIT_FAILURE == CCommon::GetInstance()->iParseItemByMidChar(paramItem, sInputParam, cncPwdCaseDescStrSeperator))
    {
        sErr = "Err: Parse to InputParam[" + sInputParam + "]";
        return EXIT_FAILURE;
    }
    if (paramItem.size() < cni7zParamNum)
    {
        sErr = "Err: Parsed ParamItemNum less than Requested";
        return EXIT_FAILURE;
    }

    vector<string>::iterator iter = paramItem.begin();
    
    ++iter;
    ++iter;
    ++iter;
    //if (!CCommon::GetInstance()->IsHexChar(*iter))
    //{
    //    sErr = "Err: Salt[" + *iter + "] Not HexString";
    //    return EXIT_FAILURE;
    //}
    ByteSeq bsData;
    //CCommon::GetInstance()->HexString2ByteData(bsData, *iter);
    //param2Val[cnsSaltKey] = bsData;
    
    ++iter;

    if(!CCommon::GetInstance()->bIsDigital(*iter))
    {
        return EXIT_FAILURE;
    }
    bsData.clear();
    int iIVLen = stoi(*iter);
    unsigned char *ucIVLen = (unsigned char *) (&iIVLen);
    int iIVucLen = sizeof(int);
    for (int i = 0; i < iIVucLen; i++)
    {
        bsData.push_back(ucIVLen[i]);
    }
    param2Val[cnsIVLen] = bsData;

    ++iter;

    if (!CCommon::GetInstance()->IsHexChar(*iter))
    {
        sErr = "Err: IVData[" + *iter + "] Not HexString";
        return EXIT_FAILURE;
    }

    bsData.clear();
    CCommon::GetInstance()->HexString2ByteData(bsData, *iter);
    param2Val[cnsIV] = bsData;

    ++iter;

    if(!CCommon::GetInstance()->bIsDigital(*iter))
    {
        return EXIT_FAILURE;
    }
    bsData.clear();
    unsigned int iCRC = stol(*iter);
    unsigned char *ucCRC = (unsigned char *) (&iCRC);
    int iCRCLen = sizeof(unsigned int);
    for (int i = 0; i < iCRCLen; i++)
    {
        bsData.push_back(ucCRC[i]);
    }
    param2Val[cnsCRC] = bsData;

    ++iter;

    if(!CCommon::GetInstance()->bIsDigital(*iter))
    {
        return EXIT_FAILURE;
    }
    bsData.clear();
    int iCipherLen = stoi(*iter);
    unsigned char *ucCipherLen = (unsigned char *) (&iCipherLen);
    for (int i = 0; i < iIVucLen; i++)
    {
        bsData.push_back(ucCipherLen[i]);
    }
    param2Val[cnsCipherLen] = bsData;

    ++iter;

    if(!CCommon::GetInstance()->bIsDigital(*iter))
    {
        return EXIT_FAILURE;
    }
    bsData.clear();

    int iUnpackCipherLen = stoi(*iter);
    unsigned char *ucUnpackCipherLen = (unsigned char *) (&iUnpackCipherLen);
    for (int i = 0; i < iIVucLen; i++)
    {
        bsData.push_back(ucUnpackCipherLen[i]);
    }
    param2Val[cnsUnpackCipherLen] = bsData;

    ++iter;

    if (!CCommon::GetInstance()->IsHexChar(*iter))
    {
        sErr = "Err: EncryptedData[" + *iter + "] Not HexString";
        return EXIT_FAILURE;
    }
    bsData.clear();
    CCommon::GetInstance()->HexString2ByteData(bsData, *iter);
    param2Val[cnsEncryptedDataKey] = bsData;
    return EXIT_SUCCESS;
}

int iParseCaseParam(const string & sInputParam, MapParam2Val & param2Val, string & sErr)
{
    if (sInputParam.empty())
    {
        ostringstream os;
        os << "CaseDesc can't Empty";
        sErr = os.str();
        return EXIT_FAILURE;
    }
    size_t nPos = sInputParam.find(cns7zPrefix);
    if (string::npos == nPos)
    {
        ostringstream os;
        os << "CaseDesc[" << sInputParam << "] not including Hashcat[" << cns7zPrefix << "]" << endl;
        sErr = os.str();
    }
    string sAlgStr;
    sAlgStr = sInputParam.substr(nPos+cns7zPrefix.length());
    if (EXIT_FAILURE == iParseAlgParam(sAlgStr, param2Val, sErr))
    {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int iExeCase(const ByteSeq& bsPwd, const MapParam2Val& param2Val, string & sErr)
{
    string sPwd;
    copy(bsPwd.begin(), bsPwd.end(), back_inserter(sPwd));

    unsigned char * pEncrypteData = NULL;
    int iEncryptedDataLen = 0;
    unsigned char * pIVData = NULL;
    int iIVLen = 0;
    unsigned int uiCRC = 0;
    int iCipherLen = 0;
    int iUnpackCipherLen = 0;
    MapParam2Val::const_iterator iter = param2Val.begin();
    for(; iter != param2Val.end(); iter++)
    {

        if (cnsEncryptedDataKey == iter->first)
        {
            iEncryptedDataLen = iter->second.size();
            pEncrypteData = new unsigned char [iEncryptedDataLen];
            memcpy(pEncrypteData,  &((iter->second)[0]), iEncryptedDataLen);
        }
        else if(cnsIVLen == iter->first)
        {
            memcpy(&iIVLen, &((iter->second)[0]), sizeof(int));
        }
        else if(cnsIV == iter->first)
        {
            pIVData = new unsigned char [iter->second.size()];
            memcpy(pIVData,  &((iter->second)[0]), iter->second.size());
        }
        else if(cnsCRC == iter->first)
        {
            memcpy(&uiCRC, &((iter->second)[0]), sizeof(int));
        }
        else if(cnsCipherLen == iter->first)
        {
            memcpy(&iCipherLen, &((iter->second)[0]), sizeof(int));
        }
        else if(cnsUnpackCipherLen == iter->first)
        {
            memcpy(&iUnpackCipherLen, &((iter->second)[0]), sizeof(int));
        }
    }
    
    Sevenz sz;
    
    // 字节序转换
		if(CCommon::GetInstance()->bNeedEndian())
		{
				iEncryptedDataLen = CCommon::GetInstance()->Endian(iEncryptedDataLen);
				iIVLen = CCommon::GetInstance()->Endian(iIVLen);
				iUnpackCipherLen = CCommon::GetInstance()->Endian(iUnpackCipherLen);
		}
		
    if (EXIT_FAILURE == sz.iVerify(sPwd, pEncrypteData, iEncryptedDataLen, pIVData, iIVLen, uiCRC, iUnpackCipherLen))
    {
        sErr = "Err: failed to verify, please check if TestCase is valid";
        if (NULL != pEncrypteData)
        {
            delete pEncrypteData;
            pEncrypteData = NULL;
        }
        if (NULL != pIVData)
        {
            delete pIVData;
            pIVData = NULL;
        }

        return EXIT_FAILURE;
    }
    if (NULL != pEncrypteData)
    {
        delete pEncrypteData;
        pEncrypteData = NULL;
    }
    if (NULL != pIVData)
    {
        delete pIVData;
        pIVData = NULL;
    }

    return EXIT_SUCCESS;
}

int iExeCase(const CaseInfoSeq & seqCaseInfo, CaseInfoStatusSeq & seqCaseInfoStatus
    , string &sErr, funOutpuDebugInfo fOpDebugInfo)
{
    if (seqCaseInfo.empty())
    {
        sErr = "CaseInfo Not Found";
        ostringstream os;
        os << "In <iExeCase> " << sErr << endl;
        fOpDebugInfo(SI_Error, sErr);
        return EXIT_FAILURE;
    }
    CaseInfoSeq::const_iterator iter = seqCaseInfo.begin();
    for (; iter != seqCaseInfo.end(); iter++)
    {
        string sSubErr;
        string sCaseData;
        copy(iter->bsCaseData.begin(), iter->bsCaseData.end(), back_inserter(sCaseData));
        MapParam2Val param2Val;
        if (EXIT_FAILURE == iParseCaseParam(sCaseData, param2Val, sSubErr))
        {
            ostringstream os;
            string sPwd;
            string sCaseData;
            copy(iter->bsPwd.begin(), iter->bsPwd.end(), back_inserter(sPwd));
            copy(iter->bsCaseData.begin(), iter->bsCaseData.end(), back_inserter(sCaseData));
            os << "In <iExeCase> failed to Parse CaseDesc[" << sPwd << ":" <<  sCaseData << "]" << endl;
            os << "Reason:" << sSubErr << endl;
            fOpDebugInfo(SI_Error, os.str());
            stCaseInfoStatus caseInfoStatus;
            caseInfoStatus.caseInfo = *iter;
            caseInfoStatus.bExeStatus = false;
            caseInfoStatus.sErr = sSubErr;
            seqCaseInfoStatus.push_back(caseInfoStatus);
            continue;
        }
        if (EXIT_FAILURE == iExeCase(iter->bsPwd, param2Val, sSubErr))
        {
            ostringstream os;
            string sPwd;
            string sCaseData;
            copy(iter->bsPwd.begin(), iter->bsPwd.end(), back_inserter(sPwd));
            copy(iter->bsCaseData.begin(), iter->bsCaseData.end(), back_inserter(sCaseData));
            os << "In <iExeCase> failed to Verify Case[" << sPwd << ":" <<  sCaseData << "]" << endl;
            os << "Reason:" << sSubErr << endl;
            fOpDebugInfo(SI_Error, os.str());
            stCaseInfoStatus caseInfoStatus;
            caseInfoStatus.caseInfo = *iter;
            caseInfoStatus.bExeStatus = false;
            caseInfoStatus.sErr = sSubErr;
            seqCaseInfoStatus.push_back(caseInfoStatus);
            continue;
        }
        else
        {
            stCaseInfoStatus caseInfoStatus;
            caseInfoStatus.caseInfo = *iter;
            caseInfoStatus.bExeStatus = true;
            seqCaseInfoStatus.push_back(caseInfoStatus);
        }
    }
    return EXIT_SUCCESS;
}

int iAutoGenCase(const int & iCaseNum, const int &iPwdLen,CaseInfoSeq & seqCaseInfo
    , string & sErr, funOutpuDebugInfo fOpDebugInfo)
{
    return EXIT_FAILURE;
}

// // 用例串的格式
int iGenCase(const string & sCaseDescInfo, CaseInfoSeq & seqCaseInfo, string & sErr
    , funOutpuDebugInfo fOpDebugInfo)
{
    return EXIT_FAILURE;
}

int iGenCaseByFile(const string & sCaseDescInfoFile, CaseInfoSeq & seqCaseInfo
    , string & sErr, funOutpuDebugInfo fOpDebugInfo)
{
    return EXIT_FAILURE;
}
