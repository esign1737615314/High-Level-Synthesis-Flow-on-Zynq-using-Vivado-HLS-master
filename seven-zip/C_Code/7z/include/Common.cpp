#include <iconv.h>
#include <fstream>
#include "Common.h"
#include "IniFile.h"

using namespace std;

const string cnsVerifiedFlag = "Cracked";

const int cniHashcatVerifyResultBsLen = 256;

CCommon * CCommon::_pInst = NULL;

CCommon::CCommon(void)
{
    return;
}


CCommon::~CCommon(void)
{
    return;
}


CCommon * CCommon::GetInstance()
{
    if (NULL == _pInst)
    {
        _pInst = new CCommon();
    }
    return _pInst;
}

int CCommon::iParseItemByPreChar(vector<string> &vItem, const string & sStr, const char &ch)
{
    string sValue = sStr;
    size_t nPos = sValue.find_first_of(ch);
    if (string::npos == nPos)
    {
        return EXIT_FAILURE;
    }
    sValue = sValue.substr(nPos+1);
    nPos = sValue.find_first_of(ch);
    while (string::npos != nPos)
    {
        vItem.push_back(sValue.substr(0, nPos));
        sValue = sValue.substr(nPos+1);
        nPos = sValue.find_first_of(ch);
    }
    if (!sValue.empty())
    {
        vItem.push_back(sValue);
    }
    return EXIT_SUCCESS;
}


int CCommon::iParseItemByMidChar(vector<string> &vItem, const string & sStr, const char &ch)
{
    string sValue = sStr;
    size_t nPos = sValue.find_first_of(ch);
    while (string::npos != nPos)
    {
        vItem.push_back(sValue.substr(0, nPos));
        sValue = sValue.substr(nPos+1);
        nPos = sValue.find_first_of(ch);
    }
    if (!sValue.empty())
    {
        vItem.push_back(sValue);
    }
    return EXIT_SUCCESS;
}

void CCommon::HexString2ByteData(ByteSeq & bsData, const string & sHexStr)
{
    const char *pStr = sHexStr.c_str();
    int iDataLen = sHexStr.length();
    for (int i = 0; i*2 <iDataLen; i++)
    {
        unsigned int ulData;
        sscanf(&pStr[i*2], "%02x", &ulData);
        bsData.push_back(ulData & 0xFF);
    }
    return;
}

// 将Byte数据转换为16进制串
int CCommon::iByteData2HexString(string &sHexStr, const unsigned char * pByteData, const int & iByteDataLen)
{
    if (NULL == pByteData)
    {
        return EXIT_FAILURE;
    }
    char sTmpData[3];
    memset(sTmpData, 0, 3);
    sHexStr.clear();
    for (int i = 0; i < iByteDataLen; i++)
    {
        sprintf(sTmpData, "%02x", pByteData[i]);
        sHexStr += string(sTmpData);
    }
    return EXIT_SUCCESS;
}

bool CCommon::IsHexChar(const string &sDst)
{
    for (string::const_iterator ch = sDst.begin(); ch != sDst.end(); ch++)
    {
        string::const_iterator iter = find(cnsHexChar.begin(), cnsHexChar.end(), *ch);
        if (iter == cnsHexChar.end())
        {
            return false;
        }
    }
    return true;
}

bool CCommon::bIsDigital(const string & sData)
{
    if (sData.empty())
    {
        return false;
    }
    int iPwdLen = sData.length();
    for (int i = 0; i < iPwdLen; i++)
    {
        if (!isdigit(sData[i]))
        {
            return false;
        }
    }
    return true;
}

int CCommon::iSrcEncodingStr2DstEncodingStr(const string &sSrcEncoding, const string & sDstEncoding, const string &sSrcEncodingStr, string & sDstEncodingStr)
{
    ostringstream os;
    iconv_t         cd = 0;
    cd = iconv_open(sDstEncoding.c_str(), sSrcEncoding.c_str());
    if( 0 ==  cd )
    {
        return EXIT_FAILURE;
    }
    sDstEncodingStr.clear();
    size_t iSrcBufLen = sSrcEncodingStr.length();
    size_t iDstBufLen = BUFFER_SIZE;
    char arDst[BUFFER_SIZE];
    char arSrc[BUFFER_SIZE];
    memset(arDst, 0, BUFFER_SIZE);
    memset(arSrc, 0, BUFFER_SIZE);
    char *pDst = arDst;
    char *pSrc = arSrc;
    memcpy(arSrc, sSrcEncodingStr.c_str(), iSrcBufLen);
    if(0>iconv(cd, (char**)&pSrc, (size_t*)&iSrcBufLen, (char**)&pDst, (size_t*)&iDstBufLen))
    {
        iconv_close(cd);
        return EXIT_FAILURE;
    }
    iconv_close(cd);
    int iDstStrLen = BUFFER_SIZE -  iDstBufLen;
    copy(arDst, arDst+iDstStrLen, back_inserter(sDstEncodingStr));
    return EXIT_SUCCESS;
}

int CCommon::iHashCatVerifyCase(const int & iHashAlgType, const string & sPwd, const string & sCaseDesc)
{
    const string sDictFileName = "testDict";
    ofstream ofs(sDictFileName.c_str());
    if (!ofs.is_open())
    {
        return EXIT_FAILURE;
    }
    ofs << sPwd;
    ofs.close();
    const string sTestCaseFileName = "testcase";
    ofstream ofss;
    ofss.open(sTestCaseFileName.c_str());
    if (!ofss.is_open())
    {
        return EXIT_FAILURE;
    }
    ofss << sCaseDesc;
    ofss.close();
    ostringstream oCmd;
    oCmd << "hashcat --potfile-disable --force -a 0 -m ";
    oCmd << iHashAlgType << " ";
    oCmd << sTestCaseFileName << " ./testDict";
    string sCommand = oCmd.str();
    FILE* pipe = popen(sCommand.c_str(), "r");
    if (pipe != NULL)
    {
        string sResultStr;
        char sResult[cniHashcatVerifyResultBsLen];
        memset(sResult, 0, cniHashcatVerifyResultBsLen);
        while(fgets(sResult, cniHashcatVerifyResultBsLen-1, pipe))
        {
            sResultStr += sResult;
            memset(sResult, 0, cniHashcatVerifyResultBsLen);
        }
        pclose(pipe);
        pipe = NULL;
        size_t nPos = sResultStr.find(cnsVerifiedFlag);
        if (string::npos != nPos)
        {
            return EXIT_SUCCESS;
        }
        else
        {
            return EXIT_FAILURE;
        }
    }
    return EXIT_FAILURE;
}

// 转换为大端
uint16_t CCommon::Endian(uint16_t src)
{
    int x = 1;
		
    if(*((char*)&x))
    {
        // 小端模式
        return Swap(src);
    }
    else
    {
        // 大端模式
        return src;
    }
}

uint32_t CCommon::Endian(uint32_t src)
{
    int x = 1;
		
    if(*((char*)&x))
    {
        // 小端模式
        return Swap(src);
    }
    else
    {
        // 大端模式
        return src;
    }
}

uint64_t CCommon::Endian(uint64_t src)
{
		int x = 1;
		
		if(*((char*)&x))
		{
				// 小端模式
				return Swap(src);
		}
		else
		{
				// 大端模式
				return src;
		}
}

int CCommon::Endian(int src)
{
		int x = 1;
		
		if(*((char*)&x))
		{
				// CPU为小端模式
				return Swap(src);
		}
		else
		{
				// CPU为大端模式
				return src;
		}
}

uint16_t CCommon::Swap(uint16_t value)
{
		uint16_t r;
		
		((uint8_t*)&r)[0] = ((uint8_t*)&value)[1];
		((uint8_t*)&r)[1] = ((uint8_t*)&value)[0];
		return r;
}

uint32_t CCommon::Swap(uint32_t value)
{
		uint32_t r;
		
		((uint8_t*)&r)[0] = ((uint8_t*)&value)[3];
		((uint8_t*)&r)[1] = ((uint8_t*)&value)[2];
		((uint8_t*)&r)[2] = ((uint8_t*)&value)[1];
		((uint8_t*)&r)[3] = ((uint8_t*)&value)[0];
		return r;
}

int CCommon::Swap(int value)
{
		int r;
		
		((uint8_t*)&r)[0] = ((uint8_t*)&value)[3];
		((uint8_t*)&r)[1] = ((uint8_t*)&value)[2];
		((uint8_t*)&r)[2] = ((uint8_t*)&value)[1];
		((uint8_t*)&r)[3] = ((uint8_t*)&value)[0];
		return r;
}

uint64_t CCommon::Swap(uint64_t value)
{
		uint64_t r;
		
		((uint8_t*)&r)[0] = ((uint8_t*)&value)[7];
		((uint8_t*)&r)[1] = ((uint8_t*)&value)[6];
		((uint8_t*)&r)[2] = ((uint8_t*)&value)[5];
		((uint8_t*)&r)[3] = ((uint8_t*)&value)[4];
		((uint8_t*)&r)[4] = ((uint8_t*)&value)[3];
		((uint8_t*)&r)[5] = ((uint8_t*)&value)[2];
		((uint8_t*)&r)[6] = ((uint8_t*)&value)[1];
		((uint8_t*)&r)[7] = ((uint8_t*)&value)[0];
		return r;
}

// 根据配置来判断是否需要做大端转换
bool CCommon::bNeedEndian()
{
		int iBigEndian = 0;
		
		if(!CIniFile::GetValue(ENDIAN_INI_KEY, INI_COMMON_SECTION, DEFAULT_INI_PATH, iBigEndian))
		{
				return false;
		}
		
		return 	iBigEndian > 0 ? true : false;
}


