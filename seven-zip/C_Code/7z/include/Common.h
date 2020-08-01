#pragma once
#include <stdio.h>
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>
#include <string.h>
#include <stdint.h>
#include "ai.h"

using namespace std;
const string cnsHexChar = "0123456789abcdefABCDEF";
const char cncItemSeparator = '$';
const char cncColumnSeparator = '*';
const string GBK_CHARCODE = "GBK";
const string UNICODE_CHARCODE             = "UNICODELITTLE";
const int  BUFFER_SIZE = (1<<20);
const string DEFAULT_INI_PATH					= "am.ini";
const string ENDIAN_INI_KEY = 			"BigEndian";
const string INI_COMMON_SECTION	=		"Common";

class CCommon
{
public:
    ~CCommon(void);
    static CCommon * GetInstance();
    // 符号前向分割字符串，分割方式如分割符‘|’，则分割为“|12345|6789”
    int iParseItemByPreChar(vector<string> &vItem, const string & sStr, const char &ch = cncItemSeparator);
    // 符号中间分割字符串，分割方式如分割符，则分割为"1234567|6789"
    int iParseItemByMidChar(vector<string> &vItem, const string & sStr, const char &ch = cncColumnSeparator);
    // 将16进制串转换为数据
    void HexString2ByteData(ByteSeq & bsData, const string & sHexStr);
    // 将Byte数据转换为16进制串
    int iByteData2HexString(string &sHexStr, const unsigned char * pByteData, const int & iByteDataLen);
    // 判断是否是16进制串
    bool IsHexChar(const string &sDst);
    //判断字符串是否是数字
    bool bIsDigital(const string & sData);
    // 字符集转换
    int iSrcEncodingStr2DstEncodingStr(const string &sSrcEncoding, const string & sDstEncoding, const string &sSrcEncodingStr, string & sDstEncodingStr);

    int iHashCatVerifyCase(const int & iHashAlgType, const string & sPwd, const string & sCaseDesc);
    
    // 转换为大端
    uint16_t Endian(uint16_t src);
    uint32_t Endian(uint32_t src);
    uint64_t Endian(uint64_t src);
    int Endian(int src);
    
    // 根据配置来判断是否需要做大端转换
    bool bNeedEndian();

private:
		uint16_t Swap(uint16_t src);
    uint32_t Swap(uint32_t src);
    uint64_t Swap(uint64_t src);   
    int Swap(int value); 	
   
private:
    CCommon(void);
    static CCommon * _pInst;
};

