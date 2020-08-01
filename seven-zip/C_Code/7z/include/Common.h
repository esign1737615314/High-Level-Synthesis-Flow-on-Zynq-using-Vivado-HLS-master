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
    // ����ǰ��ָ��ַ������ָʽ��ָ����|������ָ�Ϊ��|12345|6789��
    int iParseItemByPreChar(vector<string> &vItem, const string & sStr, const char &ch = cncItemSeparator);
    // �����м�ָ��ַ������ָʽ��ָ������ָ�Ϊ"1234567|6789"
    int iParseItemByMidChar(vector<string> &vItem, const string & sStr, const char &ch = cncColumnSeparator);
    // ��16���ƴ�ת��Ϊ����
    void HexString2ByteData(ByteSeq & bsData, const string & sHexStr);
    // ��Byte����ת��Ϊ16���ƴ�
    int iByteData2HexString(string &sHexStr, const unsigned char * pByteData, const int & iByteDataLen);
    // �ж��Ƿ���16���ƴ�
    bool IsHexChar(const string &sDst);
    //�ж��ַ����Ƿ�������
    bool bIsDigital(const string & sData);
    // �ַ���ת��
    int iSrcEncodingStr2DstEncodingStr(const string &sSrcEncoding, const string & sDstEncoding, const string &sSrcEncodingStr, string & sDstEncodingStr);

    int iHashCatVerifyCase(const int & iHashAlgType, const string & sPwd, const string & sCaseDesc);
    
    // ת��Ϊ���
    uint16_t Endian(uint16_t src);
    uint32_t Endian(uint32_t src);
    uint64_t Endian(uint64_t src);
    int Endian(int src);
    
    // �����������ж��Ƿ���Ҫ�����ת��
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

