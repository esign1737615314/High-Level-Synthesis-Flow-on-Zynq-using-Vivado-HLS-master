#include <openssl/sha.h>
#include <openssl/aes.h>
#include "Common.h"
#include "7zUnpack/7zUnpack.h"

#include "7z.h"

// 盐的长度
const int cniSaltLen = 8;

// 密文的长度
const int cniEncrayptedDataLen = 3096;

// 口令+盐+拼接次数的拼接轮数
const int cniMergeLoopCount = 0x80000;

// 拼接轮数的字节数
const int cniMergeLoopCountLen = 3;

const int cniFillLength = 5;
const int cniFillValue = 0;

const int cniCRCLeng = 4;

// AES秘钥长度
const int cniAESKeyLen = 32;

// IV的长度
const int cniIVLen = 16;

// 特征串
const unsigned char cucFlag[] = {0xC4, 0x3D, 0x7B, 0x00, 0x40, 0x07, 0x00};

Sevenz::Sevenz(void)
{
    return;
}


Sevenz::~Sevenz(void)
{
    return;
}


int Sevenz::iVerify(const string &sPwd
    , const unsigned char * ucEncryptedData, const int & ibeEncryptedLen
    , const unsigned char * ucIV, const int & ibeIVLength
    , const unsigned int & iCRC, const int & ibeUnpackCRCLen)
{
		int iEncryptedLen = ibeEncryptedLen;
		int iIVLength = ibeIVLength;
		int iUnpackCRCLen = ibeUnpackCRCLen;
		
		// 字节序转换
		if(CCommon::GetInstance()->bNeedEndian())
		{
				iEncryptedLen = CCommon::GetInstance()->Endian(ibeEncryptedLen);
				iIVLength = CCommon::GetInstance()->Endian(ibeIVLength);
				iUnpackCRCLen = CCommon::GetInstance()->Endian(ibeUnpackCRCLen);
		}
		
    // a)	获取pass，并获取口令长度pass_len；
    if (NULL == ucEncryptedData)
    {
        return EXIT_FAILURE;
    }
    
    string sUPwd;

    // utf16le pass
    // b)	pass_untf16bl = utf16le(pass)；
    if (EXIT_FAILURE == CCommon::GetInstance()->iSrcEncodingStr2DstEncodingStr(GBK_CHARCODE, UNICODE_CHARCODE, sPwd, sUPwd))
    {
        return EXIT_FAILURE;
    }

    // 计算Key和IV
    // aes的Key计算

    unsigned char ucAESKey[SHA256_DIGEST_LENGTH];
    memset(ucAESKey, 0, SHA256_DIGEST_LENGTH);
    // 初始化SHA256
    SHA256_CTX Context;
    SHA256_Init(&Context);
    Byte temp[8] = { 0,0,0,0,0,0,0,0 };

    // 拼接字符串+SHA256
    // c)	循环coutn次，拼接字符串 M[i] = { pass_untf16bl || i };(其中i 从0到count-1占8字节)；
    // d)	M_key = M [0] || M [1] || … || M [524287];
    // e)	AESKey = SHA256（M_key），AESKey长度为32字节。
    for (int i = 0; i < cniMergeLoopCount; i++)
    {
        SHA256_Update(&Context, sUPwd.c_str(), sUPwd.size());
        SHA256_Update(&Context, temp, 8);
        for (int i = 0; i < 8; i++)
            if (++(temp[i]) != 0)
                break;
    }
    SHA256_Final(ucAESKey, &Context);
#ifdef DEBUG
    printf("Key:");
    for (int i = 0; i < cniAESKeyLen; i++)
    {
        printf("%02x", ucAESKey[i]);
    }
    printf("\n");
    printf("IV:");
    for (int i = 0; i < cniIVLen; i++)
    {
        printf("%02x", ucIV[i]);
    }
    printf("\n");
#endif


    // 解密数据
    unsigned char ucDecryptedData[cniEncrayptedDataLen];
    memset(ucDecryptedData, 0, cniEncrayptedDataLen);
    C7zUnpack *pCK = new C7zUnpack();
    unsigned char ucIVTemp[16] = {0};
    memset(ucIVTemp, 0, 16);
    memcpy(ucIVTemp, ucIV, iIVLength);
    unsigned char ucEnTemp[cniEncrayptedDataLen] = {0};
    memcpy(ucEnTemp, ucEncryptedData, iEncryptedLen);

    // AES256 解密
    // b)	利用AES256解密算法解密：
    if(EXIT_FAILURE == pCK->iAesDecoder(ucEnTemp, iEncryptedLen, ucDecryptedData, iEncryptedLen, 
        ucAESKey, 32, ucIVTemp, 16))
    {
        delete pCK;
        pCK = NULL;

        return EXIT_FAILURE;
    }
    pCK->iBcjTransfor(ucDecryptedData, iEncryptedLen);

#ifdef DEBUG
    printf("ucEncryptedData:");
    for (int i = 0; i < iEncryptedLen; i++)
    {
        printf("%02x", ucEncryptedData[i]);
    }
    printf("\n");
    printf("ucDecryptedData:");
    for (int i = 0; i < iEncryptedLen; i++)
    {
        printf("%02x", ucDecryptedData[i]);
    }
    printf("\n");
#endif


    // CRC算法校验plaintext
    // c)	使用4字节CRC_in数据，利用CRC算法校验plaintext
    int iRet = pCK->iCheckCrc(ucDecryptedData, iUnpackCRCLen, iCRC);

    delete pCK;
    pCK = NULL;
    // d)	若校验正确，则当前口令验证成功
    return iRet;
}


#ifdef DEBUG
int main()
{
     string sPwd = "hashcat";
     unsigned char  ucEncryptedData[] = {0xf3,0xbc,0x2a,0x88,0x06,0x2c,0x41,0x9a,0x25,0xac,0xd4,0x0c,0x0c,0x2d,0x75,0x42
                                        ,0x1c,0xf2,0x32,0x63,0xf6,0x9c,0x51,0xb1,0x3f,0x9b,0x1a,0xad,0xa4,0x1a,0x8a,0x09
                                        ,0xf9,0xad,0xea,0xe4,0x5d,0x67,0xc6,0x0b,0x56,0xaa,0xd3,0x38,0xf2,0x0c,0x0d,0xcc
                                        ,0x5e,0xb8,0x11,0xc7,0xa6,0x11,0x28,0xee,0x07,0x46,0xf9,0x22,0xcd,0xb9,0xc5,0x90
                                        ,0x96,0x86,0x9f,0x34,0x1c,0x7a,0x9c,0xb1,0xac,0x7b,0xb7,0xd7,0x71,0xf5,0x46,0xb8
                                        ,0x2c,0xf4,0xe6,0xf1,0x1a,0x5e,0xcd,0x4b,0x61,0x75,0x1e,0x4d,0x8d,0xe6,0x6d,0xd6
                                        ,0xe2,0xdf,0xb5,0xb7,0xd1,0x02,0x2d,0x22,0x11,0xe2,0xd6,0x6e,0xa1,0x70,0x3f,0x96};
     int  ibeEncryptedLen = 112;
     unsigned char ucIV[] = {0xf6,0x19,0x62,0x59,0xa7,0x32,0x6e,0x3f,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}; 
     int ibeIVLength = 8;
     unsigned int iCRC = 185065650; 
     int ibeUnpackCRCLen = 98;
     
    Sevenz z;
    if (EXIT_SUCCESS == z.iVerify(sPwd, ucEncryptedData, ibeEncryptedLen, ucIV, ibeIVLength, iCRC, ibeUnpackCRCLen))
    {
        printf("VerifySuccess\n");
    }
    else
    {
        printf("VerifyFailed\n");
    }
    return 0;
}
#endif
