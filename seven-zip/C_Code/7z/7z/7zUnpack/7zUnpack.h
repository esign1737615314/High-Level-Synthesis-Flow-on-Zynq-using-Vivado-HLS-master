#ifndef __7ZUNPACK_H_
#define __7ZUNPACK_H_

#include "Types.h"


class C7zUnpack
{
public:
    C7zUnpack(void);
    ~C7zUnpack(void);

    // AES����
    //--------------------------------------------------------------------------
    // sEncData          : AES ciphertext data
    // lEncDataLen       : AES ciphertext data length
    // sDecData          : AES plaintext data
    // lDecDataLen       : AES plaintext data length
    // sKey              : AES key data
    // iKeyLen           : AES key data length
    // sIv               : AES iv data
    // sIvLen            : AES iv data length
    // return(int)       : EXIT_SUCCESS decode success, EXIT_FAILURE decode fail
    //--------------------------------------------------------------------------
    int iAesDecoder(unsigned char *sEncData, unsigned long long lEncDataLen,
                    unsigned char *sDecData, unsigned long long lDecDataLen,
                    unsigned char *sKey, unsigned int iKeyLen,
                    unsigned char *sIv, unsigned int iIvLen);

    // LZMA��ѹ��
    //--------------------------------------------------------------------------
    // sPackData         : compression data
    // lPackDataLen      : compression data length
    // sProps            : compression property data 
    // iPropsLen         : compression property data length
    // sUnpackData       : uncompression data
    // lUnpackDataLen    : uncompression data length
    // return(int)       : EXIT_SUCCESS unpack success, EXIT_FAILURE unpack fail
    //--------------------------------------------------------------------------
    int iLzmaUnpack(unsigned char *sPackData, unsigned long long lPackDataLen,
                    unsigned char *sProps, unsigned int iPropsLen,
                    unsigned char *sUnpackData, unsigned long long lUnpackDataLen);

    // LZMA2��ѹ��
    //--------------------------------------------------------------------------
    // sPackData         : compression data
    // lPackDataLen      : compression data length
    // sProps            : compression property data, just need one byte
    // sUnpackData       : uncompression data
    // lUnpackDataLen    : uncompression data length
    // return(int)       : EXIT_SUCCESS unpack success, EXIT_FAILURE unpack fail
    //--------------------------------------------------------------------------
    int iLzma2Unpack(unsigned char *sPackData, unsigned long long lPackDataLen,
                     unsigned char iProps,
                     unsigned char *sUnpackData, unsigned long long lUnpackDataLen);

    // BZIP2��ѹ��
    //--------------------------------------------------------------------------
    // sPackData         : compression data
    // lPackDataLen      : compression data length
    // return(int)       : EXIT_SUCCESS unpack success, EXIT_FAILURE unpack fail
    //--------------------------------------------------------------------------
    int iBzip2Unpack(unsigned char *sPackData, unsigned long long lPackDataLen);

    // PPMD��ѹ��
    //--------------------------------------------------------------------------
    // sPackData         : compression data
    // lPackDataLen      : compression data length
    // sProps            : compression property data 
    // iPropsLen         : compression property data length
    // sUnpackData       : uncompression data
    // lUnpackDataLen    : uncompression data length
    // return(int)       : EXIT_SUCCESS unpack success, EXIT_FAILURE unpack fail
    //--------------------------------------------------------------------------
    int iPpmdUnpack(unsigned char *sPackData, unsigned long long lPackDataLen,
                    unsigned char *sProps, unsigned int iPropsLen,
                    unsigned char *sUnpackData, unsigned long long lUnpackDataLen);

    // ����CRC��֤
    //--------------------------------------------------------------------------
    // sBuf              : The buffer needed to calculate crc
    // lBufSize          : The buffer size
    // iCrc              : The crc value readed from file
    // return(int)       : EXIT_SUCCESS check success, EXIT_FAILURE check fail
    //--------------------------------------------------------------------------
    int iCheckCrc(unsigned char *sBuf, unsigned long long lBufSize, unsigned int iCrc);

    // BCJת��
    //--------------------------------------------------------------------------
    // sBuf              : The buffer needed to transfor
    // lBufSize          : The buffer size
    // return(int)       : EXIT_SUCCESS transfor success, EXIT_FAILURE transfor fail
    //--------------------------------------------------------------------------
    int iBcjTransfor(unsigned char *sBuf, unsigned long long lBufSize);

    // LZMA��ѹ�������֤(�߽��ܱ߽�ѹ)
    //--------------------------------------------------------------------------
    // sEncData          : AES ciphertext data
    // lEncDataLen       : AES ciphertext data length
    // sKey              : AES key data
    // iKeyLen           : AES key data length
    // sIv               : AES iv data
    // sIvLen            : AES iv data length
    // sProps            : compression property data 
    // iPropsLen         : compression property data length
    // lPackDataLen      : compression data length
    // sUnpackData       : uncompression data
    // lUnpackDataLen    : uncompression data length
    // return(int)       : EXIT_SUCCESS check success, EXIT_FAILURE check fail
    //--------------------------------------------------------------------------
    int iLzmaCheck(unsigned char *sEncData, unsigned long long lEncDataLen, 
                   unsigned char *sKey, unsigned int iKeyLen, 
                   unsigned char *sIv, unsigned int iIvLen, 
                   unsigned char *sProps, unsigned int iPropsLen, 
                   unsigned long long lPackDataLen, 
                   unsigned char *sUnpackData, unsigned long long lUnpackDataLen);

    // LZMA2��ѹ�������֤(�߽��ܱ߽�ѹ)
    //--------------------------------------------------------------------------
    // sEncData          : AES ciphertext data
    // lEncDataLen       : AES ciphertext data length
    // sKey              : AES key data
    // iKeyLen           : AES key data length
    // sIv               : AES iv data
    // sIvLen            : AES iv data length
    // sProps            : compression property data
    // lPackDataLen      : compression data length
    // sUnpackData       : uncompression data
    // lUnpackDataLen    : uncompression data length
    // return(int)       : EXIT_SUCCESS verify success, EXIT_FAILURE verify fail
    //--------------------------------------------------------------------------
    int iLzma2Check(unsigned char *sEncData, unsigned long long lEncDataLen, 
                    unsigned char *sKey, unsigned int iKeyLen, 
                    unsigned char *sIv, unsigned int iIvLen, 
                    unsigned char sProps, 
                    unsigned long long lPackDataLen, 
                    unsigned char *sUnpackData, unsigned long long lUnpackDataLen);

    // PPMD��ѹ�������֤(�߽��ܱ߽�ѹ)
    //--------------------------------------------------------------------------
    // sEncData          : AES ciphertext data
    // lEncDataLen       : AES ciphertext data length
    // sKey              : AES key data
    // iKeyLen           : AES key data length
    // sIv               : AES iv data
    // sIvLen            : AES iv data length
    // sProps            : compression property data 
    // iPropsLen         : compression property data length
    // lPackDataLen      : compression data length
    // sUnpackData       : uncompression data
    // lUnpackDataLen    : uncompression data length
    // lCrcBufSize       : The size of buffer needing to check CRC
    // iCrc              : The crc value readed from file
    // return(int)       : EXIT_SUCCESS verify success, EXIT_FAILURE verify fail
    //--------------------------------------------------------------------------
    int iPpmdCheck(unsigned char *sEncData, unsigned long long lEncDataLen,
                   unsigned char *sKey, unsigned int iKeyLen,
                   unsigned char *sIv, unsigned int iIvLen,
                   unsigned char *sProps, unsigned int iPropsLen,
                   unsigned long long lPackDataLen, 
                   unsigned char *sUnpackData, unsigned long long lUnpackDataLen,
                   unsigned long long lCrcBufSize, unsigned int iCrc);

private:
    ISzAlloc       _Alloc;
};



#endif // __7ZUNPACK_H_