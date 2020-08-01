// Crypto/MyAes.cpp


// 基础head文件
#include <stdio.h>
// 支持EXIT_SUCCESS EXIT_FAILURE
#include <stdlib.h>
#include <string.h>

#include "MyAes.h"


CAesCbcCoder::CAesCbcCoder()
{
    memset(_aes, 0, (AES_NUM_IVMRK_WORDS + 3));
    _offset = ((0 - (unsigned)(ptrdiff_t)_aes) & 0xF) / sizeof(unsigned int);
    AesGenTables();
}

CAesCbcCoder::~CAesCbcCoder()
{

}

unsigned int CAesCbcCoder::Filter(unsigned char *data, unsigned int size)
{
  if (size == 0)
    return 0;
  if (size < AES_BLOCK_SIZE)
    return AES_BLOCK_SIZE;
  size >>= 4;
  AesCbc_Decode(_aes + _offset, data, size);
  return size << 4;
}

int CAesCbcCoder::SetKey(const unsigned char *data, unsigned int size)
{
  if ((size & 0x7) != 0 || size < 16 || size > 32)
    return EXIT_FAILURE;
  Aes_SetKey_Dec(_aes + _offset + 4, data, size);
  return EXIT_SUCCESS;
}

int CAesCbcCoder::SetInitVector(const unsigned char *data, unsigned int size)
{
  if (size != AES_BLOCK_SIZE)
    return EXIT_FAILURE;
  AesCbc_Init(_aes + _offset, data);
  return EXIT_SUCCESS;
}


