// Crypto/MyAes.h

#ifndef __CRYPTO_MY_AES_H
#define __CRYPTO_MY_AES_H

#include "Aes.h"

class CAesCbcCoder
{
protected:
  unsigned _offset;
  unsigned int _aes[AES_NUM_IVMRK_WORDS + 3];
public:
  CAesCbcCoder();
  ~CAesCbcCoder();
  int Init();
  unsigned int Filter(unsigned char *data, unsigned int size);
  int SetKey(const unsigned char *data, unsigned int size);
  int SetInitVector(const unsigned char *data, unsigned int size);
};


#endif
