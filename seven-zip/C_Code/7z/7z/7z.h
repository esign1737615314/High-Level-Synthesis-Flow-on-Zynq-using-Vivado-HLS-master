#pragma once
#include <stdlib.h>
#include <string.h>
#include <iostream>

using namespace std;
class Sevenz
{
public:
    Sevenz(void);
    ~Sevenz(void);
    // Ö´ÐÐÓÃÀý
    int iVerify(const string &sPwd
    , const unsigned char * ucEncryptedData, const int & iEncryptedLen
    , const unsigned char * ucIV, const int & iIVLength
    , const unsigned int & iCRC, const int & iUnpackCRCLen);
};

