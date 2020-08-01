//BZip2Decoder.h
#ifndef __COMPRESS_BZIP2_DECODER_H
#define __COMPRESS_BZIP2_DECODER_H

#include "InBuffer.h"
#include "BitmDecoder.h"
#include "BZip2Const.h"
#include "BZip2Crc.h"
#include "HuffmanDecoder.h"


class CBZip2Decoder
{
public:
    CBZip2Decoder();
    ~CBZip2Decoder();
    int BZip2Check(unsigned char *inStream, unsigned long long inStreamSize);

private:
    CBZip2CombinedCrc CombinedCrc;
    Byte m_Selectors[kNumSelectorsMax];
    CHuffmanDecoder<kMaxHuffmanLen, kMaxAlphaSize> m_HuffmanDecoders[kNumTablesMax];
    CBitmDecoder<CInBuffer> m_InStream;
    UInt64 _inStart;
    bool _needInStreamInit;
    UInt32 BlockSizeMax;

private:
    unsigned int ReadBits(unsigned numBits);
    unsigned char ReadByte();
    bool ReadBit();
    unsigned int ReadCrc();

    int CodeReal(unsigned char *inStream, unsigned long long inStreamSize, bool &isBZ);
    int DecodeFile(bool &isBZ);
    int ReadSignatures(bool &wasFinished, UInt32 &crc);
    int ReadBlock(UInt32 *CharCounters, UInt32 blockSizeMax, UInt32 *blockSizeRes, UInt32 *origPtrRes, bool *randRes);
    int DecodeBlock1(UInt32 *charCounters, UInt32 blockSize);
    int DecodeBlock2(const UInt32 *tt, UInt32 blockSize, UInt32 OrigPtr);
    int DecodeBlock2Rand(const UInt32 *tt, UInt32 blockSize, UInt32 OrigPtr);

};


#endif
