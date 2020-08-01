// BZip2Decoder.cpp
// 基础head文件
#include <stdio.h>
// 支持EXIT_SUCCESS EXIT_FAILURE
#include <stdlib.h>
#include <string.h>

#include "BZip2Decoder.h"
#include "Mtf8.h"


static const UInt32 kBufferSize = (1 << 17);

static const UInt16 kRandNums[512] = {
    619, 720, 127, 481, 931, 816, 813, 233, 566, 247,
    985, 724, 205, 454, 863, 491, 741, 242, 949, 214,
    733, 859, 335, 708, 621, 574, 73, 654, 730, 472,
    419, 436, 278, 496, 867, 210, 399, 680, 480, 51,
    878, 465, 811, 169, 869, 675, 611, 697, 867, 561,
    862, 687, 507, 283, 482, 129, 807, 591, 733, 623,
    150, 238, 59, 379, 684, 877, 625, 169, 643, 105,
    170, 607, 520, 932, 727, 476, 693, 425, 174, 647,
    73, 122, 335, 530, 442, 853, 695, 249, 445, 515,
    909, 545, 703, 919, 874, 474, 882, 500, 594, 612,
    641, 801, 220, 162, 819, 984, 589, 513, 495, 799,
    161, 604, 958, 533, 221, 400, 386, 867, 600, 782,
    382, 596, 414, 171, 516, 375, 682, 485, 911, 276,
    98, 553, 163, 354, 666, 933, 424, 341, 533, 870,
    227, 730, 475, 186, 263, 647, 537, 686, 600, 224,
    469, 68, 770, 919, 190, 373, 294, 822, 808, 206,
    184, 943, 795, 384, 383, 461, 404, 758, 839, 887,
    715, 67, 618, 276, 204, 918, 873, 777, 604, 560,
    951, 160, 578, 722, 79, 804, 96, 409, 713, 940,
    652, 934, 970, 447, 318, 353, 859, 672, 112, 785,
    645, 863, 803, 350, 139, 93, 354, 99, 820, 908,
    609, 772, 154, 274, 580, 184, 79, 626, 630, 742,
    653, 282, 762, 623, 680, 81, 927, 626, 789, 125,
    411, 521, 938, 300, 821, 78, 343, 175, 128, 250,
    170, 774, 972, 275, 999, 639, 495, 78, 352, 126,
    857, 956, 358, 619, 580, 124, 737, 594, 701, 612,
    669, 112, 134, 694, 363, 992, 809, 743, 168, 974,
    944, 375, 748, 52, 600, 747, 642, 182, 862, 81,
    344, 805, 988, 739, 511, 655, 814, 334, 249, 515,
    897, 955, 664, 981, 649, 113, 974, 459, 893, 228,
    433, 837, 553, 268, 926, 240, 102, 654, 459, 51,
    686, 754, 806, 760, 493, 403, 415, 394, 687, 700,
    946, 670, 656, 610, 738, 392, 760, 799, 887, 653,
    978, 321, 576, 617, 626, 502, 894, 679, 243, 440,
    680, 879, 194, 572, 640, 724, 926, 56, 204, 700,
    707, 151, 457, 449, 797, 195, 791, 558, 945, 679,
    297, 59, 87, 824, 713, 663, 412, 693, 342, 606,
    134, 108, 571, 364, 631, 212, 174, 643, 304, 329,
    343, 97, 430, 751, 497, 314, 983, 374, 822, 928,
    140, 206, 73, 263, 980, 736, 876, 478, 430, 305,
    170, 514, 364, 692, 829, 82, 855, 953, 676, 246,
    369, 970, 294, 750, 807, 827, 150, 790, 288, 923,
    804, 378, 215, 828, 592, 281, 565, 555, 710, 82,
    896, 831, 547, 261, 524, 462, 293, 465, 502, 56,
    661, 821, 976, 991, 658, 869, 905, 758, 745, 193,
    768, 550, 608, 933, 378, 286, 215, 979, 792, 961,
    61, 688, 793, 644, 986, 403, 106, 366, 905, 644,
    372, 567, 466, 434, 645, 210, 389, 550, 919, 135,
    780, 773, 635, 389, 707, 100, 626, 958, 165, 504,
    920, 176, 193, 713, 857, 265, 203, 50, 668, 108,
    645, 990, 626, 197, 510, 357, 358, 850, 858, 364,
    936, 638
};


unsigned int CBZip2Decoder::ReadBits(unsigned numBits)
{
    return m_InStream.ReadBits(numBits);
}


unsigned char CBZip2Decoder::ReadByte()
{
    return (Byte)ReadBits(8);
}


bool CBZip2Decoder::ReadBit()
{
    return ReadBits(1) != 0;
}


unsigned int CBZip2Decoder::ReadCrc()
{
  UInt32 crc = 0;
  for (int i = 0; i < 4; i++)
  {
    crc <<= 8;
    crc |= ReadByte();
  }
  return crc;
}


int CBZip2Decoder::ReadBlock(UInt32 *CharCounters, UInt32 blockSizeMax, UInt32 *blockSizeRes, UInt32 *origPtrRes, bool *randRes)
{
  if (randRes)
    *randRes = ReadBit() ? true : false;
  *origPtrRes = ReadBits(kNumOrigBits);
  
  // in original code it compares OrigPtr to (UInt32)(10 + blockSizeMax)) : why ?
  if (*origPtrRes >= blockSizeMax)
    return S_FALSE;

  CMtf8Decoder mtf;
  mtf.StartInit();
  
  int numInUse = 0;
  {
    Byte inUse16[16];
    int i;
    for (i = 0; i < 16; i++)
      inUse16[i] = (Byte)ReadBit();
    for (i = 0; i < 256; i++)
      if (inUse16[i >> 4])
      {
        if (ReadBit())
          mtf.Add(numInUse++, (Byte)i);
      }
    if (numInUse == 0)
      return S_FALSE;
    // mtf.Init(numInUse);
  }
  int alphaSize = numInUse + 2;

  int numTables = ReadBits(kNumTablesBits);
  if (numTables < kNumTablesMin || numTables > kNumTablesMax)
    return S_FALSE;
  
  UInt32 numSelectors = ReadBits(kNumSelectorsBits);
  if (numSelectors < 1 || numSelectors > kNumSelectorsMax)
    return S_FALSE;

  {
    Byte mtfPos[kNumTablesMax];
    int t = 0;
    do
      mtfPos[t] = (Byte)t;
    while(++t < numTables);
    UInt32 i = 0;
    do
    {
      int j = 0;
      while (ReadBit())
        if (++j >= numTables)
          return S_FALSE;
      Byte tmp = mtfPos[j];
      for (;j > 0; j--)
        mtfPos[j] = mtfPos[j - 1];
      m_Selectors[i] = mtfPos[0] = tmp;
    }
    while(++i < numSelectors);
  }

  int t = 0;
  do
  {
    Byte lens[kMaxAlphaSize];
    int len = (int)ReadBits(kNumLevelsBits);
    int i;
    for (i = 0; i < alphaSize; i++)
    {
      for (;;)
      {
        if (len < 1 || len > kMaxHuffmanLen)
          return S_FALSE;
        if (!ReadBit())
          break;
        len += 1 - (int)(ReadBit() << 1);
      }
      lens[i] = (Byte)len;
    }
    for (; i < kMaxAlphaSize; i++)
      lens[i] = 0;
    if(!m_HuffmanDecoders[t].SetCodeLengths(lens))
      return S_FALSE;
  }
  while(++t < numTables);

  {
    for (int i = 0; i < 256; i++)
      CharCounters[i] = 0;
  }
  
  UInt32 blockSize = 0;
  {
    UInt32 groupIndex = 0;
    UInt32 groupSize = 0;
    CHuffmanDecoder<kMaxHuffmanLen, kMaxAlphaSize> *huffmanDecoder = 0;
    int runPower = 0;
    UInt32 runCounter = 0;
    
    for (;;)
    {
      if (groupSize == 0)
      {
        if (groupIndex >= numSelectors)
          return S_FALSE;
        groupSize = kGroupSize;
        huffmanDecoder = &m_HuffmanDecoders[m_Selectors[groupIndex++]];
      }
      groupSize--;
        
      UInt32 nextSym = huffmanDecoder->DecodeSymbol(&m_InStream);
      
      if (nextSym < 2)
      {
        runCounter += ((UInt32)(nextSym + 1) << runPower++);
        if (blockSizeMax - blockSize < runCounter)
          return S_FALSE;
        continue;
      }
      if (runCounter != 0)
      {
        UInt32 b = (UInt32)mtf.GetHead();
        CharCounters[b] += runCounter;
        do
          CharCounters[256 + blockSize++] = b;
        while(--runCounter != 0);
        runPower = 0;
      }
      if (nextSym <= (UInt32)numInUse)
      {
        UInt32 b = (UInt32)mtf.GetAndMove((int)nextSym - 1);
        if (blockSize >= blockSizeMax)
          return S_FALSE;
        CharCounters[b]++;
        CharCounters[256 + blockSize++] = b;
      }
      else if (nextSym == (UInt32)numInUse + 1)
        break;
      else
        return S_FALSE;
    }
  }
  *blockSizeRes = blockSize;
  return (*origPtrRes < blockSize) ? S_OK : S_FALSE;
}


int CBZip2Decoder::DecodeBlock1(UInt32 *charCounters, UInt32 blockSize)
{
    {
        UInt32 sum = 0;
        for (UInt32 i = 0; i < 256; i++)
        {
            sum += charCounters[i];
            charCounters[i] = sum - charCounters[i];
        }
    }
  
    UInt32 *tt = charCounters + 256;
    // Compute the T^(-1) vector
    UInt32 i = 0;
    do
    {
        tt[charCounters[tt[i] & 0xFF]++] |= (i << 8);
    }
    while(++i < blockSize);

    return S_OK;
}


int CBZip2Decoder::DecodeBlock2(const UInt32 *tt, UInt32 blockSize, UInt32 OrigPtr)
{
  CBZip2Crc crc;

  // it's for speed optimization: prefetch & prevByte_init;
  UInt32 tPos = tt[tt[OrigPtr] >> 8];
  unsigned prevByte = (unsigned)(tPos & 0xFF);
  
  unsigned numReps = 0;

  do
  {
    unsigned b = (unsigned)(tPos & 0xFF);
    tPos = tt[tPos >> 8];
    
    if ((int)numReps == kRleModeRepSize)
    {
      for (; b > 0; b--)
      {
        crc.UpdateByte(prevByte);
        //m_OutStream.WriteByte((Byte)prevByte);
      }
      numReps = 0;
      continue;
    }
    if (b != prevByte)
      numReps = 0;
    numReps++;
    prevByte = b;
    crc.UpdateByte(b);
    //m_OutStream.WriteByte((Byte)b);

    /*
    prevByte = b;
    crc.UpdateByte(b);
    m_OutStream.WriteByte((Byte)b);
    for (; --blockSize != 0;)
    {
      b = (unsigned)(tPos & 0xFF);
      tPos = tt[tPos >> 8];
      crc.UpdateByte(b);
      m_OutStream.WriteByte((Byte)b);
      if (b != prevByte)
      {
        prevByte = b;
        continue;
      }
      if (--blockSize == 0)
        break;
      
      b = (unsigned)(tPos & 0xFF);
      tPos = tt[tPos >> 8];
      crc.UpdateByte(b);
      m_OutStream.WriteByte((Byte)b);
      if (b != prevByte)
      {
        prevByte = b;
        continue;
      }
      if (--blockSize == 0)
        break;
      
      b = (unsigned)(tPos & 0xFF);
      tPos = tt[tPos >> 8];
      crc.UpdateByte(b);
      m_OutStream.WriteByte((Byte)b);
      if (b != prevByte)
      {
        prevByte = b;
        continue;
      }
      --blockSize;
      break;
    }
    if (blockSize == 0)
      break;

    b = (unsigned)(tPos & 0xFF);
    tPos = tt[tPos >> 8];
    
    for (; b > 0; b--)
    {
      crc.UpdateByte(prevByte);
      m_OutStream.WriteByte((Byte)prevByte);
    }
    */
  }
  while(--blockSize != 0);
  return crc.GetDigest();
}


int CBZip2Decoder::DecodeBlock2Rand(const UInt32 *tt, UInt32 blockSize, UInt32 OrigPtr)
{
  CBZip2Crc crc;
  
  UInt32 randIndex = 1;
  UInt32 randToGo = kRandNums[0] - 2;
  
  unsigned numReps = 0;

  // it's for speed optimization: prefetch & prevByte_init;
  UInt32 tPos = tt[tt[OrigPtr] >> 8];
  unsigned prevByte = (unsigned)(tPos & 0xFF);
  
  do
  {
    unsigned b = (unsigned)(tPos & 0xFF);
    tPos = tt[tPos >> 8];
    
    {
      if (randToGo == 0)
      {
        b ^= 1;
        randToGo = kRandNums[randIndex++];
        randIndex &= 0x1FF;
      }
      randToGo--;
    }
    
    if ((int)numReps == kRleModeRepSize)
    {
      for (; b > 0; b--)
      {
        crc.UpdateByte(prevByte);
        //m_OutStream.WriteByte((Byte)prevByte);
      }
      numReps = 0;
      continue;
    }
    if (b != prevByte)
      numReps = 0;
    numReps++;
    prevByte = b;
    crc.UpdateByte(b);
    //m_OutStream.WriteByte((Byte)b);
  }
  while(--blockSize != 0);
  return crc.GetDigest();
}


CBZip2Decoder::CBZip2Decoder()
{
    _needInStreamInit = true;
}


CBZip2Decoder::~CBZip2Decoder()
{

}


int CBZip2Decoder::ReadSignatures(bool &wasFinished, UInt32 &crc)
{
    wasFinished = false;
    Byte s[6];
    for (int i = 0; i < 6; i++)
    {
        s[i] = ReadByte();
    }
    crc = ReadCrc();
    if (s[0] == kFinSig0)
    {
        if (s[1] != kFinSig1 ||
            s[2] != kFinSig2 ||
            s[3] != kFinSig3 ||
            s[4] != kFinSig4 ||
            s[5] != kFinSig5)
        {
            return S_FALSE;
        }
        wasFinished = true;
        return (crc == CombinedCrc.GetDigest()) ? S_OK : S_FALSE;
    }
    if (s[0] != kBlockSig0 ||
        s[1] != kBlockSig1 ||
        s[2] != kBlockSig2 ||
        s[3] != kBlockSig3 ||
        s[4] != kBlockSig4 ||
        s[5] != kBlockSig5)
    {
        return S_FALSE;
    }
    CombinedCrc.Update(crc);
    return S_OK;
}

int CBZip2Decoder::DecodeFile(bool &isBZ)
{
    isBZ = false;
    unsigned char s[6];
    int i;
    for (i = 0; i < 4; i++)
    {
        s[i] = ReadByte();
    }
    if (s[0] != kArSig0 ||
        s[1] != kArSig1 ||
        s[2] != kArSig2 ||
        s[3] <= kArSig3 ||
        s[3] > kArSig3 + kBlockSizeMultMax)
    {
        return S_OK;
    }
    isBZ = true;
    unsigned int dicSize = (UInt32)(s[3] - kArSig3) * kBlockSizeStep;
    unsigned int *Counters = (unsigned int *)malloc((256 + kBlockSizeMax) * sizeof(unsigned int));
    unsigned int iCalcCrc = 0;
    unsigned int crc = 0;
    bool wasFinished = false;
    CombinedCrc.Init();
    while(1)
    {
        if(S_OK != ReadSignatures(wasFinished, crc))
        {
            free(Counters);
            return S_FALSE;
        }
        if (wasFinished)
        {
            break;
        }
        unsigned int blockSize, origPtr;
        bool randMode;
        if(S_OK != ReadBlock(Counters, dicSize, &blockSize, &origPtr, &randMode))
        {
            free(Counters);
            return S_FALSE;
        }
        DecodeBlock1(Counters, blockSize);
        if(randMode == true)
        {
            iCalcCrc = DecodeBlock2Rand(Counters + 256, blockSize, origPtr);
        }
        else
        {
            iCalcCrc = DecodeBlock2(Counters + 256, blockSize, origPtr);
        }
        if (iCalcCrc != crc)
        {
            free(Counters);
            return S_FALSE;
        }
    }
    free(Counters);
    return S_OK;
}


int CBZip2Decoder::CodeReal(unsigned char *inStream, unsigned long long inStreamSize, bool &isBZ)
{
    isBZ = false;
    if (!m_InStream.Create(kBufferSize))
    {
        return E_OUTOFMEMORY;
    }
    if (inStream)
    {
        m_InStream.SetStream(inStream, inStreamSize);
    }
    if (_needInStreamInit)
    {
        m_InStream.Init();
        _needInStreamInit = false;
    }
    _inStart = m_InStream.GetProcessedSize();
    m_InStream.AlignToByte();

    return DecodeFile(isBZ);
}


int CBZip2Decoder::BZip2Check(unsigned char *inStream, unsigned long long inStreamSize)
{
    _needInStreamInit = true;
    bool isBZ = false;
    if(S_OK != CodeReal(inStream, inStreamSize, isBZ))
    {
        return EXIT_FAILURE;
    }
    return (isBZ == true) ? EXIT_SUCCESS : EXIT_FAILURE;
}





