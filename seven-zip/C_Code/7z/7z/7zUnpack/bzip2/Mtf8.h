// Mtf8.h

#ifndef __COMPRESS_MTF8_H
#define __COMPRESS_MTF8_H

#include "CpuArch.h"

#include "Types.h"



#ifdef MY_CPU_64BIT
typedef UInt64 CMtfVar;
#define MTF_MOVS 3
#else
typedef UInt32 CMtfVar;
#define MTF_MOVS 2
#endif

#define MTF_MASK ((1 << MTF_MOVS) - 1)


struct CMtf8Decoder
{
  CMtfVar Buf[256 >> MTF_MOVS];

  void StartInit() { memset(Buf, 0, sizeof(Buf)); }
  void Add(unsigned int pos, Byte val) { Buf[pos >> MTF_MOVS] |= ((CMtfVar)val << ((pos & MTF_MASK) << 3));  }
  Byte GetHead() const { return (Byte)Buf[0]; }
  Byte GetAndMove(unsigned int pos)
  {
    UInt32 lim = ((UInt32)pos >> MTF_MOVS);
    pos = (pos & MTF_MASK) << 3;
    CMtfVar prev = (Buf[lim] >> pos) & 0xFF;

    UInt32 i = 0;
    if ((lim & 1) != 0)
    {
      CMtfVar next = Buf[0];
      Buf[0] = (next << 8) | prev;
      prev = (next >> (MTF_MASK << 3));
      i = 1;
      lim -= 1;
    }
    for (; i < lim; i += 2)
    {
      CMtfVar n0 = Buf[i];
      CMtfVar n1 = Buf[i + 1];
      Buf[i    ] = (n0 << 8) | prev;
      Buf[i + 1] = (n1 << 8) | (n0 >> (MTF_MASK << 3));
      prev = (n1 >> (MTF_MASK << 3));
    }
    CMtfVar next = Buf[i];
    CMtfVar mask = (((CMtfVar)0x100 << pos) - 1);
    Buf[i] = (next & ~mask) | (((next << 8) | prev) & mask);
    return (Byte)Buf[0];
  }
};


#endif
