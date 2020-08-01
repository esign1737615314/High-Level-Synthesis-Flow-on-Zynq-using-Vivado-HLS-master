// InBuffer.h

#ifndef __INBUFFER_H
#define __INBUFFER_H

#include "Types.h"

template <class T> inline T MyMin(T a, T b)
{
    return a < b ? a : b;
}

typedef struct tag_INBUF
{
    unsigned char *sBuf;
    unsigned long long iBufSize;
    unsigned long long iCurPos;
    tag_INBUF()
    {
        sBuf = NULL;
        iBufSize = 0;
        iCurPos = 0;
    };
    void SetBufInfo(unsigned char *sBufBase, unsigned long long iSize)
    {
        sBuf = sBufBase;
        iBufSize = iSize;
    };
    int Read(unsigned char *sDstBuf, unsigned long long iNeedReadSize, unsigned long long *iProcessedSize)
    {
        unsigned long long iSizeToRead = iNeedReadSize;
        if (iNeedReadSize > 0)
        {
            iSizeToRead = MyMin(iBufSize, iNeedReadSize);
            if (iBufSize > 0)
            {
                memcpy(sDstBuf, sBuf, iSizeToRead);
                sBuf = sBuf + iSizeToRead;
                iBufSize -= iSizeToRead;
            }
        }
        if (iProcessedSize != NULL)
        {
            *iProcessedSize = iSizeToRead;
        }
        iCurPos += iSizeToRead;
        return S_OK;
    };
}INBUF;

class CInBuffer
{
  Byte *_buffer;
  Byte *_bufferLimit;
  Byte *_bufferBase;
  INBUF _stream;//CMyComPtr<ISequentialInStream> _stream;
  UInt64 _processedSize;
  UInt64 _bufferSize;
  bool _wasFinished;

  bool ReadBlock();
  Byte ReadBlock2();

public:

  CInBuffer();
  ~CInBuffer() { Free(); }

  bool Create(UInt32 bufferSize);
  void Free();

  void SetStream(Byte *stream, UInt64 iBufferSize);//(ISequentialInStream *stream);
  void Init();
  void ReleaseStream()
  {
      _buffer = NULL;
      _processedSize = 0;
  }

  bool ReadByte(Byte &b)
  {
    if (_buffer >= _bufferLimit)
      if (!ReadBlock())
        return false;
    b = *_buffer++;
    return true;
  }
  Byte ReadByte()
  {
    if (_buffer >= _bufferLimit)
      return ReadBlock2();
    return *_buffer++;
  }
  UInt32 ReadBytes(Byte *buf, UInt32 size)
  {
    if ((UInt32)(_bufferLimit - _buffer) >= size)
    {
      for (UInt32 i = 0; i < size; i++)
        buf[i] = _buffer[i];
      _buffer += size;
      return size;
    }
    for (UInt32 i = 0; i < size; i++)
    {
      if (_buffer >= _bufferLimit)
        if (!ReadBlock())
          return i;
      buf[i] = *_buffer++;
    }
    return size;
  }
  UInt64 GetProcessedSize() const { return _processedSize + (_buffer - _bufferBase); }
  bool WasFinished() const { return _wasFinished; }
};

#endif
