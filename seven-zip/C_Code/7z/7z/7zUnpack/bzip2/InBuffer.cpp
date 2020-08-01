// InBuffer.cpp
// 基础head文件
#include <stdio.h>
// 支持EXIT_SUCCESS EXIT_FAILURE
#include <stdlib.h>
#include <string.h>

#include "InBuffer.h"

CInBuffer::CInBuffer():
    _buffer(0),
    _bufferLimit(0),
    _bufferBase(0),
    //_stream(0),
    _bufferSize(0)
{}

bool CInBuffer::Create(UInt32 bufferSize)
{
    const UInt32 kMinBlockSize = 1;
    if (bufferSize < kMinBlockSize)
        bufferSize = kMinBlockSize;
    if (_bufferBase != 0 && _bufferSize == bufferSize)
        return true;
    Free();
    _bufferSize = bufferSize;
    _bufferBase = (Byte *)malloc(bufferSize);
    return (_bufferBase != 0);
}

void CInBuffer::Free()
{
    if(_bufferBase != NULL)
    {
        free(_bufferBase);
        _bufferBase = NULL;
    }
}

void CInBuffer::SetStream(Byte *stream, UInt64 iBufferSize)
{
    _stream.SetBufInfo(stream, iBufferSize);
}

void CInBuffer::Init()
{
    _processedSize = 0;
    _buffer = _bufferBase;
    _bufferLimit = _buffer;
    _wasFinished = false;
}

bool CInBuffer::ReadBlock()
{
    if (_wasFinished)
        return false;
    _processedSize += (_buffer - _bufferBase);
    UInt64 numProcessedBytes;
    int result = _stream.Read(_bufferBase, _bufferSize, &numProcessedBytes);
    if (result != S_OK)
        return false;
    _buffer = _bufferBase;
    _bufferLimit = _buffer + numProcessedBytes;
    _wasFinished = (numProcessedBytes == 0);
    return (!_wasFinished);
}

Byte CInBuffer::ReadBlock2()
{
    if (!ReadBlock())
    {
        _processedSize++;
        return 0xFF;
    }
    return *_buffer++;
}
