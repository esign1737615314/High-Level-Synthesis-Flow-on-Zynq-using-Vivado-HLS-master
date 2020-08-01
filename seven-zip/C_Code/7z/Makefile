# /////////////////////////////////////////////////////////////////////////////
# ��Ȩ���� (C) �����������Ƽ����޹�˾
#
# ˵����
#    Rar-DeepVerify so Makefile�ļ�(Linux�汾)
#
# ��		�ߣ� 	
# ����޸����ڣ� 	2014-02-28
# ��		����	V1.0
#
# /////////////////////////////////////////////////////////////////////////////


# ///////////////////////////////////////////////////////////////////////////////////////
# �����������ָ�������������cc��gcc��g++�ȣ�
CP = g++
CC = gcc


# ����Ŀ��
SERVER = 7zTest


INCPATH=../include
#INCPATH=../include

# ����Ŀ���ļ�
COMMON_OBJS = 7zCommon/7zCrc.o \
              7zCommon/CpuArch.o \
              7zUnpack/aes/Aes.o \
              7zUnpack/lzma/LzmaDec.o \
              7zUnpack/lzma2/Lzma2Dec.o \
              7zUnpack/ppmd/Ppmd7Dec.o \
              7zUnpack/ppmd/Ppmd7.o \
              7zUnpack/bcj/Bra86.o \
				
# ��Ŀ���ļ�
MAIN_OBJS = 7zUnpack/aes/MyAes.o \
            7zUnpack/ppmd/PpmdDecoder.o \
            7zUnpack/bzip2/BZip2Decoder.o \
            7zUnpack/bzip2/BZip2Crc.o \
            7zUnpack/bzip2/InBuffer.o \
            7zUnpack/7zUnpack.o \
						$(INCPATH)/Common.o $(INCPATH)/RandData.o $(INCPATH)/IniFile.o $(INCPATH)/RandGenPwd.o  7z.o 7zSo.o


# ����Ŀ���ļ�
OBJS = $(MAIN_OBJS) $(COMMON_OBJS) 

# ���������ļ�
COMMON_INC = -I. -I.. -I./7zCommon -I./7zUnpack \
             -I./7zUnpack/aes \
             -I./7zUnpack/lzma \
             -I./7zUnpack/lzma2 \
             -I./7zUnpack/bzip2 \
             -I./7zUnpack/ppmd \
             -I./7zUnpack/bcj \
             -I./7zParse \
             -I./7zCommon \
			 				-I$(INCPATH) -I/usr/local/include 

# �������п��ļ�·������
ALL_INCS=$(COMMON_INC) 


# ///////////////////////////////////////////////////////////////////////////////////////
#5. �������ѡ�����
CCFLAGS = -O3 -fPIC -Wall -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DNDEBUG -DDEBUG -D_REENTRANT -DENV_UNIX -D_7ZIP_LARGE_PAGES -DEXTERNAL_CODECS -DUNICODE -D_UNICODE 
CPFLAGS = -ftemplate-depth-128  -D_REENTRANT -fPIC -std=gnu++0x -g -Wall -DDEBUG


# ///////////////////////////////////////////////////////////////////////////////////////
#6. ��������ѡ�����
#LFLAGS = -shared -ftemplate-depth-128  -D_REENTRANT -fPIC -lpthread -ldl -L/usr/local/lib -lcrypto -liconv 
LFLAGS = -ftemplate-depth-128  -D_REENTRANT -fPIC -lpthread -ldl -L/usr/local/lib -lcrypto -liconv

# ///////////////////////////////////////////////////////////////////////////////////////
#7. ��Ŀ����������(ʹ�����ַ���@��ʹ��makeִ�������ʾ����Ļ��)
$(SERVER) : $(MAIN_OBJS) $(COMMON_OBJS)
	$(CP)  -o $(SERVER) $(OBJS) $(ALL_LIBS) $(LFLAGS)


#��ʽ��Ŀ�꼯��: Ŀ��ģʽ : Ŀ������ģʽ
#��$<����ʾ���е�����Ŀ�꼯
#��$@����ʾĿ��ģʽ��
#@echo "���ڱ������Դ�ļ�"
$(MAIN_OBJS): %.o: %.cpp
	$(CP) -c $(CPFLAGS) $(ALL_INCS) $< -o $@

$(COMMON_OBJS): %.o: %.c
	$(CP) -c $(CCFLAGS) $(ALL_INCS) $< -o $@

# ///////////////////////////////////////////////////////////////////////////////////////
#8. ��.PHONY������ʾ��ָ��һ��Ŀ���ǡ�αĿ�ꡱ
# 
.PHONY : clean
clean :
	rm $(SERVER) $(OBJS)