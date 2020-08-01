# /////////////////////////////////////////////////////////////////////////////
# 版权所有 (C) 北京神州天鸿科技有限公司
#
# 说明：
#    Rar-DeepVerify so Makefile文件(Linux版本)
#
# 作		者： 	
# 最后修改日期： 	2014-02-28
# 版		本：	V1.0
#
# /////////////////////////////////////////////////////////////////////////////


# ///////////////////////////////////////////////////////////////////////////////////////
# 定义编译连接指令变量（可以是cc、gcc、g++等）
CP = g++
CC = gcc


# 编译目标
SERVER = 7zTest


INCPATH=../include
#INCPATH=../include

# 公共目标文件
COMMON_OBJS = 7zCommon/7zCrc.o \
              7zCommon/CpuArch.o \
              7zUnpack/aes/Aes.o \
              7zUnpack/lzma/LzmaDec.o \
              7zUnpack/lzma2/Lzma2Dec.o \
              7zUnpack/ppmd/Ppmd7Dec.o \
              7zUnpack/ppmd/Ppmd7.o \
              7zUnpack/bcj/Bra86.o \
				
# 主目标文件
MAIN_OBJS = 7zUnpack/aes/MyAes.o \
            7zUnpack/ppmd/PpmdDecoder.o \
            7zUnpack/bzip2/BZip2Decoder.o \
            7zUnpack/bzip2/BZip2Crc.o \
            7zUnpack/bzip2/InBuffer.o \
            7zUnpack/7zUnpack.o \
						$(INCPATH)/Common.o $(INCPATH)/RandData.o $(INCPATH)/IniFile.o $(INCPATH)/RandGenPwd.o  7z.o 7zSo.o


# 所有目标文件
OBJS = $(MAIN_OBJS) $(COMMON_OBJS) 

# 公共包含文件
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

# 定义所有库文件路径变量
ALL_INCS=$(COMMON_INC) 


# ///////////////////////////////////////////////////////////////////////////////////////
#5. 定义编译选项变量
CCFLAGS = -O3 -fPIC -Wall -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DNDEBUG -DDEBUG -D_REENTRANT -DENV_UNIX -D_7ZIP_LARGE_PAGES -DEXTERNAL_CODECS -DUNICODE -D_UNICODE 
CPFLAGS = -ftemplate-depth-128  -D_REENTRANT -fPIC -std=gnu++0x -g -Wall -DDEBUG


# ///////////////////////////////////////////////////////////////////////////////////////
#6. 定义连接选项变量
#LFLAGS = -shared -ftemplate-depth-128  -D_REENTRANT -fPIC -lpthread -ldl -L/usr/local/lib -lcrypto -liconv 
LFLAGS = -ftemplate-depth-128  -D_REENTRANT -fPIC -lpthread -ldl -L/usr/local/lib -lcrypto -liconv

# ///////////////////////////////////////////////////////////////////////////////////////
#7. 主目标依赖命令(使用了字符“@”使得make执行命令不显示在屏幕上)
$(SERVER) : $(MAIN_OBJS) $(COMMON_OBJS)
	$(CP)  -o $(SERVER) $(OBJS) $(ALL_LIBS) $(LFLAGS)


#格式：目标集合: 目标模式 : 目标依赖模式
#“$<”表示所有的依赖目标集
#“$@”表示目标模式集
#@echo "正在编译各个源文件"
$(MAIN_OBJS): %.o: %.cpp
	$(CP) -c $(CPFLAGS) $(ALL_INCS) $< -o $@

$(COMMON_OBJS): %.o: %.c
	$(CP) -c $(CCFLAGS) $(ALL_INCS) $< -o $@

# ///////////////////////////////////////////////////////////////////////////////////////
#8. “.PHONY”来显示地指明一个目标是“伪目标”
# 
.PHONY : clean
clean :
	rm $(SERVER) $(OBJS)
