.SUFFIXES: .c .o .lo

COMPILE = $(CC) -Wall -O -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -g -DDEBUG_FLAG -DOS_LINUX
ENABLE_STATIC_LIB = 0
ENABLE_SHARED_LIB = 1
INC_PATH = -I/usr/local/include/fastcommon -I/usr/local/include/fastdfs -I/usr/local/include/fastdht
LIB_PATH = -lpthread -ldl -rdynamic
TARGET_PATH = /usr/local/bin
TARGET_LIB = /usr/local/lib
TARGET_INC = /usr/local/include
CONFIG_PATH = /etc/fdfs

FDFS_STATIC_OBJS = ../common/fdfs_global.o ../common/fdfs_http_shared.o \
                   ../common/mime_file_parser.o ../tracker/tracker_proto.o \
                   ../tracker/fdfs_shared_func.o \
                   ../storage/trunk_mgr/trunk_shared.o \
                   tracker_client.o client_func.o \
                   client_global.o storage_client.o

FDFS_SHARED_OBJS = ../common/fdfs_global.lo ../common/fdfs_http_shared.lo \
                   ../common/mime_file_parser.lo ../tracker/tracker_proto.lo \
                   ../tracker/fdfs_shared_func.lo \
                   ../storage/trunk_mgr/trunk_shared.lo \
                   tracker_client.lo client_func.lo \
                   client_global.lo storage_client.lo

FDFS_HEADER_FILES = ../common/fdfs_define.h ../common/fdfs_global.h \
                    ../common/mime_file_parser.h ../common/fdfs_http_shared.h \
                    ../tracker/tracker_types.h ../tracker/tracker_proto.h \
                    ../tracker/fdfs_shared_func.h \
                    ../storage/trunk_mgr/trunk_shared.h \
                    tracker_client.h storage_client.h storage_client1.h \
                    client_func.h client_global.h fdfs_client.h

ALL_OBJS = $(FDFS_STATIC_OBJS) $(FDFS_SHARED_OBJS)

ALL_PRGS = 

STATIC_LIBS = libfdfsclient.a

SHARED_LIBS = libfdfsclient.so.1

ALL_LIBS = $(STATIC_LIBS) $(SHARED_LIBS)

all: $(ALL_OBJS) $(ALL_PRGS) $(ALL_LIBS)
libfdfsclient.so.1:
	$(COMPILE) -o $@ $< -shared $(FDFS_SHARED_OBJS) $(LIB_PATH) -L. -lfastcommon -lfdfsclient -lfdhtclient
	ln -fs libfdfsclient.so.1 libfdfsclient.so
libfdfsclient.a:
	ar cru $@ $< $(FDFS_STATIC_OBJS)
.o:
	$(COMPILE) -o $@ $<  $(STATIC_OBJS) $(LIB_PATH) $(INC_PATH)
.c:
	$(COMPILE) -o $@ $<  $(STATIC_OBJS) $(LIB_PATH) $(INC_PATH)
.c.o:
	$(COMPILE) -c -o $@ $<  $(INC_PATH)
.c.lo:
	$(COMPILE) -c -fPIC -o $@ $<  $(INC_PATH)
install:
	mkdir -p $(TARGET_PATH)
	mkdir -p $(CONFIG_PATH)
	mkdir -p $(TARGET_LIB)
	cp -f $(ALL_PRGS) $(TARGET_PATH)
	if [ 0 -eq 1 ]; then cp -f $(STATIC_LIBS) $(TARGET_LIB); fi
	if [ 1 -eq 1 ]; then cp -f $(SHARED_LIBS) $(TARGET_LIB); fi
	if [ 1 -eq 1 ]; then ln -fs $(TARGET_LIB)/libfdfsclient.so.1 $(TARGET_LIB)/libfdfsclient.so; fi

	if [ ! -f $(CONFIG_PATH)/client.conf ]; then cp -f ../conf/client.conf ../conf/http.conf $(CONFIG_PATH); fi

	mkdir -p $(TARGET_INC)
	mkdir -p $(TARGET_INC)/fastcommon
	mkdir -p $(TARGET_INC)/fastdfs
	cp -f $(FDFS_HEADER_FILES) $(TARGET_INC)/fastdfs

	if [ 1 -eq 1 -a $(TARGET_LIB) = "/usr/local/lib" ]; then sh ./fdfs_link_library.sh; fi
clean:
	rm -f $(ALL_OBJS) $(ALL_PRGS) $(ALL_LIBS)

