.SUFFIXES: .c .o .lo

COMPILE = $(CC) -Wall -O -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -g -DDEBUG_FLAG -DOS_LINUX
ENABLE_STATIC_LIB = 0
ENABLE_SHARED_LIB = 1
INC_PATH = -I/usr/local/include/fastcommon -I/usr/local/include/fastdfs -I/usr/local/include/fastdht
LIB_PATH = -lpthread -ldl -rdynamic
TARGET_PATH = /usr/local/bin
TARGET_LIB = /usr/local/lib
TARGET_INC = /usr/local/include

MY_STATIC_OBJS = my_fdfs_client.o

MY_SHARED_OBJS = my_fdfs_client.lo

MY_HEADER_FILES = my_fdfs_client.h

ALL_OBJS = $(MY_STATIC_OBJS) $(MY_SHARED_OBJS) my_fdfs_client_test.o

ALL_PRGS = my_fdfs_client_test

STATIC_LIBS = libmyfdfsclient.a

SHARED_LIBS = libmyfdfsclient.so.1

ALL_LIBS = $(STATIC_LIBS) $(SHARED_LIBS)

all: $(ALL_OBJS) $(ALL_PRGS) $(ALL_LIBS) 
libmyfdfsclient.so.1:
	$(COMPILE) -o $@ $< -shared $(MY_SHARED_OBJS) $(LIB_PATH) -L. -lfastcommon -lfdfsclient -lfdhtclient
	ln -fs libmyfdfsclient.so.1 libmyfdfsclient.so
libmyfdfsclient.a:
	ar cru $@ $< $(MY_STATIC_OBJS)
my_fdfs_client_test: my_fdfs_client_test.o
	$(COMPILE) -o $@ $< $(LIB_PATH) -L. -lfastcommon -lfdfsclient -lfdhtclient $(MY_STATIC_OBJS)
.o:
	$(COMPILE) -o $@ $<  $(MY_STATIC_OBJS) $(LIB_PATH) $(INC_PATH)
.c:
	$(COMPILE) -o $@ $<  $(MY_STATIC_OBJS) $(LIB_PATH) $(INC_PATH)
.c.o:
	$(COMPILE) -c -o $@ $<  $(INC_PATH)
.c.lo:
	$(COMPILE) -c -fPIC -o $@ $<  $(INC_PATH)
install:
	mkdir -p $(TARGET_PATH)
	mkdir -p $(TARGET_LIB)
	cp -f $(ALL_PRGS) $(TARGET_PATH)
	if [ $(ENABLE_STATIC_LIB) -eq 1 ]; then cp -f $(STATIC_LIBS) $(TARGET_LIB); fi
	if [ $(ENABLE_SHARED_LIB) -eq 1 ]; then cp -f $(SHARED_LIBS) $(TARGET_LIB); fi
	if [ $(ENABLE_SHARED_LIB) -eq 1 ]; then ln -fs $(TARGET_LIB)/libmyfdfsclient.so.1 $(TARGET_LIB)/libmyfdfsclient.so; fi

	mkdir -p $(TARGET_INC)
	mkdir -p $(TARGET_INC)/fastcommon
	mkdir -p $(TARGET_INC)/fastdfs
	cp -f $(MY_HEADER_FILES) $(TARGET_INC)/fastdfs

	if [ $(ENABLE_SHARED_LIB) -eq 1 -a $(TARGET_LIB) = "/usr/local/lib" ]; then sh ./my_fdfs_link_library.sh; fi
clean:
	rm -f $(ALL_OBJS) $(ALL_PRGS) $(ALL_LIBS) libmyfdfsclient.so

