.PHONY: all clean distclean init

LIB_NAME=copua

LIBCOAP_DIR=../external/libcoap
LIBLUA_DIR=../external/lua
PATCH_DIR=./patch

CFLAGS+=-Wall -fPIC -DLIB_NAME=$(LIB_NAME) -I$(LIBLUA_DIR)/include \
	-I$(LIBLUA_DIR) -I$(LIBCOAP_DIR)/include

LIBS = \
     libcoap-2-openssl-realoc.a \
     liblua-realoc.a \
     -lssl \
     -lcrypto 

OBJS = \
       common.o \
       $(LIB_NAME).o

all: $(LIB_NAME).so

clean:
	$(RM) -f $(OBJS) *.a $(LIB_NAME).so $(LIB_NAME)_init.lua.h

distclean: clean
	cd $(LIBCOAP_DIR); \
	$(MAKE) clean; \
	./autogen.sh --clean; \
	git checkout -f
	-$(MAKE) -C $(LIBLUA_DIR) clean

$(LIB_NAME).o: $(LIB_NAME)_init.lua.h

$(LIB_NAME)_init.lua.h: $(LIB_NAME)_init.lua
	@echo "/*" >$@; \
	echo " * This file was auto-generated." >>$@; \
	echo " * Don't edit it or changes will be lost." >>$@; \
	echo " */" >>$@; \
	echo 'static const char *init_code =' >>$@; \
	cat $< | sed '/[ ]*--.*/d' | sed 's/\(.*\)/	"\1\\n"/' >>$@; \
	echo ';' >>$@

$(LIB_NAME).so: libcoap-2-openssl-realoc.a liblua-realoc.a $(OBJS)
	$(CC) -shared -o $@ $(OBJS) $(LIBS)

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

init: distclean
	git submodule update --init --recursive; \
	cd $(LIBCOAP_DIR); \
	./autogen.sh; \
	./configure \
	  --with-openssl --enable-dtls --disable-documentation --disable-doxygen \
	  --disable-manpages --disable-tests --disable-examples --disable-gcov
	patch -d $(LIBCOAP_DIR) -up1 < $(PATCH_DIR)/libcoap.diff

libcoap-2-openssl-realoc.a:
	$(MAKE) -C $(LIBCOAP_DIR)
	ar cr $@ $(LIBCOAP_DIR)/src/.libs/*.o

liblua-realoc.a:
	TESTS=-fPIC $(MAKE) -C $(LIBLUA_DIR)
	cp $(LIBLUA_DIR)/liblua.a $@
