MACHINE := $(shell uname -i)

CC = gcc
CPP = g++
CFLAGS = -ggdb -Wall -O -I. -I/usr/include/sasl -I/usr/include/cryptopp
LDFLAGS = -lcrypto -lsasl2 -lcryptopp
ifeq ($(MACHINE), x86_64)
PLUGIN_DIR = /usr/lib64/sasl2
endif
ifeq ($(MACHINE), i686)
PLUGIN_DIR = /usr/lib/sasl2
endif
LIBTOOL = libtool

all: libwebdavdigest.la libdhx.la liblpws_ldap.la liblpws.la libmschap.la

libwebdavdigest.la: webdavdigest.lo webdavdigest_init.lo
	$(LIBTOOL) --mode=link $(CC) $(CFLAGS) -module -rpath $(PLUGIN_DIR) -o $@ $^ $(LDFLAGS)

liblpws_ldap.la: lpws_ldap.lo
	$(LIBTOOL) --mode=link $(CC) $(CFLAGS) -module -rpath $(PLUGIN_DIR) -o $@ $^ $(LDFLAGS)

liblpws.la: lpws.lo
	$(LIBTOOL) --mode=link $(CC) $(CFLAGS) -module -rpath $(PLUGIN_DIR) -o $@ $^ $(LDFLAGS)

libdhx.la: dhx.lo dhx_init.lo
	$(LIBTOOL) --mode=link $(CPP) $(CFLAGS) -module -rpath $(PLUGIN_DIR) -o $@ $^ $(LDFLAGS)

libmschap.la: mschap.lo mschap_init.lo
	$(LIBTOOL) --mode=link $(CPP) $(CFLAGS) -module -rpath $(PLUGIN_DIR) -o $@ $^ $(LDFLAGS)

%.lo: %.c
	$(LIBTOOL) --mode=compile $(CC) $(CFLAGS) -c $<

%.lo: %.cpp
	$(LIBTOOL) --mode=compile $(CPP) $(CFLAGS) -c $<

install/%.la: %.la
	$(LIBTOOL) --mode=install install -D -c $(notdir $@) $(DESTDIR)$(PLUGIN_DIR)/$(notdir $@)
install: $(addprefix install/,libwebdavdigest.la) $(addprefix install/,libdhx.la) $(addprefix install/,liblpws_ldap.la) $(addprefix install/,liblpws.la) $(addprefix install/,libmschap.la)
	$(LIBTOOL) --mode=finish $(DESTDIR)$(PLUGIN_DIR)

clean:
	rm -rf *.o .libs *.lo *.so *.la
