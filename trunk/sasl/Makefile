CC = gcc
CPP = g++
CFLAGS = -ggdb -Wall -O -I. -I/usr/include/sasl -I/usr/include/cryptopp
LDFLAGS = -lcrypto -lsasl2 -lcryptopp
PLUGIN_DIR = /usr/lib64/sasl2
LIBTOOL = libtool

all: libwebdavdigest.la libdhx.la liblpws_ldap.la

libwebdavdigest.la: webdavdigest.lo webdavdigest_init.lo
	$(LIBTOOL) --mode=link $(CC) $(CFLAGS) -module -rpath $(PLUGIN_DIR) -o $@ $^ $(LDFLAGS)

liblpws_ldap.la: lpws_ldap.lo
	$(LIBTOOL) --mode=link $(CC) $(CFLAGS) -module -rpath $(PLUGIN_DIR) -o $@ $^ $(LDFLAGS)

libdhx.la: dhx.lo dhx_init.lo
	$(LIBTOOL) --mode=link $(CPP) $(CFLAGS) -module -rpath $(PLUGIN_DIR) -o $@ $^ $(LDFLAGS)

%.lo: %.c
	$(LIBTOOL) --mode=compile $(CC) $(CFLAGS) -c $<

%.lo: %.cpp
	$(LIBTOOL) --mode=compile $(CPP) $(CFLAGS) -c $<

install/%.la: %.la
	$(LIBTOOL) --mode=install install -c $(notdir $@) $(PLUGIN_DIR)/$(notdir $@)
install: $(addprefix install/,libwebdavdigest.la) $(addprefix install/,libdhx.la) $(addprefix install/,liblpws_ldap.la)
	$(LIBTOOL) --mode=finish $(PLUGIN_DIR)

clean:
	rm -rf *.o .libs *.lo *.so *.la
