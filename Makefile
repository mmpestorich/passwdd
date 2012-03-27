CC = gcc
CFLAGS = -ggdb -Wall -O
LDFLAGS = -lcrypto -lsasl2 -lldap
SRCS = main.c commands.c utils.c keys.c client.c config.c
SRCS += listener.c
OBJS = $(SRCS:.c=.o)
PLUGIN_DIR = /usr/lib/sasl2

all: lpws liblpws_ldap.la

lpws: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o lpws $(LDFLAGS)

liblpws_ldap.la: lpws_ldap.lo
	./libtool --mode=link $(CC) $(CFLAGS) -module -rpath $(PLUGIN_DIR) -o $@ $^ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

%.lo: %.c
	./libtool --mode=compile $(CC) $(CFLAGS) -c $<

install/%.la: %.la
	./libtool --mode=install install -c $(notdir $@) $(PLUGIN_DIR)/$(notdir $@)
install: $(addprefix install/,liblpws_ldap.la)
	./libtool --mode=finish $(PLUGIN_DIR)

clean:
	rm -rf *.o lpws .libs *.lo *.so *.la
