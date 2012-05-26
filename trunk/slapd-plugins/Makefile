CC := gcc
LIBTOOL := libtool
PREFIX := /usr
MACHINE := $(shell uname -i)

ifeq ($(MACHINE), x86_64)
LIBDIR = /lib64
endif
ifeq ($(MACHINE), i686)
LIBDIR = /lib
endif

CFLAGS += 

all: lpws.la

lpws.lo: lpws.c
	$(LIBTOOL) --mode=compile $(CC) $(CFLAGS) -Wall -shared -c $?

lpws.la: lpws.lo
	$(LIBTOOL) --mode=link $(CC) -shared -module -rpath $(PREFIX)$(LIBDIR) -o $@ $?

clean:
	rm -f lpws.lo lpws.la

install: lpws.la
	mkdir -p $(PREFIX)$(LIBDIR)/openldap
	$(LIBTOOL) --mode=install cp lpws.la $(PREFIX)$(LIBDIR)/openldap
	$(LIBTOOL) --finish $(PREFIX)$(LIBDIR)
