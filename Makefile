CC = gcc
CFLAGS = -ggdb -Wall -O
LDFLAGS = -lcrypto -lsasl2 -lldap
SRCS = main.c commands.c utils.c keys.c client.c lpws_ldap.c config.c
SRCS += listener.c
OBJS = $(SRCS:.c=.o)

all: lpws

lpws: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o lpws $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o lpws
