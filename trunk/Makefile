CC = gcc
CFLAGS = -ggdb -Wall -O
LDFLAGS = -lcrypto -lsasl2
SRCS = main.c commands.c utils.c keys.c client.c config.c
SRCS += listener.c
OBJS = $(SRCS:.c=.o)

all: lpws
	cd sasl; $(MAKE) all $(MFLAGS)

lpws: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o lpws $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf *.o lpws
	cd sasl; $(MAKE) clean $(MFLAGS)
