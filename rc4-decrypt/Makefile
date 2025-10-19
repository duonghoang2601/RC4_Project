CC = gcc
CFLAGS = -O2 -Wall -I../lib
LIB = ../lib/rc4.c

all: rc4-decrypt

rc4-decrypt: main.c $(LIB)
	$(CC) $(CFLAGS) -o $@ main.c $(LIB)

clean:
	rm -f rc4-decrypt
