CC := gcc
CFLAGS := -Wall
LIBS := -lssl -lcrypto
LDFLAGS := $(LIBS)
RM := rm -f

sources := client.c server.c util.c
targets := client server 

.PHONY: clean default all

default: all
all: $(targets)

client: client.o util.o
	$(CC) $(LDFLAGS) -o client client.o util.o

server: server.o util.o
	$(CC) $(LDFLAGS) -o server server.o util.o


client.o: client.c
	$(CC) $(CFLAGS) -c -o client.o client.c

server.o: server.c
	$(CC) $(CFLAGS) -c -o server.o server.c

util.o: util.c
	$(CC) $(CFLAGS) -c -o util.o util.c

clean:
	$(RM) $(targets) $(sources:.c=.o) *~

