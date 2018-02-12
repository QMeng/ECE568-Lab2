#ifndef _common_h
#define _common_h

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define CA_LIST "568ca.pem"
#define HOST "localhost"
#define PORT 8765
#define BUFF_SIZE 256
#define BOB_CN "Bob's Server"
#define BOB_EMAIL "ece568bob@ecf.utoronto.ca"
#define BOB_KEY_FILE "bob.pem"
#define ALICE_CN "Alice's Client"
#define ALICE_EMAIL "ece568alice@ecf.utoronto.ca"
#define ALICE_KEY_FILE "alice.pem"
#define PASSWORD "password"
#define CA_CN "ECE568 Certificate Authority"

extern BIO *bio_err;
int err_exit(char *info);
int berr_exit(char *info);
SSL_CTX *init_ctx(char *keyFileName, char *password);

#ifndef ALLOW_OLD_VERSIONS
#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
#error "Must use OpenSSL 0.9.6 or later"
#endif
#endif

#endif
