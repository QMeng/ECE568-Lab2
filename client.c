#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "util.h"

#define HOST "localhost"
#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"

// validate the server's certificate is solid
int verify_server_certificate(SSL *ssl) {
	X509 *server;
	char serverCN[BUFF_SIZE];
	char serverEmail[BUFF_SIZE];
	char issuerCN[BUFF_SIZE];

	if (SSL_get_verify_result(ssl) != X509_V_OK) {
		berr_exit(FMT_NO_VERIFY);
		return 0;
	}

	server = SSL_get_peer_certificate(ssl);
	X509_NAME_get_text_by_NID(X509_get_subject_name(server), NID_commonName, serverCN, BUFF_SIZE);
	X509_NAME_get_text_by_NID(X509_get_subject_name(server), NID_pkcs9_emailAddress, serverEmail, BUFF_SIZE);
	X509_NAME_get_text_by_NID(X509_get_issuer_name(server), NID_commonName, issuerCN, BUFF_SIZE);

	// server cn does not match
	if (strcasecmp(serverCN, BOB_CN)) {
		berr_exit(FMT_CN_MISMATCH);
		return 0;
	}

	// server email does not match
	if (strcasecmp(serverEmail, BOB_EMAIL)) {
		berr_exit(FMT_EMAIL_MISMATCH);
		return 0;
	}

	// ca cn does not match
	if (strcasecmp(issuerCN, CA_CN)) {
		berr_exit(FMT_NO_VERIFY);
		return 0;
	}
	
	printf(FMT_SERVER_INFO, serverCN, serverEmail, issuerCN);
	return 1;
}

void send_message(char* secret, char* buf, SSL *ssl) {
	int secretLength = strlen(secret);
	
	int rc = SSL_write(ssl, secret, secretLength);
	switch (SSL_get_error(ssl, rc)) {
		case SSL_ERROR_NONE:
			if (rc != secretLength) {
				berr_exit("Incomplete write");
			}
			break;

		case SSL_ERROR_SYSCALL:
			berr_exit(FMT_INCORRECT_CLOSE);
			return;

		default:
			berr_exit("SSL write have error");
	}

	rc = SSL_read(ssl, buf, BUFF_SIZE);
	switch (SSL_get_error(ssl, rc)) {
		case SSL_ERROR_NONE:
			buf[rc] = '\0';
			return;
		
		case SSL_ERROR_SYSCALL:
			berr_exit(FMT_INCORRECT_CLOSE);
			return;

		case SSL_ERROR_ZERO_RETURN:
			return;

		default:
			berr_exit("SSL read have error");
	}
}

int main(int argc, char **argv)
{
	int len, sock, port=PORT;
	char *host=HOST;
	struct sockaddr_in addr;
	struct hostent *host_entry;
	char buf[256];
	char *secret = "What's the question?";
  
	/*Parse command line arguments*/
  	switch(argc){
		case 1:
			break;
		case 3:
			host = argv[1];
			port=atoi(argv[2]);
			if (port<1||port>65535){
				fprintf(stderr,"invalid port number");
				exit(0);
			}
			break;
		default:
			printf("Usage: %s server port\n", argv[0]);
			exit(0);
	}
  
	/*get ip address of the host*/

	host_entry = gethostbyname(host);
  
	if (!host_entry){
		fprintf(stderr,"Couldn't resolve host");
		exit(0);
	}

	memset(&addr,0,sizeof(addr));
	addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
	addr.sin_family=AF_INET;
	addr.sin_port=htons(port);

	printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);

	/*open socket*/

	if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
		perror("socket");
	if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)
 		perror("connect");
  
	SSL_CTX * ctx = init_ctx(ALICE_KEY_FILE, PASSWORD);
	SSL_CTX_set_cipher_list(ctx,"SHA1");
	SSL_CTX_set_options(ctx,SSL_OP_NO_SSLv2);

	SSL * ssl = SSL_new(ctx);
	BIO * sbio = BIO_new_socket(sock, BIO_NOCLOSE);
	SSL_set_bio(ssl,sbio,sbio);

	if (SSL_connect(ssl)<=0) {
		berr_exit(FMT_CONNECT_ERR);
		goto cleanup;
	}

	verify_server_certificate(ssl);

	send_message(secret, buf, ssl);
  
	/* this is how you output something for the marker to pick up */
	printf(FMT_OUTPUT, secret, buf);
	goto cleanup;

	cleanup:
		SSL_shutdown(ssl);
		SSL_free(ssl);
		SSL_CTX_free(ctx); 
		close(sock);
	return 1;
}
