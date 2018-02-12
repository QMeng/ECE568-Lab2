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

#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"
#define FMT_CN_MISMATCH "ECE568-SERVER: Client Common Name does not match\n"
#define FMT_EMAIL_MISMATCH "ECE568-SERVER: Client Email does not match\n"

void check_client_certificate(SSL *ssl) {
	X509 *client;
	char clientCN[BUFF_SIZE];
	char clientEmail[BUFF_SIZE];
	
	client = SSL_get_peer_certificate(ssl);
	
	if (SSL_get_verify_result(ssl) != X509_V_OK) {
		berr_exit(FMT_ACCEPT_ERR);
		return 0;
	}

	X509_NAME_get_text_by_NID(X509_get_subject_name(client), NID_commonName, clientCN, BUFF_SIZE);
	X509_NAME_get_text_by_NID(X509_get_subject_name(client), NID_pkcs9_emailAddress, clientEmail, BUFF_SIZE);

	if (strcasecmp(clientCN, ALICE_CN)) {
	    printf(clientCN);
		printf(ALICE_CN);
		berr_exit(FMT_CN_MISMATCH);
		return 0;
	}

	if (strcasecmp(clientEmail, ALICE_EMAIL)) {
		berr_exit(FMT_EMAIL_MISMATCH);
		return 0;
	}

	printf(FMT_CLIENT_INFO, clientCN, clientEmail);
}

void handle_request(SSL *ssl, char *answer) {
	check_client_certificate(ssl);

	char buf[BUFF_SIZE];

	int rc = SSL_read(ssl, buf, BUFF_SIZE);

	switch (SSL_get_error(ssl, rc)) {
		case SSL_ERROR_NONE:
			buf[rc] = '\0';
			break;
		default:
			berr_exit("SSL read has problem");
	}

	printf(FMT_OUTPUT, buf, answer);

	rc = SSL_write(ssl, answer, strlen(answer));
	switch (SSL_get_error(ssl, rc)) {
		case SSL_ERROR_NONE:
			if (strlen(answer) != rc) {
				berr_exit("Incomplete write");
			}
			break;
		default:
			berr_exit("SSL write has problem");
	}
}

int main(int argc, char **argv)
{
  int s, sock, port=PORT;
  struct sockaddr_in sin;
  int val=1;
  pid_t pid;
  char *answer = "42";
  
  /*Parse command line arguments*/
  
  switch(argc){
    case 1:
      break;
    case 2:
      port=atoi(argv[1]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s port\n", argv[0]);
      exit(0);
  }

  if((sock=socket(AF_INET,SOCK_STREAM,0))<0){
    perror("socket");
    close(sock);
    exit(0);
  }
  
  SSL_CTX *ctx = init_ctx(BOB_KEY_FILE, PASSWORD);
  SSL_CTX_set_cipher_list(ctx, "SSLv2:SSLv3:TLSv1");
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

  memset(&sin,0,sizeof(sin));
  sin.sin_addr.s_addr=INADDR_ANY;
  sin.sin_family=AF_INET;
  sin.sin_port=htons(port);
  
  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));
    
  if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){
    perror("bind");
    close(sock);
    exit (0);
  }
  
  if(listen(sock,5)<0){
    perror("listen");
    close(sock);
    exit (0);
  } 
  
  while(1){
    
    if((s=accept(sock, NULL, 0))<0){
      perror("accept");
      close(sock);
      close(s);
      exit (0);
    }
    
    /*fork a child to handle the connection*/
    
    if((pid=fork())){
      close(s);
    }
    else {
      /*Child code*/
      int len;
      char buf[256];
      char *answer = "42";

      BIO *sbio = BIO_new_socket(s, BIO_NOCLOSE);
      SSL *ssl = SSL_new(ctx);
      SSL_set_bio(ssl, sbio, sbio);

      if (SSL_accept(ssl) <= 0) {
        berr_exit(FMT_ACCEPT_ERR);
        exit(0);
      }

      handle_request(ssl, answer);
   
      int rc = SSL_shutdown(ssl);

      switch (rc) {
        case 1:
          break;

        default:
          shutdown(s, SHUT_WR);
		  rc = SSL_shutdown(ssl);
		  if (rc != 1) {
			berr_exit(FMT_INCOMPLETE_CLOSE);
		  }
      }
      close(sock);
      close(s);
      return 0;
    }
  }
  
  close(sock);
  return 1;
}
