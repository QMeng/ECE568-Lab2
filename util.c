#include <openssl/err.h>
#include "util.h"

BIO *bio_err = 0;
static char *pass;
static int password_cb(char *buf,int num,int rwflag,void *userdata);
static void sigpipe_handle(int x);

int err_exit(char *info){
	fprintf(stderr, "%s\n", info);
	exit(0);
}

int berr_exit(char *info){
	BIO_printf(bio_err, "%s\n", info);
	ERR_print_errors(bio_err);
	exit(0);
}

static int password_cb(char *buf,int num,int rwflag,void *userdata) {
	if(num<strlen(pass)+1){
		return(0);
	}

    strcpy(buf,pass);
    return (strlen(pass));
}

static void sigpipe_handle(int x){}

SSL_CTX *init_ctx(char *keyFileName, char *password) {
	if (!bio_err) {
		SSL_library_init();
		SSL_load_error_strings();
		bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	}

	signal(SIGPIPE, sigpipe_handle);

	SSL_METHOD * method = SSLv23_method();
	SSL_CTX * ctx = SSL_CTX_new(method);

	if(!(SSL_CTX_use_certificate_file(ctx, keyFileName, SSL_FILETYPE_PEM))) {
		berr_exit("Couldn't read certificate file");
	}

	pass=password;
	SSL_CTX_set_default_passwd_cb(ctx, password_cb);
	if(!(SSL_CTX_use_PrivateKey_file(ctx, keyFileName, SSL_FILETYPE_PEM))) {
		berr_exit("Couldn't read key file");
	}

	if(!(SSL_CTX_load_verify_locations(ctx,CA_LIST,0))) {
		berr_exit("Couldn't read CA list");
	}
    SSL_CTX_set_verify_depth(ctx,1);

	return ctx;
}

void destroy_ctx(SSL_CTX *ctx) {
	SSL_CTX_free(ctx);
}
