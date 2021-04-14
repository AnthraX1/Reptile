/*
 * Packet Encryption Layer for Tiny SHell,
 * by Christophe Devine <devine@cr0.net>;
 * this program is licensed under the GPL.
 */

#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "aes.h"
#include "pel.h"
#include "sha1.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

/* global data */

int pel_errno;

struct pel_context {
	/* AES-CBC-128 variables */

	struct aes_context SK; /* Rijndael session key  */
	unsigned char LCT[16]; /* last ciphertext block */

	/* HMAC-SHA1 variables */

	unsigned char k_ipad[64]; /* inner padding  */
	unsigned char k_opad[64]; /* outer padding  */
	unsigned long int p_cntr; /* packet counter */
};

static struct pel_context send_ctx; /* to encrypt outgoing data */
static struct pel_context recv_ctx; /* to decrypt incoming data */

static unsigned char challenge[16] = /* version-specific */

    "\x58\x90\xAE\x86\xF1\xB9\x1C\xF6"
    "\x29\x83\x95\x71\x1D\xDE\x58\x0D";

static unsigned char buffer[BUFSIZE + 16 + 20];

/* function declaration */

static void pel_setup_context(struct pel_context *pel_ctx, char *key,
		       unsigned char IV[20]);

/* Common OpenSSL initialization. */
static void openssl_common_init(void);

/* Create and configure an OpenSSL context. */
static SSL_CTX *openssl_get_context(void);

/* Create and configure an OpenSSL accept BIO. */
static BIO *openssl_get_accept_bio(int port);

/* Perform TLS server-specific configuration. */
static bool openssl_server_configure(SSL_CTX *ctx, const char *cert_filename, const char *priv_key_filename);

/* Perform TLS client-specific configuration. */
static bool openssl_client_configure(SSL_CTX *ctx, const char *cert_filename);

bool openssl_server_init(openssl_ctx *ctx, int port, 
                         const char *cert_filename, const char *priv_key_filename) {
    if (!ctx || port > 0xFFFF || !cert_filename || !priv_key_filename) {
		fprintf(stderr, "%s: invalid argument(s)\n", __func__);
		pel_errno = PEL_UNDEFINED_ERROR;
		return false;
	}

    ctx->type = OPENSSL_SERVER;

	openssl_common_init();
	ctx->ssl_ctx = openssl_get_context();
	if (!(ctx->ssl_ctx)) {
		pel_errno = PEL_OPENSSL_ERROR;
		return false;
	}

	if (!openssl_server_configure(ctx->ssl_ctx, cert_filename, priv_key_filename)) {
		pel_errno = PEL_OPENSSL_ERROR;
		return false;
	}

	ctx->server.accept_bio = openssl_get_accept_bio(port);
	if (!(ctx->server.accept_bio)) {
		pel_errno = PEL_OPENSSL_ERROR;
		return false;
	}

	pel_errno = PEL_UNDEFINED_ERROR;
	return true;
}

bool openssl_server_accept(openssl_ctx *ctx) {
	if (!ctx || ctx->type != OPENSSL_SERVER || !(ctx->ssl_ctx) || !(ctx->server.accept_bio)) {
		fprintf(stderr, "%s: invalid argument(s)\n", __func__);
		pel_errno = PEL_UNDEFINED_ERROR;
		return false;
	}

	if (BIO_do_accept(ctx->server.accept_bio) <= 0) {
		// openssl_print_errors("Couldn't do accept");
		pel_errno = PEL_OPENSSL_ERROR;
		return false;
	}

	openssl_conn *conn = BIO_pop(ctx->server.accept_bio);
	if (!conn) {
		// openssl_print_errors("BIO was empty after accepting");
		pel_errno = PEL_OPENSSL_ERROR;
		return false;
	}

	/* Store the new connection. */
	ctx->server._client_bio = conn;

	BIO *tmp = BIO_new_ssl(ctx->ssl_ctx, OPENSSL_SERVER);
	if (!tmp) {
		// openssl_print_errors("Couldn't create new SSL BIO filter");
		pel_errno = PEL_OPENSSL_ERROR;
		openssl_conn_delete(conn);
		ctx->server._client_bio = NULL;
		return false;
	}

	BIO_push(tmp, conn);

	/* The SSL filter is now in front of the connection BIO; store that for
	 * most IO. */
	ctx->server.ssl_client_bio = tmp;

	pel_errno = PEL_UNDEFINED_ERROR;
	return true;
}

bool openssl_client_init(openssl_ctx *ctx, const char *cert_filename) {
	if (!ctx || !cert_filename) {
		fprintf(stderr, "%s: invalid argument(s)\n", __func__);
		return false;
	}

	ctx->type = OPENSSL_CLIENT;

	openssl_common_init();
	ctx->ssl_ctx = openssl_get_context();
	if (!(ctx->ssl_ctx)) {
		pel_errno = PEL_OPENSSL_ERROR;
		return false;
	}

	if (!openssl_client_configure(ctx->ssl_ctx, cert_filename)) {
		pel_errno = PEL_OPENSSL_ERROR;
		return false;
	}

	pel_errno = PEL_UNDEFINED_ERROR;
	return true;
}

bool openssl_client_connect(openssl_ctx *ctx, const char *hostname, int port) {
	/* TODO(CMK): fixed size buffer could fail. */
	char connect_addr[128] = {0};
	snprintf(connect_addr, sizeof(connect_addr), "%s:%d", hostname, port);

	BIO *conn_bio = BIO_new_connect(connect_addr);
	if (!conn_bio) {
		pel_errno = PEL_OPENSSL_ERROR;
		// openssl_print_errors("Couldn't create client connect BIO");
		return false;
	}

	if (BIO_do_connect(conn_bio) <= 0) {
		// openssl_print_errors("Couldn't do client connect");
		pel_errno = PEL_OPENSSL_ERROR;
		openssl_conn_delete(conn_bio);
		return false;
	}

	/* Store the new connection. */
	ctx->client._server_bio = conn_bio;

	BIO *ssl_bio = BIO_new_ssl(ctx->ssl_ctx, OPENSSL_CLIENT);
	if (!ssl_bio) {
		// openssl_print_errors("Couldn't create client SSL BIO");
		pel_errno = PEL_OPENSSL_ERROR;
		openssl_conn_delete(conn_bio);
		ctx->client._server_bio = NULL;
		return false;
	}

	BIO_push(ssl_bio, conn_bio);

	/* The SSL filter is now in front of the connection BIO; store that for
	 * most IO. */
	ctx->client.ssl_server_bio = ssl_bio;
	
	pel_errno = PEL_UNDEFINED_ERROR;
	return true;
}

void openssl_ctx_cleanup(openssl_ctx *ctx) {
	if (!ctx) {
		return;
	}

	if (ctx->type == OPENSSL_SERVER) {
		if (ctx->server.accept_bio) {
			BIO_free_all(ctx->server.accept_bio);
		}
		if (ctx->server.ssl_client_bio) {
			BIO_free_all(ctx->server.ssl_client_bio);
		}
	} else {
		if (ctx->client.ssl_server_bio) {
			BIO_free_all(ctx->client.ssl_server_bio);
		}
	}

	if (ctx->ssl_ctx) {
		SSL_CTX_free(ctx->ssl_ctx);
	}
}

openssl_conn *openssl_get_conn(const openssl_ctx *ctx) {
	if (!ctx) {
		return NULL;
	}

	if (ctx->type == OPENSSL_SERVER) {
		return ctx->server.ssl_client_bio;
	} else if (ctx->type == OPENSSL_CLIENT) {
		return ctx->client.ssl_server_bio;
	}

	return NULL;
}

const char *openssl_get_peer_name(openssl_ctx *ctx) {
	if (!ctx) {
		return "invalid-ctx";
	}

	if (ctx->type == OPENSSL_SERVER && ctx->server._client_bio) {
		return BIO_get_peer_name(ctx->server._client_bio);
	} else if (ctx->type == OPENSSL_CLIENT && ctx->client._server_bio) {
		return BIO_get_peer_name(ctx->client._server_bio);
	}
    
	return "invalid-ctx";
}

const char *openssl_get_peer_port(openssl_ctx *ctx) {
	if (!ctx) {
		return "invalid-ctx";
	}

	if (ctx->type == OPENSSL_SERVER && ctx->server._client_bio) {
		return BIO_get_accept_port(ctx->server._client_bio);
	} else if (ctx->type == OPENSSL_CLIENT && ctx->client._server_bio) {
		return BIO_get_accept_port(ctx->client._server_bio);
	}
    
	return "invalid-ctx";
}

int openssl_get_fd(openssl_ctx *ctx) {
	if (!ctx) {
		return -1;
	}

	if (ctx->type == OPENSSL_SERVER && ctx->server._client_bio) {
		return BIO_get_fd(ctx->server._client_bio, NULL);
	} else if (ctx->type == OPENSSL_CLIENT && ctx->client._server_bio) {
		return BIO_get_fd(ctx->client._server_bio, NULL);
	}
    
	return -1;
}

/* session setup - client side */

int pel_client_init(openssl_ctx *ctx, char *key)
{
	int ret, len, pid;
	struct timeval tv;
	struct sha1_context sha1_ctx;
	unsigned char IV1[20], IV2[20];

	if (!ctx || ctx->type != OPENSSL_SERVER || !(ctx->server.ssl_client_bio)) {
		fprintf(stderr, "%s: invalid argument(s)\n", __func__);
		pel_errno = PEL_UNDEFINED_ERROR;
		return PEL_FAILURE;
	}

	openssl_conn *client_conn = ctx->server.ssl_client_bio;

	/* generate both initialization vectors */

	pid = getpid();

	if (gettimeofday(&tv, NULL) < 0) {
		pel_errno = PEL_SYSTEM_ERROR;

		return (PEL_FAILURE);
	}

	sha1_starts(&sha1_ctx);
	sha1_update(&sha1_ctx, (uint8 *)&tv, sizeof(tv));
	sha1_update(&sha1_ctx, (uint8 *)&pid, sizeof(pid));
	sha1_finish(&sha1_ctx, &buffer[0]);

	memcpy(IV1, &buffer[0], 20);

	pid++;

	if (gettimeofday(&tv, NULL) < 0) {
		pel_errno = PEL_SYSTEM_ERROR;

		return (PEL_FAILURE);
	}

	sha1_starts(&sha1_ctx);
	sha1_update(&sha1_ctx, (uint8 *)&tv, sizeof(tv));
	sha1_update(&sha1_ctx, (uint8 *)&pid, sizeof(pid));
	sha1_finish(&sha1_ctx, &buffer[20]);

	memcpy(IV2, &buffer[20], 20);

	/* and pass them to the server */

	ret = pel_send_all(client_conn, buffer, 40);

	if (ret != PEL_SUCCESS)
		return (PEL_FAILURE);

	/* setup the session keys */

	pel_setup_context(&send_ctx, key, IV1);
	pel_setup_context(&recv_ctx, key, IV2);

	/* handshake - encrypt and send the client's challenge */

	ret = pel_send_msg(ctx, challenge, 16);

	if (ret != PEL_SUCCESS)
		return (PEL_FAILURE);

	/* handshake - decrypt and verify the server's challenge */

	ret = pel_recv_msg(ctx, buffer, &len);

	if (ret != PEL_SUCCESS)
		return (PEL_FAILURE);

	if (len != 16 || memcmp(buffer, challenge, 16) != 0) {
		pel_errno = PEL_WRONG_CHALLENGE;

		return (PEL_FAILURE);
	}

	pel_errno = PEL_UNDEFINED_ERROR;

	return (PEL_SUCCESS);
}

/* session setup - server side */

int pel_server_init(openssl_ctx *ctx, char *key)
{
	int ret, len;
	unsigned char IV1[20], IV2[20];

	if (!ctx || ctx->type != OPENSSL_CLIENT || !(ctx->client.ssl_server_bio)) {
		fprintf(stderr, "%s: invalid argument(s)\n", __func__);
		pel_errno = PEL_UNDEFINED_ERROR;
		return PEL_FAILURE;
	}	

	openssl_conn *server_conn = ctx->client.ssl_server_bio;

	/* get the IVs from the client */

	ret = pel_recv_all(server_conn, buffer, 40);

	if (ret != PEL_SUCCESS)
		return (PEL_FAILURE);

	memcpy(IV2, &buffer[0], 20);
	memcpy(IV1, &buffer[20], 20);

	/* setup the session keys */

	pel_setup_context(&send_ctx, key, IV1);
	pel_setup_context(&recv_ctx, key, IV2);

	/* handshake - decrypt and verify the client's challenge */

	ret = pel_recv_msg(ctx, buffer, &len);

	if (ret != PEL_SUCCESS)
		return (PEL_FAILURE);

	if (len != 16 || memcmp(buffer, challenge, 16) != 0) {
		pel_errno = PEL_WRONG_CHALLENGE;

		return (PEL_FAILURE);
	}

	/* handshake - encrypt and send the server's challenge */

	ret = pel_send_msg(ctx, challenge, 16);

	if (ret != PEL_SUCCESS)
		return (PEL_FAILURE);

	pel_errno = PEL_UNDEFINED_ERROR;

	return (PEL_SUCCESS);
}

/* this routine computes the AES & HMAC session keys */

static void pel_setup_context(struct pel_context *pel_ctx, char *key,
		       unsigned char IV[20])
{
	int i;
	struct sha1_context sha1_ctx;

	sha1_starts(&sha1_ctx);
	sha1_update(&sha1_ctx, (uint8 *)key, strlen(key));
	sha1_update(&sha1_ctx, IV, 20);
	sha1_finish(&sha1_ctx, buffer);

	aes_set_key(&pel_ctx->SK, buffer, 128);

	memcpy(pel_ctx->LCT, IV, 16);

	memset(pel_ctx->k_ipad, 0x36, 64);
	memset(pel_ctx->k_opad, 0x5C, 64);

	for (i = 0; i < 20; i++) {
		pel_ctx->k_ipad[i] ^= buffer[i];
		pel_ctx->k_opad[i] ^= buffer[i];
	}

	pel_ctx->p_cntr = 0;
}

/* encrypt and transmit a message */

int pel_send_msg(openssl_ctx *ctx, unsigned char *msg, int length)
{
	unsigned char digest[20];
	struct sha1_context sha1_ctx;
	int i, j, ret, blk_len;

	openssl_conn *conn = openssl_get_conn(ctx);
	if (!conn) {
		fprintf(stderr, "%s: invalid argument(s)\n", __func__);
		pel_errno = PEL_UNDEFINED_ERROR;
		return PEL_FAILURE;
	}

	/* verify the message length */

	if (length <= 0 || length > BUFSIZE) {
		pel_errno = PEL_BAD_MSG_LENGTH;

		return (PEL_FAILURE);
	}

	/* write the message length at start of buffer */

	buffer[0] = (length >> 8) & 0xFF;
	buffer[1] = (length)&0xFF;

	/* append the message content */

	memcpy(buffer + 2, msg, length);

	/* round up to AES block length (16 bytes) */

	blk_len = 2 + length;

	if ((blk_len & 0x0F) != 0) {
		blk_len += 16 - (blk_len & 0x0F);
	}

	/* encrypt the buffer with AES-CBC-128 */

	for (i = 0; i < blk_len; i += 16) {
		for (j = 0; j < 16; j++) {
			buffer[i + j] ^= send_ctx.LCT[j];
		}

		aes_encrypt(&send_ctx.SK, &buffer[i]);

		memcpy(send_ctx.LCT, &buffer[i], 16);
	}

	/* compute the HMAC-SHA1 of the ciphertext */

	buffer[blk_len] = (send_ctx.p_cntr << 24) & 0xFF;
	buffer[blk_len + 1] = (send_ctx.p_cntr << 16) & 0xFF;
	buffer[blk_len + 2] = (send_ctx.p_cntr << 8) & 0xFF;
	buffer[blk_len + 3] = (send_ctx.p_cntr) & 0xFF;

	sha1_starts(&sha1_ctx);
	sha1_update(&sha1_ctx, send_ctx.k_ipad, 64);
	sha1_update(&sha1_ctx, buffer, blk_len + 4);
	sha1_finish(&sha1_ctx, digest);

	sha1_starts(&sha1_ctx);
	sha1_update(&sha1_ctx, send_ctx.k_opad, 64);
	sha1_update(&sha1_ctx, digest, 20);
	sha1_finish(&sha1_ctx, &buffer[blk_len]);

	/* increment the packet counter */

	send_ctx.p_cntr++;

	/* transmit ciphertext and message authentication code */

	ret = pel_send_all(conn, buffer, blk_len + 20);

	if (ret != PEL_SUCCESS)
		return (PEL_FAILURE);

	pel_errno = PEL_UNDEFINED_ERROR;

	return (PEL_SUCCESS);
}

/* receive and decrypt a message */

int pel_recv_msg(openssl_ctx *ctx, unsigned char *msg, int *length)
{
	unsigned char temp[16];
	unsigned char hmac[20];
	unsigned char digest[20];
	struct sha1_context sha1_ctx;
	int i, j, ret, blk_len;

	openssl_conn *conn = openssl_get_conn(ctx);
	if (!conn) {
		fprintf(stderr, "%s: invalid argument(s)\n", __func__);
		pel_errno = PEL_UNDEFINED_ERROR;
		return PEL_FAILURE;
	}

	/* receive the first encrypted block */

	ret = pel_recv_all(conn, buffer, 16);

	if (ret != PEL_SUCCESS)
		return (PEL_FAILURE);

	/* decrypt this block and extract the message length */

	memcpy(temp, buffer, 16);

	aes_decrypt(&recv_ctx.SK, buffer);

	for (j = 0; j < 16; j++) {
		buffer[j] ^= recv_ctx.LCT[j];
	}

	*length = (((int)buffer[0]) << 8) + (int)buffer[1];

	/* restore the ciphertext */

	memcpy(buffer, temp, 16);

	/* verify the message length */

	if (*length <= 0 || *length > BUFSIZE) {
		pel_errno = PEL_BAD_MSG_LENGTH;

		return (PEL_FAILURE);
	}

	/* round up to AES block length (16 bytes) */

	blk_len = 2 + *length;

	if ((blk_len & 0x0F) != 0) {
		blk_len += 16 - (blk_len & 0x0F);
	}

	/* receive the remaining ciphertext and the mac */

	ret = pel_recv_all(conn, &buffer[16], blk_len - 16 + 20);

	if (ret != PEL_SUCCESS)
		return (PEL_FAILURE);

	memcpy(hmac, &buffer[blk_len], 20);

	/* verify the ciphertext integrity */

	buffer[blk_len] = (recv_ctx.p_cntr << 24) & 0xFF;
	buffer[blk_len + 1] = (recv_ctx.p_cntr << 16) & 0xFF;
	buffer[blk_len + 2] = (recv_ctx.p_cntr << 8) & 0xFF;
	buffer[blk_len + 3] = (recv_ctx.p_cntr) & 0xFF;

	sha1_starts(&sha1_ctx);
	sha1_update(&sha1_ctx, recv_ctx.k_ipad, 64);
	sha1_update(&sha1_ctx, buffer, blk_len + 4);
	sha1_finish(&sha1_ctx, digest);

	sha1_starts(&sha1_ctx);
	sha1_update(&sha1_ctx, recv_ctx.k_opad, 64);
	sha1_update(&sha1_ctx, digest, 20);
	sha1_finish(&sha1_ctx, digest);

	if (memcmp(hmac, digest, 20) != 0) {
		pel_errno = PEL_CORRUPTED_DATA;

		return (PEL_FAILURE);
	}

	/* increment the packet counter */

	recv_ctx.p_cntr++;

	/* finally, decrypt and copy the message */

	for (i = 0; i < blk_len; i += 16) {
		memcpy(temp, &buffer[i], 16);

		aes_decrypt(&recv_ctx.SK, &buffer[i]);

		for (j = 0; j < 16; j++) {
			buffer[i + j] ^= recv_ctx.LCT[j];
		}

		memcpy(recv_ctx.LCT, temp, 16);
	}

	// Note: must use memmove since pel init functions pass 
	//		 the global buffer as "msg" to this function.
	memmove(msg, &buffer[2], *length);

	pel_errno = PEL_UNDEFINED_ERROR;

	return (PEL_SUCCESS);
}

/* send/recv wrappers to handle fragmented TCP packets */

int pel_send_all(openssl_conn *conn, void *buf, size_t len)
{
	int n;
	size_t sum = 0;
	char *offset = buf;

	while (sum < len) {
		n = BIO_write(conn, offset, len - sum);

		if (n <= 0) {
			if (BIO_should_retry(conn)) {
				continue;
			}

			pel_errno = PEL_OPENSSL_ERROR;
			return (PEL_FAILURE);
		}

		sum += n;

		offset += n;
	}

	pel_errno = PEL_UNDEFINED_ERROR;

	return (PEL_SUCCESS);
}

int pel_recv_all(openssl_conn *conn, void *buf, size_t len)
{
	int n;
	size_t sum = 0;
	char *offset = buf;

	while (sum < len) {
		n = BIO_read(conn, offset, len - sum);

		if (n <= 0) {
			if (BIO_should_retry(conn)) {
				continue;
			}

			/* From the manpage:
			 * 	"For example if a call to BIO_read() on a socket BIO returns 0 
			 *	 and BIO_should_retry() is false then the cause will be that 
			 *	 the connection closed." */
			pel_errno = PEL_CONN_CLOSED;
			return (PEL_FAILURE);
		}

		sum += n;

		offset += n;
	}

	pel_errno = PEL_UNDEFINED_ERROR;

	return (PEL_SUCCESS);
}

/* util */
const char *pel_strerror(int pel_err)
{
	switch (pel_err) {
	case PEL_CONN_CLOSED:
		return "Connection closed";

	case PEL_SYSTEM_ERROR:
		return strerror(errno);

	case PEL_WRONG_CHALLENGE:
		return "Wrong challenge";

	case PEL_BAD_MSG_LENGTH:
		return "Bad message length";

	case PEL_CORRUPTED_DATA:
		return "Corrupted data";

	case PEL_UNDEFINED_ERROR:
		return "No error";

	case PEL_OPENSSL_ERROR:
		return "OpenSSL error";

	default:
		return "Unknown error code";
	}
}

void openssl_print_errors(const char *msg) {
	fprintf(stderr, "%s\n", msg);
	ERR_print_errors_fp(stderr);
}

static void openssl_common_init(void) {
	/* https://wiki.openssl.org/index.php/Library_Initialization */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	SSL_library_init();
#else
	OPENSSL_init_ssl(0, NULL);
#endif
	
// #ifdef DEBUG
	// support error strings when using OpenSSL's built-ins
	SSL_load_error_strings();
// #endif
}

static SSL_CTX *openssl_get_context(void) {
	/* https://quuxplusone.github.io/blog/2020/01/26/openssl-part-3/#ssl_ctx-versus-ssl */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	return SSL_CTX_new(SSLv23_method());
#else
	return SSL_CTX_new(TLS_method());
#endif
}

static BIO *openssl_get_accept_bio(int port) {
	if (port > 0xFFFF) { // ports should be 16-bit
		return NULL;
	}

	char port_str[64] = {0};
	snprintf(port_str, sizeof(port_str), "%d", port);
	BIO *bio_accept = BIO_new_accept(port_str);
	if (!bio_accept) {
		openssl_print_errors("Couldn't create new accept BIO");
		return NULL;
	}

	if (BIO_do_accept(bio_accept) <= 0) {
		openssl_print_errors("Couldn't do accept");
		BIO_free_all(bio_accept);
		return NULL;
	}

	return bio_accept;
}

static bool openssl_server_configure(SSL_CTX *ctx, const char *cert_filename, const char *priv_key_filename) {
	if (SSL_CTX_use_certificate_file(ctx, cert_filename, SSL_FILETYPE_PEM) <= 0) {
		openssl_print_errors("Couldn't load certificate file");
		return false;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, priv_key_filename, SSL_FILETYPE_PEM) <= 0) {
		openssl_print_errors("Couldn't load private key file");
		return false;
	}

	return true;
}

static bool openssl_client_configure(SSL_CTX *ctx, const char *cert_filename) {
	/* Note: we just want our made up cert to verify, don't care about 
	 * actual TLS security. So, use our made up cert for verification. */
	if (SSL_CTX_load_verify_locations(ctx, cert_filename, NULL) <= 0) {
		openssl_print_errors("Couldn't load cert verification file");
		return false;
	}

	return true;
}
