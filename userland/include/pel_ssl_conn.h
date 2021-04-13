#ifndef _PEL_H
#define _PEL_H

#include <openssl/ssl.h>

#include <stdbool.h>

#define BUFSIZE 4096    /* maximum message length */

#define PEL_SUCCESS 1
#define PEL_FAILURE 0

#define PEL_SYSTEM_ERROR        -1
#define PEL_CONN_CLOSED         -2
#define PEL_WRONG_CHALLENGE     -3
#define PEL_BAD_MSG_LENGTH      -4
#define PEL_CORRUPTED_DATA      -5
#define PEL_UNDEFINED_ERROR     -6

extern int pel_errno;

/**
 * Class data for OpenSSL. 
 * Note: For simplicity, this only supports one ongoing connection
 *       at a time.
 */
typedef struct openssl_ctx {
    enum {
        OPENSSL_UNINIT = -1,    
        OPENSSL_SERVER = 0,
        OPENSSL_CLIENT = 1,
    } type;

    SSL_CTX *ssl_ctx;

    union {
        struct {
            BIO *accept_bio;        /** BIO used for accepting incoming connections. */
            BIO *_client_bio;       /** Private: the current connection BIO (use ssl_client_bio). */
            BIO *ssl_client_bio;    /** The SSL filter in front of the connection BIO. */
        } server;

        struct {
            BIO *_server_bio;       /** Private: the current connection BIO (use ssl_server_bio). */
            BIO *ssl_server_bio;    /** The SSL filter in front of the connection BIO. */
        } client;
    };
} openssl_ctx;

/** A remote socket type. */
typedef BIO openssl_conn;

/**
 * Creates a new OpenSSL context and initializes it with default data.
 * 
 * @return NULL if there's an error, else a new OpenSSL context.
 */
static inline openssl_ctx *openssl_ctx_new() {
    openssl_ctx *ctx = calloc(1, sizeof(*ctx));
    ctx->type = OPENSSL_UNINIT;
    return ctx;
}

/**
 * Frees any resources associated with the given context.
 * 
 * @param[in] ctx the context to clean up.
 */
void openssl_ctx_cleanup(openssl_ctx *ctx);

/**
 * Frees an OpenSSL context, including any associated resources.
 * 
 * @param[in] ctx the context to delete.
 */
static inline void openssl_ctx_delete(openssl_ctx *ctx) {
    openssl_ctx_cleanup(ctx);
    free(ctx);
}

/**
 * Frees an OpenSSL connection.
 * 
 * @param[in] conn the connection to delete.
 */
static inline void openssl_conn_delete(openssl_conn *conn) {
    BIO_free_all(conn);
}

/**
 * Initializes the PEL module as an OpenSSL server.
 * 
 * @param[out] ctx the openssl context to initialize and configure.
 * @param port the port for the server to bind to.
 * @param[in] cert_filename the filename where the server's certificate is located.
 * @param[in] priv_key_filename the filename where the server's private key is located.
 * @return true if successful, else false.
 */
bool openssl_server_init(openssl_ctx *ctx, int port, 
                         const char *cert_filename, const char *priv_key_filename);

/**
 * Accepts a remote connection using the given OpenSSL server's context.
 * 
 * @param[in] ctx the OpenSSL server context.
 * @return true if successful, else false.
 */
openssl_conn *openssl_server_accept(openssl_ctx *ctx);

/**
 * Initializes the PEL module as an OpenSSL client.
 * 
 * @param[out] ctx the openssl context to initialize and configure.
 * @param[in] cert_filename the filename where the server's certificate is located.
 * @return true if successful, else false.
 */
bool openssl_client_init(openssl_ctx *ctx, const char *cert_filename);

/**
 * Connects to the given hostname and port.
 * 
 * @param[in, out] ctx the openssl client context.
 * @param[in] hostname the host to connect to.
 * @param port the host port to connect to.
 * @return NULL if there's an error, else a connection to the server.
 */
openssl_conn *openssl_client_connect(openssl_ctx *ctx, const char *hostname, int port);

/**
 * Returns the peer name for the given connection.
 * 
 * @param[in] conn the connection to retrieve the peer name for.
 * @return the peer name or NULL if unavailable.
 */
static inline const char *openssl_get_peer_name(openssl_conn *conn) {
    return BIO_get_peer_name(conn);
}

/**
 * Returns the port for the given connection.
 * 
 * @param[in] conn the connection to retrieve the port for.
 * @return the port or NULL if unavailable.
 */
static inline const char *openssl_get_peer_port(openssl_conn *conn) {
    return BIO_get_accept_port(conn);
}

/**
 * Returns the underlying file descriptor for a given connection.
 * 
 * @param[in] conn the connection to retrieve the FD for.
 * @return the FD or -1 if unavailable.
 */
static inline int openssl_get_fd(openssl_conn *conn) {
    return BIO_get_fd(conn, NULL);
}

/**
 * Performs PEL handshaking with the given client.
 * 
 * Note: the language is somewhat confusing to me; this call seems to be 
 *       from the network "server" to the network "client".
 * 
 * @param[in] client_conn the accepted client connection.
 * @param[in] key the crypto key for the underlying PEL encryption layer.
 * @return PEL_SUCCESS if successful, else PEL_FAILURE
 */
int pel_client_init(openssl_conn *client_conn, char *key);

/**
 * Performs PEL handshaking with the given server.
 * 
 * Note: the language is somewhat confusing to me; this call seems to be 
 *       from the network "client" to the network "server".
 * 
 * @param[in] server_conn the server connection.
 * @param[in] key the crypto key for the underlying PEL encryption layer.
 * @return PEL_SUCCESS if successful, else PEL_FAILURE
 */
int pel_server_init(openssl_conn *server_conn, char *key);

/** Methods for formatted, encrypted message transport. */
int pel_send_msg(openssl_conn *conn, unsigned char *msg, int  length);
int pel_recv_msg(openssl_conn *conn, unsigned char *msg, int *length);

/** Methods for underlying OpenSSL transport. */
int pel_send_all(openssl_conn *conn, void *buf, size_t len);
int pel_recv_all(openssl_conn *conn, void *buf, size_t len);

/** Util to return a string constant describing a PEL status code. */
const char *pel_strerror(int pel_err);

#endif /* pel.h */
