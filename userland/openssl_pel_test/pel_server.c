#include "pel.h"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

/* Usage: ./server <port> <cert filename> <priv key filename> */
int main(int argc, char **argv) {
    if (argc < 4) {
        printf("Usage: %s <port> <cert filename> <priv key filename>\n", argv[0]);
        return 0;
    }

    const char *port_str = argv[1];
    const char *cert_filename = argv[2];
    const char *priv_key_filename = argv[3];

    openssl_ctx *openssl_server = NULL;

    char *endptr = (char *) port_str;
    uint16_t port = (uint16_t) strtol(port_str, &endptr, 0);
    if (endptr == port_str) {
        fprintf(stderr, "Invalid port number\n");
        return -1;
    }

    openssl_server = openssl_ctx_new();
    if (!openssl_server_init(openssl_server, port, cert_filename, priv_key_filename)) {
        fprintf(stderr, "Couldn't initialize OpenSSL server\n");
        goto cleanup;
    }

    printf("OpenSSL server initialized on port %d with PEMs: \n\t%s\n\t%s\n\n",
            port, cert_filename, priv_key_filename);

    printf("Awaiting connection ...\n");

    if (!openssl_server_accept(openssl_server)) {
        fprintf(stderr, "Couldn't accept incoming client\n");
        goto cleanup;
    }

    printf("Accepted connection from:\n\t%s:%s (fd=%d)\n\n",
            openssl_get_peer_name(openssl_server),
            openssl_get_peer_port(openssl_server),
            openssl_get_fd(openssl_server));

    openssl_conn *conn = openssl_get_conn(openssl_server);
    (void) conn;

    printf("Attempting PEL handshake...\n");
    if (pel_client_init(openssl_server, "s3cr3t") != PEL_SUCCESS) {
        fprintf(stderr, "pel_client_init: %s\n", pel_strerror(pel_errno));
        goto cleanup;
    }

    printf("Sending \"Hello\"\n");
    if (pel_send_msg(openssl_server, (unsigned char *) "Hello", sizeof("Hello")) != PEL_SUCCESS) {
        fprintf(stderr, "pel_send_msg: %s\n", pel_strerror(pel_errno));
        goto cleanup;
    }

    printf("Awaiting response...\n");
    unsigned char response[1024] = {0};
    int length = 0;
    if (pel_recv_msg(openssl_server, response, &length) != PEL_SUCCESS) {
        fprintf(stderr, "pel_recv_all: %s\n", pel_strerror(pel_errno));
        goto cleanup;
    }

    printf("Got %d bytes:\n\t%s\n\n", length, (char *) response);

cleanup:
    if (openssl_server) {
        openssl_ctx_delete(openssl_server);
    }
}
