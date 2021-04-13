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

    printf("Accepted connection from:\n\t%s:%s\n\n",
            openssl_get_peer_name(openssl_server),
            openssl_get_peer_port(openssl_server));

    openssl_conn *conn = openssl_get_conn(openssl_server);

    printf("Sending \"Hello\"\n");
    if (pel_send_all(conn, "Hello", sizeof("Hello")) != PEL_SUCCESS) {
        fprintf(stderr, "pel_send_all: %s\n", pel_strerror(pel_errno));
        goto cleanup;
    }

    printf("Awaiting response...\n");
    char response[sizeof("World!")] = {0};
    if (pel_recv_all(conn, response, sizeof(response)) != PEL_SUCCESS) {
        fprintf(stderr, "pel_recv_all: %s\n", pel_strerror(pel_errno));
        goto cleanup;
    }

    printf("Got repsonse:\n\t%s\n\n", response);

cleanup:
    if (openssl_server) {
        openssl_ctx_delete(openssl_server);
    }
}
