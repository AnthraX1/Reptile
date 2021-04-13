#include "pel.h"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

/* Usage: ./server <hostname> <port> <cert filename> */
int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: %s <hostname> <port> <cert filename>\n", argv[0]);
        return 0;
    }

    const char *hostname = argv[1];
    const char *port_str = argv[2];
    const char *cert_filename = argv[3];

    openssl_ctx *openssl_client = NULL;

    char *endptr = (char *) port_str;
    uint16_t port = (uint16_t) strtol(port_str, &endptr, 0);
    if (endptr == port_str) {
        fprintf(stderr, "Invalid port number\n");
        return -1;
    }

    openssl_client = openssl_ctx_new();
    if (!openssl_client_init(openssl_client, cert_filename)) {
        fprintf(stderr, "Couldn't initialize OpenSSL client\n");
        goto cleanup;
    }

    printf("OpenSSL client initialized with cert:\n\t%s\n\n", cert_filename);

    printf("Attempting connection to %s:%d\n\n", hostname, port);

    if (!openssl_client_connect(openssl_client, hostname, port)) {
        fprintf(stderr, "Couldn't connect to server\n");
        goto cleanup;
    }

    printf("Connected to:\n\t%s:%s (fd=%d)\n\n",
            openssl_get_peer_name(openssl_client),
            openssl_get_peer_port(openssl_client),
            openssl_get_fd(openssl_client));
    openssl_conn *conn = openssl_get_conn(openssl_client);
    (void) conn;

    printf("Attempting PEL handshake...\n");
    if (pel_server_init(openssl_client, "s3cr3t") != PEL_SUCCESS) {
        fprintf(stderr, "pel_server_init: %s\n", pel_strerror(pel_errno));
        goto cleanup;
    }

    printf("Awaiting \"Hello\"\n");
    unsigned char recv_buf[1024] = {0};
    int length = 0;
    if (pel_recv_msg(openssl_client, recv_buf, &length) != PEL_SUCCESS) {
        fprintf(stderr, "pel_recv_msg: %s\n", pel_strerror(pel_errno));
        goto cleanup;
    }

    printf("Received %d bytes: %s\nSending response...\n", length, (char *) recv_buf);
    if (pel_send_msg(openssl_client, (unsigned char *) "World!", sizeof("World!")) != PEL_SUCCESS) {
        fprintf(stderr, "pel_send_msg: %s\n", pel_strerror(pel_errno));
        goto cleanup;
    }

    printf("Sent response\n");

cleanup:
    if (openssl_client) {
        openssl_ctx_delete(openssl_client);
    }
}
