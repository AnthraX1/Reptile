#include "pel.h"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <termios.h>
#include <unistd.h>

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

    printf("Init successful. Type to send a message\n!");

    /* Below simulates the "shell" function in listener.c. Want to test
     * if select works here. */
    int conn_fd = openssl_get_fd(openssl_client);
    fd_set rd;
    unsigned char message[BUFSIZE] = {0};
    int len;

    while (strncmp((char *) message, "exit", 4) != 0) {
		FD_ZERO(&rd);

        FD_SET(0, &rd);
		FD_SET(conn_fd, &rd);

		if (select(conn_fd + 1, &rd, NULL, NULL, NULL) < 0) {
			perror("select");
			goto cleanup;
		}

		if (FD_ISSET(conn_fd, &rd)) {
			if (pel_recv_msg(openssl_client, message, &len) != PEL_SUCCESS) {
				fprintf(stderr, "pel_recv_msg: %s\n", pel_strerror(pel_errno));
                goto cleanup;
			}

            message[len] = '\0';
            printf("Recv(%d bytes): %s\n", len, (char *) message);
		}

        if (FD_ISSET(0, &rd)) {
			if ((len = read(0, message, BUFSIZE)) < 0) {
				perror("read");
				goto cleanup;
			}

            message[len] = '\0';

			if (len == 0) {
				fprintf(stderr, "stdin: end-of-file\n");
				goto cleanup;
			}

			if (pel_send_msg(openssl_client, message, len) != PEL_SUCCESS) {
				fprintf(stderr, "pel_send_msg: %s\n", pel_strerror(pel_errno));
				goto cleanup;
			}
		}
    }
cleanup:
    if (openssl_client) {
        openssl_ctx_delete(openssl_client);
    }
}
