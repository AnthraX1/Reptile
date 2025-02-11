#include "pel.h"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <termios.h>
#include <unistd.h>

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

    printf("Init successful. Type to send a message!\n");

    /* Below simulates the "shell" function in listener.c. Want to test
     * if select works here. */
    int conn_fd = openssl_get_fd(openssl_server);
    fd_set rd;
    unsigned char message[BUFSIZE] = {0};
    int len;

    while (strcmp((char *) message, "exit") != 0) {
		FD_ZERO(&rd);

        FD_SET(0, &rd);
		FD_SET(conn_fd, &rd);

		if (select(conn_fd + 1, &rd, NULL, NULL, NULL) < 0) {
			perror("select");
			goto cleanup;
		}

		if (FD_ISSET(conn_fd, &rd)) {
			if (pel_recv_msg(openssl_server, message, &len) != PEL_SUCCESS) {
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

			if (pel_send_msg(openssl_server, message, len) != PEL_SUCCESS) {
				fprintf(stderr, "pel_send_msg: %s\n", pel_strerror(pel_errno));
				goto cleanup;
			}
		}
    }

cleanup:
    if (openssl_server) {
        openssl_ctx_delete(openssl_server);
    }
}
