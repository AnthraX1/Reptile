#include "pel_orig.h"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

/* Mimic the way reptile generates a client FD */
static int get_client_fd(const char *host, int port);

/* Usage: ./server <hostname> <port> */
int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: %s <hostname> <port>\n", argv[0]);
        return 0;
    }

    const char *hostname = argv[1];
    const char *port_str = argv[2];

    char *endptr = (char *) port_str;
    uint16_t port = (uint16_t) strtol(port_str, &endptr, 0);
    if (endptr == port_str) {
        fprintf(stderr, "Invalid port number\n");
        return -1;
    }

    int conn_fd = get_client_fd(hostname, port);
    if (conn_fd < 0) {
        return -1;
    }

    printf("Connected on FD %d\n\n", conn_fd);

    printf("Attempting PEL handshake...\n");
    if (pel_server_init(conn_fd, "s3cr3t") != PEL_SUCCESS) {
        fprintf(stderr, "pel_server_init: %d\n", pel_errno);
        goto cleanup;
    }

    printf("Init successful. Type to send a message\n!");

    /* Below simulates the "shell" function in listener.c. Want to test
     * if select works here. */
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
			if (pel_recv_msg(conn_fd, message, &len) != PEL_SUCCESS) {
				fprintf(stderr, "pel_recv_msg: %d\n", pel_errno);
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

			if (pel_send_msg(conn_fd, message, len) != PEL_SUCCESS) {
				fprintf(stderr, "pel_send_msg: %d\n", pel_errno);
				goto cleanup;
			}
		}
    }
cleanup:
    if (conn_fd >= 0) {
        close(conn_fd);
    }
}

static int get_client_fd(const char *host, int port) {
    int client = socket(PF_INET, SOCK_STREAM, 0);
    if (client < 0) {
        return -1;
    }

    struct hostent *client_host = gethostbyname(host);
    if (client_host == NULL) {
        perror("gethostbyname");
        close(client);
        return -1;
    }

    struct sockaddr_in client_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };
    memcpy(&client_addr.sin_addr, client_host->h_addr, client_host->h_length);

    if (connect(client, (struct sockaddr *) &client_addr, sizeof(client_addr)) < 0) {
        perror("connect");
        close(client);
        return -1;
    }

    return client;
}