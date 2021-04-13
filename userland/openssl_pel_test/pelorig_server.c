#include "pel_orig.h"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

/* Mimic the way reptile generates a server FD */
static int get_server_fd(int port);

static int accept_client(int server_fd);

/* Usage: ./server <port> */
int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <port>\n", argv[0]);
        return 0;
    }

    const char *port_str = argv[1];

    char *endptr = (char *) port_str;
    uint16_t port = (uint16_t) strtol(port_str, &endptr, 0);
    if (endptr == port_str) {
        fprintf(stderr, "Invalid port number\n");
        return -1;
    }

    int server_fd = -1;
    int client_fd = -1;

    server_fd = get_server_fd(port);
    if (server_fd < 0) {
        return -1;
    }

    printf("Bound and listening on port %d\n", port);

    client_fd = accept_client(server_fd);
    if (client_fd < 0) {
        goto cleanup;
    }

    printf("Attempting PEL handshake...\n");
    if (pel_client_init(client_fd, "s3cr3t") != PEL_SUCCESS) {
        fprintf(stderr, "pel_client_init: %d\n", pel_errno);
        goto cleanup;
    }

    printf("Init successful. Type to send a message!\n");

    /* Below simulates the "shell" function in listener.c. Want to test
     * if select works here. */
    fd_set rd;
    unsigned char message[BUFSIZE] = {0};
    int len;

    while (strcmp((char *) message, "exit") != 0) {
		FD_ZERO(&rd);

        FD_SET(0, &rd);
		FD_SET(client_fd, &rd);

		if (select(client_fd + 1, &rd, NULL, NULL, NULL) < 0) {
			perror("select");
			goto cleanup;
		}

		if (FD_ISSET(client_fd, &rd)) {
			if (pel_recv_msg(client_fd, message, &len) != PEL_SUCCESS) {
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

			if (pel_send_msg(client_fd, message, len) != PEL_SUCCESS) {
				fprintf(stderr, "pel_send_msg: %d\n", pel_errno);
				goto cleanup;
			}
		}
    }

cleanup:
    if (client_fd >= 0) {
        close(client_fd);
    }

    if (server_fd >= 0) {
        close(server_fd);
    }
}

static int get_server_fd(int port) {
    int server = socket(PF_INET, SOCK_STREAM, 0);
    if (server < 0) {
        return -1;
    }

    if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int) {1}, sizeof(int)) < 0) {
        perror("setsockopt");
        close(server);
        return -1;
    }

    struct sockaddr_in host_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = {
            .s_addr = INADDR_ANY,
        },
        .sin_zero = {0},
    };

    if (bind(server, (struct sockaddr *) &host_addr, sizeof(struct sockaddr)) < 0) {
        perror("bind");
        close(server);
        return -1;
    }

    if (listen(server, 5) < 0) {
        perror("listen");
        close(server);
        return -1;
    }

    return server;
}

static int accept_client(int server_fd) {
    struct sockaddr_in client_addr = {0};
    socklen_t sin_size = 0;
    int client = accept(server_fd, (struct sockaddr *) &client_addr, &sin_size);
    if (client < 0) {
        perror("accept");
        return -1;
    }

	printf("Connection from %s:%d\n\n",
		inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    return client;
}
