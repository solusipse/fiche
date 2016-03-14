/*
Fiche - Command line pastebin for sharing terminal output.

-------------------------------------------------------------------------------

License: MIT (http://www.opensource.org/licenses/mit-license.php)
Repository: https://github.com/solusipse/fiche/
Live example: http://code.solusipse.net/

-------------------------------------------------------------------------------

usage: fiche [-DepbsdolBuw].
             [-D] [-e] [-d domain] [-p port] [-s slug size]
             [-o output directory] [-B buffer size] [-u user name]
             [-l log file] [-b banlist] [-w whitelist]

-D option is for daemonizing fiche

-e option is for using an extended character set for the URL

Compile with Makefile or manually with -O2 and -pthread flags.
To install use `make install` command.

Use netcat to push text - example:

$ cat fiche.c | nc localhost 9999

-------------------------------------------------------------------------------
*/

#ifndef FICHE_H
#define FICHE_H

#ifndef HAVE_INET6
#define HAVE_INET6 1
#endif

#include <pwd.h>
#include <time.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

int UID = -1;
int GID = -1;
char *LOG;
char *BASEDIR;
char *BANLIST;
char *BANFILE;
char *WHITEFILE;
char *WHITELIST;
int DAEMON = 0;
int HTTPS = 0;
int PORT = 9999;
int IPv6 = 0;
int SLUG_SIZE = 4;
int BUFSIZE = 32768;
int QUEUE_SIZE = 500;
char DOMAIN[128] = "localhost/";
char symbols[67] = "abcdefghijklmnopqrstuvwxyz0123456789";

unsigned int time_seed;

struct thread_arguments
{
	int connection_socket;
	struct sockaddr_in client_address;
#if (HAVE_INET6)
	struct sockaddr_in6 client_address6;
#endif
};

struct client_data
{
	char *ip_address;
	char *hostname;
};

int create_socket();
int create_directory(char *slug);
int check_protocol(char *buffer);

void bind_to_port(int listen_socket, struct sockaddr_in serveraddr);
#if (HAVE_INET6)
void bind_to_port6(int listen_socket, struct sockaddr_in6 serveraddr6);
#endif
void error(char *buffer);
void perform_connection(int listen_socket);
void generate_url(char *buffer, char *slug, size_t slug_length, struct client_data data);
void save_to_file(char *buffer, char *slug, struct client_data data);
void display_info(struct client_data data, char *slug, char *message);
void startup_message();
void set_basedir();
void set_domain_name();
void load_list(char *file_path, int type);
void parse_parameters(int argc, char **argv);
void save_log(char *slug, char *hostaddrp, char *h_name);
void set_uid_gid();

char *check_banlist(char *ip_address);
char *check_whitelist(char *ip_address);
char *get_date();

struct sockaddr_in set_address(struct sockaddr_in serveraddr);
#if (HAVE_INET6)
struct sockaddr_in6 set_address6(struct sockaddr_in6 serveraddr6);
#endif
struct client_data get_client_address(struct sockaddr_in client_address);
#if (HAVE_INET6)
struct client_data get_client_address6(struct sockaddr_in6 client_address6);
#endif

#endif
