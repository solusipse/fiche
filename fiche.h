/*
Fiche - Command line pastebin for sharing terminal output.

-------------------------------------------------------------------------------

License: MIT (http://www.opensource.org/licenses/mit-license.php)
Repository: https://github.com/solusipse/fiche/
Live example: http://code.solusipse.net/

-------------------------------------------------------------------------------

usage: fiche [-pbsdolBuw].
             [-d domain] [-p port] [-s slug size]
             [-o output directory] [-B buffer size] [-u user name]
             [-l log file] [-b banlist] [-w whitelist]

Compile with Makefile or manually with -O2 and -pthread flags.
To install use `make install` command.

Use netcat to push text - example:

$ cat fiche.c | nc localhost 9999

-------------------------------------------------------------------------------
*/

#ifndef FICHE_H
#define FICHE_H

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
int PORT = 9999;
int SLUG_SIZE = 4;
int BUFSIZE = 32768;
int QUEUE_SIZE = 500;
char DOMAIN[128] = "http://localhost/";

unsigned int time_seed;
const char *symbols = "abcdefghijklmnopqrstuvwxyz0123456789";

struct thread_arguments
{
	int connection_socket;
	struct sockaddr_in client_address;
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
void display_line(){printf("====================================\n");}
void error(char *error_code){perror(error_code); exit(1);}
void display_date();
void perform_connection(int listen_socket);
void generate_url(char *buffer, char *slug, size_t slug_length, struct client_data data);
void save_to_file(char *buffer, char *slug, struct client_data data);
void display_info(struct client_data data, char *slug, char *message);
void startup_message();
void set_basedir();
void load_list(char *file_path, int type);
void parse_parameters(int argc, char **argv);
void save_log(char *slug, char *hostaddrp, char *h_name);
void change_owner(char *directory);
void set_uid_gid();

char *return_line(){return("\n====================================");}
char *check_banlist(char *ip_address);
char *check_whitelist(char *ip_address);
char *get_date();

struct sockaddr_in set_address(struct sockaddr_in serveraddr);
struct client_data get_client_address(struct sockaddr_in client_address);

#endif
