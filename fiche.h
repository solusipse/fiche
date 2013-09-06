/*
Fiche - terminal pastebin
*/

#ifndef FICHE_H
#define FICHE_H

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <sys/stat.h>

int BUFSIZE = 8192;
int QUEUE_SIZE = 100;
int PORT = 9999;
int SLUG_SIZE = 4;
char *BASEDIR;
char DOMAIN[128] = "http://localhost/";
const char *symbols = "abcdefghijklmnopqrstuvwxyz0123456789";

int create_socket();
int create_directory(char *slug);

void bind_to_port(int listen_socket, struct sockaddr_in serveraddr);
void display_line(){printf("====================================\n");}
void error(){perror("ERROR"); exit(1);}
void display_date();
void get_client_address(struct sockaddr_in client_address);
void perform_connection(int listen_socket);
void generate_url(char *buffer, char *slug);
void save_to_file(char *buffer, char *slug);
void startup_message();
void set_basedir();
void parse_parameters(int argc, char **argv);

struct sockaddr_in set_address(struct sockaddr_in serveraddr);

#endif