/*
Fiche - terminal pastebin
Still in development, not usable!
*/

#include "fiche.h"

int main(int argc, char **argv)
{
    srand((unsigned int) time(0));

    set_basedir();
    parse_parameters(argc, argv);
    startup_message();

    int listen_socket, address_lenght, optval = 1;
    struct sockaddr_in server_address;

    listen_socket = create_socket();
    setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));

    server_address = set_address(server_address);
    bind_to_port(listen_socket, server_address);

    while (1) perform_connection(listen_socket);
}

void *thread_connection(void *args)
{
    char buffer[BUFSIZE];
    int n, client = *(int *)args;
    bzero(buffer, BUFSIZE);

    int status = recv(client, buffer, BUFSIZE, 0);

    if (status != -1)
    {
        char slug[SLUG_SIZE];
        generate_url(buffer, slug);

        char response[strlen(slug) + strlen(DOMAIN) + 2];
        strcpy(response, DOMAIN);
        strcat(response, slug);
        strcat(response, "/\n");
        write(client, response, strlen(response));
    }
    else
    {
        printf("Invalid connection.\n");
        write(client, "Use netcat.\n", 13);
    }
    
    close(client);
    pthread_exit(NULL);
    return NULL;
}

void perform_connection(int listen_socket)
{
    void *status = 0;
    pthread_t thread_id;
    struct sockaddr_in client_address;
    
    int address_lenght = sizeof(client_address);
    int connection_socket = accept(listen_socket, (struct sockaddr *) &client_address, &address_lenght);

    struct timeval timeout;      
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    if (setsockopt (connection_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
        error();
    if (setsockopt (connection_socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
        error();

    get_client_address(client_address);

    if (pthread_create(&thread_id, NULL, &thread_connection, &connection_socket) != 0)
        error();
    else
        pthread_detach(thread_id);

}

void display_date()
{
    time_t rawtime;
    struct tm *timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    printf("%s", asctime(timeinfo));
}

void get_client_address(struct sockaddr_in client_address)
{
    display_line();

    struct hostent *hostp;
    char *hostaddrp;

    hostp = gethostbyaddr((const char *)&client_address.sin_addr.s_addr, sizeof(client_address.sin_addr.s_addr), AF_INET);
    if (hostp == NULL) error();

    hostaddrp = inet_ntoa(client_address.sin_addr);
    if (hostaddrp == NULL) error();

    display_date();
    printf("Client: %s (%s)\n", hostaddrp, hostp->h_name);
}

int create_socket()
{
    int lsocket = socket(AF_INET, SOCK_STREAM, 0);
    if (lsocket < 0)
        error();
    else return lsocket;
}

struct sockaddr_in set_address(struct sockaddr_in server_address)
{
    bzero((char *) &server_address, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons((unsigned short)PORT);
    return server_address;
}

void bind_to_port(int listen_socket, struct sockaddr_in server_address)
{
    if (bind(listen_socket, (struct sockaddr *) &server_address, sizeof(server_address)) < 0) 
        error();
    if (listen(listen_socket, QUEUE_SIZE) < 0)
        error();
}

void generate_url(char *buffer, char *slug)
{
    int i;
    int time_seed = time(0);
    memset(slug, '\0', sizeof(slug));

    for (i = 0; i <= SLUG_SIZE - 1; i++)
    {
        int symbol_id = rand_r(&time_seed) % strlen(symbols);
        slug[i] = symbols[symbol_id];
    }

    while (create_directory(slug) == -1)
    {
        int symbol_id = rand() % strlen(symbols);
        slug[strlen(slug)] = symbols[symbol_id];
    }

    save_to_file(slug, buffer);
}

int create_directory(char *slug)
{
    char *directory = malloc(100);

    strcpy(directory, BASEDIR);
    strcat(directory, slug);

    mkdir(BASEDIR, S_IRWXU | S_IRGRP | S_IROTH);
    int result = mkdir(directory, S_IRWXU | S_IRGRP | S_IROTH);

    free(directory);

    return result;
}

void save_to_file(char *slug, char *buffer)
{
    char *directory = malloc(strlen(BASEDIR) + strlen(slug) + strlen("/index.html"));
    strcpy(directory, BASEDIR);
    strcat(directory, slug);
    strcat(directory, "/index.html");

    FILE *fp;
    fp = fopen(directory, "w");
    fprintf(fp, "%s", buffer);
    fclose(fp);

    printf("Saved to: %s\n", directory);
    free(directory);
}

void set_basedir()
{
    BASEDIR = getenv("HOME");
    strcat(BASEDIR, "/code/");
}

void startup_message()
{
    printf("Fiche started listening on port %d.\n", PORT);
    printf("Domain name: %s\n", DOMAIN);
    printf("Saving files to: %s\n", BASEDIR);
}

void parse_parameters(int argc, char **argv)
{
    int c;

    while ((c = getopt (argc, argv, "p:b:q:s:d:o:")) != -1)
        switch (c)
        {
            case 'd':
                snprintf(DOMAIN, sizeof DOMAIN, "%s%s%s", "http://", optarg, "/");
                break;
            case 'p':
                PORT = atoi(optarg);
                break;
            case 'b':
                BUFSIZE = atoi(optarg);
                printf("Buffer size set to: %d.\n", BUFSIZE);
                break;
            case 'q':
                QUEUE_SIZE = atoi(optarg);
                printf("Queue size set to: %d.\n", QUEUE_SIZE);
                break;
            case 's':
                SLUG_SIZE = atoi(optarg);
                printf("Slug size set to: %d.\n", SLUG_SIZE);
                break;
            case 'o':
                BASEDIR = optarg;
                if((BASEDIR[strlen(BASEDIR) - 1]) != '/')
                    strcat(BASEDIR, "/");
                break;
            default:
                printf("usage: fiche [-bdpqs].\n");
                printf("             [-d host_domain.com] [-p port] [-s slug_size]\n");
                printf("             [-o output_directory] [-b buffer_size] [-q queue_size]\n");
                exit(1);
        }
}