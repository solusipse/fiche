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

#include "fiche.h"

int main(int argc, char **argv)
{
    time_seed = time(0);

    parse_parameters(argc, argv);
    if (BASEDIR == NULL)
        set_basedir();
    
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
    int connection_socket = ((struct thread_arguments *) args ) -> connection_socket;
    struct sockaddr_in client_address = ((struct thread_arguments *) args ) -> client_address;

    struct client_data data = get_client_address(client_address);

    int n;
    char buffer[BUFSIZE];
    bzero(buffer, BUFSIZE);
    int status = recv(connection_socket, buffer, BUFSIZE, MSG_WAITALL);

    if (WHITELIST != NULL)
        if (check_whitelist(data.ip_address) == NULL)
        {
            printf("Rejected connection from unknown user.\n");
            display_line();
            save_log(NULL, data.ip_address, data.hostname);
            write(connection_socket, "You are not whitelisted!\n", 17);
            close(connection_socket);
            pthread_exit(NULL);
        }

    if ((BANLIST != NULL))
        if (check_banlist(data.ip_address) != NULL)
        {
            printf("Rejected connection from banned user.\n");
            display_line();
            save_log(NULL, data.ip_address, data.hostname);
            write(connection_socket, "You are banned!\n", 17);
            close(connection_socket);
            pthread_exit(NULL);
        }

    if (status != -1)
    {
        char slug[SLUG_SIZE];
        generate_url(buffer, slug);
        save_log(slug, data.ip_address, data.hostname);
        char response[strlen(slug) + strlen(DOMAIN) + 2];
        snprintf(response, sizeof response, "%s%s\n", DOMAIN, slug);
        write(connection_socket, response, strlen(response));
    }
    else
    {
        printf("Invalid connection.\n");
        display_line();
        save_log(NULL, data.ip_address, data.hostname);
        write(connection_socket, "Use netcat.\n", 13);
    }

    close(connection_socket);
    pthread_exit(NULL);
}

void perform_connection(int listen_socket)
{
    void *status = 0;
    pthread_t thread_id;
    struct sockaddr_in client_address;
    
    int address_lenght = sizeof(client_address);
    int connection_socket = accept(listen_socket, (struct sockaddr *) &client_address, (void *) &address_lenght);

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    if (setsockopt (connection_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
        error("ERROR while setting setsockopt timeout");
    if (setsockopt (connection_socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
        error("ERROR while setting setsockopt timeout");

    struct thread_arguments arguments;
    arguments.connection_socket = connection_socket;
    arguments.client_address = client_address;

    if (pthread_create(&thread_id, NULL, &thread_connection, &arguments) != 0)
        error("ERROR on thread creation");
    else
        pthread_detach(thread_id);
}

void display_date()
{
    printf("%s", get_date());
}

char *get_date()
{
    time_t rawtime;
    struct tm *timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    return asctime(timeinfo);
}

struct client_data get_client_address(struct sockaddr_in client_address)
{
    struct hostent *hostp;
    struct client_data data;
    char *hostaddrp;

    hostp = gethostbyaddr((const char *)&client_address.sin_addr.s_addr, sizeof(client_address.sin_addr.s_addr), AF_INET);
    if (hostp == NULL)
    {
        /*nerror("ERROR: Couldn't obtain client's hostname");*/
        printf("ERROR: Couldn't obtain client's hostname");
        data.hostname = "error";
    }
    else
        data.hostname = hostp->h_name;

    hostaddrp = inet_ntoa(client_address.sin_addr);
    if (hostaddrp == NULL)
    {
        nerror("ERROR: Couldn't obtain client's address");
        data.ip_address = "error";
    }
    else
        data.ip_address = hostaddrp;

    display_date();
    printf("Client: %s (%s)\n", data.ip_address, data.hostname);

    

    return data;
}

void save_log(char *slug, char *hostaddrp, char *h_name)
{
    if (LOG != NULL)
    {
        char contents[256];

        if (slug != NULL)
            snprintf(contents, sizeof contents, "\n%s%s|%s|%s%s", get_date(), slug, hostaddrp, h_name, return_line());
        else
            snprintf(contents, sizeof contents, "\n%s%s|%s|%s%s", get_date(), "rejected", hostaddrp, h_name, return_line());

        FILE *fp;
        fp = fopen(LOG, "a");
        fprintf(fp, "%s", contents);
        fclose(fp);
    }
}

char *check_banlist(char *ip_address)
{
    load_list(BANFILE, 0);
    return strstr(BANLIST, ip_address);
}

char *check_whitelist(char *ip_address)
{
    load_list(WHITEFILE, 1);
    return strstr(WHITELIST, ip_address);
}

void load_list(char *file_path, int type)
{
    FILE *fp = fopen(file_path, "r");
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *buffer = malloc(fsize + 1);
    fread(buffer, fsize, 1, fp);
    fclose(fp);

    buffer[fsize] = 0;

    if (type == 0)
        BANLIST = buffer;
    else
        WHITELIST = buffer;

    free(buffer);
}

int create_socket()
{
    int lsocket = socket(AF_INET, SOCK_STREAM, 0);
    if (lsocket < 0)
        error("ERROR: Couldn't open socket");
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
        error("ERROR while binding to port");
    if (listen(listen_socket, QUEUE_SIZE) < 0)
        error("ERROR while starting listening");
}

void generate_url(char *buffer, char *slug)
{
    int i;
    memset(slug, '\0', sizeof(slug));

    for (i = 0; i <= SLUG_SIZE - 1; i++)
    {
        int symbol_id = rand_r(&time_seed) % strlen(symbols);
        slug[i] = symbols[symbol_id];
    }

    while (create_directory(slug) == -1)
    {
        int symbol_id = rand_r(&time_seed) % strlen(symbols);
        slug[strlen(slug)] = symbols[symbol_id];
    }

    save_to_file(slug, buffer);
}

int create_directory(char *slug)
{
    char *directory = malloc(strlen(BASEDIR) + strlen(slug));

    strcpy(directory, BASEDIR);
    strcat(directory, slug);

    mkdir(BASEDIR, S_IRWXU | S_IRGRP | S_IROTH | S_IXOTH | S_IXGRP);
    int result = mkdir(directory, S_IRWXU | S_IRGRP | S_IROTH | S_IXOTH | S_IXGRP);

    change_owner(directory);

    free(directory);

    return result;
}

void save_to_file(char *slug, char *buffer)
{
    char *directory = malloc(strlen(BASEDIR) + strlen(slug) + strlen("/index.txt"));
    strcpy(directory, BASEDIR);
    strcat(directory, slug);
    strcat(directory, "/index.txt");

    FILE *fp;
    fp = fopen(directory, "w");
    fprintf(fp, "%s", buffer);
    fclose(fp);

    change_owner(directory);

    printf("Saved to: %s\n", directory);
    display_line();
    free(directory);
}

void change_owner(char *directory)
{
    if ((UID != -1)&&(GID != -1))
    chown(directory, UID, GID);
}

void set_uid_gid(char *username)
{
    struct passwd *userdata = getpwnam(username);
    if (userdata == NULL)
        error("Provided user doesn't exist");

    UID = userdata->pw_uid;
    GID = userdata->pw_gid;
}

void set_basedir()
{
    BASEDIR = getenv("HOME");
    strcat(BASEDIR, "/code/");
}

void startup_message()
{
    display_line();
    printf("Domain name: %s\n", DOMAIN);
    printf("Saving files to: %s\n", BASEDIR);
    printf("Fiche started listening on port %d.\n", PORT);
    display_line();
}

void parse_parameters(int argc, char **argv)
{
    int c;

    while ((c = getopt (argc, argv, "p:b:s:d:o:l:B:u:w:")) != -1)
        switch (c)
        {
            case 'd':
                snprintf(DOMAIN, sizeof DOMAIN, "%s%s%s", "http://", optarg, "/");
                break;
            case 'p':
                PORT = atoi(optarg);
                break;
            case 'B':
                BUFSIZE = atoi(optarg);
                printf("Buffer size set to: %d.\n", BUFSIZE);
                break;
            case 'b':
                BANFILE = optarg;
                load_list(BANFILE, 0);
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
            case 'l':
                LOG = optarg;
                printf("Log file: %s\n", LOG);
                break;
            case 'u':
                set_uid_gid(optarg);
                break;
            case 'w':
                WHITEFILE = optarg;
                load_list(WHITEFILE, 1);
                break;
            default:
                printf("usage: fiche [-pbsdolBuw].\n");
                printf("                     [-d domain] [-p port] [-s slug_size]\n");
                printf("                     [-o output directory] [-B buffer_size] [-u user name]\n");
                printf("                     [-l log file] [-b banlist] [-w whitelist]\n");
                exit(1);
        }
}