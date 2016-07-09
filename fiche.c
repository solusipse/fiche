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

#include <sys/param.h>
#include "fiche.h"

int main(int argc, char **argv)
{
    time_seed = time(0);

    parse_parameters(argc, argv);
    set_domain_name();

    if (getuid() == 0)
    {
        if (UID == -1)
            error("user not set");
        if (setgid(GID) != 0)
            error("Unable to drop group privileges");
        if (setuid(UID) != 0)
            error("Unable to drop user privileges");
    }

    if (BASEDIR == NULL)
        set_basedir();

    startup_message();

    int listen_socket, optval = 1;
    struct sockaddr_in server_address;

    listen_socket = create_socket();
    setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));

#if (HAVE_INET6)
    struct sockaddr_in6 server_address6;
    if (IPv6)
    {
        server_address6 = set_address6(server_address6);
        bind_to_port6(listen_socket, server_address6);
    }
    else
    {
#else
    if (1) {
#endif
        server_address = set_address(server_address);
        bind_to_port(listen_socket, server_address);
    }

    if (DAEMON)
    {
        pid_t pid;

        pid = fork();
        if (pid == -1)
            error("Failed to fork");
        if (pid == 0)
            while (1) perform_connection(listen_socket);
    }
    else
        while (1) perform_connection(listen_socket);

    return 0;
}

void *thread_connection(void *args)
{
    int connection_socket = ((struct thread_arguments *) args ) -> connection_socket;
    struct sockaddr_in client_address;
    struct client_data data;
#if (HAVE_INET6)
    struct sockaddr_in6 client_address6;
    if (IPv6)
    {
        client_address6 = ((struct thread_arguments *) args ) -> client_address6;
        data = get_client_address6(client_address6);
    }
    else
    {
#else
    if (1) {
#endif
        client_address = ((struct thread_arguments *) args ) -> client_address;
        data = get_client_address(client_address);
    }

    char buffer[BUFSIZE];
    bzero(buffer, BUFSIZE);
    int status = recv(connection_socket, buffer, BUFSIZE, MSG_WAITALL);

    if (WHITELIST != NULL && check_whitelist(data.ip_address) == NULL)
    {
        display_info(data, NULL, "Rejected connection from unknown user.");
        save_log(NULL, data.ip_address, data.hostname);
        if (write(connection_socket, "You are not whitelisted!\n", 26) < 0)
          printf("Error writing on stream socket\n");
        close(connection_socket);
        pthread_exit(NULL);
    }

    if (BANLIST != NULL && check_banlist(data.ip_address) != NULL)
    {
        display_info(data, NULL, "Rejected connection from banned user.");
        save_log(NULL, data.ip_address, data.hostname);
        if (write(connection_socket, "You are banned!\n", 17) < 0)
          printf("Error writing on stream socket\n");
        close(connection_socket);
        pthread_exit(NULL);
    }

    if (check_protocol(buffer) == 1)
        status = -1;

    if (status != -1)
    {
        char slug[SLUG_SIZE+8];
        generate_url(buffer, slug, SLUG_SIZE+8, data);
        save_log(slug, data.ip_address, data.hostname);
        char response[strlen(slug) + strlen(DOMAIN) + 2];
        snprintf(response, sizeof response, "%s%s\n", DOMAIN, slug);
        if (write(connection_socket, response, strlen(response)) < 0)
          printf("Error writing on stream socket\n");
    }
    else
    {
        display_info(data, NULL, "Invalid connection.");
        save_log(NULL, data.ip_address, data.hostname);
        if (write(connection_socket, "Use netcat.\n", 12) < 0)
          printf("Error writing on stream socket\n");
    }

    close(connection_socket);
    pthread_exit(NULL);
}

void perform_connection(int listen_socket)
{
    pthread_t thread_id;
    struct sockaddr_in client_address;

    int address_length;
    int connection_socket;

#if (HAVE_INET6)
    struct sockaddr_in6 client_address6;
    if (IPv6)
    {
        address_length = sizeof(client_address6);
        connection_socket = accept(listen_socket, (struct sockaddr *) &client_address6, (void *) &address_length);
    }
    else
    {
#else
    if (1) {
#endif
        address_length = sizeof(client_address);
        connection_socket = accept(listen_socket, (struct sockaddr *) &client_address, (void *) &address_length);
    }

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    if (setsockopt (connection_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
        error("while setting setsockopt timeout");
    if (setsockopt (connection_socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
        error("while setting setsockopt timeout");

    struct thread_arguments arguments;
    arguments.connection_socket = connection_socket;
#if (HAVE_INET6)
    if (IPv6)
        arguments.client_address6 = client_address6;
    else
#endif
        arguments.client_address = client_address;

    if (pthread_create(&thread_id, NULL, &thread_connection, &arguments) != 0)
        error("on thread creation");
    else
        pthread_detach(thread_id);
}

char *get_date()
{
    time_t rawtime;
    struct tm *timeinfo;
    char *timechar;

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    timechar = asctime(timeinfo);
    timechar[strlen(timechar)-1] = 0;

    return timechar;
}

struct client_data get_client_address(struct sockaddr_in client_address)
{
    struct hostent *hostp;
    struct client_data data;
    char *hostaddrp;

    hostp = gethostbyaddr((const char *)&client_address.sin_addr.s_addr, sizeof(client_address.sin_addr.s_addr), AF_INET);
    if (hostp == NULL)
    {
        printf("WARNING: Couldn't obtain client's hostname\n");
        data.hostname = "n/a";
    }
    else
        data.hostname = hostp->h_name;

    hostaddrp = inet_ntoa(client_address.sin_addr);
    if (hostaddrp == NULL)
    {
        printf("WARNING: Couldn't obtain client's address\n");
        data.ip_address = "n/a";
    }
    else
        data.ip_address = hostaddrp;

    return data;
}

#if (HAVE_INET6)
struct client_data get_client_address6(struct sockaddr_in6 client_address6)
{
    struct hostent *hostp;
    struct client_data data;
    static char hostaddrp[INET6_ADDRSTRLEN];

    hostp = gethostbyaddr((const char *)&client_address6.sin6_addr, sizeof(client_address6.sin6_addr), AF_INET6);
    if (hostp == NULL)
    {
        printf("WARNING: Couldn't obtain client's hostname\n");
        data.hostname = "n/a";
    }
    else
        data.hostname = hostp->h_name;

    inet_ntop(AF_INET6, &(client_address6.sin6_addr), hostaddrp,
              INET6_ADDRSTRLEN);
    if (hostaddrp == NULL)
    {
        printf("WARNING: Couldn't obtain client's address\n");
        data.ip_address = "n/a";
    }
    else
        data.ip_address = hostaddrp;

    return data;
}
#endif

void save_log(char *slug, char *hostaddrp, char *h_name)
{
    if (LOG != NULL)
    {
        char contents[256];

        if (slug != NULL)
            snprintf(contents, sizeof contents, "%s -- %s -- %s (%s)\n", slug, get_date(), hostaddrp, h_name);
        else
            snprintf(contents, sizeof contents, "%s -- %s -- %s (%s)\n", "rej", get_date(), hostaddrp, h_name);

        FILE *fp;
        fp = fopen(LOG, "a");
        fprintf(fp, "%s", contents);
        fclose(fp);
    }
}

void display_info(struct client_data data, char *slug, char *message)
{
    if (DAEMON)
        return;

    if (slug == NULL)
        printf("%s\n", message);
    else
        printf("Saved to: %s\n", slug);

    printf("%s\n", get_date());
    printf("Client: %s (%s)\n", data.ip_address, data.hostname);
    printf("====================================\n");
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
    FILE *fp;
    
    if (( fp = fopen(file_path, "r")) == NULL )
      error("cannot load list");
    
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *buffer = malloc(fsize + 1);
    if (fread(buffer, fsize, 1, fp) != fsize)
      error("reading list failed");
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
    int lsocket;
#if (HAVE_INET6)
    if (IPv6)
        lsocket = socket(AF_INET6, SOCK_STREAM, 0);
    else
#endif
        lsocket = socket(AF_INET, SOCK_STREAM, 0);

    if (lsocket < 0)
        error("Couldn't open socket");

    return lsocket;
}

struct sockaddr_in set_address(struct sockaddr_in server_address)
{
    bzero((char *) &server_address, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons((unsigned short)PORT);
    return server_address;
}

#if (HAVE_INET6)
struct sockaddr_in6 set_address6(struct sockaddr_in6 server_address6)
{
    bzero((char *) &server_address6, sizeof(server_address6));
    server_address6.sin6_family = AF_INET6;
    server_address6.sin6_addr = in6addr_any;
    server_address6.sin6_port = htons((unsigned short)PORT);
    return server_address6;
}
#endif

void bind_to_port(int listen_socket, struct sockaddr_in server_address)
{
    if (bind(listen_socket, (struct sockaddr *) &server_address, sizeof(server_address)) < 0) 
        error("while binding to port");
    if (listen(listen_socket, QUEUE_SIZE) < 0)
        error("while starting listening");
}

#if (HAVE_INET6)
void bind_to_port6(int listen_socket, struct sockaddr_in6 server_address6)
{
    if (bind(listen_socket, (struct sockaddr *) &server_address6, sizeof(server_address6)) < 0) 
        error("while binding to port");
    if (listen(listen_socket, QUEUE_SIZE) < 0)
        error("while starting listening");
}
#endif

void generate_url(char *buffer, char *slug, size_t slug_length, struct client_data data)
{
    int i;
    memset(slug, '\0', slug_length);

    for (i = 0; i <= SLUG_SIZE - 1; i++)
    {
#if defined(BSD)
	int symbol_id = arc4random() % strlen(symbols);
#else
        int symbol_id = rand_r(&time_seed) % strlen(symbols);
#endif
        slug[i] = symbols[symbol_id];
    }

    while (create_directory(slug) == -1)
    {
#if defined(BSD)
	int symbol_id = arc4random() % strlen(symbols);
#else
        int symbol_id = rand_r(&time_seed) % strlen(symbols);
#endif
        slug[strlen(slug)] = symbols[symbol_id];
    }

    save_to_file(slug, buffer, data);
}

int create_directory(char *slug)
{
    char *directory = malloc(strlen(BASEDIR) + strlen(slug) + sizeof(char) + 1);

    snprintf(directory, strlen(BASEDIR) + strlen(slug) + sizeof(char) + 1, "%s%s%s", BASEDIR, "/", slug);

    mkdir(BASEDIR, S_IRWXU | S_IRGRP | S_IROTH | S_IXOTH | S_IXGRP);
    int result = mkdir(directory, S_IRWXU | S_IRGRP | S_IROTH | S_IXOTH | S_IXGRP);

    free(directory);

    return result;
}

void save_to_file(char *slug, char *buffer, struct client_data data)
{
    char *directory = malloc(strlen(BASEDIR) + strlen(slug) + 11 * sizeof(char) + 1 );

    snprintf(directory, strlen(BASEDIR) + strlen(slug) + 11 * sizeof(char) + 1, "%s%s%s%s", BASEDIR , "/", slug, "/index.txt");

    FILE *fp;
    fp = fopen(directory, "w");
    fprintf(fp, "%s", buffer);
    fclose(fp);

    display_info(data, directory, "");

    free(directory);
}

void set_uid_gid(char *username)
{
    struct passwd *userdata = getpwnam(username);
    if (userdata == NULL)
        error("Provided user doesn't exist");

    UID = userdata->pw_uid;
    GID = userdata->pw_gid;
}

int check_protocol(char *buffer)
{
    if (strlen(buffer) < 3)
        return 1;
    if ((strncmp(buffer, "GET", 3) == 0)||(strncmp(buffer, "POST", 4) == 0))
        if (strstr(buffer, "HTTP/1."))
            return 1;
    return 0;
}

void set_basedir()
{
    BASEDIR = getenv("HOME");
    strncat(BASEDIR, "/code", 5 * sizeof(char));
}

void startup_message()
{
    if (DAEMON)
        return;

    printf("====================================\n");
    printf("Domain name: %s\n", DOMAIN);
    printf("Saving files to: %s\n", BASEDIR);
    printf("Fiche started listening on port %d.\n", PORT);
    printf("Buffer size set to: %d.\n", BUFSIZE);
    printf("Slug size set to: %d.\n", SLUG_SIZE);
    printf("Log file: %s\n", LOG);
    printf("====================================\n");
}

void error(char *buffer)
{
    printf("Error: %s\n", buffer);
    exit(1);
}

void set_domain_name() {
    char b[128];
    memcpy(b, DOMAIN, sizeof DOMAIN);

    if (HTTPS)
        snprintf(DOMAIN, sizeof DOMAIN, "%s%s", "https://", b);
    else
        snprintf(DOMAIN, sizeof DOMAIN, "%s%s", "http://", b);
}

void parse_parameters(int argc, char **argv)
{
    int c;

    while ((c = getopt (argc, argv, "D6eSp:b:s:d:o:l:B:u:w:")) != -1)
        switch (c)
        {
            case 'D':
                DAEMON = 1;
                break;
            case '6':
                IPv6 = 1;
                break;
            case 'e':
                snprintf(symbols, sizeof symbols, "%s", "abcdefghijklmnopqrstuvwxyz0123456789-+_=.ABCDEFGHIJKLMNOPQRSTUVWXYZ");
                break;
            case 'S':
                HTTPS = 1;
                break;
            case 'd':
                snprintf(DOMAIN, sizeof DOMAIN, "%s%s", optarg, "/");
                break;
            case 'p':
                PORT = atoi(optarg);
                break;
            case 'B':
                BUFSIZE = atoi(optarg);
                break;
            case 'b':
                BANFILE = optarg;
                load_list(BANFILE, 0);
                break;
            case 's':
                SLUG_SIZE = atoi(optarg);
                break;
            case 'o':
                BASEDIR = optarg;
                break;
            case 'l':
                LOG = optarg;
                break;
            case 'u':
                set_uid_gid(optarg);
                break;
            case 'w':
                WHITEFILE = optarg;
                load_list(WHITEFILE, 1);
                break;
            default:
                printf("usage: fiche [-D6epbsdSolBuw].\n");
                printf("                     [-d domain] [-p port] [-s slug_size]\n");
                printf("                     [-o output directory] [-B buffer_size] [-u user name]\n");
                printf("                     [-l log file] [-b banlist] [-w whitelist]\n");
                exit(1);
        }
}
