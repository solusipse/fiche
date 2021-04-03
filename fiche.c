/*
Fiche - Command line pastebin for sharing terminal output.

-------------------------------------------------------------------------------

License: MIT (http://www.opensource.org/licenses/mit-license.php)
Repository: https://github.com/solusipse/fiche/
Live example: http://termbin.com

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

#include "fiche.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <pwd.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include <fcntl.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in.h>


/******************************************************************************
 * Various declarations
 */
const char *Fiche_Symbols = "abcdefghijklmnopqrstuvwxyz0123456789";


/******************************************************************************
 * Inner structs
 */

struct fiche_connection {
    int socket;
    struct sockaddr_in address;

    Fiche_Settings *settings;
};


/******************************************************************************
 * Static function declarations
 */

// Settings-related

/**
 * @brief Sets domain name
 * @warning settings.domain has to be freed after using this function!
 */
static int set_domain_name(Fiche_Settings *settings);

/**
 * @brief Changes user running this program to requested one
 * @warning Application has to be run as root to use this function
 */
static int perform_user_change(const Fiche_Settings *settings);


// Server-related

/**
 * @brief Starts server with settings provided in Fiche_Settings struct
 */
static int start_server(Fiche_Settings *settings);

/**
 * @brief Dispatches incoming connections by spawning threads
 */
static void dispatch_connection(int socket, Fiche_Settings *settings);

/**
 * @brief Handles connections
 * @remarks Is being run by dispatch_connection in separate threads
 * @arg args Struct fiche_connection containing connection details
 */
static void *handle_connection(void *args);

// Server-related utils


/**
 * @brief Generates a slug that will be used for paste creation
 * @warning output has to be freed after using!
 *
 * @arg output pointer to output string containing full path to directory
 * @arg length default or user-requested length of a slug
 * @arg extra_length additional length that was added to speed-up the
 *      generation process
 *
 * This function is used in connection with create_directory function
 * It generates strings that are used to create a directory for
 * user-provided data. If directory already exists, we ask this function
 * to generate another slug with increased size.
 */
static void generate_slug(char **output, uint8_t length, uint8_t extra_length);


/**
 * @brief Creates a directory at requested path using requested slug
 * @returns 0 if succeded, 1 if failed or dir already existed
 *
 * @arg output_dir root directory for all pastes
 * @arg slug directory name for a particular paste
 */
static int create_directory(char *output_dir, char *slug);


/**
 * @brief Saves data to file at requested path
 *
 * @arg data Buffer with data received from the user
 * @arg path Path at which file containing data from the buffer will be created
 */
static int save_to_file(const Fiche_Settings *s, uint8_t *data, char *slug);


// Logging-related

/**
 * @brief Displays error messages
 */
static void print_error(const char *format, ...);


/**
 * @brief Displays status messages
 */
static void print_status(const char *format, ...);


/**
 * @brief Displays horizontal line
 */
static void print_separator();


/**
 * @brief Saves connection entry to the logfile
 */
static void log_entry(const Fiche_Settings *s, const char *ip,
        const char *hostname, const char *slug);


/**
 * @brief Returns string containing current date
 * @warning Output has to be freed!
 */
static void get_date(char *buf);


/**
 * @brief Time seed
 */
unsigned int seed;

/******************************************************************************
 * Public fiche functions
 */

void fiche_init(Fiche_Settings *settings) {

    // Initialize everything to default values
    // or to NULL in case of pointers

    struct Fiche_Settings def = {
        // domain
        "example.com",
        // output dir
        "code",
	// listen_addr
	"0.0.0.0",
        // port
        9999,
        // slug length
        4,
        // https
        false,
        // buffer length
        32768,
        // user name
        NULL,
        // path to log file
        NULL,
        // path to banlist
        NULL,
        // path to whitelist
        NULL
    };

    // Copy default settings to provided instance
    *settings = def;
}

int fiche_run(Fiche_Settings settings) {

    seed = time(NULL);

    // Display welcome message
    {
        char date[64];
        get_date(date);
        print_status("Starting fiche on %s...", date);
    }

    // Try to set requested user
    if ( perform_user_change(&settings) != 0) {
        print_error("Was not able to change the user!");
        return -1;
    }

    // Check if output directory is writable
    // - First we try to create it
    {
        mkdir(
            settings.output_dir_path,
            S_IRWXU | S_IRGRP | S_IROTH | S_IXOTH | S_IXGRP
        );
        // - Then we check if we can write there
        if ( access(settings.output_dir_path, W_OK) != 0 ) {
            print_error("Output directory not writable!");
            return -1;
        }
    }

    // Check if log file is writable (if set)
    if ( settings.log_file_path ) {

        // Create log file if it doesn't exist
        FILE *f = fopen(settings.log_file_path, "a+");
        fclose(f);

        // Then check if it's accessible
        if ( access(settings.log_file_path, W_OK) != 0 ) {
            print_error("Log file not writable!");
            return -1;
        }

    }

    // Try to set domain name
    if ( set_domain_name(&settings) != 0 ) {
        print_error("Was not able to set domain name!");
        return -1;
    }

    // Main loop in this method
    start_server(&settings);

    // Perform final cleanup

    // This is allways allocated on the heap
    free(settings.domain);

    return 0;

}


/******************************************************************************
 * Static functions below
 */

static void print_error(const char *format, ...) {
    va_list args;
    va_start(args, format);

    printf("[Fiche][ERROR] ");
    vprintf(format, args);
    printf("\n");

    va_end(args);
}


static void print_status(const char *format, ...) {
    va_list args;
    va_start(args, format);

    printf("[Fiche][STATUS] ");
    vprintf(format, args);
    printf("\n");

    va_end(args);
}


static void print_separator() {
    printf("============================================================\n");
}


static void log_entry(const Fiche_Settings *s, const char *ip,
    const char *hostname, const char *slug)
{
    // Logging to file not enabled, finish here
    if (!s->log_file_path) {
        return;
    }

    FILE *f = fopen(s->log_file_path, "a");
    if (!f) {
        print_status("Was not able to save entry to the log!");
        return;
    }

    char date[64];
    get_date(date);

    // Write entry to file
    fprintf(f, "%s -- %s -- %s (%s)\n", slug, date, ip, hostname);
    fclose(f);
}


static void get_date(char *buf) {
    struct tm curtime;
    time_t ltime;

    ltime=time(&ltime);
    localtime_r(&ltime, &curtime);

    // Save data to provided buffer
    if (asctime_r(&curtime, buf) == 0) {
        // Couldn't get date, setting first byte of the
        // buffer to zero so it won't be displayed
        buf[0] = 0;
        return;
    }

    // Remove newline char
    buf[strlen(buf)-1] = 0;
}


static int set_domain_name(Fiche_Settings *settings) {

    char *prefix = "";
    if (settings->https) {
        prefix = "https://";
    } else {
        prefix = "http://";
    }
    const int len = strlen(settings->domain) + strlen(prefix) + 1;

    char *b = malloc(len);
    if (!b) {
        return -1;
    }

    strcpy(b, prefix);
    strcat(b, settings->domain);

    settings->domain = b;

    print_status("Domain set to: %s.", settings->domain);

    return 0;
}


static int perform_user_change(const Fiche_Settings *settings) {

    // User change wasn't requested, finish here
    if (settings->user_name == NULL) {
        return 0;
    }

    // Check if root, if not - finish here
    if (getuid() != 0) {
        print_error("Run as root if you want to change the user!");
        return -1;
    }

    // Get user details
    const struct passwd *userdata = getpwnam(settings->user_name);

    const int uid = userdata->pw_uid;
    const int gid = userdata->pw_gid;

    if (uid == -1 || gid == -1) {
        print_error("Could find requested user: %s!", settings->user_name);
        return -1;
    }

    if (setgid(gid) != 0) {
        print_error("Couldn't switch to requested user: %s!", settings->user_name);
    }

    if (setuid(uid) != 0) {
        print_error("Couldn't switch to requested user: %s!", settings->user_name);
    }

    print_status("User changed to: %s.", settings->user_name);

    return 0;
}


static int start_server(Fiche_Settings *settings) {

    // Perform socket creation
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        print_error("Couldn't create a socket!");
        return -1;
    }

    // Set socket settings
    if ( setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 } , sizeof(int)) != 0 ) {
        print_error("Couldn't prepare the socket!");
        return -1;
    }

    // Prepare address and port handler
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(settings->listen_addr);
    address.sin_port = htons(settings->port);

    // Bind to port
    if ( bind(s, (struct sockaddr *) &address, sizeof(address)) != 0) {
        print_error("Couldn't bind to the port: %d!", settings->port);
        return -1;
    }

    // Start listening
    if ( listen(s, 128) != 0 ) {
        print_error("Couldn't start listening on the socket!");
        return -1;
    }

    print_status("Server started listening on: %s:%d.",
		    settings->listen_addr, settings->port);
    print_separator();

    // Run dispatching loop
    while (1) {
        dispatch_connection(s, settings);
    }

    // Give some time for all threads to finish
    // NOTE: this code is reached only in testing environment
    // There is currently no way to kill the main thread from any thread
    // Something like this can be done for testing purpouses:
    // int i = 0;
    // while (i < 3) {
    //     dispatch_connection(s, settings);
    //     i++;
    // }

    sleep(5);

    return 0;
}


static void dispatch_connection(int socket, Fiche_Settings *settings) {

    // Create address structs for this socket
    struct sockaddr_in address;
    socklen_t addlen = sizeof(address);

    // Accept a connection and get a new socket id
    const int s = accept(socket, (struct sockaddr *) &address, &addlen);
    if (s < 0 ) {
        print_error("Error on accepting connection!");
        return;
    }

    // Set timeout for accepted socket
    const struct timeval timeout = { 5, 0 };

    if ( setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ) {
        print_error("Couldn't set a timeout!");
    }

    if ( setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0 ) {
        print_error("Couldn't set a timeout!");
    }

    // Create an argument for the thread function
    struct fiche_connection *c = malloc(sizeof(*c));
    if (!c) {
        print_error("Couldn't allocate memory!");
        return;
    }
    c->socket = s;
    c->address = address;
    c->settings = settings;

    // Spawn a new thread to handle this connection
    pthread_t id;

    if ( pthread_create(&id, NULL, &handle_connection, c) != 0 ) {
        print_error("Couldn't spawn a thread!");
        return;
    }

    // Detach thread if created succesfully
    // TODO: consider using pthread_tryjoin_np
    pthread_detach(id);

}


static void *handle_connection(void *args) {
    char *slug = NULL;

    // Cast args to it's previous type
    struct fiche_connection *c = (struct fiche_connection *) args;

    // Get client's IP
    const char *ip = inet_ntoa(c->address.sin_addr);

    // Get client's hostname
    char hostname[1024];

    if (getnameinfo((struct sockaddr *)&c->address, sizeof(c->address),
            hostname, sizeof(hostname), NULL, 0, 0) != 0 ) {

        // Couldn't resolve a hostname
        strcpy(hostname, "n/a");
    }

    // Print status on this connection
    {
        char date[64];
        get_date(date);
        print_status("%s", date);

        print_status("Incoming connection from: %s (%s).", ip, hostname);
    }

    // Create a buffer
    uint8_t buffer[c->settings->buffer_len];
    memset(buffer, 0, c->settings->buffer_len);

    const int r = recv(c->socket, buffer, sizeof(buffer), MSG_WAITALL);
    if (r <= 0) {
        print_error("No data received from the client!");
        print_separator();

        goto exit;
    }

    // - Check if request was performed with a known protocol
    // TODO

    // - Check if on whitelist
    // TODO

    // - Check if on banlist
    // TODO

    // Generate slug and use it to create an url
    uint8_t extra = 0;

    do {

        // Generate slugs until it's possible to create a directory
        // with generated slug on disk
        generate_slug(&slug, c->settings->slug_len, extra);

        // Something went wrong in slug generation, break here
        if (!slug) {
            break;
        }

        // Increment counter for additional letters needed
        ++extra;

        // If i was incremented more than 128 times, something
        // for sure went wrong. We are closing connection and
        // killing this thread in such case
        if (extra > 128) {
            print_error("Couldn't generate a valid slug!");
            print_separator();

            goto exit;
        }

    }
    while(create_directory(c->settings->output_dir_path, slug) != 0);


    // Slug generation failed, we have to finish here
    if (!slug) {
        print_error("Couldn't generate a slug!");
        print_separator();

        goto exit;
    }


    // Save to file failed, we have to finish here
    if ( save_to_file(c->settings, buffer, slug) != 0 ) {
        print_error("Couldn't save a file!");
        print_separator();

        goto exit;
    }

    // Write a response to the user
    {
        // Create an url (additional byte for slash and one for new line)
        const size_t len = strlen(c->settings->domain) + strlen(slug) + 3;

        char url[len];
        snprintf(url, len, "%s%s%s%s", c->settings->domain, "/", slug, "\n");

        // Send the response
        write(c->socket, url, len);
    }

    print_status("Received %d bytes, saved to: %s.", r, slug);
    print_separator();

    // Log connection
    // TODO: log unsuccessful and rejected connections
    log_entry(c->settings, ip, hostname, slug);

exit:
    // Close the connection
    close(c->socket);

    // Perform cleanup of values used in this thread
    free(slug);
    free(c);

    pthread_exit(NULL);

    return NULL;
}


static void generate_slug(char **output, uint8_t length, uint8_t extra_length) {

    // Realloc buffer for slug when we want it to be bigger
    // This happens in case when directory with this name already
    // exists. To save time, we don't generate new slugs until
    // we spot an available one. We add another letter instead.

    if (extra_length > 0) {
        free(*output);
    }

    // Create a buffer for slug with extra_length if any
    *output = calloc(length + 1 + extra_length, sizeof(char));

    if (*output == NULL) {
        return;
    }

    // Take n-th symbol from symbol table and use it for slug generation
    for (int i = 0; i < length + extra_length; i++) {
        int n = rand_r(&seed) % strlen(Fiche_Symbols);
        *(output[0] + sizeof(char) * i) = Fiche_Symbols[n];
    }

}


static int create_directory(char *output_dir, char *slug) {
    if (!slug) {
        return -1;
    }

    // Additional byte is for the slash
    size_t len = strlen(output_dir) + strlen(slug) + 2;

    // Generate a path
    char *path = malloc(len);
    if (!path) {
        return -1;
    }
    snprintf(path, len, "%s%s%s", output_dir, "/", slug);

    // Create output directory, just in case
    mkdir(output_dir, S_IRWXU | S_IRGRP | S_IROTH | S_IXOTH | S_IXGRP);

    // Create slug directory
    const int r = mkdir(
        path,
        S_IRWXU | S_IRGRP | S_IROTH | S_IXOTH | S_IXGRP
    );

    free(path);

    return r;
}


static int save_to_file(const Fiche_Settings *s, uint8_t *data, char *slug) {
    char *file_name = "index.txt";

    // Additional 2 bytes are for 2 slashes
    size_t len = strlen(s->output_dir_path) + strlen(slug) + strlen(file_name) + 3;

    // Generate a path
    char *path = malloc(len);
    if (!path) {
        return -1;
    }

    snprintf(path, len, "%s%s%s%s%s", s->output_dir_path, "/", slug, "/", file_name);

    // Attempt file saving
    FILE *f = fopen(path, "w");
    if (!f) {
        free(path);
        return -1;
    }

    // Null-terminate buffer if not null terminated already
    data[s->buffer_len - 1] = 0;

    if ( fprintf(f, "%s", data) < 0 ) {
        fclose(f);
        free(path);
        return -1;
    }

    fclose(f);
    free(path);

    return 0;
}
