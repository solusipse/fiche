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

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

/******************************************************************************
 * Various declarations
 */
const char *Fiche_Symbols = "abcdefghijklmnopqrstuvwxyz0123456789";

EVP_PKEY       *g_key  = NULL;
STACK_OF(X509) *g_cert_chain = NULL;
SSL_METHOD     *g_method = NULL;
X509_STORE     *g_store = NULL;
SSL_CTX        *g_ctx = NULL;

bool debug = 0;

/******************************************************************************
 * Inner structs
 */

struct fiche_connection {
    int socket;
    struct sockaddr_in address;
    SSL *ssl;
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
        NULL,
	// cert
	NULL,
	// key
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

static void print_debug(const char *format, ...) {
    va_list args;

    va_start(args, format);

    printf("[Fiche][DEBUG] ");
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

bool is_ssl(Fiche_Settings *settings) {
    if (settings->cert && settings->key)
        return true;
    else
        return false;
}

EVP_PKEY *read_key(char *key) {
    FILE *fp;
    unsigned long my_err;
    EVP_PKEY *new_key;

    if (!key || !*key) {
        return NULL;
    }

    fp = fopen(key, "r");
    if (!fp) {
        print_error("SSL Private Key fopen() Error: %s", strerror(errno));
        return NULL;
    }
    new_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!new_key) {
        while ((my_err = ERR_get_error())) {
            print_error("SSL Private Key Loading Error: %s", ERR_error_string(my_err, NULL));
        }
    }

    return new_key;
}

STACK_OF(X509) *read_cert_chain(char *cert) {
    FILE *fp = NULL;
    unsigned long my_err = 0;
    X509 *new_cert = NULL;
    STACK_OF(X509) *new_cert_chain = NULL;

    if (!cert || !*cert) {
        return NULL;
    }

    fp = fopen(cert, "r");
    if (!fp) {
        print_error("SSL Certificate fopen() Error: %s", strerror(errno));
        return NULL;
    }

    new_cert_chain = sk_X509_new_null();
    if (!new_cert_chain) {
        print_error("SSL Certificate sk_X509_new_null() Error");
        fclose(fp);
        return NULL;
    }

    while((new_cert = PEM_read_X509(fp, NULL, NULL, NULL))) {
        sk_X509_push(new_cert_chain, new_cert);
    }

    fclose(fp);

    if (!new_cert_chain || sk_X509_num(new_cert_chain) <= 0) {
        while ((my_err = ERR_get_error())) {
            print_error("SSL Certificate Loading Error: %s", ERR_error_string(my_err, NULL));
        }
        if (new_cert_chain) {
            sk_X509_free(new_cert_chain);
        }
        return NULL;
    }

    return new_cert_chain;
}

X509_STORE *make_cert_store(void) {
    X509_STORE *store = NULL;

    store = X509_STORE_new();

    if (!store) {
        print_error("SSL Certificate Error: X509_STORE_new() Failed");
        return NULL;
    }

    X509_STORE_set_default_paths(store);

    return store;
}

void info_callback(SSL *s, int where, int ret) {
    where = where;
    ret = ret;
    if (debug) print_debug("SSL info: %s", SSL_state_string_long(s));
    return;
}

SSL_CTX *make_ctx(STACK_OF(X509) *cert_chain, EVP_PKEY *key) {

    SSL_CTX *new_ctx=NULL;
    unsigned long my_err=0;
    EC_KEY *ecdh=NULL;
    int i=0;

    if (!cert_chain || sk_X509_num(cert_chain) <= 0 || !key)
        return NULL;

    if (!g_method)
        return NULL;

    new_ctx = SSL_CTX_new(g_method);
    if (!new_ctx) {
        while ((my_err = ERR_get_error()))
            print_error("SSL Context Structure Error: %s", ERR_error_string(my_err, NULL));
        return NULL;
    }

    if (!SSL_CTX_use_certificate(new_ctx, sk_X509_value(cert_chain, 0))) {
        while ((my_err = ERR_get_error()))
            print_error("SSL Certificate Error: %s", ERR_error_string(my_err, NULL));
        SSL_CTX_free(new_ctx);
        new_ctx = NULL;
        return NULL;
    }

    for (i=1; i < sk_X509_num(cert_chain); i++) {
        if (!SSL_CTX_add_extra_chain_cert(new_ctx, sk_X509_value(cert_chain, i))) {
             while ((my_err = ERR_get_error()))
                 print_error("SSL Certificate Error: %s", ERR_error_string(my_err, NULL));
             SSL_CTX_free(new_ctx);
             new_ctx = NULL;
            return NULL;
        }
    }

    if (!SSL_CTX_use_PrivateKey(new_ctx, key)) {
        while ((my_err = ERR_get_error()))
            print_error("SSL Private Key Error: %s", ERR_error_string(my_err, NULL));
        SSL_CTX_free(new_ctx);
        new_ctx = NULL;
        return NULL;
    }

    if (!SSL_CTX_check_private_key(new_ctx)) {
        print_error("SSL Error: Private key does not match the certificate public key");
        SSL_CTX_free(new_ctx);
        new_ctx = NULL;
        return NULL;
    }

    SSL_CTX_set_options(new_ctx, SSL_OP_ALL);

    SSL_CTX_set_info_callback(new_ctx, (void (*)())info_callback);

    SSL_CTX_set_mode(new_ctx, SSL_MODE_AUTO_RETRY);

    ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (ecdh) {
        SSL_CTX_set_tmp_ecdh(new_ctx, ecdh);
        EC_KEY_free(ecdh);
    } else {
        print_error("SSL Error: Elliptic curve Diffie-Hellman failure");
    }

    return new_ctx;

}

int fiche_ssl_init(Fiche_Settings *settings) {

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

#ifdef HAVE_SHA256
    EVP_add_digest(EVP_sha256());
#endif


    if (!g_method) {
        // this is a static structure. it will never be NULL. nothing to free.
        g_method = (SSL_METHOD *)SSLv23_method();
    }

    g_key = read_key(settings->key);
    if (!g_key) {
        g_method = NULL;
        return -1;
    }

    g_cert_chain = read_cert_chain(settings->cert);
    if (!g_cert_chain) {
        EVP_PKEY_free(g_key);
        g_key = NULL;
        g_method = NULL;
        return -1;
    }

    if (sk_X509_num(g_cert_chain) <= 0) {
        sk_X509_pop_free(g_cert_chain, X509_free);
        g_cert_chain = NULL;
        EVP_PKEY_free(g_key);
        g_key = NULL;
        g_method = NULL;
        return -1;
    }

    g_store = make_cert_store();
    if (!g_store) {
        sk_X509_pop_free(g_cert_chain, X509_free);
        g_cert_chain = NULL;
        EVP_PKEY_free(g_key);
        g_key = NULL;
        g_method = NULL;
        return -1;
    }

    g_ctx = make_ctx(g_cert_chain, g_key);
    if (!g_ctx) {
        X509_STORE_free(g_store);
        g_store = NULL;
        sk_X509_pop_free(g_cert_chain, X509_free);
        g_cert_chain = NULL;
        EVP_PKEY_free(g_key);
        g_key = NULL;
        g_method = NULL;
        return -1;
    }

    return 0;
}

int accept_ssl(SSL *ssl) {
    int need_more;
    int ssl_err;
    unsigned long my_err;

    do {

        need_more = 0;
        ssl_err = SSL_accept(ssl);
        switch(SSL_get_error(ssl, ssl_err)){
            case SSL_ERROR_NONE:
            break;
            case SSL_ERROR_SSL:
                while ((my_err = ERR_get_error()))
                    print_error("SSL_accept: SSL_ERROR_SSL: %s", ERR_error_string(my_err, NULL));
                return -1;
            break;
            case SSL_ERROR_SYSCALL:
                if (ERR_peek_error()) {
                    while ((my_err = ERR_get_error()))
                        print_error("SSL_accept: SSL_ERROR_SYSCALL: %s", ERR_error_string(my_err, NULL));
                } else {
                    if (ssl_err)
                        print_error("SSL_accept: SSL_ERROR_SYSCALL errno: %s", strerror(errno));
                    else
                        print_error("SSL_accept: SSL_ERROR_SYSCALL EOF");
                }
                return -1;
            break;
            case SSL_ERROR_ZERO_RETURN:
                print_error("SSL_accept: SSL_ERROR_ZERO_RETURN");
                return -1;
            break;
            case SSL_ERROR_WANT_READ:
                need_more = 1;
                if (debug) print_debug("SSL_accept: SSL_ERROR_WANT_READ");
            break;
            case SSL_ERROR_WANT_WRITE:
                need_more = 1;
                if (debug) print_debug("SSL_accept: SSL_ERROR_WANT_WRITE");
            break;
            case SSL_ERROR_WANT_ACCEPT:
                need_more = 1;
                if (debug) print_debug("SSL_accept: SSL_ERROR_WANT_ACCEPT");
            break;
            default:
                print_error("SSL_accept: SSL accept problem");
                return -1;
            break;
        }

    } while(need_more);

    return 0;
}

int read_ssl(SSL *ssl, void *buf, int count) {

    int need_more;
    unsigned long my_err;
    int inbound_offset = 0;
    int ret = 0;

    if (!ssl || !buf || count < 1)
        return -1;

    do {
        need_more = 0;
        ret = SSL_read(ssl, buf, count);
        if (ret >= 0)
            inbound_offset += ret;
        switch(SSL_get_error(ssl, ret)) {
            case SSL_ERROR_NONE:
            break;
            case SSL_ERROR_SSL:
                while ((my_err = ERR_get_error()))
                    print_error("SSL_read: SSL_ERROR_SSL: %s", ERR_error_string(my_err, NULL));
            break;
            case SSL_ERROR_SYSCALL:
                if (ERR_peek_error()) {
                    while ((my_err = ERR_get_error()))
                        print_error("SSL_read: SSL_ERROR_SYSCALL: %s", ERR_error_string(my_err, NULL));
                } else {
                    if (ret)
                        print_error("SSL_read: SSL_ERROR_SYSCALL errno: %s", strerror(errno));
                }
            break;
            case SSL_ERROR_ZERO_RETURN:
                print_error("SSL_read: SSL_ERROR_ZERO_RETURN");
            break;
            case SSL_ERROR_WANT_READ:
                need_more = 1;
                if (debug) print_debug("SSL_read: SSL_ERROR_WANT_READ");
            break;
            case SSL_ERROR_WANT_WRITE:
                need_more = 1;
                if (debug) print_debug("SSL_read: SSL_ERROR_WANT_WRITE");
            break;
            default:
                print_error("SSL_read: SSL read problem");
            break;
        }
    } while (need_more);

    return inbound_offset;
}

int read_ssl_waitall(SSL *ssl, void *buf, int count) {

    ssize_t inbound_offset=0;
    ssize_t ret=0;

    if (!ssl || !buf || count < 1)
        return -1;

    while (inbound_offset < count) {
        ret = read_ssl(ssl, (char *)buf + inbound_offset, count - inbound_offset);

        if (ret <= 0)
            break;

        inbound_offset += ret;

    }

    return inbound_offset;
}

static int start_server(Fiche_Settings *settings) {

    int s;

    if (is_ssl(settings)) {
        if (fiche_ssl_init(settings) < 0) {
            print_error("Couldn't initialize SSL!");
            return -1;
        }
    }

    // Perform socket creation
    s = socket(AF_INET, SOCK_STREAM, 0);
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
    if (s < 0) {
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
    c->ssl = NULL;
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

    if(is_ssl(c->settings)) {
        c->ssl = SSL_new(g_ctx);
        if (!c->ssl) {
	    close(c->socket);
	    free(c);
	    pthread_exit(NULL);
	    return 0;
        }

        SSL_set_accept_state(c->ssl);
        SSL_set_fd(c->ssl, c->socket);
        SSL_set_mode(c->ssl, SSL_MODE_AUTO_RETRY);

        if (accept_ssl(c->ssl) < 0) {
            if (c->ssl) {
                SSL_shutdown(c->ssl);
                SSL_free(c->ssl);
            }
            c->ssl = NULL;
            close(c->socket);
            free(c);
            pthread_exit(NULL);
            return 0;
        }
    }

    // Create a buffer
    uint8_t buffer[c->settings->buffer_len];
    memset(buffer, 0, c->settings->buffer_len);

    int r;

    if (is_ssl(c->settings))
        r = read_ssl_waitall(c->ssl, buffer, sizeof(buffer));
    else
        r = recv(c->socket, buffer, sizeof(buffer), MSG_WAITALL);

    if (r <= 0) {
        print_error("No data received from the client!");
        print_separator();

        if (is_ssl(c->settings)) {
            if (c->ssl) {
                SSL_shutdown(c->ssl);
                SSL_free(c->ssl);
            }
            c->ssl = NULL;
        }

        // Close the socket
        close(c->socket);

        // Cleanup
        free(c);
        pthread_exit(NULL);

        return 0;
    }

    // - Check if request was performed with a known protocol
    // TODO

    // - Check if on whitelist
    // TODO

    // - Check if on banlist
    // TODO

    // Generate slug and use it to create an url
    char *slug;
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

            if (is_ssl(c->settings)) {
                if (c->ssl) {
                    SSL_shutdown(c->ssl);
                    SSL_free(c->ssl);
                }
                c->ssl = NULL;
            }

            // Cleanup
            free(slug);
            close(c->socket);
            free(c);
            pthread_exit(NULL);
            return NULL;
        }

    }
    while(create_directory(c->settings->output_dir_path, slug) != 0);


    // Slug generation failed, we have to finish here
    if (!slug) {
        print_error("Couldn't generate a slug!");
        print_separator();

        if (is_ssl(c->settings)) {
            if (c->ssl) {
                SSL_shutdown(c->ssl);
                SSL_free(c->ssl);
            }
            c->ssl = NULL;
        }

        close(c->socket);

        // Cleanup
        free(c);
        pthread_exit(NULL);
        return NULL;
    }


    // Save to file failed, we have to finish here
    if ( save_to_file(c->settings, buffer, slug) != 0 ) {
        print_error("Couldn't save a file!");
        print_separator();

        if (is_ssl(c->settings)) {
            if (c->ssl) {
                SSL_shutdown(c->ssl);
                SSL_free(c->ssl);
            }
            c->ssl = NULL;
        }

        close(c->socket);

        // Cleanup
        free(c);
        free(slug);
        pthread_exit(NULL);
        return NULL;
    }

    // Write a response to the user
    {
        // Create an url (additional byte for slash and one for new line)
        const size_t len = strlen(c->settings->domain) + strlen(slug) + 3;

        char url[len];
        snprintf(url, len, "%s%s%s%s", c->settings->domain, "/", slug, "\n");

        // Send the response
        if(is_ssl(c->settings))
            SSL_write(c->ssl, url, len);
        else
            write(c->socket, url, len);
    }

    print_status("Received %d bytes, saved to: %s.", r, slug);
    print_separator();

    // Log connection
    // TODO: log unsuccessful and rejected connections
    log_entry(c->settings, ip, hostname, slug);

    if (is_ssl(c->settings)) {
        if (c->ssl) {
            SSL_shutdown(c->ssl);
            SSL_free(c->ssl);
        }
        c->ssl = NULL;
    }

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
