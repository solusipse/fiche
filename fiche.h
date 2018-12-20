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

Use netcat to push text - example:
$ cat fiche.c | nc localhost 9999

-------------------------------------------------------------------------------
*/

#ifndef FICHE_H
#define FICHE_H

#include <stdint.h>
#include <stdbool.h>


/**
 * @brief Used as a container for fiche settings. Create before
 *        the initialization
 *
 */
typedef struct Fiche_Settings {
    /**
     * @brief Domain used in output links
     */
    char *domain;

    /**
     * @brief Path to directory used for storing uploaded pastes
     */
    char *output_dir_path;

    /**
     * @brief Address on which fiche is waiting for connections
     */
    char *listen_addr;

    /**
     * @brief Port on which fiche is waiting for connections
     */
    uint16_t port;

    /**
     * @brief Length of a paste's name
     */
    uint8_t slug_len;

    /**
     * @brief If set, returns url with https prefix instead of http
     */
    bool https;

    /**
     * @brief Connection buffer length
     *
     * @remarks Length of this buffer limits max size of uploaded files
     */
    uint32_t buffer_len;

    /**
     * @brief Name of the user that runs fiche process
     */
    char *user_name;

    /**
     * @brief Path to the log file
     */
    char *log_file_path;

    /**
     * @brief Path to the file with banned IPs
     */
    char *banlist_path;

    /**
     * @brief Path to the file with whitelisted IPs
     */
    char *whitelist_path;



} Fiche_Settings;


/**
 *  @brief Initializes Fiche_Settings instance
 */
void fiche_init(Fiche_Settings *settings);


/**
 *  @brief Runs fiche server
 *
 *  @return 0 if it was able to start, any other value otherwise
 */
int fiche_run(Fiche_Settings settings);


/**
 * @brief array of symbols used in slug generation
 * @remarks defined in fiche.c
 */
extern const char *Fiche_Symbols;


#endif
