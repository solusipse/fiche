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

#include "fiche.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>


int main(int argc, char **argv) {

    // Fiche settings instance
    Fiche_Settings fs;

    // Initialize settings instance to default values
    fiche_init(&fs);

    // Note: fiche_run is responsible for checking if these values
    // were set correctly

    // Note: according to getopt documentation, we don't need to
    // copy strings, so we decided to go with pointer approach for these

    // Parse input arguments
    int c;
    while ((c = getopt(argc, argv, "D6eSL:p:b:s:d:o:l:B:u:w:")) != -1) {
        switch (c) {

            // domain
            case 'd':
            {
                fs.domain = optarg;
            }
            break;

            // port
            case 'p':
            {
                fs.port = atoi(optarg);
            }
            break;

            // listen_addr
            case 'L':
            {
                fs.listen_addr = optarg;
            }
            break;

            // slug size
            case 's':
            {
                fs.slug_len = atoi(optarg);
            }
            break;

            // https
            case 'S':
            {
                fs.https = true;
            }
            break;

            // output directory path
            case 'o':
            {
                fs.output_dir_path = optarg;
            }
            break;

            // buffer size
            case 'B':
            {
                fs.buffer_len = atoi(optarg);
            }
            break;

            // user name
            case 'u':
            {
                fs.user_name = optarg;
            }
            break;

            // log file path
            case 'l':
            {
                fs.log_file_path = optarg;
            }
            break;

            // banlist file path
            case 'b':
            {
                fs.banlist_path = optarg;
            }
            break;

            // whitelist file path
            case 'w':
            {
                fs.whitelist_path = optarg;
            }
            break;

            // Display help in case of any unsupported argument
            default:
            {
                printf("usage: fiche [-dLpsSoBulbw].\n");
                printf("             [-d domain] [-L listen_addr] [-p port] [-s slug size]\n");
                printf("             [-o output directory] [-B buffer size] [-u user name]\n");
                printf("             [-l log file] [-b banlist] [-w whitelist] [-S]\n");
                return 0;
            }
            break;
        }
    }


    fiche_run(fs);


    return 0;
}


