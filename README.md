fiche
=====

Command line pastebin for sharing terminal output.

## Installation ##

1. Clone into repository:

    ```
    https://github.com/solusipse/fiche.git
    ```

2. Build program:

    ```
    make
    ```
    
3. Install:

    ```
    sudo make install
    ```

## Client-side usage ##

Self explanatory live examples:

```
ls -la | nc localhost 9999
```

```
cat file.txt | nc someserverrunningfiche.net 1234
```

```
echo just testing! | nc code.solusipse.net 9999
```

If you already haven't set up your server on localhost, try third line! My server is providing terminal 
pastebin server powered by fiche - ```code.solusipse.net``` on port ```9999```.

- To upload text you need to have netcat installed (to check if netcat is installed, simply type ```nc``` in terminal).

## Server-side usage ##

```
usage: fiche [-bdpqs].
             [-d host_domain.com] [-p port] [-s slug_size]
             [-o output_directory] [-b buffer_size] [-q queue_size]
```

These are command line arguments. You don't have to provide any, but doing that is recommended. Without them, program
will use these default settings:

```C
domain = "http://localhost/";
basedir= "~/code/";
port = 9999;
slug_size = 4;
buffer_size = 8192;
queue_size = 100;
```

### Basic arguments ###

Most important is providing **basedir** and **domain**.

Basedir should be **absolute** path to directory where you would like to store text files.

Domain should be provided in such format ```domain.com```.

Slug size: ```yourserver.com/SLUG_OF_CHOSEN_LENGTH/```.

### Parameters for advanced users ###

- Buffer size
- Queue size

## Running as service ##

You can run fiche as service, there is simple systemd example:

```
[Unit]
Description=FICHE-SERVER

[Service]
ExecStart=/usr/local/bin/fiche -d code.solusipse.net -o /home/www/code/

[Install]
WantedBy=multi-user.target
```

## Webserver ##

To make files available for users, you need to host them somehow. Http server is easiest option. Just set root 
directory to ```BASEDIR```. **Remember that you have to distribute these files as plain text for safety measures!**

There is sample configuration for nginx:

```
server {
    listen 80;
    server_name mysite.com www.mysite.com;
    add_header Content-Type text/plain;

    location / {
            root /home/www/code/;
            index index.html;
    }
}
```

## License ##

Fiche is MIT licensed.
