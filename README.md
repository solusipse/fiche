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
cat file.txt | nc solusipse.net 9999
```

```
echo just testing! | nc code.solusipse.net 9999
```

If you haven't already set up your server on localhost, try second or third command. My personal server is
providing fiche-based service all the time on this address `solusipse.net` and this port `9999`.

- To upload text you need to have netcat installed (to check if netcat is installed, simply type ```nc``` in terminal).

## Server-side usage ##

```
usage: fiche [-pbsdolBuw].
             [-d domain] [-p port] [-s slug size]
             [-o output directory] [-B buffer size] [-u user name]
             [-l log file] [-b banlist] [-w whitelist]
```

These are command line arguments. You don't have to provide any, but providing basic is recommended. Without them, program
will use these default settings:

```
domain = "http://localhost/";
basedir= "~/code/";
port = 9999;
slug_size = 4;
buffer_size = 8192;
```

### Arguments ###

Most important is providing **basedir** and **domain**.

-----------------

#### Basedir ####

Basedir should be **absolute** path to directory where you would like to store text files.


```
fiche -o /absolute/path/to/directory/
```

```
fiche -o /home/www/code/
```

-----------------

#### Domain ####

Domain should be provided in such format ```domain.com```.

```
fiche -d domain.com
```

```
fiche -d subdomain.domain.com
```

-----------------

#### Slug size ####

This will force fiche to create random slugs with given length, example:

```
fiche -s 6
```

```
http://domain.com/abcdef/
```

-----------------

#### User name ####

If you use fiche as service (see details below) you may want to save files as other user, to do that use `-u` option,
there's example:

```
fiche -u http
```

-----------------

#### Buffersize ####

This parameter defines max file size uploaded by user, by default it is set to `32768`.
Use `-B` parameter to change it:

```
fiche -B 2048
```

-----------------

#### Log file ###

Path to file where all logs will be stored:

```
fiche -l /home/www/fiche-log.txt
```

-----------------

#### Ban list ###

Path to file where you provided all banned IP adresses:

```
fiche -b /home/www/fiche-bans.txt
```

-----------------

#### White list ####

If whitelist mode is enabled, only addresses from list will be able to upload files. There's example:

```
fiche -w /home/www/fiche-whitelist.txt
```

-----------------

#### Whitelist and banlist syntax ####

There is no specific syntax, there files may contain not only addresses.

-----------------

#### Examples ####

Logging connections with banlist:

```
fiche -d domain.com -l /home/www/log.txt -b /home/www/bans.txt
```

-----------------

Only for personal use with whitelist

```
fiche -d domain.com -w /home/www/whitelist.txt
```

-----------------

Custom output directory, bigger slug size, reduced buffer, custom port:

```
fiche -d domain.com -o /media/disk/fiche/ -s 8 -B 2048 -p 6666
```



## Running as service ##
You can run fiche as service, there is simple systemd example:

```
[Unit]
Description=FICHE-SERVER

[Service]
ExecStart=/usr/local/bin/fiche -d code.solusipse.net -o /home/www/code/ -l /home/www/log.txt

[Install]
WantedBy=multi-user.target
```

In service mode you have to set output directory with `-o` parameter, there's example:

```
fiche -o /home/www/code/
```

## Webserver ##

To make files available for users, you need to host them somehow. Http server is easiest option. Just set root 
directory to ```BASEDIR```.

There is sample configuration for nginx:

```
server {
    listen 80;
    server_name mysite.com www.mysite.com;
    charset utf-8;

    location / {
            root /home/www/code/;
            index index.txt index.html;
    }
}
```

## License ##

Fiche is MIT licensed.
