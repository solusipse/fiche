fiche [![Build Status](https://travis-ci.org/solusipse/fiche.svg?branch=master)](https://travis-ci.org/solusipse/fiche)
=====

Command line pastebin for sharing terminal output.

# Client-side usage

Self-explanatory live examples (using public server):

```
echo just testing! | nc termbin.com 9999
```

```
cat file.txt | nc termbin.com 9999
```

In case you installed and started fiche on localhost:

```
ls -la | nc localhost 9999
```

You will get an url to your paste as a response, e.g.:

```
http://termbin.com/ydxh
```

You can use our beautification service to get any paste colored and numbered. Just ask for it using `l.termbin.com` subdomain, e.g.:

```
http://l.termbin.com/ydxh
```

-------------------------------------------------------------------------------

## Useful aliases

You can make your life easier by adding a termbin alias to your rc file. We list some of them here:

-------------------------------------------------------------------------------

### Pure-bash alternative to netcat

__Linux/macOS:__
```
alias tb="(exec 3<>/dev/tcp/termbin.com/9999; cat >&3; cat <&3; exec 3<&-)"
```

```
echo less typing now! | tb
```

_See [#42](https://github.com/solusipse/fiche/issues/42), [#43](https://github.com/solusipse/fiche/issues/43) for more info._

-------------------------------------------------------------------------------

### `tb` alias

__Linux (Bash):__
```
echo 'alias tb="nc termbin.com 9999"' >> .bashrc
```

```
echo less typing now! | tb
```

__macOS:__

```
echo 'alias tb="nc termbin.com 9999"' >> .bash_profile
```

```
echo less typing now! | tb
```

-------------------------------------------------------------------------------

### Copy output to clipboard

__Linux (Bash):__
```
echo 'alias tbc="netcat termbin.com 9999 | xclip -selection c"' >> .bashrc
```

```
echo less typing now! | tbc
```

__macOS:__

```
echo 'alias tbc="nc termbin.com 9999 | pbcopy"' >> .bash_profile
```

```
echo less typing now! | tbc
```

__Remember__ to reload the shell with `source ~/.bashrc` or `source ~/.bash_profile` after adding any of provided above!

-------------------------------------------------------------------------------

## Requirements
To use fiche you have to have netcat installed. You probably already have it - try typing `nc` or `netcat` into your terminal!

-------------------------------------------------------------------------------

# Server-side usage

## Installation

1. Clone:

    ```
    git clone https://github.com/solusipse/fiche.git
    ```

2. Build:

    ```
    make
    ```
    
3. Install:

    ```
    sudo make install
    ```

### Using Ports on FreeBSD

To install the port: `cd /usr/ports/net/fiche/ && make install clean`. To add the package: `pkg install fiche`.

_See [#86](https://github.com/solusipse/fiche/issues/86) for more info._

-------------------------------------------------------------------------------

## Usage

```
usage: fiche [-D6epbsdSolBuw].
             [-d domain] [-L listen_addr ] [-p port] [-s slug size]
             [-o output directory] [-B buffer size] [-u user name]
             [-l log file] [-b banlist] [-w whitelist] [-S]
```

These are command line arguments. You don't have to provide any of them to run the application. Default settings will be used in such case. See section below for more info.

### Settings

-------------------------------------------------------------------------------

#### Output directory `-o`

Relative or absolute path to the directory where you want to store user-posted pastes.

```
fiche -o ./code
```

```
fiche -o /home/www/code/
```

__Default value:__ `./code`

-------------------------------------------------------------------------------

#### Domain `-d`

This will be used as a prefix for an output received by the client.
Value will be prepended with `http`.

```
fiche -d domain.com
```

```
fiche -d subdomain.domain.com
```

```
fiche -d subdomain.domain.com/some_directory
```

__Default value:__ `localhost`

-------------------------------------------------------------------------------

#### Slug size `-s`

This will force slugs to be of required length:

```
fiche -s 6
```

__Output url with default value__: `http://localhost/xxxx`,
where x is a randomized character

__Output url with example value 6__: `http://localhost/xxxxxx`,
where x is a randomized character

__Default value:__ 4

-------------------------------------------------------------------------------

#### HTTPS `-S`

If set, fiche returns url with https prefix instead of http

```
fiche -S
```

__Output url with this parameter__: `https://localhost/xxxx`,
where x is a randomized character

-------------------------------------------------------------------------------

#### User name `-u`

Fiche will try to switch to the requested user on startup if any is provided.

```
fiche -u _fiche
```

__Default value:__ not set

__WARNING:__ This requires that fiche is started as a root.

-------------------------------------------------------------------------------

#### Buffer size `-B`

This parameter defines size of the buffer used for getting data from the user.
Maximum size (in bytes) of all input files is defined by this value.

```
fiche -B 2048
```

__Default value:__ 32768

-------------------------------------------------------------------------------

#### Log file `-l`

```
fiche -l /home/www/fiche-log.txt
```

__Default value:__ not set

__WARNING:__ this file has to be user-writable

-------------------------------------------------------------------------------

#### Ban list `-b`

Relative or absolute path to a file containing IP addresses of banned users.

```
fiche -b fiche-bans.txt
```

__Format of the file:__ this file should contain only addresses, one per line.

__Default value:__ not set

__WARNING:__ not implemented yet

-------------------------------------------------------------------------------

#### White list `-w`

If whitelist mode is enabled, only addresses from the list will be able
to upload files.

```
fiche -w fiche-whitelist.txt
```

__Format of the file:__ this file should contain only addresses, one per line.

__Default value:__ not set

__WARNING:__ not implemented yet

-------------------------------------------------------------------------------

### Running as a service

There's a simple systemd example:
```
[Unit]
Description=FICHE-SERVER

[Service]
ExecStart=/usr/local/bin/fiche -d yourdomain.com -o /path/to/output -l /path/to/log -u youruser

[Install]
WantedBy=multi-user.target
```

__WARNING:__ In service mode you have to set output directory with `-o` parameter.

-------------------------------------------------------------------------------

### Example nginx config

Fiche has no http server built-in, thus you need to setup one if you want to make files available through http.

There's a sample configuration for nginx:

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

## License

Fiche is MIT licensed.
