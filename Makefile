# -----------------------------------
# Fiche MAKEFILE
# https://github.com/solusipse/fiche
# solusipse.net
# -----------------------------------

CC=gcc
CFLAGS=-pthread -O2
prefix=/usr/local

all: fiche.c
	$(CC) -o fiche $(CFLAGS) fiche.c

install: fiche
	install -m 0755 fiche $(prefix)/bin
