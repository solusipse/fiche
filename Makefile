# -----------------------------------
# Fiche MAKEFILE
# https://github.com/solusipse/fiche
# solusipse.net
# -----------------------------------

CC=musl-gcc
CFLAGS+=-pthread -O2

all: fiche

docker: fiche
	docker build . -t fiche:latest

install: fiche
	install -m 0755 fiche ${PREFIX}

clean:
	rm -f fiche

.PHONY: clean
