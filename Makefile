# -----------------------------------
# Fiche MAKEFILE
# https://github.com/solusipse/fiche
# solusipse.net
# -----------------------------------

CFLAGS+=-pthread -O2
prefix=/usr/local

all: fiche

install: fiche
	install -m 0755 fiche $(prefix)/bin

clean:
	rm -f fiche

.PHONY: clean
