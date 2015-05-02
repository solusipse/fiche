# -----------------------------------
# Fiche MAKEFILE
# https://github.com/solusipse/fiche
# solusipse.net
# -----------------------------------

CFLAGS+=-pthread -O2

all: fiche

install: fiche
	install -m 0755 fiche ${PREFIX}/bin

clean:
	rm -f fiche

.PHONY: clean
