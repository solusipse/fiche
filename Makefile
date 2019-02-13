# for debug add -g -O0 to line below
CFLAGS+=-pthread -O2 -Wall -Wextra -Wpedantic -Wstrict-overflow -fno-strict-aliasing -std=gnu11 -g -O0
DESTDIR?=
PREFIX?=/usr/local/bin

all:
	${CC} main.c fiche.c $(CFLAGS) -o fiche

install: fiche
	install -d $(DESTDIR)$(PREFIX)
	install -m 0755 fiche $(DESTDIR)$(PREFIX)
	install -d $(DESTDIR)/usr/lib/systemd/system
	install -m 644 extras/systemd.fiche@.service $(DESTDIR)/usr/lib/systemd/system/fiche@.service

clean:
	rm -f fiche

.PHONY: clean
