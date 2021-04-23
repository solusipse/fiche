OS := $(shell uname -o)
ifeq ($(OS),illumos)
# for debug add -g -O0 to line below
    CFLAGS+=-pthread -O2 -Wall -Wextra -Wpedantic -Wstrict-overflow -fno-strict-aliasing -std=gnu11 -lsocket  -lnsl
    prefix=/opt/local/bin

all:
	${CC} main.c fiche.c $(CFLAGS) -o fiche

install: fiche
	install  -m 0755 fiche $(prefix)
	svccfg import fiche.xml
else
# for debug add -g -O0 to line below
    CFLAGS+=-pthread -O2 -Wall -Wextra -Wpedantic -Wstrict-overflow -fno-strict-aliasing -std=gnu11 -g -O0
    prefix=/usr/local/bin

all:
	${CC} main.c fiche.c $(CFLAGS) -o fiche

install: fiche
	install -m 0755 fiche $(prefix)
endif

clean:
	rm -f fiche

.PHONY: clean
