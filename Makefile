TARGET = fiche
CFLAGS += -pthread -O2 -Wall -Wextra -Wpedantic -Wstrict-overflow -fno-strict-aliasing -std=gnu11
PREFIX = /usr/local/bin
LIBS = -lm

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

.PHONY: all install debug clean

default: all

all: $(TARGET)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS)
	${CC} $(OBJECTS) $(CFLAGS) $(LIBS) -o $@

debug: CFLAGS += -g -O0
debug: $(TARGET)

install: $(TARGET)
	install -m 0755 $(TARGET) $(PREFIX)

clean:
	$(RM) *.o
	$(RM) $(TARGET)
