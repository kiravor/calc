CC ?= cc
CPPFLAGS += -Iinclude -D_POSIX_C_SOURCE=200809L
CFLAGS ?= -O2 -g
CFLAGS += -std=c17 -Wall -Wextra -Wpedantic -Werror -pthread
LDFLAGS += -pthread
SOURCES := $(wildcard src/*.c)
OBJECTS := $(SOURCES:src/%.c=build/%.o)

.PHONY: all clean test sanitize
all: build/gost-c

build/gost-c: $(OBJECTS)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

build/%.o: src/%.c include/gost.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

build:
	mkdir -p $@

test: build/gost-c
	python3 -m unittest discover -s tests -v

sanitize:
	$(MAKE) clean
	$(MAKE) CFLAGS='-O1 -g -std=c17 -Wall -Wextra -Wpedantic -Werror -pthread -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie' LDFLAGS='-pthread -fsanitize=address,undefined -no-pie' test

clean:
	rm -rf build
