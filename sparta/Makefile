CC ?= cc
AR ?= ar
CPPFLAGS += -I../include -Iinclude -Ivendor -D_POSIX_C_SOURCE=200809L
CFLAGS ?= -O2 -g
CFLAGS += -std=c17 -Wall -Wextra -Wpedantic -Werror -pthread -fPIC
LDLIBS += $(shell pkg-config --libs openssl libcurl) -lm -pthread
CPPFLAGS += $(shell pkg-config --cflags openssl libcurl)
BASE := $(filter-out ../src/main.c,$(wildcard ../src/*.c))
SRC := $(filter-out src/main.c,$(wildcard src/*.c))
OBJ := $(BASE:../src/%.c=build/base_%.o) $(SRC:src/%.c=build/%.o) build/cJSON.o
.PHONY: all test sanitize clean
all: build/sparta build/libsparta.a
build/sparta: build/main.o build/libsparta.a
	$(CC) $(CFLAGS) $^ $(LDFLAGS) $(LDLIBS) -o $@
build/libsparta.a: $(OBJ)
	$(AR) rcs $@ $^
build/base_%.o: ../src/%.c ../include/gost.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/%.o: src/%.c include/sparta.h include/internal.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/cJSON.o: vendor/cJSON.c vendor/cJSON.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build:
	mkdir -p $@
build/probe: tests/probe.c build/libsparta.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ $(LDFLAGS) $(LDLIBS) -o $@
build/dns-probe: tests/dns_probe.c build/libsparta.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ $(LDFLAGS) -Wl,--wrap=getaddrinfo -Wl,--wrap=connect $(LDLIBS) -o $@
build/node-fixture: tests/node_fixture.c build/libsparta.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ $(LDFLAGS) -Wl,--wrap=sp_authorize_target -Wl,--wrap=sp_destination_allowed $(LDLIBS) -o $@
CLIENT := client client_udp common websocket wire
CLIENT_OBJ := $(CLIENT:%=build/clientonly_%.o) $(BASE:../src/%.c=build/base_%.o) build/cJSON.o
build/clientonly_%.o: src/%.c include/sparta.h include/internal.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -DSPARTA_CLIENT_ONLY -c $< -o $@
build/libsparta-client.a: $(CLIENT_OBJ)
	$(AR) rcs $@ $^
build/client-probe: tests/probe.c build/libsparta-client.a
	$(CC) $(CPPFLAGS) $(CFLAGS) -DSPARTA_CLIENT_ONLY $^ $(LDFLAGS) -lssl -lcrypto -lm -pthread -o $@
test: all build/probe build/node-fixture build/client-probe build/dns-probe
	python3 -m unittest discover -s tests -v
sanitize:
	$(MAKE) clean
	$(MAKE) CFLAGS='-O1 -g -std=c17 -Wall -Wextra -Wpedantic -Werror -pthread -fPIC -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie' LDFLAGS='-fsanitize=address,undefined -no-pie' test
clean:
	rm -rf build
