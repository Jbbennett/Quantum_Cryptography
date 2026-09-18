CC ?= clang
HOMEBREW_PREFIX ?= $(shell brew --prefix 2>/dev/null || echo /opt/homebrew)

CPPFLAGS += -I$(HOMEBREW_PREFIX)/include
LDFLAGS += -L$(HOMEBREW_PREFIX)/lib
LDLIBS += -loqs -lcrypto
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2

PROGRAMS := pqc_kem pqc_hybrid_encrypt

.PHONY: all clean run-kem run-hybrid

all: $(PROGRAMS)

pqc_kem: pqc_kem.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LDFLAGS) $(LDLIBS) -o $@

pqc_hybrid_encrypt: pqc_hybrid_encrypt.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LDFLAGS) $(LDLIBS) -o $@

run-kem: pqc_kem
	./pqc_kem

run-hybrid: pqc_hybrid_encrypt
	./pqc_hybrid_encrypt

clean:
	rm -f $(PROGRAMS)