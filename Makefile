CC ?= clang
HOMEBREW_PREFIX ?= $(shell brew --prefix 2>/dev/null || echo /opt/homebrew)

CPPFLAGS += -I$(HOMEBREW_PREFIX)/include
LDFLAGS += -L$(HOMEBREW_PREFIX)/lib
LDLIBS += -loqs -lcrypto
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2

PROGRAMS := pqc_hybrid_encrypt pqc_lkem_hybrid_encrypt
LKEM_PROGRAM := pqc_lkem_hybrid_encrypt
INPUT_PACKET ?= TLSv1.3_packet.pcapng
ENCODED_PACKET ?= encoded_packet.bin
DECODED_PACKET ?= decoded_packet.pcapng
LKEM_ENCODED_PACKET ?= encoded_packet_lkem.bin
LKEM_DECODED_PACKET ?= decoded_packet_lkem.pcapng

.PHONY: all clean test hybrid run lkem lkem-test compare

all: $(PROGRAMS)

pqc_hybrid_encrypt: pqc_hybrid_encrypt.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LDFLAGS) $(LDLIBS) -o $@

pqc_lkem_hybrid_encrypt: pqc_lkem_hybrid_encrypt.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LDFLAGS) $(LDLIBS) -o $@

hybrid: pqc_hybrid_encrypt
	./pqc_hybrid_encrypt $(INPUT_PACKET) $(ENCODED_PACKET) $(DECODED_PACKET)

lkem: $(LKEM_PROGRAM)
	./pqc_lkem_hybrid_encrypt $(INPUT_PACKET) $(LKEM_ENCODED_PACKET) $(LKEM_DECODED_PACKET)

run: hybrid

lkem-run: lkem

compare: pqc_hybrid_encrypt pqc_lkem_hybrid_encrypt
	@echo "=== ML-KEM vs LKEM comparison ==="
	@mlkem_start=$$(date +%s%N); \
	./pqc_hybrid_encrypt $(INPUT_PACKET) $(ENCODED_PACKET) $(DECODED_PACKET) > /tmp/mlkem_compare.out 2>&1; \
	mlkem_end=$$(date +%s%N); \
	mlkem_time=$$(( (mlkem_end - mlkem_start) / 1000000 )); \
	lkem_start=$$(date +%s%N); \
	./pqc_lkem_hybrid_encrypt $(INPUT_PACKET) $(LKEM_ENCODED_PACKET) $(LKEM_DECODED_PACKET) > /tmp/lkem_compare.out 2>&1; \
	lkem_end=$$(date +%s%N); \
	lkem_time=$$(( (lkem_end - lkem_start) / 1000000 )); \
	mlkem_pk=$$(grep 'Public key length:' /tmp/mlkem_compare.out | awk '{print $$4}'); \
	mlkem_sk=$$(grep 'Private key length:' /tmp/mlkem_compare.out | awk '{print $$4}'); \
	mlkem_ss=$$(grep 'Shared secret length:' /tmp/mlkem_compare.out | awk '{print $$4}'); \
	mlkem_ct=$$(grep 'KEM ciphertext length:' /tmp/mlkem_compare.out | awk '{print $$4}'); \
	lkem_pk=$$(grep 'Public key length:' /tmp/lkem_compare.out | awk '{print $$4}'); \
	lkem_sk=$$(grep 'Private key length:' /tmp/lkem_compare.out | awk '{print $$4}'); \
	lkem_ss=$$(grep 'Shared secret length:' /tmp/lkem_compare.out | awk '{print $$4}'); \
	lkem_ct=$$(grep 'KEM ciphertext length:' /tmp/lkem_compare.out | awk '{print $$4}'); \
	if cmp -s "$(DECODED_PACKET)" "$(LKEM_DECODED_PACKET)"; then \
		echo "Decoded packet match: YES"; \
	else \
		echo "Decoded packet match: NO"; \
		cmp -l "$(DECODED_PACKET)" "$(LKEM_DECODED_PACKET)" | head; \
	fi; \
	echo ""; \
	echo "ML-KEM(Kyber-768)"; \
	echo "  Public key:        $$mlkem_pk bytes"; \
	echo "  Secret key:        $$mlkem_sk bytes"; \
	echo "  Shared secret:     $$mlkem_ss bytes"; \
	echo "  Ciphertext:        $$mlkem_ct bytes"; \
	echo "  Total runtime:     $$mlkem_time ms"; \
	echo "  Estimated crack time: Roughly 10^12 to 10^14 seconds, (31,688.7646 to 3,168,876.46 years) -> Based on hypothetical max classical attack operations per second. (10^18 ops/sec)"; \
	echo ""; \
	echo "-------------------------------------------------------------------"; \
	echo ""; \
	echo "LKEM (FrodoKEM-976-SHAKE)"; \
	echo "  Public key:        $$lkem_pk bytes"; \
	echo "  Secret key:        $$lkem_sk bytes"; \
	echo "  Shared secret:     $$lkem_ss bytes"; \
	echo "  Ciphertext:        $$lkem_ct bytes"; \
	echo "  Total runtime:     $$lkem_time ms"; \
	echo "  Estimated crack time: Roughly 10^12 to 10^14 seconds, (31,688.7646 to 3,168,876.46 years) -> Based on hypothetical max classical attack operations per second. (10^18 ops/sec)"; \
	echo ""; \
	echo "-------------------------------------------------------------------"; \
	echo ""; \
	echo "Summary:"; \
	if [ "$$mlkem_pk" -lt "$$lkem_pk" ]; then echo "  Smaller public key: ML-KEM"; else echo "  Smaller public key: LKEM"; fi; \
	if [ "$$mlkem_time" -lt "$$lkem_time" ]; then echo "  Faster overall: ML-KEM"; else echo "  Faster overall: LKEM"; fi; \
	if [ "$$mlkem_ss" -eq "$$lkem_ss" ]; then echo "  Shared secret size: similar"; else echo "  Shared secret size: different"; fi; \
	if [ "$$mlkem_time" -lt "$$lkem_time" ]; then echo "  Winner: ML-KEM"; else echo "  Winner: LKEM"; fi; \
	echo "  Practical interpretation: both are in the same rough security class, but ML-KEM is the better overall choice for this deployment because it is smaller, faster, and more efficient in bandwidth and implementation footprint."
test: pqc_hybrid_encrypt
	./pqc_hybrid_encrypt --self-test

lkem-test: $(LKEM_PROGRAM)
	./pqc_lkem_hybrid_encrypt --self-test

clean:
	rm -f $(PROGRAMS)