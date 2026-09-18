#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <oqs/oqs.h>

static void print_hex(const char *label, const uint8_t *data, size_t length) {
    printf("%s (%zu bytes): ", label, length);
    for (size_t index = 0; index < length; index++) {
        printf("%02x", data[index]);
    }
    putchar('\n');
}

int main(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        fprintf(stderr, "ML-KEM-768 not available\n");
        return 1;
    }

    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret_enc = malloc(kem->length_shared_secret);
    uint8_t *shared_secret_dec = malloc(kem->length_shared_secret);

    // Receiver generates a keypair
    OQS_KEM_keypair(kem, public_key, secret_key);
    print_hex("Receiver public key", public_key, kem->length_public_key);

    // Sender encapsulates a shared secret using the receiver's public key
    OQS_KEM_encaps(kem, ciphertext, shared_secret_enc, public_key);
    print_hex("Sent ciphertext", ciphertext, kem->length_ciphertext);
    print_hex("Sender shared secret", shared_secret_enc, kem->length_shared_secret);

    // Receiver decapsulates using their secret key
    OQS_KEM_decaps(kem, shared_secret_dec, ciphertext, secret_key);
    print_hex("Receiver shared secret", shared_secret_dec, kem->length_shared_secret);

    int match = 1;
    for (size_t i = 0; i < kem->length_shared_secret; i++) {
        if (shared_secret_enc[i] != shared_secret_dec[i]) match = 0;
    }
    printf("Shared secrets match: %s\n", match ? "yes" : "no");

    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(shared_secret_enc);
    free(shared_secret_dec);
    OQS_KEM_free(kem);
    return 0;
}
