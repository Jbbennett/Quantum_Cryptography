#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
// liboqs API for post-quantum algorithms, including ML-KEM.
#include <oqs/oqs.h>
// OpenSSL high-level cryptography API for AES-GCM.
#include <openssl/evp.h>
// OpenSSL cryptographically secure random-number functions.
#include <openssl/rand.h>

// AES-256 uses a 32-byte key. ML-KEM-768 produces a shared secret of this size.
#define AES_KEY_LEN 32
// Twelve bytes is the standard IV length for AES-GCM.
#define GCM_IV_LEN 12
// A 16-byte GCM tag provides the full authentication-tag length.
#define GCM_TAG_LEN 16
// AES-GCM's internal GHASH subkey is one 128-bit block.
#define GCM_GHASH_SUBKEY_LEN 16
// SHA-256 produces a 32-byte digest.
#define SHA256_LEN 32

// Print a label followed by a byte buffer formatted as hexadecimal.
static void print_hex(const char *label, const uint8_t *data, size_t length) {
    printf("%s (%zu bytes): ", label, length);
    for (size_t index = 0; index < length; index++) {
        printf("%02x", data[index]);
    }
    putchar('\n');
}

// Print a SHA-256 digest on its own line so terminal output remains readable.
static void print_hash(const char *label, const uint8_t digest[SHA256_LEN]) {
    printf("%s:\n  ", label);
    for (size_t index = 0; index < SHA256_LEN; index++) {
        printf("%02x", digest[index]);
    }
    putchar('\n');
}

// Hash a byte buffer with SHA-256 and write the digest to the caller's buffer.
static int sha256_digest(const uint8_t *data, size_t length,
                         uint8_t digest[SHA256_LEN]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int digest_length = 0;
    int ok = ctx != NULL &&
             EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, data, length) == 1 &&
             EVP_DigestFinal_ex(ctx, digest, &digest_length) == 1 &&
             digest_length == SHA256_LEN;
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

// Read an entire binary file into a newly allocated buffer.
// The caller owns the returned buffer and must release it with free().
static uint8_t *read_file(const char *path, size_t *length) {
    // Open the file in binary read mode so its bytes are preserved exactly.
    FILE *file = fopen(path, "rb");
    long file_size;
    uint8_t *data;

    if (file == NULL) {
        perror(path);
        return NULL;
    }

    // Seek to the end first to determine how much memory the file requires.
    if (fseek(file, 0, SEEK_END) != 0 || (file_size = ftell(file)) < 0 ||
        fseek(file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Could not determine size of '%s'\n", path);
        fclose(file);
        return NULL;
    }

    // The encryption calls below accept int lengths, so reject larger files.
    if ((unsigned long)file_size > (unsigned long)INT_MAX) {
        fprintf(stderr, "File '%s' is too large to encrypt\n", path);
        fclose(file);
        return NULL;
    }

    // Allocate at least one byte even for an empty file, because malloc(0)
    // is allowed to return NULL on some platforms.
    *length = (size_t)file_size;
    data = malloc(*length > 0 ? *length : 1);
    if (data == NULL) {
        fprintf(stderr, "Could not allocate memory for '%s'\n", path);
        fclose(file);
        return NULL;
    }

    // Read the file only when it contains data; empty files need no read.
    if (*length > 0 && fread(data, 1, *length, file) != *length) {
        fprintf(stderr, "Could not read '%s'\n", path);
        free(data);
        fclose(file);
        return NULL;
    }

    fclose(file);
    return data;
}

// Write a byte buffer to a binary file. Return 0 on success and -1 on error.
static int write_file(const char *path, const uint8_t *data, size_t length) {
    // Opening with "wb" creates or truncates the output file.
    FILE *file = fopen(path, "wb");
    int result = 0;

    if (file == NULL) {
        perror(path);
        return -1;
    }

    // Write exactly the requested number of bytes.
    if (length > 0 && fwrite(data, 1, length, file) != length) {
        fprintf(stderr, "Could not write '%s'\n", path);
        result = -1;
    }

    // Closing can also fail, for example if buffered data cannot be flushed.
    if (fclose(file) != 0) {
        fprintf(stderr, "Could not close '%s'\n", path);
        result = -1;
    }
    return result;
}

// Wireshark's own link-layer type for undissected raw bytes, so the encoded
// packet is shown as a plain hex payload instead of being misparsed as Ethernet/IP.
#define PCAPNG_LINKTYPE_USER0 147

// Round a length up to the next 4-byte boundary, as required between blocks.
static uint32_t pcapng_pad4(uint32_t length) {
    return (length + 3u) & ~3u;
}

// Wrap a byte buffer in a minimal pcapng file (Section Header, Interface
// Description, and a single Enhanced Packet Block) so tools such as
// Wireshark can open the encoded packet the same way as a real capture.
static int write_pcapng(const char *path, const uint8_t *data, size_t length) {
    FILE *file = fopen(path, "wb");
    if (file == NULL) {
        perror(path);
        return -1;
    }

    uint32_t zero = 0;
    int ok = 1;

    // Section Header Block: identifies the file as pcapng and its byte order.
    uint32_t shb_type = 0x0A0D0D0A;
    uint32_t shb_len = 28;
    uint32_t byte_order_magic = 0x1A2B3C4D;
    uint16_t version_major = 1, version_minor = 0;
    int64_t section_len = -1;
    ok &= fwrite(&shb_type, 4, 1, file) == 1;
    ok &= fwrite(&shb_len, 4, 1, file) == 1;
    ok &= fwrite(&byte_order_magic, 4, 1, file) == 1;
    ok &= fwrite(&version_major, 2, 1, file) == 1;
    ok &= fwrite(&version_minor, 2, 1, file) == 1;
    ok &= fwrite(&section_len, 8, 1, file) == 1;
    ok &= fwrite(&shb_len, 4, 1, file) == 1;

    // Interface Description Block: declares the link-layer type used below.
    uint32_t idb_type = 0x00000001;
    uint32_t idb_len = 20;
    uint16_t link_type = PCAPNG_LINKTYPE_USER0, reserved = 0;
    uint32_t snap_len = 0;
    ok &= fwrite(&idb_type, 4, 1, file) == 1;
    ok &= fwrite(&idb_len, 4, 1, file) == 1;
    ok &= fwrite(&link_type, 2, 1, file) == 1;
    ok &= fwrite(&reserved, 2, 1, file) == 1;
    ok &= fwrite(&snap_len, 4, 1, file) == 1;
    ok &= fwrite(&idb_len, 4, 1, file) == 1;

    // Enhanced Packet Block: holds the encoded packet as its single payload.
    uint32_t padded_len = pcapng_pad4((uint32_t)length);
    uint32_t epb_len = 32 + padded_len;
    uint32_t epb_type = 0x00000006;
    uint32_t interface_id = 0;
    uint32_t ts_high = 0, ts_low = 0;
    uint32_t cap_len = (uint32_t)length, orig_len = (uint32_t)length;
    ok &= fwrite(&epb_type, 4, 1, file) == 1;
    ok &= fwrite(&epb_len, 4, 1, file) == 1;
    ok &= fwrite(&interface_id, 4, 1, file) == 1;
    ok &= fwrite(&ts_high, 4, 1, file) == 1;
    ok &= fwrite(&ts_low, 4, 1, file) == 1;
    ok &= fwrite(&cap_len, 4, 1, file) == 1;
    ok &= fwrite(&orig_len, 4, 1, file) == 1;
    if (length > 0) {
        ok &= fwrite(data, 1, length, file) == length;
    }
    if (padded_len > length) {
        ok &= fwrite(&zero, 1, padded_len - (uint32_t)length, file) == padded_len - (uint32_t)length;
    }
    ok &= fwrite(&epb_len, 4, 1, file) == 1;

    if (!ok) {
        fprintf(stderr, "Could not write '%s'\n", path);
    }
    if (fclose(file) != 0) {
        fprintf(stderr, "Could not close '%s'\n", path);
        ok = 0;
    }
    return ok ? 0 : -1;
}

// The exported packet header is authenticated as AES-GCM additional data.
typedef struct {
    uint32_t kem_ciphertext_len;
    uint32_t payload_len;
} packet_header_t;

static int packet_layout_valid(size_t packet_len,
                               const packet_header_t *header,
                               size_t kem_ciphertext_len) {
    size_t expected_len = sizeof(*header);

    if (header->kem_ciphertext_len != kem_ciphertext_len ||
        expected_len > SIZE_MAX - header->kem_ciphertext_len) {
        return 0;
    }
    expected_len += header->kem_ciphertext_len;
    if (expected_len > SIZE_MAX - GCM_IV_LEN - GCM_TAG_LEN ||
        expected_len + GCM_IV_LEN + GCM_TAG_LEN > SIZE_MAX - header->payload_len) {
        return 0;
    }
    expected_len += GCM_IV_LEN + GCM_TAG_LEN + header->payload_len;
    return packet_len == expected_len;
}

// Encrypt plaintext with AES-256-GCM using the 32-byte ML-KEM shared secret as
// the AES key. The IV and tag are public values that accompany the ciphertext.
static int aes_gcm_encrypt(const uint8_t *key, const uint8_t *iv,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *plaintext, size_t plaintext_len,
                            uint8_t *ciphertext, uint8_t *tag) {
    // OpenSSL uses this context to hold the state of the AES-GCM operation.
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    // Select AES-256-GCM. The key and IV are supplied in the next call.
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    // Tell OpenSSL that this operation uses a 12-byte IV.
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL);
    // Set the AES key and the per-message IV.
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    // Authenticate the packet metadata without encrypting it.
    EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len);

    // Encrypt the plaintext(ABE Cipher) into the ciphertext buffer.
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len);
    ciphertext_len = len;

    // Finish the encryption operation. GCM does not normally add padding.
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    // Retrieve the authentication tag generated by GCM.
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag);
    // Release OpenSSL's encryption context.
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// Decrypt AES-256-GCM ciphertext and verify its authentication tag.
// Return the plaintext length on success, or -1 if authentication fails.
static int aes_gcm_decrypt(const uint8_t *key, const uint8_t *iv,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *ciphertext, size_t ciphertext_len,
                            const uint8_t *tag, uint8_t *plaintext) {
    // Create a new context for the decryption operation.
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len, ret;

    // Select AES-256-GCM for decryption.
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    // Configure the expected IV length and then set the key and IV.
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    // Authenticate the same packet metadata used during encryption.
    EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len);

    // Decrypt the ciphertext into the caller-provided plaintext buffer.
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ciphertext_len);
    plaintext_len = len;

    // Provide the expected tag. OpenSSL checks it when finalizing decryption.
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, (void *)tag);
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    // The context is no longer needed after finalization.
    EVP_CIPHER_CTX_free(ctx);

    // A non-positive result means authentication failed: the data may have
    // been modified, or the key, IV, or tag may be incorrect.
    if (ret <= 0) return -1;
    plaintext_len += len;
    return plaintext_len;
}

static int report_self_test(const char *name, int passed) {
    printf("[%s] %s\n", passed ? "PASS" : "FAIL", name);
    return passed ? 0 : 1;
}

static int self_test_round_trip(const char *name, const uint8_t *key,
                                const uint8_t *data, size_t data_len) {
    static const uint8_t aad[] = "self-test metadata";
    uint8_t iv[GCM_IV_LEN];
    uint8_t tag[GCM_TAG_LEN];
    uint8_t *ciphertext = malloc(data_len > 0 ? data_len : 1);
    uint8_t *decoded = malloc(data_len > 0 ? data_len : 1);
    int ciphertext_len;
    int decoded_len;
    int passed = 0;

    if (ciphertext != NULL && decoded != NULL &&
        RAND_bytes(iv, GCM_IV_LEN) == 1) {
        ciphertext_len = aes_gcm_encrypt(key, iv, aad, sizeof(aad) - 1,
                                          data, data_len, ciphertext, tag);
        decoded_len = aes_gcm_decrypt(key, iv, aad, sizeof(aad) - 1,
                                      ciphertext, (size_t)ciphertext_len,
                                      tag, decoded);
        passed = decoded_len >= 0 && (size_t)decoded_len == data_len &&
                 memcmp(data, decoded, data_len) == 0;
    }

    free(ciphertext);
    free(decoded);
    return report_self_test(name, passed);
}

static int self_test_authentication(const uint8_t *key,
                                    const uint8_t *kem_ciphertext,
                                    size_t kem_ciphertext_len,
                                    OQS_KEM *kem, const uint8_t *secret_key) {
    static const uint8_t aad[] = "authenticated test metadata";
    static const uint8_t data[] = "tamper detection test";
    uint8_t iv[GCM_IV_LEN];
    uint8_t tag[GCM_TAG_LEN];
    uint8_t wrong_key[AES_KEY_LEN];
    uint8_t *ciphertext = malloc(sizeof(data) - 1);
    uint8_t *decoded = malloc(sizeof(data) - 1);
    uint8_t *tampered_kem_ciphertext = malloc(kem_ciphertext_len);
    uint8_t *tampered_shared_secret = malloc(kem->length_shared_secret);
    int ciphertext_len;
    int failures = 0;

    if (ciphertext == NULL || decoded == NULL || tampered_kem_ciphertext == NULL ||
        tampered_shared_secret == NULL || RAND_bytes(iv, GCM_IV_LEN) != 1) {
        free(ciphertext);
        free(decoded);
        free(tampered_kem_ciphertext);
        free(tampered_shared_secret);
        return report_self_test("tamper test setup", 0);
    }

    ciphertext_len = aes_gcm_encrypt(key, iv, aad, sizeof(aad) - 1,
                                      data, sizeof(data) - 1, ciphertext, tag);

    ciphertext[0] ^= 1;
    failures += report_self_test("modified ciphertext rejected",
        aes_gcm_decrypt(key, iv, aad, sizeof(aad) - 1, ciphertext,
                        (size_t)ciphertext_len, tag, decoded) < 0);
    ciphertext[0] ^= 1;

    uint8_t modified_aad[sizeof(aad) - 1];
    memcpy(modified_aad, aad, sizeof(modified_aad));
    modified_aad[0] ^= 1;
    failures += report_self_test("modified AAD rejected",
        aes_gcm_decrypt(key, iv, modified_aad, sizeof(modified_aad), ciphertext,
                        (size_t)ciphertext_len, tag, decoded) < 0);
    failures += report_self_test("truncated AAD rejected",
        aes_gcm_decrypt(key, iv, aad, sizeof(aad) - 2, ciphertext,
                        (size_t)ciphertext_len, tag, decoded) < 0);

    tag[0] ^= 1;
    failures += report_self_test("modified authentication tag rejected",
        aes_gcm_decrypt(key, iv, aad, sizeof(aad) - 1, ciphertext,
                        (size_t)ciphertext_len, tag, decoded) < 0);
    tag[0] ^= 1;

    iv[0] ^= 1;
    failures += report_self_test("modified IV rejected",
        aes_gcm_decrypt(key, iv, aad, sizeof(aad) - 1, ciphertext,
                        (size_t)ciphertext_len, tag, decoded) < 0);
    iv[0] ^= 1;

    failures += report_self_test("truncated ciphertext rejected",
        aes_gcm_decrypt(key, iv, aad, sizeof(aad) - 1, ciphertext,
                        (size_t)ciphertext_len - 1, tag, decoded) < 0);
    failures += report_self_test("empty ciphertext rejected for non-empty input",
        aes_gcm_decrypt(key, iv, aad, sizeof(aad) - 1, ciphertext, 0,
                        tag, decoded) < 0);

    memcpy(wrong_key, key, sizeof(wrong_key));
    wrong_key[0] ^= 1;
    failures += report_self_test("wrong AES key rejected",
        aes_gcm_decrypt(wrong_key, iv, aad, sizeof(aad) - 1, ciphertext,
                        (size_t)ciphertext_len, tag, decoded) < 0);

    memcpy(tampered_kem_ciphertext, kem_ciphertext, kem_ciphertext_len);
    tampered_kem_ciphertext[0] ^= 1;
    OQS_KEM_decaps(kem, tampered_shared_secret, tampered_kem_ciphertext, secret_key);
    failures += report_self_test("modified ML-KEM ciphertext rejected",
        aes_gcm_decrypt(tampered_shared_secret, iv, aad, sizeof(aad) - 1,
                        ciphertext, (size_t)ciphertext_len, tag, decoded) < 0);

    free(ciphertext);
    free(decoded);
    free(tampered_kem_ciphertext);
    free(tampered_shared_secret);
    return failures;
}

static int self_test_packet_layout(size_t kem_ciphertext_len) {
    packet_header_t header = {
        .kem_ciphertext_len = (uint32_t)kem_ciphertext_len,
        .payload_len = 17,
    };
    size_t valid_length = sizeof(header) + kem_ciphertext_len +
                          GCM_IV_LEN + GCM_TAG_LEN + header.payload_len;
    int failures = 0;

    failures += report_self_test("valid packet layout accepted",
        packet_layout_valid(valid_length, &header, kem_ciphertext_len));
    failures += report_self_test("truncated packet rejected",
        !packet_layout_valid(valid_length - 1, &header, kem_ciphertext_len));
    failures += report_self_test("extra packet data rejected",
        !packet_layout_valid(valid_length + 1, &header, kem_ciphertext_len));

    header.kem_ciphertext_len++;
    failures += report_self_test("wrong KEM ciphertext length rejected",
        !packet_layout_valid(valid_length, &header, kem_ciphertext_len));
    header.kem_ciphertext_len = (uint32_t)kem_ciphertext_len;

    header.payload_len++;
    failures += report_self_test("wrong payload length rejected",
        !packet_layout_valid(valid_length, &header, kem_ciphertext_len));

    header.kem_ciphertext_len = UINT32_MAX;
    failures += report_self_test("impossible packet length rejected",
        !packet_layout_valid(valid_length, &header, kem_ciphertext_len));
    return failures;
}

static int self_test_hashes(void) {
    static const uint8_t first_data[] = "hash test data";
    static const uint8_t second_data[] = "hash test datb";
    uint8_t first_hash[SHA256_LEN];
    uint8_t second_hash[SHA256_LEN];
    int hashes_work = sha256_digest(first_data, sizeof(first_data) - 1, first_hash) == 0 &&
                      sha256_digest(first_data, sizeof(first_data) - 1, second_hash) == 0;
    int failures = 0;

    failures += report_self_test("same data produces same SHA-256 hash",
        hashes_work && memcmp(first_hash, second_hash, SHA256_LEN) == 0);
    failures += report_self_test("changed data produces different SHA-256 hash",
        sha256_digest(second_data, sizeof(second_data) - 1, second_hash) == 0 &&
        memcmp(first_hash, second_hash, SHA256_LEN) != 0);
    return failures;
}

static int run_self_tests(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    uint8_t *kem_ciphertext = NULL;
    uint8_t *shared_secret_enc = NULL;
    uint8_t *shared_secret_dec = NULL;
    uint8_t *large_data = NULL;
    uint8_t binary_data[256];
    uint8_t embedded_null_data[] = {'a', 'b', '\0', 'c', 'd'};
    int failures = 0;

    printf("SELF-TESTS\n==========\n");
    if (kem == NULL) {
        fprintf(stderr, "ML-KEM-768 not available\n");
        return 1;
    }

    public_key = malloc(kem->length_public_key);
    secret_key = malloc(kem->length_secret_key);
    kem_ciphertext = malloc(kem->length_ciphertext);
    shared_secret_enc = malloc(kem->length_shared_secret);
    shared_secret_dec = malloc(kem->length_shared_secret);
    large_data = malloc(1024 * 1024);
    for (size_t index = 0; index < sizeof(binary_data); index++) {
        binary_data[index] = (uint8_t)index;
    }

    if (public_key == NULL || secret_key == NULL || kem_ciphertext == NULL ||
        shared_secret_enc == NULL || shared_secret_dec == NULL || large_data == NULL ||
        OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS ||
        OQS_KEM_encaps(kem, kem_ciphertext, shared_secret_enc, public_key) != OQS_SUCCESS ||
        OQS_KEM_decaps(kem, shared_secret_dec, kem_ciphertext, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "Could not prepare self-tests\n");
        failures = 1;
        goto cleanup;
    }

    failures += report_self_test("ML-KEM shared secrets match",
        memcmp(shared_secret_enc, shared_secret_dec, kem->length_shared_secret) == 0);
    failures += self_test_round_trip("empty input", shared_secret_enc, NULL, 0);
    failures += self_test_round_trip("1-byte input", shared_secret_enc, binary_data, 1);
    failures += self_test_round_trip("16-byte input", shared_secret_enc, binary_data, 16);
    failures += self_test_round_trip("32-byte input", shared_secret_enc, binary_data, 32);
    failures += self_test_round_trip("128-byte input", shared_secret_enc, binary_data, 128);
    failures += self_test_round_trip("all byte values", shared_secret_enc,
                                     binary_data, sizeof(binary_data));
    failures += self_test_round_trip("embedded null bytes", shared_secret_enc,
                                     embedded_null_data, sizeof(embedded_null_data));

    for (size_t index = 0; index < 1024 * 1024; index++) {
        large_data[index] = (uint8_t)(index * 31u);
    }
    failures += self_test_round_trip("1 MiB input", shared_secret_enc,
                                     large_data, 1024 * 1024);
    failures += self_test_packet_layout(kem->length_ciphertext);
    failures += self_test_authentication(shared_secret_enc, kem_ciphertext,
                                         kem->length_ciphertext, kem, secret_key);
    failures += self_test_hashes();

    uint8_t iv_one[GCM_IV_LEN], iv_two[GCM_IV_LEN];
    uint8_t tag_one[GCM_TAG_LEN], tag_two[GCM_TAG_LEN];
    uint8_t ciphertext_one[sizeof(binary_data)], ciphertext_two[sizeof(binary_data)];
    int ciphertext_one_len = aes_gcm_encrypt(shared_secret_enc, iv_one,
        NULL, 0, binary_data, sizeof(binary_data), ciphertext_one, tag_one);
    int ciphertext_two_len = aes_gcm_encrypt(shared_secret_enc, iv_two,
        NULL, 0, binary_data, sizeof(binary_data), ciphertext_two, tag_two);
    int different_outputs = ciphertext_one_len == ciphertext_two_len &&
        memcmp(iv_one, iv_two, GCM_IV_LEN) != 0 &&
        (memcmp(ciphertext_one, ciphertext_two, sizeof(binary_data)) != 0 ||
         memcmp(tag_one, tag_two, GCM_TAG_LEN) != 0);
    failures += report_self_test("fresh IV creates different ciphertext", different_outputs);

    uint8_t fixed_iv[GCM_IV_LEN] = {0};
    uint8_t fixed_tag_one[GCM_TAG_LEN], fixed_tag_two[GCM_TAG_LEN];
    uint8_t fixed_ciphertext_one[sizeof(binary_data)];
    uint8_t fixed_ciphertext_two[sizeof(binary_data)];
    int fixed_length_one = aes_gcm_encrypt(shared_secret_enc, fixed_iv,
        NULL, 0, binary_data, sizeof(binary_data), fixed_ciphertext_one, fixed_tag_one);
    int fixed_length_two = aes_gcm_encrypt(shared_secret_enc, fixed_iv,
        NULL, 0, binary_data, sizeof(binary_data), fixed_ciphertext_two, fixed_tag_two);
    failures += report_self_test("same key and IV are deterministic",
        fixed_length_one == fixed_length_two &&
        memcmp(fixed_ciphertext_one, fixed_ciphertext_two, sizeof(binary_data)) == 0 &&
        memcmp(fixed_tag_one, fixed_tag_two, GCM_TAG_LEN) == 0);

cleanup:
    free(public_key);
    free(secret_key);
    free(kem_ciphertext);
    free(shared_secret_enc);
    free(shared_secret_dec);
    free(large_data);
    OQS_KEM_free(kem);
    printf("\nSelf-tests %s (%d failure%s)\n", failures == 0 ? "passed" : "failed",
           failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
    // input_len records the number of bytes read from the input file.
    size_t input_len;
    // input_data points to the input file contents held in memory.
    uint8_t *input_data;

    // The program needs the original packet plus paths for the encoded and
    // decoded output files.
    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) {
        return run_self_tests();
    }
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <input-packet-file> <encoded-packet-file> <decoded-packet-file>\n", argv[0]);
        fprintf(stderr, "       %s --self-test\n", argv[0]);
        return 1;
    }

    // Load the input bytes that will be encrypted (e.g. a captured TLS record).
    input_data = read_file(argv[1], &input_len);
    if (input_data == NULL) {
        return 1;
    }

    // Create an ML-KEM-768 algorithm instance from liboqs.
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        fprintf(stderr, "ML-KEM-768 not available\n");
        free(input_data);
        return 1;
    }

    // Allocate buffers using the sizes required by the selected ML-KEM.
    uint8_t *public_key = malloc(kem->length_public_key);
    // The private key must remain secret and is used for decapsulation.
    uint8_t *secret_key = malloc(kem->length_secret_key);
    // This is sent to the receiver so it can recover the shared secret.
    uint8_t *kem_ciphertext = malloc(kem->length_ciphertext);
    // Sender-side and receiver-side copies of the same ML-KEM shared secret.
    uint8_t *shared_secret_enc = malloc(kem->length_shared_secret);
    uint8_t *shared_secret_dec = malloc(kem->length_shared_secret);
    // AES-GCM output and its decryption destination.
    uint8_t *ciphertext = malloc(input_len > 0 ? input_len : 1);
    uint8_t *decrypted = malloc(input_len > 0 ? input_len : 1);
    uint8_t encoded_hash[SHA256_LEN];
    // Per-message AES-GCM metadata: a public IV and authentication tag.
    uint8_t iv[GCM_IV_LEN];
    uint8_t tag[GCM_TAG_LEN];

    // Receiver: generate the long-term ML-KEM public/private key pair.
    OQS_KEM_keypair(kem, public_key, secret_key);

    // Sender: use the receiver's public key to create a KEM ciphertext and a
    // shared secret. Only the KEM ciphertext needs to be sent to the receiver.
    OQS_KEM_encaps(kem, kem_ciphertext, shared_secret_enc, public_key);
    // Generate a fresh random IV for this AES-GCM encryption.
    RAND_bytes(iv, GCM_IV_LEN);

    // GCM does not change the payload length, so the header can be authenticated
    // before encryption and then serialized unchanged into the packet.
    packet_header_t header = {
        .kem_ciphertext_len = (uint32_t)kem->length_ciphertext,
        .payload_len = (uint32_t)input_len,
    };
    // Encrypt the input using the sender's ML-KEM-derived AES key.
    int ct_len = aes_gcm_encrypt(shared_secret_enc, iv,
                                 (const uint8_t *)&header, sizeof(header),
                                 input_data, input_len, ciphertext, tag);

    // Assemble the exported packet: a small header followed by the KEM
    // ciphertext, IV, authentication tag, and AES-GCM ciphertext in sequence.
    size_t packet_len = sizeof(header) + kem->length_ciphertext + GCM_IV_LEN + GCM_TAG_LEN + (size_t)ct_len;
    uint8_t *packet = malloc(packet_len);
    uint8_t *cursor = packet;
    memcpy(cursor, &header, sizeof(header)); cursor += sizeof(header);
    memcpy(cursor, kem_ciphertext, kem->length_ciphertext); cursor += kem->length_ciphertext;
    memcpy(cursor, iv, GCM_IV_LEN); cursor += GCM_IV_LEN;
    memcpy(cursor, tag, GCM_TAG_LEN); cursor += GCM_TAG_LEN;
    memcpy(cursor, ciphertext, (size_t)ct_len);

    if (write_file(argv[2], packet, packet_len) != 0) {
        free(packet);
        free(public_key); free(secret_key); free(kem_ciphertext);
        free(shared_secret_enc); free(shared_secret_dec);
        free(ciphertext); free(decrypted); free(input_data);
        OQS_KEM_free(kem);
        return 1;
    }
    // Also wrap the same encoded packet in a pcapng capture file, so it can
    // be opened in Wireshark alongside the original TLS capture.
    char pcapng_path[PATH_MAX];
    snprintf(pcapng_path, sizeof(pcapng_path), "%s.pcapng", argv[2]);
    if (write_pcapng(pcapng_path, packet, packet_len) != 0) {
        free(packet);
        free(public_key); free(secret_key); free(kem_ciphertext);
        free(shared_secret_enc); free(shared_secret_dec);
        free(ciphertext); free(decrypted); free(input_data);
        OQS_KEM_free(kem);
        return 1;
    }
    if (sha256_digest(packet, packet_len, encoded_hash) != 0) {
        fprintf(stderr, "Could not calculate the encrypted packet SHA-256 hash\n");
        free(packet);
        free(public_key); free(secret_key); free(kem_ciphertext);
        free(shared_secret_enc); free(shared_secret_dec);
        free(ciphertext); free(decrypted); free(input_data);
        OQS_KEM_free(kem);
        return 1;
    }
    free(packet);

    // Decoder: read the exported packet back from disk, as a receiver would,
    // and parse the header, KEM ciphertext, IV, tag, and AES-GCM ciphertext.
    size_t read_packet_len;
    uint8_t *read_packet = read_file(argv[2], &read_packet_len);
    int status = 0;
    if (read_packet == NULL || read_packet_len < sizeof(header)) {
        fprintf(stderr, "Could not read exported packet '%s'\n", argv[2]);
        status = 1;
    } else {
        packet_header_t read_header;
        memcpy(&read_header, read_packet, sizeof(read_header));
        if (!packet_layout_valid(read_packet_len, &read_header,
                                 kem->length_ciphertext)) {
            fprintf(stderr, "Exported packet '%s' is malformed\n", argv[2]);
            status = 1;
        } else {
            uint8_t *rcursor = read_packet + sizeof(read_header);
            const uint8_t *read_kem_ct = rcursor; rcursor += read_header.kem_ciphertext_len;
            const uint8_t *read_iv = rcursor; rcursor += GCM_IV_LEN;
            const uint8_t *read_tag = rcursor; rcursor += GCM_TAG_LEN;
            const uint8_t *read_payload = rcursor;

            // Receiver: use the ML-KEM private key and KEM ciphertext to recover
            // the same shared secret independently of the sender.
            OQS_KEM_decaps(kem, shared_secret_dec, read_kem_ct, secret_key);
            // Decrypt and authenticate the AES-GCM ciphertext using the recovered key.
            int pt_len = aes_gcm_decrypt(shared_secret_dec, read_iv,
                                         (const uint8_t *)&read_header, sizeof(read_header),
                                         read_payload, read_header.payload_len,
                                         read_tag, decrypted);
            if (pt_len < 0) {
                // A failed tag check means the ciphertext cannot be trusted.
                fprintf(stderr, "Decryption failed: authentication tag mismatch\n");
                status = 1;
            } else if ((size_t)pt_len != input_len || memcmp(input_data, decrypted, input_len) != 0) {
                // This verifies that the output has the same length and bytes as the input.
                fprintf(stderr, "Decryption failed: recovered data does not match the input packet\n");
                status = 1;
            } else if (write_file(argv[3], decrypted, (size_t)pt_len) != 0) {
                status = 1;
            }
        }
    }
    free(read_packet);

    printf("\nML-KEM\n======\n");
    printf("Public key length: %zu bytes\n", kem->length_public_key);
    printf("Private key length: %zu bytes\n", kem->length_secret_key);
    printf("Shared secret length: %zu bytes\n\n", kem->length_shared_secret);
    printf("KEM ciphertext length: %zu bytes\n", kem->length_ciphertext);

    printf("\nAES-GCM\n=======\n");
    printf("AES key length: %d bytes (KEM shared secret)\n", AES_KEY_LEN);
    printf("GHASH subkey length: %d bytes (internal AES-GCM value)\n",
           GCM_GHASH_SUBKEY_LEN);
    printf("AAD length: %zu bytes (packet header)\n\n", sizeof(packet_header_t));
    print_hex("AAD", (const uint8_t *)&header, sizeof(header));
    print_hex("IV", iv, GCM_IV_LEN);
    print_hex("Authentication tag", tag, GCM_TAG_LEN);
    printf("Ciphertext length: %d bytes\n", ct_len);

    const char *demo_string = "This is to test the encryption using a string";
    size_t demo_string_len = strlen(demo_string);
    uint8_t string_iv[GCM_IV_LEN];
    uint8_t string_tag[GCM_TAG_LEN];
    uint8_t *string_ciphertext = malloc(demo_string_len > 0 ? demo_string_len : 1);
    uint8_t *string_decoded = malloc(demo_string_len + 1);

    if (string_ciphertext == NULL || string_decoded == NULL ||
        RAND_bytes(string_iv, GCM_IV_LEN) != 1) {
        fprintf(stderr, "Could not prepare the string encryption test\n");
        free(string_ciphertext);
        free(string_decoded);
        status = 1;
    } else {
        int string_ciphertext_len = aes_gcm_encrypt(
            shared_secret_enc, string_iv, NULL, 0,
            (const uint8_t *)demo_string, demo_string_len,
            string_ciphertext, string_tag);
        int string_decoded_len = aes_gcm_decrypt(
            shared_secret_dec, string_iv, NULL, 0,
            string_ciphertext, (size_t)string_ciphertext_len,
            string_tag, string_decoded);

        if (string_decoded_len < 0 || (size_t)string_decoded_len != demo_string_len) {
            fprintf(stderr, "String decryption failed: authentication tag mismatch\n");
            status = 1;
        } else {
            string_decoded[string_decoded_len] = '\0';
            printf("\nString\n==================\n");
            printf("Original string:\n%s\n\n", demo_string);
            print_hex("Encrypted string", string_ciphertext,
                      (size_t)string_ciphertext_len);
            putchar('\n');
            printf("Decoded string:\n%s\n", string_decoded);
        }
    }
    free(string_ciphertext);
    free(string_decoded);

    uint8_t original_hash[SHA256_LEN];
    uint8_t decoded_hash[SHA256_LEN];
    if (status == 0 &&
        sha256_digest(input_data, input_len, original_hash) == 0 &&
        sha256_digest(decrypted, input_len, decoded_hash) == 0) {
        printf("\nSHA-256 hashes\n==============\n");
        print_hash("Original TLS file", original_hash);
        print_hash("Encrypted file", encoded_hash);
        print_hash("Decoded file", decoded_hash);
    } else {
        fprintf(stderr, "Could not calculate all SHA-256 file hashes\n");
    }

    printf("\nRESULTS\n=======\n");
    printf("Input packet: %s (%zu bytes)\n", argv[1], input_len);
    printf("Encoded packet written to %s (%zu bytes)\n", argv[2], packet_len);
    printf("Encoded packet capture written to %s\n", pcapng_path);
    if (status == 0) {
        printf("Decoded packet written to %s (%zu bytes)\n", argv[3], input_len);
        printf("Decoded data matches the original input packet\n");
    }

    // Release all allocated buffers and the liboqs algorithm object.
    free(public_key);
    free(secret_key);
    free(kem_ciphertext);
    free(shared_secret_enc);
    free(shared_secret_dec);
    free(ciphertext);
    free(decrypted);
    free(input_data);
    OQS_KEM_free(kem);
    return status;
}
