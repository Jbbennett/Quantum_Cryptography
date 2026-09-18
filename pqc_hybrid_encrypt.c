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

// Print a label followed by a byte buffer formatted as hexadecimal.
static void print_hex(const char *label, const uint8_t *data, size_t length) {
    printf("%s (%zu bytes): ", label, length);
    for (size_t index = 0; index < length; index++) {
        printf("%02x", data[index]);
    }
    putchar('\n');
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

// Encrypt plaintext with AES-256-GCM using the 32-byte ML-KEM shared secret as
// the AES key. The IV and tag are public values that accompany the ciphertext.
static int aes_gcm_encrypt(const uint8_t *key, const uint8_t *iv,
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

// The exported packet is a self-contained header followed by the AES-GCM
// ciphertext, so it can be written to disk and later parsed back out again.
typedef struct {
    uint32_t kem_ciphertext_len;
    uint32_t payload_len;
} packet_header_t;

int main(int argc, char **argv) {
    // input_len records the number of bytes read from the input file.
    size_t input_len;
    // input_data points to the input file contents held in memory.
    uint8_t *input_data;

    // The program needs the original packet plus paths for the encoded and
    // decoded output files.
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <input-packet-file> <encoded-packet-file> <decoded-packet-file>\n", argv[0]);
        return 1;
    }

    // Load the input bytes that will be encrypted (e.g. a captured TLS record).
    input_data = read_file(argv[1], &input_len);
    if (input_data == NULL) {
        return 1;
    }

    printf("Input packet: %s (%zu bytes)\n", argv[1], input_len);

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
    // Encrypt the input using the sender's ML-KEM-derived AES key.
    int ct_len = aes_gcm_encrypt(shared_secret_enc, iv, input_data, input_len, ciphertext, tag);

    // Assemble the exported packet: a small header followed by the KEM
    // ciphertext, IV, authentication tag, and AES-GCM ciphertext in sequence.
    packet_header_t header = {
        .kem_ciphertext_len = (uint32_t)kem->length_ciphertext,
        .payload_len = (uint32_t)ct_len,
    };
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
    printf("Encoded packet written to %s (%zu bytes)\n", argv[2], packet_len);

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
    printf("Encoded packet capture written to %s\n", pcapng_path);
    print_hex("KEM ciphertext", kem_ciphertext, kem->length_ciphertext);
    print_hex("AES-GCM IV", iv, GCM_IV_LEN);
    print_hex("AES-GCM authentication tag", tag, GCM_TAG_LEN);
    print_hex("AES-GCM ciphertext", ciphertext, (size_t)ct_len);
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
        size_t expected_len = sizeof(read_header) + read_header.kem_ciphertext_len + GCM_IV_LEN + GCM_TAG_LEN + read_header.payload_len;
        if (read_header.kem_ciphertext_len != kem->length_ciphertext || read_packet_len != expected_len) {
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
            int pt_len = aes_gcm_decrypt(shared_secret_dec, read_iv, read_payload, read_header.payload_len, read_tag, decrypted);
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
            } else {
                printf("Decoded packet written to %s (%d bytes)\n", argv[3], pt_len);
                printf("Decoded data matches the original input packet\n");
            }
        }
    }
    free(read_packet);

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
