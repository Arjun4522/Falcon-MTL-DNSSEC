#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <openssl/sha.h>

#define WOTS_KEY_SIZE (18 * 24) // 432 bytes (P = 18, N = 24)
#define FALCON512_PUBLIC_KEY_SIZE 897 // Falcon-512 public key size
#define MAX_NAME_LENGTH 256
#define N 24 // SHA-192 for WOTS+

// SHA-256
void sha256_hash(const uint8_t *input, size_t len, uint8_t output[32]) {
    SHA256(input, len, output);
}

// SHA-192
void hash_sha192(const uint8_t *in, size_t inlen, uint8_t *out) {
    uint8_t full[32];
    SHA256(in, inlen, full);
    memcpy(out, full, N);
}

// Generate random bytes
void generate_random_bytes(uint8_t *buf, size_t len) {
    static int initialized = 0;
    if (!initialized) {
        srand(time(NULL));
        initialized = 1;
    }
    for (size_t i = 0; i < len; i++) {
        buf[i] = rand() % 256;
    }
}

// WOTS+ public key generation
void wots_gen_pk(const uint8_t sk[18][24], uint8_t pk[18][24]) {
    for (int i = 0; i < 18; i++) {
        memcpy(pk[i], sk[i], 24);
        for (int j = 0; j < 65535; j++) {
            uint8_t temp[24];
            hash_sha192(pk[i], 24, temp);
            memcpy(pk[i], temp, 24);
        }
    }
}

// WOTS+ signature (simplified: use private key chains as signature)
void wots_sign(const uint8_t *msg, size_t len, const uint8_t sk[18][24], uint8_t signature[18][24]) {
    uint8_t msg_hash[32];
    sha256_hash(msg, len, msg_hash);
    for (int i = 0; i < 18; i++) {
        memcpy(signature[i], sk[i], 24); // Simplified signature
    }
}

// Calculate key tag
uint16_t calculate_key_tag(const uint8_t *pubkey, size_t pubkey_len, uint8_t algorithm) {
    unsigned long sum = 0;
    uint8_t dnskey[2048];
    uint16_t flags = (algorithm == 8) ? htons(257) : htons(256); // 257 for KSK, 256 for ZSK
    uint8_t protocol = 3;
    size_t dnskey_len = 0;

    memcpy(dnskey, &flags, 2);
    dnskey_len += 2;
    dnskey[dnskey_len++] = protocol;
    dnskey[dnskey_len++] = algorithm; // 8 for WOTS+, 16 for Falcon
    memcpy(dnskey + dnskey_len, pubkey, pubkey_len);
    dnskey_len += pubkey_len;

    for (size_t i = 0; i < dnskey_len; i++) {
        if (i % 2 == 0) sum += (dnskey[i] << 8);
        else sum += dnskey[i];
    }
    sum += (sum >> 16) & 0xFFFF;
    return sum & 0xFFFF;
}

// Load key from file
size_t load_key(const char *filename, uint8_t *key, size_t expected_len) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Failed to open %s\n", filename);
        exit(1);
    }
    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    fseek(f, 0, SEEK_SET);
    printf("Loading %s: actual size %zu, expected %zu\n", filename, len, expected_len);
    if (len != expected_len) {
        fprintf(stderr, "Key %s size %zu, expected %zu\n", filename, len, expected_len);
        fclose(f);
        exit(1);
    }
    if (fread(key, 1, len, f) != len) {
        fprintf(stderr, "Failed to read %s\n", filename);
        fclose(f);
        exit(1);
    }
    fclose(f);
    return len;
}

// Save signature
void save_signature(const uint8_t *sig, size_t len, const char *filename) {
    FILE *f = fopen(filename, "wb");
    if (!f) {
        fprintf(stderr, "Failed to open %s\n", filename);
        exit(1);
    }
    if (fwrite(sig, 1, len, f) != len) {
        fprintf(stderr, "Failed to write %s\n", filename);
        fclose(f);
        exit(1);
    }
    fclose(f);
}

// Canonicalize domain name
void canonicalize_name(const char *name, char *output) {
    strcpy(output, name);
    size_t len = strlen(output);
    if (len > 0 && output[len - 1] == '.') {
        output[len - 1] = '\0';
    }
    for (size_t i = 0; i < len; i++) {
        if (output[i] >= 'A' && output[i] <= 'Z') {
            output[i] += ('a' - 'A');
        }
    }
}

// Encode to Base64
void to_base64(const uint8_t *input, size_t len, char *output) {
    const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, j = 0;
    for (i = 0; i < len - 2; i += 3) {
        output[j++] = b64[(input[i] >> 2) & 0x3F];
        output[j++] = b64[((input[i] & 0x3) << 4) | ((input[i + 1] >> 4) & 0x0F)];
        output[j++] = b64[((input[i + 1] & 0x0F) << 2) | ((input[i + 2] >> 6) & 0x3)];
        output[j++] = b64[input[i + 2] & 0x3F];
    }
    if (i < len) {
        output[j++] = b64[(input[i] >> 2) & 0x3F];
        if (i == len - 1) {
            output[j++] = b64[((input[i] & 0x3) << 4)];
            output[j++] = '=';
            output[j++] = '=';
        } else {
            output[j++] = b64[((input[i] & 0x3) << 4) | ((input[i + 1] >> 4) & 0xF)];
            output[j++] = b64[((input[i + 1] & 0xF) << 2)];
            output[j++] = '=';
        }
    }
    output[j] = '\0';
}

int main(int argc, char *argv[]) {
    printf("WOTS+ KSK / Falcon-512 ZSK DNSKEY RRset Signing Demonstration\n");
    printf("=======================================\n\n");

    // Parse arguments
    char zone[MAX_NAME_LENGTH] = "example.com.";
    int ttl = 3600;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            strncpy(zone, argv[i + 1], MAX_NAME_LENGTH - 1);
            zone[MAX_NAME_LENGTH - 1] = '\0';
            i++;
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            ttl = atoi(argv[i + 1]);
            i++;
        }
    }

    // Load keys
    uint8_t ksk_pub[WOTS_KEY_SIZE], zsk_pub[FALCON512_PUBLIC_KEY_SIZE];
    uint8_t ksk_priv[WOTS_KEY_SIZE];
    size_t ksk_pub_len = load_key("ksk0_pubkey_wots.bin", ksk_pub, WOTS_KEY_SIZE);
    size_t zsk_pub_len = load_key("zsk_pubkey.bin", zsk_pub, FALCON512_PUBLIC_KEY_SIZE);
    size_t ksk_priv_len = load_key("ksk0_privkey_wots.bin", ksk_priv, WOTS_KEY_SIZE);
    if (ksk_pub_len != WOTS_KEY_SIZE || zsk_pub_len != FALCON512_PUBLIC_KEY_SIZE || ksk_priv_len != WOTS_KEY_SIZE) {
        fprintf(stderr, "Invalid key sizes\n");
        return 1;
    }

    // Canonicalize zone name
    char canonical_zone[MAX_NAME_LENGTH];
    canonicalize_name(zone, canonical_zone);

    // Encode public keys to Base64
    char ksk_base64[2048], zsk_base64[2048];
    to_base64(ksk_pub, WOTS_KEY_SIZE, ksk_base64);
    to_base64(zsk_pub, FALCON512_PUBLIC_KEY_SIZE, zsk_base64);

    // Create canonical DNSKEY RRset
    char ksk_record[4096], zsk_record[4096];
    snprintf(ksk_record, sizeof(ksk_record), "%s %d IN DNSKEY 257 3 8 %s", canonical_zone, ttl, ksk_base64); // WOTS+ alg 8
    snprintf(zsk_record, sizeof(zsk_record), "%s %d IN DNSKEY 256 3 16 %s", canonical_zone, ttl, zsk_base64); // Falcon alg 16

    char canonical_dnskey[8192];
    size_t canonical_dnskey_len = 0;
    char *sorted_records[2] = {ksk_record, zsk_record};
    if (strcmp(ksk_record, zsk_record) > 0) {
        sorted_records[0] = zsk_record;
        sorted_records[1] = ksk_record;
    }
    for (int i = 0; i < 2; i++) {
        size_t len = strlen(sorted_records[i]);
        memcpy(canonical_dnskey + canonical_dnskey_len, sorted_records[i], len);
        canonical_dnskey_len += len;
    }

    // Prepare RRSIG data
    uint8_t dnskey_hash[32];
    sha256_hash((uint8_t *)canonical_dnskey, canonical_dnskey_len, dnskey_hash);

    uint8_t rrsig_data[4096];
    size_t rrsig_data_len = 0;
    uint16_t type_covered = htons(48); // DNSKEY
    uint8_t algorithm = 8; // WOTS+
    uint8_t labels = 0;
    for (const char *p = canonical_zone; *p; p++) if (*p == '.') labels++;
    labels++;
    uint32_t original_ttl = htonl(ttl);
    time_t now;
    FILE *f = fopen("timestamp_wots.bin", "rb");
    if (!f || fread(&now, sizeof(time_t), 1, f) != 1) {
        fprintf(stderr, "Failed to read timestamp_wots.bin\n");
        if (f) fclose(f);
        return 1;
    }
    fclose(f);
    uint32_t sig_expiration = htonl((uint32_t)(now + 30 * 24 * 3600));
    uint32_t sig_inception = htonl((uint32_t)now);
    uint16_t key_tag = htons(calculate_key_tag(ksk_pub, WOTS_KEY_SIZE, 8));

    memcpy(rrsig_data, &type_covered, 2);
    rrsig_data_len += 2;
    rrsig_data[rrsig_data_len++] = algorithm;
    rrsig_data[rrsig_data_len++] = labels;
    memcpy(rrsig_data + rrsig_data_len, &original_ttl, 4);
    rrsig_data_len += 4;
    memcpy(rrsig_data + rrsig_data_len, &sig_expiration, 4);
    rrsig_data_len += 4;
    memcpy(rrsig_data + rrsig_data_len, &sig_inception, 4);
    rrsig_data_len += 4;
    memcpy(rrsig_data + rrsig_data_len, &key_tag, 2);
    rrsig_data_len += 2;
    strcpy((char *)rrsig_data + rrsig_data_len, canonical_zone);
    rrsig_data_len += strlen(canonical_zone) + 1;
    memcpy(rrsig_data + rrsig_data_len, dnskey_hash, 32);
    rrsig_data_len += 32;

    // Generate WOTS+ signature
    uint8_t ksk_sk[18][24], signature[18][24];
    memcpy(ksk_sk[0], ksk_priv, WOTS_KEY_SIZE); // Load private key
    wots_sign(rrsig_data, rrsig_data_len, ksk_sk, signature);

    // Save signature
    save_signature(signature[0], WOTS_KEY_SIZE, "dnskey_rrsig_wots.out");
    printf("DNSKEY signature saved to dnskey_rrsig_wots.out\n");

    return 0;
}