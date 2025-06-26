#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include "falcon.h"

// Falcon-512 constants
#define FALCON_LOGN 9
#define FALCON512_PUBLIC_KEY_SIZE FALCON_PUBKEY_SIZE(FALCON_LOGN)   // 897 bytes
#define FALCON512_PRIVATE_KEY_SIZE FALCON_PRIVKEY_SIZE(FALCON_LOGN) // 1281 bytes
#define FALCON512_SIGNATURE_SIZE FALCON_SIG_CT_SIZE(FALCON_LOGN)    // 666 bytes
#define FALCON512_SIGN_TMP_SIZE FALCON_TMPSIZE_SIGNDYN(FALCON_LOGN) // Typically ~35025 bytes

typedef struct {
    char *data;
    int ttl;
    char *type;
} RR;

void sha256_hash(const unsigned char *input, size_t len, unsigned char output[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_MD_CTX\n");
        exit(1);
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, input, len) != 1 ||
        EVP_DigestFinal_ex(ctx, output, NULL) != 1) {
        fprintf(stderr, "SHA-256 hash computation failed\n");
        EVP_MD_CTX_free(ctx);
        exit(1);
    }
    EVP_MD_CTX_free(ctx);
}

size_t load_key(const char *filename, unsigned char *key, size_t max_len) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Failed to open %s\n", filename);
        exit(1);
    }
    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len > max_len) {
        fprintf(stderr, "Key %s too large\n", filename);
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

void save_key(const unsigned char *key, size_t len, const char *filename) {
    FILE *f = fopen(filename, "wb");
    if (!f) {
        fprintf(stderr, "Failed to open %s\n", filename);
        exit(1);
    }
    if (fwrite(key, 1, len, f) != len) {
        fprintf(stderr, "Failed to write %s\n", filename);
        fclose(f);
        exit(1);
    }
    fclose(f);
}

void to_base64(const unsigned char *input, size_t len, char *output) {
    const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, j = 0;
    for (i = 0; i < len - 2; i += 3) {
        output[j++] = b64[(input[i] >> 2) & 0x3F];
        output[j++] = b64[((input[i] & 0x3) << 4) | ((input[i + 1] >> 4) & 0xF)];
        output[j++] = b64[((input[i + 1] & 0xF) << 2) | ((input[i + 2] >> 6) & 0x3)];
        output[j++] = b64[input[i + 2] & 0x3F];
    }
    if (i < len) {
        output[j++] = b64[(input[i] >> 2) & 0x3F];
        if (i == len - 1) {
            output[j++] = b64[(input[i] & 0x3) << 4];
            output[j++] = '=';
            output[j++] = '=';
        } else {
            output[j++] = b64[((input[i] & 0x3) << 4) | ((input[i + 1] >> 4) & 0xF)];
            output[j++] = b64[(input[i + 1] & 0xF) << 2];
            output[j++] = '=';
        }
    }
    output[j] = '\0';
}

uint16_t calculate_key_tag(const unsigned char *pubkey, size_t pubkey_len) {
    unsigned long sum = 0;
    unsigned char dnskey[2048];
    uint16_t flags = htons(256); // ZSK
    uint8_t protocol = 3;
    uint8_t algorithm = 16;
    size_t dnskey_len = 0;

    memcpy(dnskey, &flags, 2);
    dnskey_len += 2;
    dnskey[dnskey_len++] = protocol;
    dnskey[dnskey_len++] = algorithm;
    memcpy(dnskey + dnskey_len, pubkey, pubkey_len);
    dnskey_len += pubkey_len;

    for (size_t i = 0; i < dnskey_len; i++) {
        if (i % 2 == 0) sum += (dnskey[i] << 8);
        else sum += dnskey[i];
    }
    sum += (sum >> 16) & 0xFFFF;
    return sum & 0xFFFF;
}

void canonicalize_name(const char *name, char *output) {
    strcpy(output, name);
    size_t len = strlen(output);
    if (len > 0 && output[len - 1] == '.') {
        output[len - 1] = '\0';
    }
    for (size_t i = 0; output[i]; i++) {
        if (output[i] >= 'A' && output[i] <= 'Z') {
            output[i] += ('a' - 'A');
        }
    }
}

int load_rrset(const char *filename, RR **rrset, int *rrset_count, int default_ttl) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "Failed to open %s\n", filename);
        return 0;
    }
    char line[512];
    *rrset_count = 0;
    RR *temp = NULL;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = '\0';
        if (strlen(line) == 0) continue;
        temp = realloc(temp, (*rrset_count + 1) * sizeof(RR));
        if (!temp) {
            fprintf(stderr, "Memory allocation failed\n");
            fclose(f);
            return 0;
        }
        char *token = strtok(line, " ");
        if (!token) continue;
        int ttl = default_ttl;
        char *type = NULL, *data = NULL;
        if (atoi(token) > 0) {
            ttl = atoi(token);
            token = strtok(NULL, " ");
        }
        if (token && strcmp(token, "IN") == 0) {
            token = strtok(NULL, " ");
        }
        if (token) {
            type = strdup(token);
            if (!type) {
                fprintf(stderr, "Memory allocation failed\n");
                fclose(f);
                for (int i = 0; i < *rrset_count; i++) {
                    free(temp[i].type);
                    free(temp[i].data);
                }
                free(temp);
                return 0;
            }
            token = strtok(NULL, "");
            if (token) {
                while (*token == ' ') token++;
                data = strdup(token);
                if (!data) {
                    fprintf(stderr, "Memory allocation failed\n");
                    fclose(f);
                    free(type);
                    for (int i = 0; i < *rrset_count; i++) {
                        free(temp[i].type);
                        free(temp[i].data);
                    }
                    free(temp);
                    return 0;
                }
            }
        }
        if (type && data) {
            temp[*rrset_count].ttl = ttl;
            temp[*rrset_count].type = type;
            temp[*rrset_count].data = data;
            (*rrset_count)++;
        } else {
            free(type);
            free(data);
        }
    }
    fclose(f);
    *rrset = temp;
    return *rrset_count > 0;
}

void free_rrset(RR *rrset, int rrset_count) {
    if (!rrset) return;
    for (int i = 0; i < rrset_count; i++) {
        free(rrset[i].type);
        free(rrset[i].data);
    }
    free(rrset);
}

void canonicalize_rrset(RR *rrset, int rrset_count, const char *owner,
                        char *output, size_t *output_len, int ttl) {
    char canonical_owner[256];
    canonicalize_name(owner, canonical_owner);
    char **sorted_rrset = malloc(rrset_count * sizeof(char *));
    if (!sorted_rrset) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    for (int i = 0; i < rrset_count; i++) {
        sorted_rrset[i] = malloc(512);
        if (!sorted_rrset[i]) {
            fprintf(stderr, "Memory allocation failed\n");
            for (int j = 0; j < i; j++) free(sorted_rrset[j]);
            free(sorted_rrset);
            exit(1);
        }
        snprintf(sorted_rrset[i], 512, "%d IN %s %s", rrset[i].ttl, rrset[i].type, rrset[i].data);
    }
    for (int i = 0; i < rrset_count - 1; i++) {
        for (int j = i + 1; j < rrset_count; j++) {
            if (strcmp(sorted_rrset[i], sorted_rrset[j]) > 0) {
                char *temp = sorted_rrset[i];
                sorted_rrset[i] = sorted_rrset[j];
                sorted_rrset[j] = temp;
            }
        }
    }
    *output_len = 0;
    for (int i = 0; i < rrset_count; i++) {
        char record[512];
        snprintf(record, sizeof(record), "%s %s", canonical_owner, sorted_rrset[i]);
        size_t len = strlen(record);
        memcpy(output + *output_len, record, len);
        *output_len += len;
        free(sorted_rrset[i]);
    }
    free(sorted_rrset);
}

void benchmark_zsk_generation() {
    shake256_context rng;
    unsigned char seed[48] = {0};
    seed[47] = 0xFE;
    shake256_init_prng_from_seed(&rng, seed, sizeof(seed));
    shake256_flip(&rng);

    unsigned char pubkey[FALCON512_PUBLIC_KEY_SIZE];
    unsigned char privkey[FALCON512_PRIVATE_KEY_SIZE];
    unsigned char tmp[FALCON_TMPSIZE_KEYGEN(FALCON_LOGN)];

    if (falcon_keygen_make(&rng, FALCON_LOGN,
                         privkey, FALCON512_PRIVATE_KEY_SIZE,
                         pubkey, FALCON512_PUBLIC_KEY_SIZE,
                         tmp, sizeof(tmp)) != 0) {
        fprintf(stderr, "Failed to generate ZSK\n");
        exit(1);
    }
}

void benchmark_rrset_signing(int iterations) {
    shake256_context rng;
    unsigned char seed[48] = {0};
    seed[47] = 0xFE;
    shake256_init_prng_from_seed(&rng, seed, sizeof(seed));
    shake256_flip(&rng);

    // Generate a test key pair
    unsigned char pubkey[FALCON512_PUBLIC_KEY_SIZE];
    unsigned char privkey[FALCON512_PRIVATE_KEY_SIZE];
    unsigned char tmp[FALCON_TMPSIZE_KEYGEN(FALCON_LOGN)];
    
    if (falcon_keygen_make(&rng, FALCON_LOGN,
                         privkey, FALCON512_PRIVATE_KEY_SIZE,
                         pubkey, FALCON512_PUBLIC_KEY_SIZE,
                         tmp, sizeof(tmp)) != 0) {
        fprintf(stderr, "Failed to generate ZSK\n");
        exit(1);
    }

    // Create test data to sign
    const char* test_data = "www.example.com. 3600 IN A 192.0.2.1";
    size_t data_len = strlen(test_data);
    unsigned char signature[FALCON512_SIGNATURE_SIZE];
    size_t sig_len = FALCON512_SIGNATURE_SIZE;

    for (int i = 0; i < iterations; i++) {
        if (falcon_sign_dyn(&rng, signature, &sig_len,
                          privkey, FALCON512_PRIVATE_KEY_SIZE,
                          (unsigned char*)test_data, data_len,
                          1, tmp, sizeof(tmp)) != 0) {
            fprintf(stderr, "Failed to sign RRset\n");
            exit(1);
        }
    }
}

int main(int argc, char *argv[]) {
    printf("Falcon-512 RRset Signing Demonstration\n");
    printf("=====================================\n\n");

    // Parse arguments
    char owner[256] = "www.example.com.";
    int ttl = 3600;
    char rrset_file[256] = "rrset.conf";
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            strncpy(owner, argv[i + 1], sizeof(owner) - 1);
            owner[sizeof(owner) - 1] = '\0';
            i++;
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            ttl = atoi(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            strncpy(rrset_file, argv[i + 1], sizeof(rrset_file) - 1);
            rrset_file[sizeof(rrset_file) - 1] = '\0';
            i++;
        }
    }

    // Generate ZSK
    shake256_context rng;
    unsigned char seed[48] = {0};
    seed[47] = 0xFE; // Different seed from KSK
    shake256_init_prng_from_seed(&rng, seed, sizeof(seed));
    shake256_flip(&rng);

    unsigned char pubkey[FALCON512_PUBLIC_KEY_SIZE];
    unsigned char privkey[FALCON512_PRIVATE_KEY_SIZE];
    unsigned char tmp[FALCON512_SIGN_TMP_SIZE];

    if (falcon_keygen_make(&rng, FALCON_LOGN,
                           privkey, FALCON512_PRIVATE_KEY_SIZE,
                           pubkey, FALCON512_PUBLIC_KEY_SIZE,
                           tmp, FALCON512_SIGN_TMP_SIZE) != 0) {
        fprintf(stderr, "Failed to generate ZSK\n");
        return 1;
    }

    save_key(pubkey, FALCON512_PUBLIC_KEY_SIZE, "zsk_pubkey.bin");
    save_key(privkey, FALCON512_PRIVATE_KEY_SIZE, "zsk_privkey.bin");
    printf("ZSK keys saved to zsk_pubkey.bin and zsk_privkey.bin\n");

    // Print DNSKEY
    char pubkey_b64[2048];
    to_base64(pubkey, FALCON512_PUBLIC_KEY_SIZE, pubkey_b64);
    printf("Signing RRset for %s\n", owner);
    printf("%s %d IN DNSKEY 256 3 16 %s\n", owner, ttl, pubkey_b64);

    // Load RRset
    RR *rrset;
    int rrset_count;
    printf("%s", owner);
    if (!load_rrset(rrset_file, &rrset, &rrset_count, ttl)) {
        fprintf(stderr, "Failed to load RRset\n");
        return 1;
    }
    for (int i = 0; i < rrset_count; i++) {
        printf("%s %d IN %s %s\n", owner, rrset[i].ttl, rrset[i].type, rrset[i].data);
    }

    // Canonicalize RRset
    char canonical[4096];
    size_t canonical_len;
    canonicalize_rrset(rrset, rrset_count, owner, canonical, &canonical_len, ttl);
    printf("Canonicalized RRset:\n%.*s\n", (int)canonical_len, canonical);

    // Prepare RRSIG data
    unsigned char rr_hash[32];
    sha256_hash((unsigned char *)canonical, canonical_len, rr_hash);

    unsigned char rrsig_data[4096];
    size_t rrsig_data_len = 0;
    uint16_t type_covered = htons(1); // A
    uint8_t algorithm = 16;
    uint8_t labels = 0;
    char canonical_owner[256];
    canonicalize_name(owner, canonical_owner);
    for (const char *p = canonical_owner; *p; p++) if (*p == '.') labels++;
    labels++; // Count the last label
    uint32_t original_ttl = htonl(ttl);

    // Load timestamp
    time_t now;
    FILE *f = fopen("timestamp.bin", "rb");
    if (!f || fread(&now, sizeof(time_t), 1, f) != 1) {
        fprintf(stderr, "Failed to read timestamp.bin\n");
        if (f) fclose(f);
        free_rrset(rrset, rrset_count);
        return 1;
    }
    fclose(f);
    time_t inception = now;
    time_t expiration = now + 30 * 24 * 3600;

    uint32_t sig_expiration = htonl((uint32_t)expiration);
    uint32_t sig_inception = htonl((uint32_t)inception);
    uint16_t key_tag = htons(calculate_key_tag(pubkey, FALCON512_PUBLIC_KEY_SIZE));
    char signer_name[256];
    canonicalize_name(owner, signer_name);

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
    strcpy((char *)rrsig_data + rrsig_data_len, signer_name);
    rrsig_data_len += strlen(signer_name) + 1;
    memcpy(rrsig_data + rrsig_data_len, rr_hash, 32);
    rrsig_data_len += 32;

    // Sign RRset
    unsigned char sig[FALCON512_SIGNATURE_SIZE];
    size_t sig_len = FALCON512_SIGNATURE_SIZE;
    if (falcon_sign_dyn(&rng, sig, &sig_len, privkey, FALCON512_PRIVATE_KEY_SIZE,
                        rrsig_data, rrsig_data_len, 1,
                        tmp, FALCON512_SIGN_TMP_SIZE) != 0) {
        fprintf(stderr, "Failed to sign RRset\n");
        free_rrset(rrset, rrset_count);
        return 1;
    }

    // Save signature
    char sig_b64[2048];
    to_base64(sig, sig_len, sig_b64);
    FILE *sig_f = fopen("zsk_rrsig.out", "w");
    if (!sig_f || fprintf(sig_f, "%s\n", sig_b64) < 0) {
        fprintf(stderr, "Failed to write zsk_rrsig.out\n");
        if (sig_f) fclose(sig_f);
        free_rrset(rrset, rrset_count);
        return 1;
    }
    fclose(sig_f);
    printf("%s Signatures saved to zsk_rrsig.out\n", owner);

    free_rrset(rrset, rrset_count);
    return 0;
}