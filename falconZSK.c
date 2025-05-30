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
#define FALCON512_KEYGEN_TMP_SIZE FALCON_TMPSIZE_KEYGEN(FALCON_LOGN) // 15879 bytes
#define FALCON512_SIGNDYN_TMP_SIZE FALCON_TMPSIZE_SIGNDYN(FALCON_LOGN) // 39943 bytes

typedef struct {
    unsigned char pubkey[FALCON512_PUBLIC_KEY_SIZE];
    size_t pubkey_len;
    unsigned char privkey[FALCON512_PRIVATE_KEY_SIZE];
    size_t privkey_len;
} FalconKeyPair;

typedef struct {
    char *data;
    int ttl;
    char *type;
} RR;

void sha256_hash(const unsigned char *input, size_t len, unsigned char output[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input, len);
    EVP_DigestFinal_ex(ctx, output, NULL);
    EVP_MD_CTX_free(ctx);
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

int falcon512_keygen(FalconKeyPair *keypair, int index) {
    shake256_context rng;
    unsigned char seed[48] = {0};
    seed[47] = (unsigned char)index;
    shake256_init_prng_from_seed(&rng, seed, sizeof(seed));
    shake256_flip(&rng);

    unsigned char tmp[FALCON512_KEYGEN_TMP_SIZE];
    keypair->pubkey_len = FALCON512_PUBLIC_KEY_SIZE;
    keypair->privkey_len = FALCON512_PRIVATE_KEY_SIZE;

    int ret = falcon_keygen_make(&rng, FALCON_LOGN,
                                 keypair->privkey, keypair->privkey_len,
                                 keypair->pubkey, keypair->pubkey_len,
                                 tmp, sizeof(tmp));
    if (ret != 0) {
        fprintf(stderr, "Falcon key generation failed for index %d: %d\n", index, ret);
        return 0;
    }
    return 1;
}

void save_key(const unsigned char *key, size_t key_len, const char *filename) {
    FILE *f = fopen(filename, "wb");
    if (!f) {
        fprintf(stderr, "Failed to open %s for writing\n", filename);
        exit(1);
    }
    if (fwrite(key, 1, key_len, f) != key_len) {
        fprintf(stderr, "Failed to write to %s\n", filename);
        fclose(f);
        exit(1);
    }
    fclose(f);
}

uint16_t calculate_key_tag(const unsigned char *pubkey, size_t pubkey_len, int is_ksk) {
    unsigned long sum = 0;
    unsigned char dnskey[2048];
    uint16_t flags = is_ksk ? 257 : 256; // KSK or ZSK
    uint8_t protocol = 3; // DNSSEC
    uint8_t algorithm = 16; // Falcon-512
    size_t dnskey_len = 0;

    flags = htons(flags);
    memcpy(dnskey, &flags, 2);
    dnskey_len += 2;
    dnskey[dnskey_len++] = protocol;
    dnskey[dnskey_len++] = algorithm;
    memcpy(dnskey + dnskey_len, pubkey, pubkey_len);
    dnskey_len += pubkey_len;

    for (size_t i = 0; i < dnskey_len; i++) {
        if (i % 2 == 0) {
            sum += (dnskey[i] << 8);
        } else {
            sum += dnskey[i];
        }
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

int falcon512_sign(const unsigned char *data, size_t data_len,
                   const unsigned char *privkey, size_t privkey_len,
                   unsigned char *signature, size_t *sig_len) {
    shake256_context rng;
    unsigned char seed[48] = {0};
    seed[47] = 0xFF;
    shake256_init_prng_from_seed(&rng, seed, sizeof(seed));
    shake256_flip(&rng);

    unsigned char tmp[FALCON512_SIGNDYN_TMP_SIZE];
    *sig_len = FALCON512_SIGNATURE_SIZE;

    int ret = falcon_sign_dyn(&rng, signature, sig_len,
                              privkey, privkey_len,
                              data, data_len,
                              1, tmp, sizeof(tmp));
    if (ret != 0) {
        fprintf(stderr, "Falcon signing failed: %d\n", ret);
        return 0;
    }
    return 1;
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
            token = strtok(NULL, "");
            if (token) {
                while (*token == ' ') token++;
                data = strdup(token);
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
    for (int i = 0; i < rrset_count; i++) {
        sorted_rrset[i] = malloc(512);
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

void sign_rrset(FalconKeyPair *zsk, const char *owner, int ttl,
                time_t inception, time_t expiration, RR *rrset, int rrset_count) {
    char canonical_data[4096];
    size_t canonical_len;
    canonicalize_rrset(rrset, rrset_count, owner, canonical_data, &canonical_len, ttl);

    unsigned char rrset_hash[32];
    sha256_hash((unsigned char *)canonical_data, canonical_len, rrset_hash);

    unsigned char rrsig_data[4096];
    size_t rrsig_data_len = 0;
    uint16_t type_covered = 0; // Dynamic based on first record type
    if (strcmp(rrset[0].type, "A") == 0) type_covered = 1;
    else if (strcmp(rrset[0].type, "AAAA") == 0) type_covered = 28;
    else if (strcmp(rrset[0].type, "TXT") == 0) type_covered = 16;
    else {
        fprintf(stderr, "Unsupported RR type: %s\n", rrset[0].type);
        return;
    }
    type_covered = htons(type_covered);
    uint8_t algorithm = 16;
    uint8_t labels = 0;
    for (const char *p = owner; *p; p++) if (*p == '.') labels++;
    if (owner[strlen(owner) - 1] != '.') labels++;
    uint32_t original_ttl = htonl(ttl);
    uint32_t sig_expiration = htonl((uint32_t)expiration);
    uint32_t sig_inception = htonl((uint32_t)inception);
    uint16_t key_tag = calculate_key_tag(zsk->pubkey, zsk->pubkey_len, 0);
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
    memcpy(rrsig_data + rrsig_data_len, rrset_hash, 32);
    rrsig_data_len += 32;

    unsigned char signature[FALCON512_SIGNATURE_SIZE];
    size_t sig_len;
    if (!falcon512_sign(rrsig_data, rrsig_data_len,
                        zsk->privkey, zsk->privkey_len,
                        signature, &sig_len)) {
        fprintf(stderr, "Failed to sign RRset\n");
        return;
    }

    printf("%s %d IN DNSKEY 256 3 16 ", owner, ttl);
    char pubkey_base64[2048];
    to_base64(zsk->pubkey, zsk->pubkey_len, pubkey_base64);
    printf("%s\n", pubkey_base64);

    for (int i = 0; i < rrset_count; i++) {
        printf("%s %d IN %s %s\n", owner, rrset[i].ttl, rrset[i].type, rrset[i].data);
    }

    char sig_base64[2048];
    to_base64(signature, sig_len, sig_base64);
    printf("%s %d IN RRSIG %s %d %d %d %ld %ld %d %s %s\n",
           owner, ttl, rrset[0].type, algorithm, labels, ttl,
           (long)expiration, (long)inception, key_tag, signer_name, sig_base64);
}

int main(int argc, char *argv[]) {
    printf("Falcon-512 RRset Signing Demonstration\n");
    printf("=====================================\n\n");

    const char *owner = "www.example.com.";
    int ttl = 3600;
    const char *rrset_file = "rrset.conf";

    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            owner = argv[++i];
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            ttl = atoi(argv[++i]);
            if (ttl <= 0) {
                fprintf(stderr, "Invalid TTL: %d\n", ttl);
                return 1;
            }
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            rrset_file = argv[++i];
        } else {
            fprintf(stderr, "Usage: %s [-o <owner>] [-t <ttl>] [-f <rrset_file>]\n", argv[0]);
            return 1;
        }
    }

    FalconKeyPair zsk;
    if (!falcon512_keygen(&zsk, 1)) {
        fprintf(stderr, "ZSK generation failed\n");
        return 1;
    }

    // Save ZSK keys
    save_key(zsk.pubkey, zsk.pubkey_len, "zsk_pubkey.bin");
    save_key(zsk.privkey, zsk.privkey_len, "zsk_privkey.bin");
    printf("ZSK keys saved to zsk_pubkey.bin and zsk_privkey.bin\n");

    // Read timestamp
    time_t now;
    FILE *f = fopen("timestamp.bin", "rb");
    if (!f || fread(&now, sizeof(time_t), 1, f) != 1) {
        fprintf(stderr, "Failed to read timestamp.bin\n");
        return 1;
    }
    fclose(f);
    time_t inception = now;
    time_t expiration = now + 30 * 24 * 3600;

    // Load RRset
    RR *rrset;
    int rrset_count;
    if (!load_rrset(rrset_file, &rrset, &rrset_count, ttl)) {
        fprintf(stderr, "Failed to load RRset from %s\n", rrset_file);
        return 1;
    }

    printf("Signing RRset for %s\n", owner);
    sign_rrset(&zsk, owner, ttl, inception, expiration, rrset, rrset_count);

    free_rrset(rrset, rrset_count);
    return 0;
}