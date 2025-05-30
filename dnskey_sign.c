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
#define FALCON512_SIGNDYN_TMP_SIZE FALCON_TMPSIZE_SIGNDYN(FALCON_LOGN) // 39936 bytes

typedef struct {
    unsigned char pubkey[FALCON512_PUBLIC_KEY_SIZE];
    size_t pubkey_len;
    unsigned char privkey[FALCON512_PRIVATE_KEY_SIZE];
    size_t privkey_len;
} FalconKeyPair;

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

uint16_t calculate_key_tag(const unsigned char *pubkey, size_t pubkey_len, int is_ksk) {
    unsigned long sum = 0;
    unsigned char dnskey[2048];
    uint16_t flags = is_ksk ? 257 : 256;
    uint8_t protocol = 3;
    uint8_t algorithm = 16;
    size_t dnskey_len = 0;

    flags = htons(flags);
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

void canonicalize_dnskey_rrset(const unsigned char *ksk_pubkey, size_t ksk_len,
                               const unsigned char *zsk_pubkey, size_t zsk_len,
                               const char *owner, int ttl, char *output, size_t *output_len) {
    char canonical_owner[256];
    canonicalize_name(owner, canonical_owner);

    char ksk_base64[2048], zsk_base64[2048];
    to_base64(ksk_pubkey, ksk_len, ksk_base64);
    to_base64(zsk_pubkey, zsk_len, zsk_base64);

    char ksk_record[4096], zsk_record[4096];
    snprintf(ksk_record, sizeof(ksk_record), "%s %d IN DNSKEY 257 3 16 %s", canonical_owner, ttl, ksk_base64);
    snprintf(zsk_record, sizeof(zsk_record), "%s %d IN DNSKEY 256 3 16 %s", canonical_owner, ttl, zsk_base64);

    char *sorted_records[2] = {ksk_record, zsk_record};
    if (strcmp(ksk_record, zsk_record) > 0) {
        sorted_records[0] = zsk_record;
        sorted_records[1] = ksk_record;
    }

    *output_len = 0;
    for (int i = 0; i < 2; i++) {
        size_t len = strlen(sorted_records[i]);
        memcpy(output + *output_len, sorted_records[i], len);
        *output_len += len;
    }
}

void sign_dnskey_rrset(FalconKeyPair *ksk, FalconKeyPair *zsk, const char *owner, int ttl,
                       time_t inception, time_t expiration) {
    char canonical_data[4096];
    size_t canonical_len;
    canonicalize_dnskey_rrset(ksk->pubkey, ksk->pubkey_len, zsk->pubkey, zsk->pubkey_len,
                              owner, ttl, canonical_data, &canonical_len);

    unsigned char rrset_hash[32];
    sha256_hash((unsigned char *)canonical_data, canonical_len, rrset_hash);

    unsigned char rrsig_data[4096];
    size_t rrsig_data_len = 0;
    uint16_t type_covered = htons(48); // DNSKEY
    uint8_t algorithm = 16;
    uint8_t labels = 0;
    for (const char *p = owner; *p; p++) if (*p == '.') labels++;
    if (owner[strlen(owner) - 1] != '.') labels--;
    uint32_t original_ttl = htonl(ttl);
    uint32_t sig_expiration = htonl((uint32_t)expiration);
    uint32_t sig_inception = htonl((uint32_t)inception);
    uint16_t key_tag = calculate_key_tag(ksk->pubkey, ksk->pubkey_len, 1);
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
    if (!falcon512_sign(rrsig_data, rrsig_data_len, ksk->privkey, ksk->privkey_len, signature, &sig_len)) {
        fprintf(stderr, "Failed to sign DNSKEY RRset\n");
        return;
    }

    // Print output
    printf("%s %d IN DNSKEY 257 3 16 ", owner, ttl);
    char ksk_base64[2048];
    to_base64(ksk->pubkey, ksk->pubkey_len, ksk_base64);
    printf("%s\n", ksk_base64);

    printf("%s %d IN DNSKEY 256 3 16 ", owner, ttl);
    char zsk_base64[2048];
    to_base64(zsk->pubkey, zsk->pubkey_len, zsk_base64);
    printf("%s\n", zsk_base64);

    // Save RRSIG
    char sig_base64[2048];
    to_base64(signature, sig_len, sig_base64);
    FILE *sig_f = fopen("dnskey_rrsig.out", "w");
    if (!sig_f) {
        fprintf(stderr, "Failed to open dnskey_rrsig.out\n");
        return;
    }
    fprintf(sig_f, "%s\n", sig_base64);
    fclose(sig_f);
    printf("%s Signature saved to dnskey_rrsig.out\n", owner);
}

int main(int argc, char *argv[]) {
    printf("Falcon-512 DNSKEY RRset Signing Demonstration\n");
    printf("============================================\n\n");

    // Parse arguments
    char owner[256] = "example.com.";
    int ttl = 3600;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            strncpy(owner, argv[i + 1], sizeof(owner) - 1);
            owner[sizeof(owner) - 1] = '\0';
            i++;
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            ttl = atoi(argv[i + 1]);
            i++;
        }
    }

    // Load timestamp
    time_t now;
    FILE *ts_f = fopen("timestamp.bin", "rb");
    if (!ts_f || fread(&now, sizeof(time_t), 1, ts_f) != 1) {
        fprintf(stderr, "Failed to read timestamp.bin\n");
        if (ts_f) fclose(ts_f);
        return 1;
    }
    fclose(ts_f);
    time_t inception = now;
    time_t expiration = now + 30 * 24 * 3600;

    // Load keys
    FalconKeyPair ksk, zsk;
    ksk.pubkey_len = load_key("ksk0_pubkey.bin", ksk.pubkey, FALCON512_PUBLIC_KEY_SIZE);
    ksk.privkey_len = load_key("ksk0_privkey.bin", ksk.privkey, FALCON512_PRIVATE_KEY_SIZE);
    zsk.pubkey_len = load_key("zsk_pubkey.bin", zsk.pubkey, FALCON512_PUBLIC_KEY_SIZE);
    zsk.privkey_len = load_key("zsk_privkey.bin", zsk.privkey, FALCON512_PRIVATE_KEY_SIZE);

    if (ksk.pubkey_len != FALCON512_PUBLIC_KEY_SIZE || ksk.privkey_len != FALCON512_PRIVATE_KEY_SIZE ||
        zsk.pubkey_len != FALCON512_PUBLIC_KEY_SIZE || zsk.privkey_len != FALCON512_PRIVATE_KEY_SIZE) {
        fprintf(stderr, "Invalid key sizes\n");
        return 1;
    }
    printf("Loaded KSK and ZSK keys\n");

    printf("Signing DNSKEY RRset for %s\n", owner);
    sign_dnskey_rrset(&ksk, &zsk, owner, ttl, inception, expiration);

    return 0;
}