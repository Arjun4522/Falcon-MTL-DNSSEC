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
#define FALCON512_SIGNATURE_SIZE FALCON_SIG_CT_SIZE(FALCON_LOGN)    // 666 bytes
#define FALCON512_VERIFY_TMP_SIZE FALCON_TMPSIZE_VERIFY(FALCON_LOGN) // 39936
#define MAX_AUTH_PATHS 10

typedef struct {
    unsigned char pubkey[FALCON512_PUBLIC_KEY_SIZE];
    size_t pubkey_len;
} FalconKeyPair;

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

void hash_pair(const unsigned char left[32], const unsigned char right[32], unsigned char output[32]) {
    unsigned char concat[64];
    memcpy(concat, left, 32);
    memcpy(concat + 32, right, 32);
    sha256_hash(concat, 64, output);
}

void to_hex(const unsigned char *input, size_t len, char *output) {
    for (size_t i = 0; i < len; i++) {
        sprintf(output + 2 * i, "%02x", input[i]);
    }
}

size_t base64_decode(const char *input, unsigned char *output, size_t max_len) {
    const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t len = strlen(input), out_len = 0;
    int i, j, k;
    unsigned char val[4];

    for (i = 0; i < len; i += 4) {
        for (j = 0; j < 4 && (i + j) < len; j++) {
            val[j] = 0;
            for (k = 0; k < 64; k++) {
                if (b64[k] == input[i + j]) {
                    val[j] = k;
                    break;
                }
            }
            if (input[i + j] == '=') val[j] = 0;
        }
        if (out_len + 3 > max_len) return 0;
        output[out_len++] = (val[0] << 2) | (val[1] >> 4);
        if (j > 2) output[out_len++] = ((val[1] & 0x0F) << 4) | (val[2] >> 2);
        if (j > 3) output[out_len++] = ((val[2] & 0x03) << 6) | val[3];
    }
    return out_len;
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

char *load_signature(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "Failed to open %s\n", filename);
        exit(1);
    }
    char *sig = malloc(2048);
    if (!sig) {
        fprintf(stderr, "Memory allocation failed for signature\n");
        fclose(f);
        exit(1);
    }
    if (!fgets(sig, 2048, f)) {
        fprintf(stderr, "Failed to read %s\n", filename);
        fclose(f);
        free(sig);
        exit(1);
    }
    sig[strcspn(sig, "\n")] = '\0';
    fclose(f);
    return sig;
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
    for (size_t i = 0; i < len; i++) {
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
            fprintf(stderr, "Memory allocation failed for RRset\n");
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
                fprintf(stderr, "Memory allocation failed for type\n");
                fclose(f);
                free(temp);
                return 0;
            }
            token = strtok(NULL, "");
            if (token) {
                while (*token == ' ') token++;
                data = strdup(token);
                if (!data) {
                    fprintf(stderr, "Memory allocation failed for data\n");
                    fclose(f);
                    free(type);
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
        fprintf(stderr, "Memory allocation failed for sorted_rrset\n");
        exit(1);
    }
    for (int i = 0; i < rrset_count; i++) {
        sorted_rrset[i] = malloc(512);
        if (!sorted_rrset[i]) {
            fprintf(stderr, "Memory allocation failed for sorted_rrset entry\n");
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

int verify_merkle_tree(const unsigned char *pubkey, size_t pubkey_len,
                       unsigned char auth_paths[][32], int num_levels,
                       const unsigned char *root, int key_index) {
    unsigned char current_hash[32];
    sha256_hash(pubkey, pubkey_len, current_hash);
    char hash_hex[65];
    to_hex(current_hash, 32, hash_hex);
    printf("Initial KSK: %s\n", hash_hex);

    int index = key_index;
    for (int level = 0; level < num_levels; level++) {
        unsigned char next_hash[32];
        to_hex(auth_paths[level], 32, hash_hex);
        printf("Level %d auth path: %s\n", level, hash_hex);
        if (index % 2 == 0) {
            hash_pair(current_hash, auth_paths[level], next_hash);
        } else {
            hash_pair(auth_paths[level], current_hash, next_hash);
        }
        memcpy(current_hash, next_hash, 32);
        to_hex(current_hash, 32, hash_hex);
        printf("Level %d computed hash: %s\n", level, hash_hex);
        index /= 2;
    }
    to_hex(root, 32, hash_hex);
    printf("Expected Merkle root: %s\n", hash_hex);
    int result = memcmp(current_hash, root, 32) == 0;
    if (!result) {
        to_hex(current_hash, 32, hash_hex);
        printf("Computed root: %s\n", hash_hex);
    }
    return result;
}

int main(int argc, char *argv[]) {
    printf("DNSSEC Resolver Verification for Falcon-512\n");
    printf("==========================================\n\n");

    // Parse arguments
    char owner[256] = "www.example.com.";
    char rrset_file[256] = "rrset.conf";
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            strncpy(owner, argv[i + 1], sizeof(owner) - 1);
            owner[sizeof(owner) - 1] = '\0';
            i++;
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            strncpy(rrset_file, argv[i + 1], sizeof(rrset_file) - 1);
            rrset_file[sizeof(rrset_file) - 1] = '\0';
            i++;
        }
    }

    // Load keys
    FalconKeyPair ksk, zsk;
    ksk.pubkey_len = load_key("ksk0_pubkey.bin", ksk.pubkey, FALCON512_PUBLIC_KEY_SIZE);
    zsk.pubkey_len = load_key("zsk_pubkey.bin", zsk.pubkey, FALCON512_PUBLIC_KEY_SIZE);
    if (ksk.pubkey_len != FALCON512_PUBLIC_KEY_SIZE || zsk.pubkey_len != FALCON512_PUBLIC_KEY_SIZE) {
        fprintf(stderr, "Invalid key sizes\n");
        return 1;
    }

    // Check if KSK and ZSK are identical
    if (memcmp(ksk.pubkey, zsk.pubkey, FALCON512_PUBLIC_KEY_SIZE) == 0) {
        fprintf(stderr, "Error: KSK and ZSK public keys are identical\n");
        return 1;
    }

    // Compute key tags
    uint16_t ksk_key_tag = calculate_key_tag(ksk.pubkey, ksk.pubkey_len, 1);
    uint16_t zsk_key_tag = calculate_key_tag(zsk.pubkey, zsk.pubkey_len, 0);
    printf("KSK Key Tag: %u\nZSK Key Tag: %u\n", ksk_key_tag, zsk_key_tag);

    // Load timestamp
    time_t now;
    FILE *f = fopen("timestamp.bin", "rb");
    if (!f || fread(&now, sizeof(time_t), 1, f) != 1) {
        fprintf(stderr, "Failed to read timestamp.bin\n");
        if (f) fclose(f);
        return 1;
    }
    fclose(f);
    time_t inception = now;
    time_t expiration = now + 30 * 24 * 3600;

    // Load Merkle data
    unsigned char merkle_root[32];
    unsigned char auth_paths[MAX_AUTH_PATHS][32];
    int num_keys;
    FILE *merkle_f = fopen("merkle_data.bin", "rb");
    if (!merkle_f || fread(&num_keys, sizeof(int), 1, merkle_f) != 1 ||
        fread(merkle_root, 1, 32, merkle_f) != 32) {
        fprintf(stderr, "Failed to read merkle_data.bin\n");
        if (merkle_f) fclose(merkle_f);
        return 1;
    }
    int log_n = 0;
    int n = num_keys;
    while (n > 1) {
        n = (n + 1) / 2;
        log_n++;
    }
    if (log_n > MAX_AUTH_PATHS) {
        fprintf(stderr, "Too many Merkle tree levels: %d\n", log_n);
        fclose(merkle_f);
        return 1;
    }
    if (fread(auth_paths, 1, log_n * 32, merkle_f) != log_n * 32) {
        fprintf(stderr, "Failed to read auth paths\n");
        fclose(merkle_f);
        return 1;
    }
    fclose(merkle_f);

    // Verify Merkle tree
    if (verify_merkle_tree(ksk.pubkey, ksk.pubkey_len, auth_paths, log_n, merkle_root, 0)) {
        printf("Merkle tree verification successful\n");
    } else {
        fprintf(stderr, "Merkle tree verification failed\n");
        return 1;
    }

    // Load RRset
    RR *rrset = NULL;
    int rrset_count;
    if (!load_rrset(rrset_file, &rrset, &rrset_count, 3600)) {
        fprintf(stderr, "Failed to load RRset\n");
        return 1;
    }

    // Canonicalize A/AAAA/TXT RRset
    char canonical_a[4096];
    size_t canonical_a_len;
    canonicalize_rrset(rrset, rrset_count, owner, canonical_a, &canonical_a_len, 3600);
    printf("Canonicalized RRset:\n%.*s\n", (int)canonical_a_len, canonical_a);

    // Prepare RRSIG data for A/AAAA/TXT
    unsigned char rr_hash[32];
    sha256_hash((unsigned char *)canonical_a, canonical_a_len, rr_hash);
    char hash_hex[65];
    to_hex(rr_hash, 32, hash_hex);
    printf("RRSIG rr_hash: %s\n", hash_hex);

    unsigned char rrsig_data_a[4096];
    size_t rrsig_data_a_len = 0;
    uint16_t type_covered = htons(1); // A
    uint8_t algorithm = 16;
    uint8_t labels = 0;
    char canonical_owner[256];
    canonicalize_name(owner, canonical_owner);
    for (const char *p = canonical_owner; *p; p++) if (*p == '.') labels++;
    labels++; // Count the last label
    printf("RRSIG labels: %u\n", labels);
    uint32_t original_ttl = htonl(3600);
    uint32_t sig_expiration = htonl((uint32_t)expiration);
    uint32_t sig_inception = htonl((uint32_t)inception);
    uint16_t key_tag = htons(zsk_key_tag);
    char signer_name[256];
    canonicalize_name(owner, signer_name);
    printf("RRSIG signer_name: %s\n", signer_name);

    memcpy(rrsig_data_a, &type_covered, 2);
    rrsig_data_a_len += 2;
    rrsig_data_a[rrsig_data_a_len++] = algorithm;
    rrsig_data_a[rrsig_data_a_len++] = labels;
    memcpy(rrsig_data_a + rrsig_data_a_len, &original_ttl, 4);
    rrsig_data_a_len += 4;
    memcpy(rrsig_data_a + rrsig_data_a_len, &sig_expiration, 4);
    rrsig_data_a_len += 4;
    memcpy(rrsig_data_a + rrsig_data_a_len, &sig_inception, 4);
    rrsig_data_a_len += 4;
    memcpy(rrsig_data_a + rrsig_data_a_len, &key_tag, 2);
    rrsig_data_a_len += 2;
    strcpy((char *)rrsig_data_a + rrsig_data_a_len, signer_name);
    rrsig_data_a_len += strlen(signer_name) + 1;
    memcpy(rrsig_data_a + rrsig_data_a_len, rr_hash, 32);
    rrsig_data_a_len += 32;

    // Load and decode A/AAAA/TXT signature
    char *a_sig_base64 = load_signature("zsk_rrsig.out");
    unsigned char a_sig[FALCON512_SIGNATURE_SIZE];
    size_t a_sig_len = base64_decode(a_sig_base64, a_sig, FALCON512_SIGNATURE_SIZE);
    free(a_sig_base64);
    if (a_sig_len != FALCON512_SIGNATURE_SIZE) {
        fprintf(stderr, "Invalid signature length: %zu\n", a_sig_len);
        free_rrset(rrset, rrset_count);
        return 1;
    }

    // Verify A/AAAA/TXT signature
    unsigned char tmp[FALCON512_VERIFY_TMP_SIZE];
    if (falcon_verify(a_sig, a_sig_len, zsk.pubkey, zsk.pubkey_len,
                      rrsig_data_a, rrsig_data_a_len, tmp, sizeof(tmp)) == 0) {
        printf("A/AAAA/TXT RRset signature verified successfully\n");
    } else {
        fprintf(stderr, "A/AAAA/TXT RRset signature verification failed\n");
        free_rrset(rrset, rrset_count);
        return 1;
    }

    // Verify RRset integrity
    unsigned char computed_hash[32];
    sha256_hash((unsigned char *)canonical_a, canonical_a_len, computed_hash);
    if (memcmp(computed_hash, rr_hash, 32) == 0) {
        printf("A/AAAA/TXT RRset integrity check passed\n");
    } else {
        fprintf(stderr, "A/AAAA/TXT RRset integrity check failed\n");
        free_rrset(rrset, rrset_count);
        return 1;
    }
    free_rrset(rrset, rrset_count);

    // Canonicalize DNSKEY RRset
    char dnskey_owner[256];
    strncpy(dnskey_owner, owner, sizeof(dnskey_owner));
    char *last_dot = strrchr(dnskey_owner, '.');
    if (last_dot && strcmp(last_dot, ".example.com.") == 0) {
        strcpy(last_dot, ".example.com.");
    } else {
        strcpy(dnskey_owner, "example.com.");
    }
    char canonical_dnskey[4096];
    size_t canonical_dnskey_len;
    canonicalize_dnskey_rrset(ksk.pubkey, ksk.pubkey_len, zsk.pubkey, zsk.pubkey_len,
                              dnskey_owner, 3600, canonical_dnskey, &canonical_dnskey_len);

    // Prepare RRSIG data for DNSKEY
    unsigned char dnskey_hash[32];
    sha256_hash((unsigned char *)canonical_dnskey, canonical_dnskey_len, dnskey_hash);

    unsigned char rrsig_data_dnskey[4096];
    size_t rrsig_data_dnskey_len = 0;
    type_covered = htons(48); // DNSKEY
    labels = 0;
    for (const char *p = dnskey_owner; *p; p++) if (*p == '.') labels++;
    labels++; // Count the last label
    // Reuse sig_expiration and sig_inception from A/AAAA/TXT
    key_tag = htons(ksk_key_tag); // Reassign key_tag for KSK
    char signer_name_dnskey[256];
    canonicalize_name(dnskey_owner, signer_name_dnskey);

    memcpy(rrsig_data_dnskey, &type_covered, 2);
    rrsig_data_dnskey_len += 2;
    rrsig_data_dnskey[rrsig_data_dnskey_len++] = algorithm;
    rrsig_data_dnskey[rrsig_data_dnskey_len++] = labels;
    memcpy(rrsig_data_dnskey + rrsig_data_dnskey_len, &original_ttl, 4);
    rrsig_data_dnskey_len += 4;
    memcpy(rrsig_data_dnskey + rrsig_data_dnskey_len, &sig_expiration, 4);
    rrsig_data_dnskey_len += 4;
    memcpy(rrsig_data_dnskey + rrsig_data_dnskey_len, &sig_inception, 4);
    rrsig_data_dnskey_len += 4;
    memcpy(rrsig_data_dnskey + rrsig_data_dnskey_len, &key_tag, 2);
    rrsig_data_dnskey_len += 2;
    strcpy((char *)rrsig_data_dnskey + rrsig_data_dnskey_len, signer_name_dnskey);
    rrsig_data_dnskey_len += strlen(signer_name_dnskey) + 1;
    memcpy(rrsig_data_dnskey + rrsig_data_dnskey_len, dnskey_hash, 32);
    rrsig_data_dnskey_len += 32;

    // Load and decode DNSKEY signature
    char *dnskey_sig_base64 = load_signature("dnskey_rrsig.out");
    unsigned char dnskey_sig[FALCON512_SIGNATURE_SIZE];
    size_t dnskey_sig_len = base64_decode(dnskey_sig_base64, dnskey_sig, FALCON512_SIGNATURE_SIZE);
    free(dnskey_sig_base64);

    // Verify DNSKEY signature
    if (falcon_verify(dnskey_sig, dnskey_sig_len, ksk.pubkey, ksk.pubkey_len,
                      rrsig_data_dnskey, rrsig_data_dnskey_len, tmp, sizeof(tmp)) == 0) {
        printf("DNSKEY RRset signature verified successfully\n");
    } else {
        fprintf(stderr, "DNSKEY RRset signature verification failed\n");
        return 1;
    }

    return 0;
}