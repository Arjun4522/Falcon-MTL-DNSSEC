#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include "falcon.h"
#include <math.h>
#include <x86intrin.h> // For __rdtsc()

#define FALCON_LOGN 9
#define FALCON512_PUBLIC_KEY_SIZE FALCON_PUBKEY_SIZE(FALCON_LOGN)
#define FALCON512_PRIVATE_KEY_SIZE FALCON_PRIVKEY_SIZE(FALCON_LOGN)

typedef struct {
    struct timeval start_time, end_time;
    struct rusage start_usage, end_usage;
    size_t mem_usage;
} Benchmark;

void start_benchmark(Benchmark *bench) {
    gettimeofday(&bench->start_time, NULL);
    getrusage(RUSAGE_SELF, &bench->start_usage);
}

void end_benchmark(Benchmark *bench, const char *label) {
    gettimeofday(&bench->end_time, NULL);
    getrusage(RUSAGE_SELF, &bench->end_usage);
    
    long seconds = bench->end_time.tv_sec - bench->start_time.tv_sec;
    long microseconds = bench->end_time.tv_usec - bench->start_time.tv_usec;
    double elapsed = seconds + microseconds * 1e-6;
    
    long user_time = (bench->end_usage.ru_utime.tv_sec - bench->start_usage.ru_utime.tv_sec) * 1000000 + 
                    (bench->end_usage.ru_utime.tv_usec - bench->start_usage.ru_utime.tv_usec);
    long system_time = (bench->end_usage.ru_stime.tv_sec - bench->start_usage.ru_stime.tv_sec) * 1000000 + 
                      (bench->end_usage.ru_stime.tv_usec - bench->start_usage.ru_stime.tv_usec);
    
    printf("\n=== Benchmark: %s ===\n", label);
    printf("Wall-clock time: %.6f seconds\n", elapsed);
    printf("CPU user time:   %.6f seconds\n", user_time / 1e6);
    printf("CPU system time: %.6f seconds\n", system_time / 1e6);
    printf("Max RSS:         %ld KB\n", bench->end_usage.ru_maxrss);
}

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

void hash_pair(const unsigned char *left, const unsigned char *right, unsigned char *output) {
    unsigned char concat[64];
    memcpy(concat, left, 32);
    memcpy(concat + 32, right, 32);
    sha256_hash(concat, 64, output);
}

void verify_all_keys(unsigned char (*pubkeys)[FALCON512_PUBLIC_KEY_SIZE], int n) {
    unsigned char dummy[32];
    for (int i = 0; i < n; i++) {
        sha256_hash(pubkeys[i], FALCON512_PUBLIC_KEY_SIZE, dummy);
    }
}

void verify_merkle_path(const unsigned char *leaf, 
                       unsigned char (*auth_path)[32], 
                       int path_len, 
                       const unsigned char *root,
                       int position) {
    unsigned char current[32];
    memcpy(current, leaf, 32);
    
    for (int i = 0; i < path_len; i++) {
        unsigned char next[32];
        if (((position >> i) & 1) == 0) {
            hash_pair(current, auth_path[i], next);
        } else {
            hash_pair(auth_path[i], current, next);
        }
        memcpy(current, next, 32);
    }
    
    if (memcmp(current, root, 32) != 0) {
        printf("Merkle verification failed!\n");
    } else {
        //printf("Merkle verification successful!\n");
    }
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

void run_detailed_benchmarks(unsigned char (*pubkeys)[FALCON512_PUBLIC_KEY_SIZE],
                           unsigned char (*pubkey_hashes)[32],
                           unsigned char (*auth_path)[32],
                           unsigned char *root,
                           int n, int k, int tree_depth) {
    const int warmup = 1000;
    const int measure = 10000;
    uint64_t start, end;
    double plain_total = 0, mtl_total = 0;

    // Warm up
    for (int i = 0; i < warmup; i++) {
        verify_all_keys(pubkeys, n);
        verify_merkle_path(pubkey_hashes[k], auth_path, tree_depth, root, k);
    }

    // Benchmark plain verification
    start = __rdtsc();
    for (int i = 0; i < measure; i++) {
        verify_all_keys(pubkeys, n);
    }
    end = __rdtsc();
    plain_total = (double)(end - start)/measure;

    // Benchmark MTL verification
    start = __rdtsc();
    for (int i = 0; i < measure; i++) {
        verify_merkle_path(pubkey_hashes[k], auth_path, tree_depth, root, k);
    }
    end = __rdtsc();
    mtl_total = (double)(end - start)/measure;

    printf("\n=== Detailed Performance Metrics ===\n");
    printf("Plain Falcon Verification:\n");
    printf("- Total cycles: %.0f\n", plain_total);
    printf("- Cycles/key: %.1f\n", plain_total/n);
    printf("- Time/key: %.2f ns (at 3GHz)\n", plain_total/n/3);
    
    printf("\nFalcon-MTL Verification:\n");
    printf("- Total cycles: %.0f\n", mtl_total);
    printf("- Cycles/hash: %.1f\n", mtl_total/tree_depth);
    printf("- Time/hash: %.2f ns (at 3GHz)\n", mtl_total/tree_depth/3);
    
    printf("\nComparison:\n");
    printf("- Absolute speedup: %.1fx\n", plain_total/mtl_total);
    printf("- Theoretical speedup: %.1fx\n", (double)n/tree_depth);
    printf("- Efficiency: %.1f%%\n", 100.0*(double)tree_depth/n*plain_total/mtl_total);
}

int main(int argc, char *argv[]) {
    printf("Falcon-512 KSK Management: Plain vs Merkle Tree (Falcon-MTL)\n");
    printf("===========================================================\n\n");

    int n = 64, k = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            n = atoi(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            k = atoi(argv[i + 1]);
            i++;
        }
    }
    if (n < 1 || k < 0 || k >= n) {
        fprintf(stderr, "Invalid n=%d or k=%d\n", n, k);
        return 1;
    }

    Benchmark total_bench, keygen_bench, plain_verify_bench, mtl_verify_bench;
    start_benchmark(&total_bench);

    printf("\nGenerating %d Falcon-512 key pairs...\n", n);
    start_benchmark(&keygen_bench);
    
    shake256_context rng;
    unsigned char seed[48] = {0};
    seed[47] = 0xFF;
    shake256_init_prng_from_seed(&rng, seed, sizeof(seed));
    shake256_flip(&rng);

    unsigned char (*pubkeys)[FALCON512_PUBLIC_KEY_SIZE] = malloc(n * FALCON512_PUBLIC_KEY_SIZE);
    unsigned char (*privkeys)[FALCON512_PRIVATE_KEY_SIZE] = malloc(n * FALCON512_PRIVATE_KEY_SIZE);
    unsigned char tmp[FALCON_TMPSIZE_KEYGEN(FALCON_LOGN)];

    for (int i = 0; i < n; i++) {
        if (falcon_keygen_make(&rng, FALCON_LOGN,
                               privkeys[i], FALCON512_PRIVATE_KEY_SIZE,
                               pubkeys[i], FALCON512_PUBLIC_KEY_SIZE,
                               tmp, sizeof(tmp)) != 0) {
            fprintf(stderr, "Failed to generate key %d\n", i);
            return 1;
        }
    }
    end_benchmark(&keygen_bench, "Key Generation");

    char pub_filename[32], priv_filename[32];
    snprintf(pub_filename, sizeof(pub_filename), "ksk%d_pubkey.bin", k);
    snprintf(priv_filename, sizeof(priv_filename), "ksk%d_privkey.bin", k);
    save_key(pubkeys[k], FALCON512_PUBLIC_KEY_SIZE, pub_filename);
    save_key(privkeys[k], FALCON512_PRIVATE_KEY_SIZE, priv_filename);
    printf("\nKSK keys saved to %s (pub) and %s (priv)\n", pub_filename, priv_filename);

    unsigned char (*pubkey_hashes)[32] = malloc(n * 32);
    for (int i = 0; i < n; i++) {
        sha256_hash(pubkeys[i], FALCON512_PUBLIC_KEY_SIZE, pubkey_hashes[i]);
    }

    printf("\nBuilding Merkle tree for %d keys...\n", n);
    int tree_depth = (int)ceil(log2(n));
    unsigned char **tree = calloc(tree_depth + 1, sizeof(unsigned char *));
    for (int i = 0; i <= tree_depth; i++) {
        tree[i] = malloc(n * 32);
    }
    
    memcpy(tree[0], pubkey_hashes, n * 32);
    
    int level_size = n;
    for (int level = 0; level < tree_depth; level++) {
        int next_level_size = (level_size + 1) / 2;
        for (int i = 0; i < next_level_size; i++) {
            int left = 2 * i;
            int right = (2 * i + 1 < level_size) ? (2 * i + 1) : left;
            hash_pair(&tree[level][left * 32], &tree[level][right * 32], &tree[level + 1][i * 32]);
        }
        level_size = next_level_size;
    }
    
    unsigned char *root = tree[tree_depth];
    char root_hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(root_hex + 2 * i, "%02x", root[i]);
    }
    printf("Merkle root: %s\n", root_hex);

    unsigned char (*auth_path)[32] = malloc(tree_depth * 32);
    int index = k;
    for (int level = 0; level < tree_depth; level++) {
        int sibling = (index % 2) ? (index - 1) : ((index + 1 < (n >> level)) ? (index + 1) : index);
        memcpy(auth_path[level], &tree[level][sibling * 32], 32);
        index /= 2;
    }

    printf("\nBenchmarking verification approaches...\n");
    
    start_benchmark(&plain_verify_bench);
    verify_all_keys(pubkeys, n);
    end_benchmark(&plain_verify_bench, "Plain Falcon Verification (all keys)");
    
    start_benchmark(&mtl_verify_bench);
    verify_merkle_path(pubkey_hashes[k], auth_path, tree_depth, root, k);
    end_benchmark(&mtl_verify_bench, "Falcon-MTL Verification (Merkle path)");

    // Run detailed benchmarks
    run_detailed_benchmarks(pubkeys, pubkey_hashes, auth_path, root, n, k, tree_depth);

    printf("\n=== Theoretical Comparison ===\n");
    printf("Trust Model:\n");
    printf("- Plain Falcon: Must trust all %d keys (O(n) trust)\n", n);
    printf("- Falcon-MTL:   Only trust the Merkle root (O(1) trust)\n\n");
    
    printf("Verification Complexity:\n");
    printf("- Plain Falcon: Verify all %d keys (O(n) operations)\n", n);
    printf("- Falcon-MTL:   Verify %d hashes (O(log n) operations)\n", tree_depth);
    
    end_benchmark(&total_bench, "Total Execution");
    
    free(pubkeys);
    free(privkeys);
    free(pubkey_hashes);
    free(auth_path);
    for (int i = 0; i <= tree_depth; i++) {
        free(tree[i]);
    }
    free(tree);

    return 0;
}