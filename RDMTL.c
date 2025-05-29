#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

// structure is defined for an individual RR
typedef struct {
    char *data;
} RRRecord;

// here struct is defined for an RRSet
typedef struct {
    char *type;
    RRRecord *records;
    int count;
} RRSet;

// this generates SHA-256 hash of a given string
void sha256_hash(const char *input, unsigned char *output) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input, strlen(input));
    EVP_DigestFinal_ex(ctx, output, NULL);
    EVP_MD_CTX_free(ctx);
}

// it hashes a pair of 32-byte hashes into a single 32-byte hash - used for MT
void hash_pair(const unsigned char *left, const unsigned char *right, unsigned char *output) {
    unsigned char concat[64];
    memcpy(concat, left, 32);
    memcpy(concat + 32, right, 32);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, concat, 64);
    EVP_DigestFinal_ex(ctx, output, NULL);
    EVP_MD_CTX_free(ctx);
}

// this converts binary hash to hex string for display
void hash_to_string(const unsigned char *hash, char *output) {
    for (int i = 0; i < 32; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = '\0';
}

// this is used to hold all levels of a Merkle tree for proof generation
typedef struct {
    unsigned char **levels; // array of hashes per level
    int *level_sizes;       // number of nodes per level
    int levels_count;
} MerkleTree;

// free memory used by the MT structure
void free_merkle_tree(MerkleTree *tree) {
    if (!tree) return;
    for (int i = 0; i < tree->levels_count; i++) {
        free(tree->levels[i]);
    }
    free(tree->levels);
    free(tree->level_sizes);
    tree->levels = NULL;
    tree->level_sizes = NULL;
    tree->levels_count = 0;
}

// build MT and store all levels inside MT structure
void build_merkle_tree_levels(RRSet *rrset, MerkleTree *tree) {
    int count = rrset->count;
    if (count == 0) {
        tree->levels = NULL;
        tree->level_sizes = NULL;
        tree->levels_count = 0;
        return;
    }

    // calculate maximum levels needed in M tree
    int max_levels = 0;
    int n = count;
    while (n > 1) {
        n = (n + 1) / 2;
        max_levels++;
    }
    max_levels++; // including leaf level

    tree->levels = malloc(max_levels * sizeof(unsigned char *));
    tree->level_sizes = malloc(max_levels * sizeof(int));
    tree->levels_count = max_levels;

    // Leaf level: hash each RR record
    tree->level_sizes[0] = count;
    tree->levels[0] = malloc(count * 32);
    for (int i = 0; i < count; i++) {
        sha256_hash(rrset->records[i].data, tree->levels[0] + (i * 32));
    }

    // build upper levels by hashing pairs of lower level nodes
    for (int level = 1; level < max_levels; level++) {
        int prev_count = tree->level_sizes[level - 1];
        int curr_count = (prev_count + 1) / 2;
        tree->level_sizes[level] = curr_count;
        tree->levels[level] = malloc(curr_count * 32);

        for (int i = 0; i < curr_count; i++) {
            int left_idx = 2 * i;
            int right_idx = 2 * i + 1;
            unsigned char *left = tree->levels[level - 1] + (left_idx * 32);
            unsigned char *right = (right_idx < prev_count) ? (tree->levels[level - 1] + (right_idx * 32)) : NULL;
            if (right) {
                hash_pair(left, right, tree->levels[level] + (i * 32));
            } else {
                // if no right sibling, just copy the left hash up
                memcpy(tree->levels[level] + (i * 32), left, 32);
            }
        }
    }
}

// generate a merkle proof for a given leaf index
void generate_merkle_proof(MerkleTree *tree, int leaf_index, unsigned char **proof_out) {
    int index = leaf_index;
    for (int level = 0; level < tree->levels_count - 1; level++) {
        int sibling_index = (index % 2 == 0) ? index + 1 : index - 1;
        if (sibling_index >= tree->level_sizes[level]) {
            proof_out[level] = NULL; // if no sibling, treat as null
        } else {
            proof_out[level] = tree->levels[level] + (sibling_index * 32);
        }
        index /= 2;
    }
}

// compute MTL signature using current and previous Merkle roots
void compute_mtl_signature(unsigned char *current_root, unsigned char *prev_root, unsigned char *signature) {
    hash_pair(current_root, prev_root, signature);
}

// process query: build Merkle tree for RRSet, compute root, MTL signature, and proof
void query_rrset(RRSet *rrsets, int rrset_count, const char *query_type, unsigned char *prev_roots, unsigned char *latest_root) {
    int rrset_index = -1;
    for (int i = 0; i < rrset_count; i++) {
        if (strcmp(rrsets[i].type, query_type) == 0) {
            rrset_index = i;
            break;
        }
    }

    if (rrset_index == -1) {
        printf("Error: RRset type %s not found\n", query_type);
        return;
    }

    MerkleTree tree;
    build_merkle_tree_levels(&rrsets[rrset_index], &tree);

    if (tree.levels_count == 0) {
        printf("RRset is empty.\n");
        return;
    }

    unsigned char *current_root = tree.levels[tree.levels_count - 1];

    // compute MTL signature with previous root
    unsigned char mtl_signature[32];
    compute_mtl_signature(current_root, prev_roots + (rrset_index * 32), mtl_signature);

    // update previous root for future reference
    memcpy(prev_roots + (rrset_index * 32), current_root, 32);

    // update latest root for TXT hint
    memcpy(latest_root, current_root, 32);

    // convert hashes to strings for printing
    char current_root_str[65], mtl_signature_str[65], latest_root_str[65];
    hash_to_string(current_root, current_root_str);
    hash_to_string(mtl_signature, mtl_signature_str);
    hash_to_string(latest_root, latest_root_str);

    // display the RRset
    printf("\n--- RRset (%s) ---\n", query_type);
    for (int i = 0; i < rrsets[rrset_index].count; i++) {
        printf("%s\n", rrsets[rrset_index].records[i].data);
    }

    // display MTL signature and TXT record hint
    printf("\nMTL Signature: %s\n", mtl_signature_str);
    printf("Merkle Root Hint (TXT): aiori.in. 3600 IN TXT \"mtlroot=%s\"\n", latest_root_str);

    // display Merkle proof for the first leaf (index 0)
    if (rrsets[rrset_index].count > 0) {
        unsigned char *proof[tree.levels_count - 1];
        generate_merkle_proof(&tree, 0, proof);

        printf("\nMerkle Proof for leaf 0 (%s):\n", rrsets[rrset_index].records[0].data);
        for (int i = 0; i < tree.levels_count - 1; i++) {
            if (proof[i]) {
                char proof_str[65];
                hash_to_string(proof[i], proof_str);
                printf("Level %d sibling hash: %s\n", i, proof_str);
            } else {
                printf("Level %d sibling hash: (none)\n", i);
            }
        }
    }

    free_merkle_tree(&tree);
}

// main func to initialize RRsets, handle queries, and display results
int main() {
    RRRecord a_records[] = {
        {"aiori.in. 3600 IN A 192.0.2.1"},
        {"aiori.in. 3600 IN A 192.0.2.2"},
        {"aiori.in. 3600 IN A 192.0.2.3"},
        {"aiori.in. 3600 IN A 192.0.2.4"},
        {"aiori.in. 3600 IN A 192.0.2.5"}
    };

    RRRecord aaaa_records[] = {
        {"aiori.in. 3600 IN AAAA 2001:db8::1"},
        {"aiori.in. 3600 IN AAAA 2001:db8::2"},
        {"aiori.in. 3600 IN AAAA 2001:db8::3"}
    };

    RRRecord txt_records[] = {
        {"aiori.in. 3600 IN TXT \"v=spf1 a mx -all\""},
        {"aiori.in. 3600 IN TXT \"description=example site\""},
        {"aiori.in 3600 IN TXT \"contact=email@example.com\""}
    };

    // aggregate all RRsets
    RRSet rrsets[] = {
        {"A", a_records, 5},
        {"AAAA", aaaa_records, 3},
        {"TXT", txt_records, 3}
    };
    int rrset_count = 3;

    // initialize previous roots and latest root
    unsigned char prev_roots[rrset_count * 32];
    unsigned char latest_root[32];
    memset(prev_roots, 0, 32 * rrset_count);
    memset(latest_root, 0, 32);

    // query loop
    while (1) {
        char input_type[16];
        printf("\nEnter query (A, AAAA, TXT) or 'exit': ");
        scanf("%15s", input_type);
        if (strcmp(input_type, "exit") == 0) break;

        query_rrset(rrsets, rrset_count, input_type, prev_roots, latest_root);
    }

    return 0;
}
