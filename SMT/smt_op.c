#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "smt.h"

int main() {
    SMT tree;
    if (smt_init(&tree) != SMT_SUCCESS) {
        fprintf(stderr, "Failed to initialize SMT\n");
        return 1;
    }

    // Insert some key-value pairs
    const char* keys[] = {"apple", "banana", "cherry"};
    const char* values[] = {"red", "yellow", "dark red"};

    for (int i = 0; i < 3; i++) {
        if (smt_insert(&tree, keys[i], values[i]) != SMT_SUCCESS) {
            fprintf(stderr, "Failed to insert key %s\n", keys[i]);
        } else {
            printf("Inserted (%s -> %s)\n", keys[i], values[i]);
        }
    }

    // Lookup inserted keys
    for (int i = 0; i < 3; i++) {
        char* value = NULL;
        if (smt_lookup(&tree, keys[i], &value) == SMT_SUCCESS) {
            printf("Found key '%s' with value '%s'\n", keys[i], value);
            free(value);
        } else {
            printf("Key '%s' not found\n", keys[i]);
        }
    }

    // Generate and verify proofs
    for (int i = 0; i < 3; i++) {
        MembershipProof proof;
        memset(&proof, 0, sizeof(proof));
        
        printf("\nGenerating proof for key '%s'\n", keys[i]);
        smt_error_t err = smt_generate_proof(&tree, keys[i], &proof);
        if (err != SMT_SUCCESS) {
            fprintf(stderr, "Failed to generate proof for key %s: error %d\n", keys[i], err);
            continue;
        }
        
        printf("Proof generated successfully:\n");
        printf("  Layer priority: %d\n", proof.layer_priority);
        printf("  Element index: %d\n", proof.element_index);
        printf("  Layer proof length: %zu\n", proof.layer_proof_len);
        printf("  Top level proof length: %zu\n", proof.top_level_proof_len);
        
        // Verify the proof
        int valid = 0;
        err = smt_verify_proof(&tree, keys[i], values[i], &proof, &valid);
        if (err != SMT_SUCCESS) {
            fprintf(stderr, "Proof verification failed for key %s: error %d\n", keys[i], err);
        } else {
            printf("Proof verification %s for key '%s'\n", valid ? "SUCCEEDED" : "FAILED", keys[i]);
        }
        
        // Cleanup the proof
        membership_proof_cleanup(&proof);
    }

    // Test with invalid key (should fail)
    {
        const char* invalid_key = "nonexistent";
        MembershipProof proof;
        memset(&proof, 0, sizeof(proof));
        
        printf("\nTesting with invalid key '%s'\n", invalid_key);
        smt_error_t err = smt_generate_proof(&tree, invalid_key, &proof);
        if (err == SMT_ERROR_KEY_NOT_FOUND) {
            printf("Correctly failed to generate proof for non-existent key\n");
        } else if (err == SMT_SUCCESS) {
            printf("ERROR: Generated proof for non-existent key!\n");
            membership_proof_cleanup(&proof);
        } else {
            printf("Unexpected error for non-existent key: %d\n", err);
        }
    }

    // Test with wrong value (should fail verification)
    {
        const char* key = "apple";
        const char* wrong_value = "blue";
        MembershipProof proof;
        memset(&proof, 0, sizeof(proof));
        
        printf("\nTesting with wrong value for key '%s'\n", key);
        smt_error_t err = smt_generate_proof(&tree, key, &proof);
        if (err != SMT_SUCCESS) {
            fprintf(stderr, "Failed to generate proof for key %s: error %d\n", key, err);
        } else {
            int valid = 0;
            err = smt_verify_proof(&tree, key, wrong_value, &proof, &valid);
            if (err != SMT_SUCCESS) {
                fprintf(stderr, "Proof verification failed: error %d\n", err);
            } else {
                printf("Proof verification %s (expected to fail with wrong value)\n", 
                      valid ? "SUCCEEDED" : "FAILED");
            }
            membership_proof_cleanup(&proof);
        }
    }

    smt_print_stats(&tree);
    smt_cleanup(&tree);
    return 0;
}