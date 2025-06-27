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

    smt_print_stats(&tree);
    smt_cleanup(&tree);
    return 0;
}