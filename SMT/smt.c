// smt.c (optimized)
#include "smt.h"

static void safe_hash(const void* data, size_t len, unsigned char* hash);
static void element_cleanup(Element* element);

static int compute_priority(const char* key) {
    if (!key) return 0;
    
    unsigned char hash[HASH_SIZE];
    safe_hash(key, strlen(key), hash);
    
    printf("Key: '%s' | Hash: ", key);
    for (int i = 0; i < 4; i++) printf("%02x", hash[i]);
    printf(" | ");
    
    uint32_t priority = 0;
    for (int i = 0; i < 4; i++) {
        priority = (priority << 8) | hash[i];
    }
    
    int layer = priority % MAX_LAYERS;
    printf("Priority: %u | Layer: %d\n", priority, layer);
    
    return layer;
}

static void safe_hash(const void* data, size_t len, unsigned char* hash) {
    if (!data || !hash || len == 0) {
        memset(hash, 0, HASH_SIZE);
        return;
    }
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx) {
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
            EVP_DigestUpdate(ctx, data, len) == 1) {
            unsigned int hash_len;
            EVP_DigestFinal_ex(ctx, hash, &hash_len);
        } else {
            memset(hash, 0, HASH_SIZE);
        }
        EVP_MD_CTX_free(ctx);
    } else {
        SHA256((const unsigned char*)data, len, hash);
    }
}

static smt_error_t layer_init(Layer* layer) {
    if (!layer) return SMT_ERROR_NULL_POINTER;
    
    layer->elements = NULL;
    layer->element_count = 0;
    layer->capacity = 0;
    layer->dirty = 1;
    memset(layer->merkle_root, 0, HASH_SIZE);
    
    return SMT_SUCCESS;
}

static void element_cleanup(Element* element) {
    if (!element) return;
    
    free(element->key);
    free(element->value);
    memset(element, 0, sizeof(Element));
}

static void layer_cleanup(Layer* layer) {
    if (!layer) return;
    
    for (int i = 0; i < layer->element_count; i++) {
        element_cleanup(&layer->elements[i]);
    }
    
    free(layer->elements);
    layer->elements = NULL;
    layer->element_count = 0;
    layer->capacity = 0;
}

// Binary search implementation for finding elements
static int find_element_in_layer(const Layer* layer, const char* key) {
    if (!layer || !key) return -1;
    
    int low = 0;
    int high = layer->element_count - 1;
    
    while (low <= high) {
        int mid = low + (high - low) / 2;
        int cmp = strcmp(layer->elements[mid].key, key);
        
        if (cmp == 0) {
            return mid;
        } else if (cmp < 0) {
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }
    
    return -1;
}

// Insert element in sorted order
static smt_error_t layer_add_element(Layer* layer, const char* key, const char* value, int priority) {
    if (!layer || !key) return SMT_ERROR_NULL_POINTER;
    
    // Check if we need to expand capacity
    if (layer->element_count >= layer->capacity) {
        int new_capacity = layer->capacity == 0 ? 8 : layer->capacity * 2;
        Element* new_elements = realloc(layer->elements, sizeof(Element) * new_capacity);
        if (!new_elements) return SMT_ERROR_MEMORY_ALLOCATION;
        
        layer->elements = new_elements;
        layer->capacity = new_capacity;
    }
    
    // Find insertion position
    int insert_pos = 0;
    while (insert_pos < layer->element_count && 
           strcmp(layer->elements[insert_pos].key, key) < 0) {
        insert_pos++;
    }
    
    // Shift elements to make space if needed
    if (insert_pos < layer->element_count) {
        memmove(&layer->elements[insert_pos+1], 
                &layer->elements[insert_pos],
                (layer->element_count - insert_pos) * sizeof(Element));
    }
    
    // Initialize new element at the correct position
    Element* elem = &layer->elements[insert_pos];
    
    elem->key_len = strlen(key);
    elem->key = malloc(elem->key_len + 1);
    if (!elem->key) return SMT_ERROR_MEMORY_ALLOCATION;
    strcpy(elem->key, key);
    
    if (value) {
        elem->value_len = strlen(value);
        elem->value = malloc(elem->value_len + 1);
        if (!elem->value) {
            free(elem->key);
            return SMT_ERROR_MEMORY_ALLOCATION;
        }
        strcpy(elem->value, value);
    } else {
        elem->value = NULL;
        elem->value_len = 0;
    }
    
    elem->priority = priority;
    layer->element_count++;
    layer->dirty = 1;
    
    return SMT_SUCCESS;
}

static smt_error_t calculate_layer_merkle_root(Layer* layer) {
    if (!layer) return SMT_ERROR_NULL_POINTER;
    
    if (!layer->dirty) return SMT_SUCCESS;
    
    if (layer->element_count == 0) {
        memset(layer->merkle_root, 0, HASH_SIZE);
        layer->dirty = 0;
        return SMT_SUCCESS;
    }
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        SHA256_CTX old_ctx;
        SHA256_Init(&old_ctx);
        
        for (int i = 0; i < layer->element_count; i++) {
            Element* elem = &layer->elements[i];
            SHA256_Update(&old_ctx, elem->key, elem->key_len);
            if (elem->value) {
                SHA256_Update(&old_ctx, elem->value, elem->value_len);
            }
            SHA256_Update(&old_ctx, &elem->priority, sizeof(elem->priority));
        }
        
        SHA256_Final(layer->merkle_root, &old_ctx);
        layer->dirty = 0;
        return SMT_SUCCESS;
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1) {
        for (int i = 0; i < layer->element_count; i++) {
            Element* elem = &layer->elements[i];
            EVP_DigestUpdate(ctx, elem->key, elem->key_len);
            if (elem->value) {
                EVP_DigestUpdate(ctx, elem->value, elem->value_len);
            }
            EVP_DigestUpdate(ctx, &elem->priority, sizeof(elem->priority));
        }
        
        unsigned int hash_len;
        EVP_DigestFinal_ex(ctx, layer->merkle_root, &hash_len);
    }
    
    EVP_MD_CTX_free(ctx);
    layer->dirty = 0;
    
    return SMT_SUCCESS;
}

static smt_error_t update_top_level_root(SMT* smt) {
    if (!smt) return SMT_ERROR_NULL_POINTER;
    
    if (!smt->dirty) return SMT_SUCCESS;
    
    int active_layers = 0;
    
    for (int i = 0; i < smt->layer_count; i++) {
        if (smt->layers[i].element_count > 0) {
            smt_error_t err = calculate_layer_merkle_root(&smt->layers[i]);
            if (err != SMT_SUCCESS) return err;
            active_layers++;
        }
    }
    
    if (active_layers == 0) {
        memset(smt->top_level_root, 0, HASH_SIZE);
    } else {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1) {
            for (int i = 0; i < smt->layer_count; i++) {
                if (smt->layers[i].element_count > 0) {
                    EVP_DigestUpdate(ctx, smt->layers[i].merkle_root, HASH_SIZE);
                }
            }
            
            unsigned int hash_len;
            EVP_DigestFinal_ex(ctx, smt->top_level_root, &hash_len);
            EVP_MD_CTX_free(ctx);
        } else {
            SHA256_CTX old_ctx;
            SHA256_Init(&old_ctx);
            
            for (int i = 0; i < smt->layer_count; i++) {
                if (smt->layers[i].element_count > 0) {
                    SHA256_Update(&old_ctx, smt->layers[i].merkle_root, HASH_SIZE);
                }
            }
            
            SHA256_Final(smt->top_level_root, &old_ctx);
            if (ctx) EVP_MD_CTX_free(ctx);
        }
    }
    
    smt->dirty = 0;
    return SMT_SUCCESS;
}

smt_error_t smt_init(SMT* smt) {
    if (!smt) return SMT_ERROR_NULL_POINTER;
    
    memset(smt, 0, sizeof(SMT));
    
    for (int i = 0; i < MAX_LAYERS; i++) {
        smt_error_t err = layer_init(&smt->layers[i]);
        if (err != SMT_SUCCESS) {
            for (int j = 0; j < i; j++) {
                layer_cleanup(&smt->layers[j]);
            }
            return err;
        }
    }
    
    smt->layer_count = 0;
    smt->dirty = 1;
    smt->total_elements = 0;
    memset(smt->top_level_root, 0, HASH_SIZE);
    
    return SMT_SUCCESS;
}

void smt_cleanup(SMT* smt) {
    if (!smt) return;
    
    for (int i = 0; i < MAX_LAYERS; i++) {
        layer_cleanup(&smt->layers[i]);
    }
    
    memset(smt, 0, sizeof(SMT));
}

smt_error_t smt_insert(SMT* smt, const char* key, const char* value) {
    if (!smt || !key) return SMT_ERROR_NULL_POINTER;
    
    int priority = compute_priority(key);
    if (priority < 0 || priority >= MAX_LAYERS) return SMT_ERROR_INVALID_PARAMETER;
    
    if (priority >= smt->layer_count) {
        smt->layer_count = priority + 1;
    }
    
    Layer* layer = &smt->layers[priority];
    int existing_index = find_element_in_layer(layer, key);
    
    if (existing_index >= 0) {
        Element* elem = &layer->elements[existing_index];
        free(elem->value);
        
        if (value) {
            elem->value_len = strlen(value);
            elem->value = malloc(elem->value_len + 1);
            if (!elem->value) return SMT_ERROR_MEMORY_ALLOCATION;
            strcpy(elem->value, value);
        } else {
            elem->value = NULL;
            elem->value_len = 0;
        }
        
        layer->dirty = 1;
        smt->dirty = 1;
    } else {
        smt_error_t err = layer_add_element(layer, key, value, priority);
        if (err != SMT_SUCCESS) return err;
        
        smt->total_elements++;
        smt->dirty = 1;
    }
    
    return SMT_SUCCESS;
}

smt_error_t smt_lookup(const SMT* smt, const char* key, char** value) {
    if (!smt || !key || !value) return SMT_ERROR_NULL_POINTER;
    
    *value = NULL;
    
    unsigned char hash[HASH_SIZE];
    safe_hash(key, strlen(key), hash);
    printf("Key: '%s' | Hash: ", key);
    for (int i = 0; i < 4; i++) printf("%02x", hash[i]);
    printf(" | ");
    
    uint32_t priority = 0;
    for (int i = 0; i < 4; i++) {
        priority = (priority << 8) | hash[i];
    }
    int layer = priority % MAX_LAYERS;
    printf("Priority: %u | Layer: %d | ", priority, layer);
    
    if (layer < 0 || layer >= smt->layer_count) {
        printf("Key not found (invalid layer)\n");
        return SMT_ERROR_KEY_NOT_FOUND;
    }
    
    const Layer* layer_ptr = &smt->layers[layer];
    int index = find_element_in_layer(layer_ptr, key);
    
    if (index < 0) {
        printf("Key not found (missing in layer)\n");
        return SMT_ERROR_KEY_NOT_FOUND;
    }
    
    const Element* elem = &layer_ptr->elements[index];
    if (elem->value) {
        *value = malloc(elem->value_len + 1);
        if (!*value) return SMT_ERROR_MEMORY_ALLOCATION;
        strcpy(*value, elem->value);
        printf("Found value: '%s'\n", *value);
    } else {
        printf("Found NULL value\n");
    }
    
    return SMT_SUCCESS;
}

smt_error_t smt_delete(SMT* smt, const char* key) {
    if (!smt || !key) return SMT_ERROR_NULL_POINTER;
    
    int priority = compute_priority(key);
    if (priority < 0 || priority >= smt->layer_count) return SMT_ERROR_KEY_NOT_FOUND;
    
    Layer* layer = &smt->layers[priority];
    int index = find_element_in_layer(layer, key);
    
    if (index < 0) return SMT_ERROR_KEY_NOT_FOUND;
    
    element_cleanup(&layer->elements[index]);
    
    // Shift remaining elements to maintain sorted order
    if (index < layer->element_count - 1) {
        memmove(&layer->elements[index], 
                &layer->elements[index+1],
                (layer->element_count - index - 1) * sizeof(Element));
    }
    
    layer->element_count--;
    layer->dirty = 1;
    smt->dirty = 1;
    smt->total_elements--;
    
    return SMT_SUCCESS;
}

smt_error_t smt_get_root(SMT* smt, unsigned char* root) {
    if (!smt || !root) return SMT_ERROR_NULL_POINTER;
    
    smt_error_t err = update_top_level_root(smt);
    if (err != SMT_SUCCESS) return err;
    
    memcpy(root, smt->top_level_root, HASH_SIZE);
    return SMT_SUCCESS;
}

void smt_print_stats(const SMT* smt) {
    if (!smt) return;
    
    printf("\n=== SMT Statistics ===\n");
    printf("Total Elements: %zu\n", smt->total_elements);
    printf("Active Layers: %d\n", smt->layer_count);
    printf("Max Layers: %d\n", MAX_LAYERS);
    
    int active_layers = 0;
    for (int i = 0; i < smt->layer_count; i++) {
        if (smt->layers[i].element_count > 0) active_layers++;
    }
    printf("Non-empty Layers: %d\n", active_layers);
    
    printf("\nLayer Distribution:\n");
    for (int i = 0; i < smt->layer_count; i++) {
        if (smt->layers[i].element_count > 0) {
            printf("  Layer %d: %d elements\n", i, smt->layers[i].element_count);
        }
    }
    
    unsigned char root[HASH_SIZE];
    SMT* mutable_smt = (SMT*)smt;
    if (smt_get_root(mutable_smt, root) == SMT_SUCCESS) {
        printf("\nTop-level Root: ");
        for (int i = 0; i < HASH_SIZE; i++) printf("%02x", root[i]);
        printf("\n");
    } else {
        printf("\nTop-level Root: <calculation failed>\n");
    }
}