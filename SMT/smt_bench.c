#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <openssl/evp.h>

#define HASH_SIZE 32
#define NUM_ELEMENTS 100000
#define MAX_KEY_SIZE 32
#define MAX_VALUE_SIZE 32
#define INITIAL_LAYER_CAPACITY 4

// ================== COMMON STRUCTURES ==================
typedef struct {
    char key[MAX_KEY_SIZE];
    char value[MAX_VALUE_SIZE];
    int priority;
    int x, y;
} Element;

// ================== STABLE SMT IMPLEMENTATION ==================
typedef struct {
    unsigned count;
    unsigned capacity;
    Element* elements;
    unsigned char root[HASH_SIZE];
} Layer;

typedef struct {
    Layer* layers[256];
    unsigned active_layers;
} SMT;

void hash_element(const Element* elem, unsigned char* hash) {
    if (!elem || !hash) return;
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return;
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return;
    }
    
    EVP_DigestUpdate(ctx, elem->key, strlen(elem->key));
    EVP_DigestUpdate(ctx, elem->value, strlen(elem->value));
    EVP_DigestUpdate(ctx, &elem->priority, sizeof(elem->priority));
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);
}

void smt_init(SMT* smt) {
    if (!smt) return;
    memset(smt, 0, sizeof(SMT));
}

void smt_insert(SMT* smt, Element* elem) {
    if (!smt || !elem) return;
    
    unsigned priority = elem->priority % 256;
    Layer* layer = smt->layers[priority];
    
    if (!layer) {
        layer = calloc(1, sizeof(Layer));
        if (!layer) return;
        
        layer->elements = malloc(INITIAL_LAYER_CAPACITY * sizeof(Element));
        if (!layer->elements) {
            free(layer);
            return;
        }
        
        layer->capacity = INITIAL_LAYER_CAPACITY;
        smt->layers[priority] = layer;
        smt->active_layers++;
    }
    
    if (layer->count >= layer->capacity) {
        unsigned new_capacity = layer->capacity * 2;
        Element* new_elements = realloc(layer->elements, new_capacity * sizeof(Element));
        if (!new_elements) return;
        
        layer->elements = new_elements;
        layer->capacity = new_capacity;
    }
    
    layer->elements[layer->count++] = *elem;
    
    // Update root hash
    unsigned char new_root[HASH_SIZE] = {0};
    for (unsigned i = 0; i < layer->count; i++) {
        unsigned char elem_hash[HASH_SIZE];
        hash_element(&layer->elements[i], elem_hash);
        for (int j = 0; j < HASH_SIZE; j++) {
            new_root[j] ^= elem_hash[j];
        }
    }
    memcpy(layer->root, new_root, HASH_SIZE);
}

int smt_search(SMT* smt, const char* key) {
    if (!smt || !key) return 0;
    
    unsigned char hash[HASH_SIZE];
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, key, strlen(key)) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    EVP_MD_CTX_free(ctx);
    
    uint32_t priority = 0;
    for (int i = 0; i < 4; i++) {
        priority = (priority << 8) | hash[i];
    }
    
    Layer* layer = smt->layers[priority % 256];
    if (!layer) return 0;
    
    for (unsigned i = 0; i < layer->count; i++) {
        if (strcmp(layer->elements[i].key, key) == 0) {
            return 1;
        }
    }
    return 0;
}

void smt_cleanup(SMT* smt) {
    if (!smt) return;
    
    for (int i = 0; i < 256; i++) {
        if (smt->layers[i]) {
            free(smt->layers[i]->elements);
            free(smt->layers[i]);
        }
    }
}

// ================== CMT IMPLEMENTATION ==================
typedef struct CMTNode {
    Element elem;
    unsigned char hash[HASH_SIZE];
    struct CMTNode *left, *right;
} CMTNode;

void cmt_hash_node(CMTNode* node) {
    if (!node) return;
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return;
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return;
    }
    
    if (node->left) EVP_DigestUpdate(ctx, node->left->hash, HASH_SIZE);
    EVP_DigestUpdate(ctx, node->elem.key, strlen(node->elem.key));
    EVP_DigestUpdate(ctx, node->elem.value, strlen(node->elem.value));
    if (node->right) EVP_DigestUpdate(ctx, node->right->hash, HASH_SIZE);
    EVP_DigestFinal_ex(ctx, node->hash, NULL);
    EVP_MD_CTX_free(ctx);
}

CMTNode* cmt_insert(CMTNode* root, Element* elem, int* depth, int* max_depth) {
    if (!elem) return root;
    
    if (!root) {
        CMTNode* new_node = calloc(1, sizeof(CMTNode));
        if (!new_node) return NULL;
        
        new_node->elem = *elem;
        cmt_hash_node(new_node);
        if (*depth > *max_depth) *max_depth = *depth;
        return new_node;
    }

    (*depth)++;
    if (elem->x < root->elem.x || (elem->x == root->elem.x && elem->y < root->elem.y)) {
        root->left = cmt_insert(root->left, elem, depth, max_depth);
    } else {
        root->right = cmt_insert(root->right, elem, depth, max_depth);
    }
    cmt_hash_node(root);
    return root;
}

int cmt_search(CMTNode* root, const char* key) {
    if (!root || !key) return 0;
    if (strcmp(root->elem.key, key) == 0) return 1;
    return cmt_search(root->left, key) || cmt_search(root->right, key);
}

void cmt_cleanup(CMTNode* root) {
    if (!root) return;
    cmt_cleanup(root->left);
    cmt_cleanup(root->right);
    free(root);
}

// ================== BENCHMARK UTILS ==================
double get_time() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

size_t get_memory_usage() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return usage.ru_maxrss;
}

void generate_elements(Element* elements, int count) {
    for (int i = 0; i < count; i++) {
        snprintf(elements[i].key, MAX_KEY_SIZE, "key_%d", i);
        snprintf(elements[i].value, MAX_VALUE_SIZE, "value_%d", i);
        elements[i].priority = rand() % 256;
        elements[i].x = rand() % 1000;
        elements[i].y = rand() % 1000;
    }
}

size_t count_cmt_nodes(CMTNode* root) {
    if (!root) return 0;
    return 1 + count_cmt_nodes(root->left) + count_cmt_nodes(root->right);
}

size_t calculate_smt_memory(SMT* smt) {
    if (!smt) return 0;
    
    size_t total = sizeof(SMT);
    for (int i = 0; i < 256; i++) {
        if (smt->layers[i]) {
            total += sizeof(Layer) + (smt->layers[i]->capacity * sizeof(Element));
        }
    }
    return total;
}

// ================== MAIN BENCHMARK ==================
int main() {
    srand(time(NULL));
    Element elements[NUM_ELEMENTS];
    generate_elements(elements, NUM_ELEMENTS);

    // Benchmark SMT
    SMT smt;
    smt_init(&smt);
    double start = get_time();
    for (int i = 0; i < NUM_ELEMENTS; i++) {
        smt_insert(&smt, &elements[i]);
    }
    double smt_insert_time = get_time() - start;

    start = get_time();
    volatile int smt_found = 0;
    for (int i = 0; i < NUM_ELEMENTS; i++) {
        smt_found += smt_search(&smt, elements[i].key);
    }
    double smt_search_time = get_time() - start;

    // Benchmark CMT
    CMTNode* cmt_root = NULL;
    int cmt_depth = 0, cmt_max_depth = 0;
    start = get_time();
    for (int i = 0; i < NUM_ELEMENTS; i++) {
        int current_depth = 0;
        cmt_root = cmt_insert(cmt_root, &elements[i], &current_depth, &cmt_max_depth);
    }
    double cmt_insert_time = get_time() - start;

    start = get_time();
    volatile int cmt_found = 0;
    for (int i = 0; i < NUM_ELEMENTS; i++) {
        cmt_found += cmt_search(cmt_root, elements[i].key);
    }
    double cmt_search_time = get_time() - start;

    // Calculate memory usage
    size_t smt_mem = calculate_smt_memory(&smt);
    size_t cmt_mem = count_cmt_nodes(cmt_root) * sizeof(CMTNode);

    // Print results
    printf("============= Benchmark Results (n=%d) =============\n", NUM_ELEMENTS);
    printf("Metric               SMT                 CMT\n");
    printf("----------------------------------------------------\n");
    printf("Insert Time:     %8.3f ms         %8.3f ms\n", smt_insert_time * 1000, cmt_insert_time * 1000);
    printf("Search Time:     %8.3f ms         %8.3f ms\n", smt_search_time * 1000, cmt_search_time * 1000);
    printf("Max Depth:       N/A                %8d\n", cmt_max_depth);
    printf("Memory Usage:    %8zu KB          %8zu KB\n", 
           smt_mem / 1024,
           cmt_mem / 1024);

    // Cleanup
    smt_cleanup(&smt);
    cmt_cleanup(cmt_root);

    return 0;
}