#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <openssl/sha.h>

#define MAX_LAYERS 256
#define HASH_SIZE 32
#define NUM_ELEMENTS 10000

// ================== COMMON STRUCTURES ==================
typedef struct {
    char key[32];
    char value[32];
    int priority;  // For SMT
    int x, y;      // For CMT
} Element;

// ================== SMT IMPLEMENTATION ==================
typedef struct {
    Element* elements;
    int count;
    unsigned char root[HASH_SIZE];
} Layer;

typedef struct {
    Layer layers[MAX_LAYERS];
    int layer_count;
} SMT;

void smt_init(SMT* smt) {
    memset(smt, 0, sizeof(SMT));
}

void hash_element(const Element* elem, unsigned char* hash) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, elem->key, strlen(elem->key));
    SHA256_Update(&ctx, elem->value, strlen(elem->value));
    SHA256_Update(&ctx, &elem->priority, sizeof(elem->priority));
    SHA256_Final(hash, &ctx);
}

void smt_insert(SMT* smt, Element* elem) {
    int priority = elem->priority % MAX_LAYERS;
    Layer* layer = &smt->layers[priority];
    
    // Resize layer
    layer->elements = realloc(layer->elements, (layer->count + 1) * sizeof(Element));
    layer->elements[layer->count] = *elem;
    
    // Update layer root
    unsigned char new_root[HASH_SIZE] = {0};
    for (int i = 0; i <= layer->count; i++) {
        unsigned char elem_hash[HASH_SIZE];
        hash_element(&layer->elements[i], elem_hash);
        for (int j = 0; j < HASH_SIZE; j++) {
            new_root[j] ^= elem_hash[j];  // Simple XOR for demo
        }
    }
    memcpy(layer->root, new_root, HASH_SIZE);
    layer->count++;
}

int smt_search(SMT* smt, const char* key) {
    for (int i = 0; i < MAX_LAYERS; i++) {
        Layer* layer = &smt->layers[i];
        for (int j = 0; j < layer->count; j++) {
            if (strcmp(layer->elements[j].key, key) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

// ================== CMT IMPLEMENTATION ==================
typedef struct CMTNode {
    Element elem;
    unsigned char hash[HASH_SIZE];
    struct CMTNode *left, *right;
} CMTNode;

void cmt_hash_node(CMTNode* node) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    if (node->left) SHA256_Update(&ctx, node->left->hash, HASH_SIZE);
    SHA256_Update(&ctx, node->elem.key, strlen(node->elem.key));
    SHA256_Update(&ctx, node->elem.value, strlen(node->elem.value));
    if (node->right) SHA256_Update(&ctx, node->right->hash, HASH_SIZE);
    SHA256_Final(node->hash, &ctx);
}

CMTNode* cmt_insert(CMTNode* root, Element* elem, int* depth, int* max_depth) {
    if (!root) {
        CMTNode* new_node = malloc(sizeof(CMTNode));
        new_node->elem = *elem;
        new_node->left = new_node->right = NULL;
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
    if (!root) return 0;
    if (strcmp(root->elem.key, key) == 0) return 1;
    return cmt_search(root->left, key) || cmt_search(root->right, key);
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
    return usage.ru_maxrss; // KB
}

void generate_elements(Element* elements, int count) {
    for (int i = 0; i < count; i++) {
        sprintf(elements[i].key, "key_%d", i);
        sprintf(elements[i].value, "value_%d", i);
        elements[i].priority = rand() % MAX_LAYERS;
        elements[i].x = rand() % 1000;
        elements[i].y = rand() % 1000;
    }
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

    // Print results
    printf("============= Benchmark Results (n=%d) =============\n", NUM_ELEMENTS);
    printf("Metric               SMT                 CMT\n");
    printf("----------------------------------------------------\n");
    printf("Insert Time:     %8.3f ms         %8.3f ms\n", smt_insert_time * 1000, cmt_insert_time * 1000);
    printf("Search Time:     %8.3f ms         %8.3f ms\n", smt_search_time * 1000, cmt_search_time * 1000);
    printf("Max Depth:       N/A                %8d\n", cmt_max_depth);
    printf("Memory Usage:    %8zu KB          %8zu KB\n", 
           get_memory_usage() / 1024,  // SMT (approx)
           (cmt_max_depth * sizeof(CMTNode)) / 1024);  // CMT (approx)

    return 0;
}