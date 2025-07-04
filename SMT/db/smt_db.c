#include "smt_db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <jansson.h>

#define MAX_DATABASES 10

// Global database manager
static DatabaseManager g_db_manager = {0};

// Helper functions
static Database* find_database(const char* db_name) {
    if (!db_name || !g_db_manager.is_initialized) return NULL;
    
    pthread_mutex_lock(&g_db_manager.lock);
    for (size_t i = 0; i < g_db_manager.db_count; i++) {
        if (strcmp(g_db_manager.databases[i].name, db_name) == 0 && 
            g_db_manager.databases[i].is_open) {
            pthread_mutex_unlock(&g_db_manager.lock);
            return &g_db_manager.databases[i];
        }
    }
    pthread_mutex_unlock(&g_db_manager.lock);
    return NULL;
}

static Collection* find_collection(Database* db, const char* collection_name) {
    if (!db || !collection_name) return NULL;
    
    pthread_rwlock_rdlock(&db->lock);
    for (size_t i = 0; i < db->collection_count; i++) {
        if (strcmp(db->collections[i].name, collection_name) == 0 && 
            db->collections[i].is_open) {
            pthread_rwlock_unlock(&db->lock);
            return &db->collections[i];
        }
    }
    pthread_rwlock_unlock(&db->lock);
    return NULL;
}

static db_error_t ensure_persistence_dir() {
    if (g_db_manager.persistence_path[0] == '\0') {
        return DB_SUCCESS;
    }
    
    struct stat st = {0};
    if (stat(g_db_manager.persistence_path, &st) == -1) {
        if (mkdir(g_db_manager.persistence_path, 0700) == -1) {
            return DB_ERROR_IO_ERROR;
        }
    }
    return DB_SUCCESS;
}

static db_error_t serialize_database(Database* db, int fd) {
    json_t* root = json_object();
    if (!root) return DB_ERROR_MEMORY_ALLOCATION;
    
    // Serialize database metadata
    json_object_set_new(root, "name", json_string(db->name));
    json_object_set_new(root, "created_at", json_integer(db->stats.created_at));
    json_object_set_new(root, "last_modified", json_integer(db->stats.last_modified));
    
    // Serialize collections
    json_t* collections = json_array();
    for (size_t i = 0; i < db->collection_count; i++) {
        Collection* col = &db->collections[i];
        if (!col->is_open) continue;
        
        json_t* collection_obj = json_object();
        json_object_set_new(collection_obj, "name", json_string(col->name));
        json_object_set_new(collection_obj, "created_at", json_integer(col->created_at));
        json_object_set_new(collection_obj, "last_modified", json_integer(col->last_modified));
        
        // Serialize SMT data
        unsigned char root_hash[HASH_SIZE];
        if (smt_get_root(&col->tree, root_hash) == SMT_SUCCESS) {
            char hash_str[2*HASH_SIZE+1];
            for (size_t j = 0; j < HASH_SIZE; j++) {
                sprintf(hash_str + 2*j, "%02x", root_hash[j]);
            }
            json_object_set_new(collection_obj, "root_hash", json_string(hash_str));
        }
        
        json_array_append_new(collections, collection_obj);
    }
    json_object_set_new(root, "collections", collections);
    
    // Write to file
    char* json_str = json_dumps(root, JSON_COMPACT);
    json_decref(root);
    
    if (!json_str) return DB_ERROR_MEMORY_ALLOCATION;
    
    ssize_t written = write(fd, json_str, strlen(json_str));
    free(json_str);
    
    if (written == -1) return DB_ERROR_IO_ERROR;
    
    return DB_SUCCESS;
}

static db_error_t deserialize_database(Database* db, int fd) {
    struct stat st;
    if (fstat(fd, &st) == -1) return DB_ERROR_IO_ERROR;
    
    char* buffer = malloc(st.st_size + 1);
    if (!buffer) return DB_ERROR_MEMORY_ALLOCATION;
    
    if (read(fd, buffer, st.st_size) != st.st_size) {
        free(buffer);
        return DB_ERROR_IO_ERROR;
    }
    buffer[st.st_size] = '\0';
    
    json_error_t error;
    json_t* root = json_loads(buffer, 0, &error);
    free(buffer);
    
    if (!root) return DB_ERROR_CORRUPTED_DATA;
    
    // Deserialize database metadata
    json_t* name = json_object_get(root, "name");
    if (name) strncpy(db->name, json_string_value(name), MAX_DB_NAME_LEN - 1);
    
    json_t* created_at = json_object_get(root, "created_at");
    if (created_at) db->stats.created_at = json_integer_value(created_at);
    
    json_t* last_modified = json_object_get(root, "last_modified");
    if (last_modified) db->stats.last_modified = json_integer_value(last_modified);
    
    // Deserialize collections
    json_t* collections = json_object_get(root, "collections");
    if (collections && json_is_array(collections)) {
        size_t index;
        json_t* value;
        json_array_foreach(collections, index, value) {
            json_t* col_name = json_object_get(value, "name");
            if (!col_name) continue;
            
            const char* name_str = json_string_value(col_name);
            db_create_collection(db->name, name_str);
            
            // Additional collection data would be loaded here
        }
    }
    
    json_decref(root);
    return DB_SUCCESS;
}

// Initialization
db_error_t db_manager_init(const char* persistence_path) {
    return db_manager_init_with_config(DEFAULT_MAX_DATABASES, 
                                     DEFAULT_MAX_COLLECTIONS, 
                                     persistence_path);
}

db_error_t db_manager_init_with_config(size_t max_databases, 
                                     size_t max_collections,
                                     const char* persistence_path) {
    if (g_db_manager.is_initialized) {
        return DB_SUCCESS;
    }
    
    memset(&g_db_manager, 0, sizeof(DatabaseManager));
    
    if (pthread_mutex_init(&g_db_manager.lock, NULL) != 0) {
        return DB_ERROR_MEMORY_ALLOCATION;
    }
    
    g_db_manager.databases = calloc(max_databases, sizeof(Database));
    if (!g_db_manager.databases) {
        pthread_mutex_destroy(&g_db_manager.lock);
        return DB_ERROR_MEMORY_ALLOCATION;
    }
    
    g_db_manager.db_capacity = max_databases;
    g_db_manager.db_count = 0;
    
    if (persistence_path) {
        strncpy(g_db_manager.persistence_path, persistence_path, 
               sizeof(g_db_manager.persistence_path) - 1);
        db_error_t err = ensure_persistence_dir();
        if (err != DB_SUCCESS) {
            free(g_db_manager.databases);
            pthread_mutex_destroy(&g_db_manager.lock);
            return err;
        }
    }
    
    g_db_manager.is_initialized = 1;
    return DB_SUCCESS;
}

void db_manager_cleanup() {
    if (!g_db_manager.is_initialized) return;
    
    pthread_mutex_lock(&g_db_manager.lock);
    
    for (size_t i = 0; i < g_db_manager.db_count; i++) {
        Database* db = &g_db_manager.databases[i];
        if (db->is_open) {
            pthread_rwlock_wrlock(&db->lock);
            
            for (size_t j = 0; j < db->collection_count; j++) {
                Collection* col = &db->collections[j];
                if (col->is_open) {
                    pthread_rwlock_wrlock(&col->lock);
                    smt_cleanup(&col->tree);
                    pthread_rwlock_unlock(&col->lock);
                    pthread_rwlock_destroy(&col->lock);
                }
            }
            
            free(db->collections);
            pthread_rwlock_unlock(&db->lock);
            pthread_rwlock_destroy(&db->lock);
        }
    }
    
    free(g_db_manager.databases);
    pthread_mutex_unlock(&g_db_manager.lock);
    pthread_mutex_destroy(&g_db_manager.lock);
    
    memset(&g_db_manager, 0, sizeof(DatabaseManager));
}

// Database operations
db_error_t db_create(const char* db_name) {
    if (!db_name) return DB_ERROR_NULL_POINTER;
    if (strlen(db_name) >= MAX_DB_NAME_LEN) return DB_ERROR_INVALID_PARAMETER;
    
    pthread_mutex_lock(&g_db_manager.lock);
    
    for (size_t i = 0; i < g_db_manager.db_count; i++) {
        if (strcmp(g_db_manager.databases[i].name, db_name) == 0) {
            pthread_mutex_unlock(&g_db_manager.lock);
            return g_db_manager.databases[i].is_open ? 
                   DB_ERROR_DATABASE_EXISTS : DB_SUCCESS;
        }
    }
    
    if (g_db_manager.db_count >= g_db_manager.db_capacity) {
        pthread_mutex_unlock(&g_db_manager.lock);
        return DB_ERROR_MAX_LIMIT_REACHED;
    }
    
    Database* db = &g_db_manager.databases[g_db_manager.db_count++];
    memset(db, 0, sizeof(Database));
    
    strncpy(db->name, db_name, MAX_DB_NAME_LEN - 1);
    db->collection_capacity = DEFAULT_MAX_COLLECTIONS;
    db->collections = calloc(db->collection_capacity, sizeof(Collection));
    if (!db->collections) {
        g_db_manager.db_count--;
        pthread_mutex_unlock(&g_db_manager.lock);
        return DB_ERROR_MEMORY_ALLOCATION;
    }
    
    if (pthread_rwlock_init(&db->lock, NULL) != 0) {
        free(db->collections);
        g_db_manager.db_count--;
        pthread_mutex_unlock(&g_db_manager.lock);
        return DB_ERROR_MEMORY_ALLOCATION;
    }
    
    db->stats.created_at = time(NULL);
    db->stats.last_modified = db->stats.created_at;
    db->is_open = 1;
    
    pthread_mutex_unlock(&g_db_manager.lock);
    return DB_SUCCESS;
}

db_error_t db_open(const char* db_name) {
    if (!db_name) return DB_ERROR_NULL_POINTER;
    
    pthread_mutex_lock(&g_db_manager.lock);
    
    for (size_t i = 0; i < g_db_manager.db_count; i++) {
        if (strcmp(g_db_manager.databases[i].name, db_name) == 0) {
            if (g_db_manager.databases[i].is_open) {
                pthread_mutex_unlock(&g_db_manager.lock);
                return DB_SUCCESS;
            }
            
            g_db_manager.databases[i].is_open = 1;
            pthread_mutex_unlock(&g_db_manager.lock);
            return DB_SUCCESS;
        }
    }
    
    pthread_mutex_unlock(&g_db_manager.lock);
    return DB_ERROR_DATABASE_NOT_FOUND;
}

db_error_t db_close(const char* db_name) {
    if (!db_name) return DB_ERROR_NULL_POINTER;
    
    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;
    
    pthread_rwlock_wrlock(&db->lock);
    db->is_open = 0;
    pthread_rwlock_unlock(&db->lock);
    
    return DB_SUCCESS;
}

db_error_t db_drop(const char* db_name) {
    if (!db_name) return DB_ERROR_NULL_POINTER;
    
    pthread_mutex_lock(&g_db_manager.lock);
    
    for (size_t i = 0; i < g_db_manager.db_count; i++) {
        if (strcmp(g_db_manager.databases[i].name, db_name) == 0) {
            Database* db = &g_db_manager.databases[i];
            
            pthread_rwlock_wrlock(&db->lock);
            
            for (size_t j = 0; j < db->collection_count; j++) {
                Collection* col = &db->collections[j];
                if (col->is_open) {
                    pthread_rwlock_wrlock(&col->lock);
                    smt_cleanup(&col->tree);
                    pthread_rwlock_unlock(&col->lock);
                    pthread_rwlock_destroy(&col->lock);
                }
            }
            
            free(db->collections);
            pthread_rwlock_unlock(&db->lock);
            pthread_rwlock_destroy(&db->lock);
            
            // Shift remaining databases
            for (size_t j = i; j < g_db_manager.db_count - 1; j++) {
                g_db_manager.databases[j] = g_db_manager.databases[j+1];
            }
            
            g_db_manager.db_count--;
            pthread_mutex_unlock(&g_db_manager.lock);
            return DB_SUCCESS;
        }
    }
    
    pthread_mutex_unlock(&g_db_manager.lock);
    return DB_ERROR_DATABASE_NOT_FOUND;
}

db_error_t db_exists(const char* db_name, int* exists) {
    if (!db_name || !exists) return DB_ERROR_NULL_POINTER;
    
    *exists = 0;
    pthread_mutex_lock(&g_db_manager.lock);
    
    for (size_t i = 0; i < g_db_manager.db_count; i++) {
        if (strcmp(g_db_manager.databases[i].name, db_name) == 0) {
            *exists = 1;
            break;
        }
    }
    
    pthread_mutex_unlock(&g_db_manager.lock);
    return DB_SUCCESS;
}

db_error_t db_list(char*** db_names, size_t* count) {
    if (!db_names || !count) return DB_ERROR_NULL_POINTER;
    
    *db_names = NULL;
    *count = 0;
    
    pthread_mutex_lock(&g_db_manager.lock);
    
    if (g_db_manager.db_count == 0) {
        pthread_mutex_unlock(&g_db_manager.lock);
        return DB_SUCCESS;
    }
    
    *db_names = malloc(g_db_manager.db_count * sizeof(char*));
    if (!*db_names) {
        pthread_mutex_unlock(&g_db_manager.lock);
        return DB_ERROR_MEMORY_ALLOCATION;
    }
    
    for (size_t i = 0; i < g_db_manager.db_count; i++) {
        (*db_names)[i] = strdup(g_db_manager.databases[i].name);
        if (!(*db_names)[i]) {
            for (size_t j = 0; j < i; j++) {
                free((*db_names)[j]);
            }
            free(*db_names);
            *db_names = NULL;
            pthread_mutex_unlock(&g_db_manager.lock);
            return DB_ERROR_MEMORY_ALLOCATION;
        }
    }
    
    *count = g_db_manager.db_count;
    pthread_mutex_unlock(&g_db_manager.lock);
    return DB_SUCCESS;
}

db_error_t db_get_stats(const char* db_name, DatabaseStats* stats) {
    if (!db_name || !stats) return DB_ERROR_NULL_POINTER;
    
    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;
    
    pthread_rwlock_rdlock(&db->lock);
    
    // Copy basic stats
    *stats = db->stats;
    
    // Calculate combined root hash from all collections
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1) {
        for (size_t i = 0; i < db->collection_count; i++) {
            Collection* col = &db->collections[i];
            if (!col->is_open) continue;
            
            pthread_rwlock_rdlock(&col->lock);
            
            // Get each collection's root hash
            unsigned char col_root[HASH_SIZE];
            if (smt_get_root(&col->tree, col_root) == SMT_SUCCESS) {
                EVP_DigestUpdate(ctx, col_root, HASH_SIZE);
                // Include collection name in hash
                EVP_DigestUpdate(ctx, col->name, strlen(col->name));
            }
            
            pthread_rwlock_unlock(&col->lock);
        }
        
        // Finalize the combined hash
        unsigned int hash_len;
        EVP_DigestFinal_ex(ctx, stats->root_hash, &hash_len);
    } else {
        // Fallback: set zero hash if couldn't calculate
        memset(stats->root_hash, 0, HASH_SIZE);
    }
    
    if (ctx) EVP_MD_CTX_free(ctx);
    pthread_rwlock_unlock(&db->lock);
    
    return DB_SUCCESS;
}

// Collection operations
db_error_t db_create_collection(const char* db_name, const char* collection_name) {
    if (!db_name || !collection_name) return DB_ERROR_NULL_POINTER;
    if (strlen(collection_name) >= MAX_COLLECTION_NAME_LEN) return DB_ERROR_INVALID_PARAMETER;
    
    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;
    
    pthread_rwlock_wrlock(&db->lock);
    
    // Check if collection exists
    for (size_t i = 0; i < db->collection_count; i++) {
        if (strcmp(db->collections[i].name, collection_name) == 0) {
            pthread_rwlock_unlock(&db->lock);
            return db->collections[i].is_open ? 
                   DB_ERROR_COLLECTION_EXISTS : DB_SUCCESS;
        }
    }
    
    // Check capacity
    if (db->collection_count >= db->collection_capacity) {
        size_t new_capacity = db->collection_capacity * 2;
        Collection* new_collections = realloc(db->collections, new_capacity * sizeof(Collection));
        if (!new_collections) {
            pthread_rwlock_unlock(&db->lock);
            return DB_ERROR_MEMORY_ALLOCATION;
        }
        
        db->collections = new_collections;
        db->collection_capacity = new_capacity;
    }
    
    // Initialize new collection
    Collection* col = &db->collections[db->collection_count++];
    memset(col, 0, sizeof(Collection));
    
    strncpy(col->name, collection_name, MAX_COLLECTION_NAME_LEN - 1);
    col->created_at = time(NULL);
    col->last_modified = col->created_at;
    col->is_open = 1;
    
    if (pthread_rwlock_init(&col->lock, NULL) != 0) {
        db->collection_count--;
        pthread_rwlock_unlock(&db->lock);
        return DB_ERROR_MEMORY_ALLOCATION;
    }
    
    smt_error_t err = smt_init(&col->tree);
    if (err != SMT_SUCCESS) {
        pthread_rwlock_destroy(&col->lock);
        db->collection_count--;
        pthread_rwlock_unlock(&db->lock);
        return (db_error_t)err;
    }
    
    db->stats.total_collections++;
    db->stats.last_modified = time(NULL);
    
    pthread_rwlock_unlock(&db->lock);
    return DB_SUCCESS;
}

db_error_t db_drop_collection(const char* db_name, const char* collection_name) {
    if (!db_name || !collection_name) return DB_ERROR_NULL_POINTER;
    
    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;
    
    pthread_rwlock_wrlock(&db->lock);
    
    for (size_t i = 0; i < db->collection_count; i++) {
        if (strcmp(db->collections[i].name, collection_name) == 0) {
            Collection* col = &db->collections[i];
            
            pthread_rwlock_wrlock(&col->lock);
            smt_cleanup(&col->tree);
            pthread_rwlock_unlock(&col->lock);
            pthread_rwlock_destroy(&col->lock);
            
            // Shift remaining collections
            for (size_t j = i; j < db->collection_count - 1; j++) {
                db->collections[j] = db->collections[j+1];
            }
            
            db->collection_count--;
            db->stats.total_collections--;
            db->stats.last_modified = time(NULL);
            
            pthread_rwlock_unlock(&db->lock);
            return DB_SUCCESS;
        }
    }
    
    pthread_rwlock_unlock(&db->lock);
    return DB_ERROR_COLLECTION_NOT_FOUND;
}

db_error_t db_list_collections(const char* db_name, char*** collection_names, size_t* count) {
    if (!db_name || !collection_names || !count) return DB_ERROR_NULL_POINTER;
    
    *collection_names = NULL;
    *count = 0;
    
    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;
    
    pthread_rwlock_rdlock(&db->lock);
    
    if (db->collection_count == 0) {
        pthread_rwlock_unlock(&db->lock);
        return DB_SUCCESS;
    }
    
    *collection_names = malloc(db->collection_count * sizeof(char*));
    if (!*collection_names) {
        pthread_rwlock_unlock(&db->lock);
        return DB_ERROR_MEMORY_ALLOCATION;
    }
    
    for (size_t i = 0; i < db->collection_count; i++) {
        (*collection_names)[i] = strdup(db->collections[i].name);
        if (!(*collection_names)[i]) {
            for (size_t j = 0; j < i; j++) {
                free((*collection_names)[j]);
            }
            free(*collection_names);
            *collection_names = NULL;
            pthread_rwlock_unlock(&db->lock);
            return DB_ERROR_MEMORY_ALLOCATION;
        }
    }
    
    *count = db->collection_count;
    pthread_rwlock_unlock(&db->lock);
    return DB_SUCCESS;
}

db_error_t db_collection_exists(const char* db_name, const char* collection_name, int* exists) {
    if (!db_name || !collection_name || !exists) return DB_ERROR_NULL_POINTER;
    
    *exists = 0;
    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;
    
    pthread_rwlock_rdlock(&db->lock);
    
    for (size_t i = 0; i < db->collection_count; i++) {
        if (strcmp(db->collections[i].name, collection_name) == 0) {
            *exists = 1;
            break;
        }
    }
    
    pthread_rwlock_unlock(&db->lock);
    return DB_SUCCESS;
}

// CRUD operations
db_error_t db_insert(const char* db_name, const char* collection_name,
                    const char* key, const char* value) {
    if (!db_name || !collection_name || !key) return DB_ERROR_NULL_POINTER;
    
    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;
    
    Collection* col = find_collection(db, collection_name);
    if (!col) return DB_ERROR_COLLECTION_NOT_FOUND;
    
    pthread_rwlock_wrlock(&col->lock);
    
    // Check if key exists
    char* existing_value = NULL;
    smt_error_t lookup_result = smt_lookup(&col->tree, key, &existing_value);
    
    smt_error_t err = smt_insert(&col->tree, key, value);
    if (err != SMT_SUCCESS) {
        if (existing_value) free(existing_value);
        pthread_rwlock_unlock(&col->lock);
        return (db_error_t)err;
    }
    
    // Update statistics
    if (lookup_result == SMT_ERROR_KEY_NOT_FOUND) {
        col->record_count++;
        db->stats.total_records++;
    } else if (value && existing_value && strcmp(value, existing_value) != 0) {
        // Count as update if value changed
        db->stats.total_updates++;
    }
    
    col->last_modified = time(NULL);
    db->stats.last_modified = col->last_modified;
    
    if (existing_value) free(existing_value);
    pthread_rwlock_unlock(&col->lock);
    
    return DB_SUCCESS;
}

db_error_t db_find(const char* db_name, const char* collection_name,
                 const char* key, char** value) {
    if (!db_name || !collection_name || !key || !value) return DB_ERROR_NULL_POINTER;
    
    *value = NULL;
    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;
    
    Collection* col = find_collection(db, collection_name);
    if (!col) return DB_ERROR_COLLECTION_NOT_FOUND;
    
    pthread_rwlock_rdlock(&col->lock);
    smt_error_t err = smt_lookup(&col->tree, key, value);
    pthread_rwlock_unlock(&col->lock);
    
    return (db_error_t)err;
}

db_error_t db_update(const char* db_name, const char* collection_name,
                    const char* key, const char* value) {
    // Update is same as insert in SMT
    return db_insert(db_name, collection_name, key, value);
}

db_error_t db_delete(const char* db_name, const char* collection_name,
                    const char* key) {
    if (!db_name || !collection_name || !key) return DB_ERROR_NULL_POINTER;
    
    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;
    
    Collection* col = find_collection(db, collection_name);
    if (!col) return DB_ERROR_COLLECTION_NOT_FOUND;
    
    pthread_rwlock_wrlock(&col->lock);
    
    smt_error_t err = smt_delete(&col->tree, key);
    if (err != SMT_SUCCESS) {
        pthread_rwlock_unlock(&col->lock);
        return (db_error_t)err;
    }
    
    col->record_count--;
    db->stats.total_records--;
    col->last_modified = time(NULL);
    db->stats.last_modified = col->last_modified;
    
    pthread_rwlock_unlock(&col->lock);
    return DB_SUCCESS;
}

// Batch operations
db_error_t db_batch_insert(const char* db_name, const char* collection_name,
                          const char** keys, const char** values, size_t count) {
    if (!db_name || !collection_name || !keys || !values) return DB_ERROR_NULL_POINTER;
    if (count == 0) return DB_SUCCESS;
    
    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;
    
    Collection* col = find_collection(db, collection_name);
    if (!col) return DB_ERROR_COLLECTION_NOT_FOUND;
    
    pthread_rwlock_wrlock(&col->lock);
    
    size_t new_records = 0;
    db_error_t final_error = DB_SUCCESS;
    
    for (size_t i = 0; i < count; i++) {
        if (!keys[i]) {
            final_error = DB_ERROR_NULL_POINTER;
            break;
        }
        
        char* existing_value = NULL;
        smt_error_t lookup_result = smt_lookup(&col->tree, keys[i], &existing_value);
        
        smt_error_t err = smt_insert(&col->tree, keys[i], values ? values[i] : NULL);
        if (err != SMT_SUCCESS) {
            final_error = (db_error_t)err;
            if (existing_value) free(existing_value);
            break;
        }
        
        if (lookup_result == SMT_ERROR_KEY_NOT_FOUND) {
            new_records++;
        }
        
        if (existing_value) free(existing_value);
    }
    
    col->record_count += new_records;
    db->stats.total_records += new_records;
    col->last_modified = time(NULL);
    db->stats.last_modified = col->last_modified;
    
    pthread_rwlock_unlock(&col->lock);
    return final_error;
}

db_error_t db_find_all(const char* db_name, const char* collection_name,
                      char*** keys, char*** values, size_t* count) {
    if (!db_name || !collection_name || !keys || !values || !count) {
        return DB_ERROR_NULL_POINTER;
    }
    
    *keys = NULL;
    *values = NULL;
    *count = 0;
    
    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;
    
    Collection* col = find_collection(db, collection_name);
    if (!col) return DB_ERROR_COLLECTION_NOT_FOUND;
    
    // Note: This is a simplified implementation. A real implementation would need
    // to iterate through all keys in the SMT, which would require additional
    // functionality in the SMT implementation.
    
    return DB_SUCCESS;
}

// Verification operations
db_error_t db_get_root_hash(const char* db_name, const char* collection_name,
                          unsigned char* root_hash) {
    if (!db_name || !collection_name || !root_hash) return DB_ERROR_NULL_POINTER;
    
    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;
    
    Collection* col = find_collection(db, collection_name);
    if (!col) return DB_ERROR_COLLECTION_NOT_FOUND;
    
    pthread_rwlock_rdlock(&col->lock);
    smt_error_t err = smt_get_root(&col->tree, root_hash);
    pthread_rwlock_unlock(&col->lock);
    
    return (db_error_t)err;
}

db_error_t db_generate_proof(const char* db_name, const char* collection_name,
                           const char* key, MembershipProof* proof) {
    if (!db_name || !collection_name || !key || !proof) {
        return DB_ERROR_NULL_POINTER;
    }
    
    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;
    
    pthread_rwlock_rdlock(&db->lock);
    Collection* col = find_collection(db, collection_name);
    if (!col) {
        pthread_rwlock_unlock(&db->lock);
        return DB_ERROR_COLLECTION_NOT_FOUND;
    }
    
    pthread_rwlock_rdlock(&col->lock);
    smt_error_t err = smt_generate_proof(&col->tree, key, proof);
    pthread_rwlock_unlock(&col->lock);
    pthread_rwlock_unlock(&db->lock);
    
    return (db_error_t)err;
}

db_error_t db_verify_proof(const char* db_name, const char* collection_name,
                         const char* key, const char* value,
                         const MembershipProof* proof, int* valid) {
    if (!db_name || !collection_name || !key || !proof || !valid) {
        return DB_ERROR_NULL_POINTER;
    }
    
    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;
    
    pthread_rwlock_rdlock(&db->lock);
    Collection* col = find_collection(db, collection_name);
    if (!col) {
        pthread_rwlock_unlock(&db->lock);
        return DB_ERROR_COLLECTION_NOT_FOUND;
    }
    
    pthread_rwlock_rdlock(&col->lock);
    smt_error_t err = smt_verify_proof(&col->tree, key, value, proof, valid);
    pthread_rwlock_unlock(&col->lock);
    pthread_rwlock_unlock(&db->lock);
    
    return (db_error_t)err;
}

// Persistence operations
db_error_t db_save(const char* db_name) {
    if (!db_name) return DB_ERROR_NULL_POINTER;
    if (!g_db_manager.is_initialized) return DB_ERROR_INVALID_PARAMETER;
    if (g_db_manager.persistence_path[0] == '\0') return DB_ERROR_IO_ERROR;
    
    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;
    
    char path[2048];
    snprintf(path, sizeof(path), "%s/%s.smtdb", g_db_manager.persistence_path, db_name);
    
    // Create temp file first
    char temp_path[2048];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);
    
    int fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd == -1) return DB_ERROR_IO_ERROR;
    
    db_error_t err = serialize_database(db, fd);
    close(fd);
    
    if (err != DB_SUCCESS) {
        unlink(temp_path);
        return err;
    }
    
    // Atomic rename
    if (rename(temp_path, path) == -1) {
        unlink(temp_path);
        return DB_ERROR_IO_ERROR;
    }
    
    return DB_SUCCESS;
}

db_error_t db_load(const char* db_name) {
    if (!db_name) return DB_ERROR_NULL_POINTER;
    if (!g_db_manager.is_initialized) return DB_ERROR_INVALID_PARAMETER;
    if (g_db_manager.persistence_path[0] == '\0') return DB_ERROR_IO_ERROR;
    
    char path[2048];
    snprintf(path, sizeof(path), "%s/%s.smtdb", g_db_manager.persistence_path, db_name);
    
    int fd = open(path, O_RDONLY);
    if (fd == -1) return DB_ERROR_IO_ERROR;
    
    // Create or find existing database
    db_error_t err = db_create(db_name);
    if (err != DB_SUCCESS && err != DB_ERROR_DATABASE_EXISTS) {
        close(fd);
        return err;
    }
    
    Database* db = find_database(db_name);
    if (!db) {
        close(fd);
        return DB_ERROR_DATABASE_NOT_FOUND;
    }
    
    pthread_rwlock_wrlock(&db->lock);
    err = deserialize_database(db, fd);
    pthread_rwlock_unlock(&db->lock);
    
    close(fd);
    return err;
}

db_error_t db_save_all() {
    if (!g_db_manager.is_initialized) return DB_ERROR_INVALID_PARAMETER;
    if (g_db_manager.persistence_path[0] == '\0') return DB_ERROR_IO_ERROR;
    
    //printf("DEBUG: Entering db_save_all\n");
    pthread_mutex_lock(&g_db_manager.lock);
    //printf("DEBUG: Acquired mutex in db_save_all\n");
    
    char* db_names[MAX_DATABASES];
    size_t db_count = 0;
    for (size_t i = 0; i < g_db_manager.db_count; i++) {
        if (g_db_manager.databases[i].is_open) {
            db_names[db_count] = strdup(g_db_manager.databases[i].name);
            if (!db_names[db_count]) {
                //printf("DEBUG: Memory allocation failed for db_names\n");
                for (size_t j = 0; j < db_count; j++) {
                    free(db_names[j]);
                }
                pthread_mutex_unlock(&g_db_manager.lock);
                return DB_ERROR_MEMORY_ALLOCATION;
            }
            db_count++;
        }
    }
    
    //printf("DEBUG: Releasing mutex in db_save_all\n");
    pthread_mutex_unlock(&g_db_manager.lock);
    
    db_error_t final_error = DB_SUCCESS;
    for (size_t i = 0; i < db_count; i++) {
        //printf("DEBUG: Saving database %s\n", db_names[i]);
        db_error_t err = db_save(db_names[i]);
        if (err != DB_SUCCESS) {
            //printf("DEBUG: Error saving database %s: %s\n", 
                   //db_names[i], db_error_string(err));
            final_error = err;
            // Free remaining names and break
            for (size_t j = i; j < db_count; j++) {
                free(db_names[j]);
                db_names[j] = NULL;
            }
            break;
        }
        free(db_names[i]);
        db_names[i] = NULL; // Prevent double free
    }
    
    //printf("DEBUG: Exiting db_save_all\n");
    return final_error;
}

db_error_t db_load_all() {
    if (!g_db_manager.is_initialized) return DB_ERROR_INVALID_PARAMETER;
    if (g_db_manager.persistence_path[0] == '\0') return DB_ERROR_IO_ERROR;
    
    DIR* dir = opendir(g_db_manager.persistence_path);
    if (!dir) return DB_ERROR_IO_ERROR;
    
    struct dirent* entry;
    db_error_t final_error = DB_SUCCESS;
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG && 
            strlen(entry->d_name) > 7 && 
            strcmp(entry->d_name + strlen(entry->d_name) - 7, ".smtdb") == 0) {
            
            char db_name[MAX_DB_NAME_LEN];
            strncpy(db_name, entry->d_name, strlen(entry->d_name) - 7);
            db_name[strlen(entry->d_name) - 7] = '\0';
            
            db_error_t err = db_load(db_name);
            if (err != DB_SUCCESS) {
                final_error = err;
                break;
            }
        }
    }
    
    closedir(dir);
    return final_error;
}

// Utility functions
const char* db_error_string(db_error_t error) {
    switch (error) {
        case DB_SUCCESS: return "Success";
        case DB_ERROR_NULL_POINTER: return "Null pointer";
        case DB_ERROR_MEMORY_ALLOCATION: return "Memory allocation failed";
        case DB_ERROR_INVALID_PARAMETER: return "Invalid parameter";
        case DB_ERROR_KEY_NOT_FOUND: return "Key not found";
        case DB_ERROR_DATABASE_NOT_FOUND: return "Database not found";
        case DB_ERROR_COLLECTION_NOT_FOUND: return "Collection not found";
        case DB_ERROR_DATABASE_EXISTS: return "Database already exists";
        case DB_ERROR_COLLECTION_EXISTS: return "Collection already exists";
        case DB_ERROR_MAX_LIMIT_REACHED: return "Maximum limit reached";
        case DB_ERROR_INVALID_JSON: return "Invalid JSON format";
        case DB_ERROR_CONCURRENT_ACCESS: return "Concurrent access error";
        case DB_ERROR_DATABASE_CLOSED: return "Database is closed";
        case DB_ERROR_IO_ERROR: return "I/O error";
        case DB_ERROR_CORRUPTED_DATA: return "Corrupted data";
        default: return "Unknown error";
    }
}

db_error_t db_compact(const char* db_name) {
    // In-memory database doesn't need compaction
    // This would be more relevant for a disk-based implementation
    return DB_SUCCESS;
}

db_error_t db_verify_integrity(const char* db_name) {
    if (!db_name) return DB_ERROR_NULL_POINTER;
    
    Database* db = find_database(db_name);
    if (!db) return DB_ERROR_DATABASE_NOT_FOUND;
    
    pthread_rwlock_rdlock(&db->lock);
    
    db_error_t final_error = DB_SUCCESS;
    for (size_t i = 0; i < db->collection_count; i++) {
        Collection* col = &db->collections[i];
        if (!col->is_open) continue;
        
        pthread_rwlock_rdlock(&col->lock);
        
        // Verify the SMT structure
        unsigned char root_hash[HASH_SIZE];
        smt_error_t err = smt_get_root(&col->tree, root_hash);
        if (err != SMT_SUCCESS) {
            final_error = (db_error_t)err;
            pthread_rwlock_unlock(&col->lock);
            break;
        }
        
        // Additional verification could be added here
        
        pthread_rwlock_unlock(&col->lock);
    }
    
    pthread_rwlock_unlock(&db->lock);
    return final_error;
}