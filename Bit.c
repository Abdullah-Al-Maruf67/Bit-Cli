#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <zlib.h>
#include <stdlib.h>
#include <dirent.h>
#include <time.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <ctype.h>
#include <strings.h>
#include <inttypes.h>

#ifdef _WIN32
#include <io.h>
#define make_dir(path, mode) mkdir(path)
#define strcasecmp _stricmp
#else
#define make_dir(path, mode) mkdir(path, mode)
#endif

// Configuration
#define BIT_DIRECTORY ".bit"
#define AUTH_TOKEN_FILE ".bit/auth_token"
#define SHARE_TOKEN_FILE ".bit/share_token"
#define REPO_ID_FILE ".bit/repo_id"
#define LAST_COMMIT_ID_FILE ".bit/last_commit_id"
#define SERVER_URL "https://bit-backend-644w.onrender.com"
#define API_BASE_URL "https://bit-backend-644w.onrender.com/api"
#define SUCCESS 0
#define FAILURE -1
#define MAX_PATH_LENGTH 1024
#define MAX_TOKEN_LENGTH 256
#define MAX_RESPONSE_SIZE 8192

// Data structures
typedef struct {
    char *hash;
    size_t file_size;
    unsigned char *compressed_data;
    size_t compressed_size;
} BitBlob;

typedef struct {
    char *path;
    char *hash;
} IndexEntry;

typedef struct {
    char *author;
    char *hash;
    time_t timestamp;
    char *message;
    char **staged_files;
    char **staged_hashes;
    size_t staged_files_count;
    char *email;
    char *parent_hash;
} BitCommit;

typedef struct {
    char *token;
    time_t expires;
} AuthSession;

struct FilePair {
    char *path;
    char *hash;
};

// Global variables
char g_auth_token[MAX_TOKEN_LENGTH] = "";
char g_share_token[MAX_TOKEN_LENGTH] = "";
char g_server_url[256] = SERVER_URL;

// HTTP response structure
struct MemoryStruct {
    char *memory;
    size_t size;
};

// Function prototypes
void print_help();
int handle_error(const char *operation);
int is_bit_initialized(const char *path);
int initialize_directory(const char *path);
int create_bit_directories();
int add_file(const char *filepath);
char *generate_commit_hash(BitCommit *commit);
int write_commit_file(BitCommit *commit);
int create_commit(const char *author, const char *email, const char *message);
unsigned char *read_file(const char *filepath, size_t *file_size);
void compute_sha1_hash(const unsigned char *data, size_t data_size, char *hash_out);
unsigned char *compress_data(const unsigned char *data, size_t data_size, size_t *compressed_size);
unsigned char *decompress_data(const unsigned char *compressed, size_t comp_size, size_t *dec_size);
int mkdir_p(const char *path);
int add_directory_recursive(const char *dirpath);
char* base64_encode(const unsigned char *data, size_t input_length);
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);
void get_object_path(const char *hash, char *path, size_t path_size);
int get_object_dir(const char *hash, char *dir_path, size_t dir_size);

// Authentication functions
int save_auth_token(const char *token);
char* load_auth_token();
int save_share_token(const char *token);
char* load_share_token();

// Repo and commit ID functions
int save_repo_id(const char *id);
char* load_repo_id();
int save_last_commit_id(const char *id);
char* load_last_commit_id();

// API functions
int bit_login(const char *username, const char *password);
int bit_create_repo(const char *name, const char *description);
int bit_generate_share_token(const char *repo_id);
int bit_commit_to_server(const char *author, const char *email, const char *message);
int bit_push();
int bit_status();
int bit_log();
int bit_sync();

// HTTP helper functions
int http_post(const char *url, const char *data, const char *auth_header, char **response);
int http_get(const char *url, const char *auth_header, char **response);

// Utility functions
char* get_input(const char *prompt);
void trim_whitespace(char *str);
bool is_valid_json(const char *json_str);

// Index functions
int load_entries(const char *file_path, IndexEntry **entries, size_t *count);
int save_entries(const char *file_path, const IndexEntry *entries, size_t count);
void free_index(IndexEntry *entries, size_t count);
int find_index_entry(const IndexEntry *entries, size_t count, const char *path);

// HEAD functions
char *get_current_head();
int set_head(const char *hash);

// Comparator for qsort
int pair_cmp(const void *a, const void *b) {
    return strcmp(((const struct FilePair*)a)->path, ((const struct FilePair*)b)->path);
}

// ============================================================================
// OBJECT PATH HELPERS
// ============================================================================

int get_object_dir(const char *hash, char *dir_path, size_t dir_size) {
    if (strlen(hash) != 40) {
        return FAILURE;
    }
    char dir[3];
    strncpy(dir, hash, 2);
    dir[2] = '\0';
    snprintf(dir_path, dir_size, ".bit/objects/%s", dir);
    return SUCCESS;
}

void get_object_path(const char *hash, char *path, size_t path_size) {
    char dir[3];
    strncpy(dir, hash, 2);
    dir[2] = '\0';
    char rest[39];
    strcpy(rest, hash + 2);
    snprintf(path, path_size, ".bit/objects/%s/%s", dir, rest);
}

// ============================================================================
// HTTP HELPER FUNCTIONS
// ============================================================================

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

int http_post(const char *url, const char *data, const char *auth_header, char **response) {
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    struct MemoryStruct chunk = {0};

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize CURL\n");
        return FAILURE;
    }

    // Set headers
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (auth_header && strlen(auth_header) > 0) {
        headers = curl_slist_append(headers, auth_header);
    }

    // Set CURL options
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);

    // Perform request
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "CURL error: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        return FAILURE;
    }

    // Get response code
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    // Allocate response memory
    *response = malloc(chunk.size + 1);
    if (*response) {
        memcpy(*response, chunk.memory, chunk.size);
        (*response)[chunk.size] = '\0';
    }

    // Cleanup
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    free(chunk.memory);

    return (int)response_code;
}

int http_get(const char *url, const char *auth_header, char **response) {
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    struct MemoryStruct chunk = {0};

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize CURL\n");
        return FAILURE;
    }

    // Set headers
    if (auth_header && strlen(auth_header) > 0) {
        headers = curl_slist_append(headers, auth_header);
    }

    // Set CURL options
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);

    // Perform request
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "CURL error: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        return FAILURE;
    }

    // Get response code
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    // Allocate response memory
    *response = malloc(chunk.size + 1);
    if (*response) {
        memcpy(*response, chunk.memory, chunk.size);
        (*response)[chunk.size] = '\0';
    }

    // Cleanup
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    free(chunk.memory);

    return (int)response_code;
}

// ============================================================================
// AUTHENTICATION FUNCTIONS
// ============================================================================

int save_auth_token(const char *token) {
    FILE *file = fopen(AUTH_TOKEN_FILE, "w");
    if (!file) {
        fprintf(stderr, "Failed to save auth token\n");
        return FAILURE;
    }
    fprintf(file, "%s", token);
    fclose(file);
    return SUCCESS;
}

char* load_auth_token() {
    FILE *file = fopen(AUTH_TOKEN_FILE, "r");
    if (!file) {
        return NULL;
    }

    char *token = malloc(MAX_TOKEN_LENGTH);
    if (!token) {
        fclose(file);
        return NULL;
    }

    if (fgets(token, MAX_TOKEN_LENGTH, file)) {
        trim_whitespace(token);
        fclose(file);
        return token;
    }
    
    fclose(file);
    free(token);
    return NULL;
}

int save_share_token(const char *token) {
    FILE *file = fopen(SHARE_TOKEN_FILE, "w");
    if (!file) {
        fprintf(stderr, "Failed to save share token\n");
        return FAILURE;
    }
    fprintf(file, "%s", token);
    fclose(file);
    return SUCCESS;
}

char* load_share_token() {
    FILE *file = fopen(SHARE_TOKEN_FILE, "r");
    if (!file) {
        return NULL;
    }
    
    char *token = malloc(MAX_TOKEN_LENGTH);
    if (!token) {
        fclose(file);
        return NULL;
    }
    
    if (fgets(token, MAX_TOKEN_LENGTH, file)) {
        trim_whitespace(token);
        fclose(file);
        return token;
    }
    
    fclose(file);
    free(token);
    return NULL;
}

// ============================================================================
// REPO AND COMMIT ID FUNCTIONS
// ============================================================================

int save_repo_id(const char *id) {
    FILE *file = fopen(REPO_ID_FILE, "w");
    if (!file) {
        fprintf(stderr, "Failed to save repo id\n");
        return FAILURE;
    }
    fprintf(file, "%s", id);
    fclose(file);
    return SUCCESS;
}

char* load_repo_id() {
    FILE *file = fopen(REPO_ID_FILE, "r");
    if (!file) {
        return NULL;
    }

    char *id = malloc(MAX_TOKEN_LENGTH);
    if (!id) {
        fclose(file);
        return NULL;
    }

    if (fgets(id, MAX_TOKEN_LENGTH, file)) {
        trim_whitespace(id);
        fclose(file);
        return id;
    }
    
    fclose(file);
    free(id);
    return NULL;
}

int save_last_commit_id(const char *id) {
    FILE *file = fopen(LAST_COMMIT_ID_FILE, "w");
    if (!file) {
        fprintf(stderr, "Failed to save last commit id\n");
        return FAILURE;
    }
    fprintf(file, "%s", id);
    fclose(file);
    return SUCCESS;
}

char* load_last_commit_id() {
    FILE *file = fopen(LAST_COMMIT_ID_FILE, "r");
    if (!file) {
        return NULL;
    }

    char *id = malloc(MAX_TOKEN_LENGTH);
    if (!id) {
        fclose(file);
        return NULL;
    }

    if (fgets(id, MAX_TOKEN_LENGTH, file)) {
        trim_whitespace(id);
        fclose(file);
        return id;
    }
    
    fclose(file);
    free(id);
    return NULL;
}

// ============================================================================
// API FUNCTIONS
// ============================================================================

int bit_login(const char *username, const char *password) {
    printf("Logging in as %s...\n", username);
    
    // Build JSON payload
    struct json_object *json_payload = json_object_new_object();
    json_object_object_add(json_payload, "username", json_object_new_string(username));
    json_object_object_add(json_payload, "password", json_object_new_string(password));
    
    char *json_str = (char*)json_object_to_json_string(json_payload);
    
    // Make HTTP request
    char *response = NULL;
    char url[512];
    snprintf(url, sizeof(url), "%s/users/login/", API_BASE_URL);
    
    int status_code = http_post(url, json_str, NULL, &response);
    

    if (status_code == 200) {
        // Parse response
        struct json_object *json_response = json_tokener_parse(response);
        if (!json_response) {
            printf("Failed to parse JSON response\n");
            free(response);
            json_object_put(json_payload);
            return FAILURE;
        }
        
        struct json_object *access_token_obj;
        if (json_object_object_get_ex(json_response, "access", &access_token_obj)) {
            const char *access_token = json_object_get_string(access_token_obj);
            if (access_token && strlen(access_token) > 0) {
                strcpy(g_auth_token, access_token);
                save_auth_token(access_token);
                printf("Login successful!\n");
            } else {
                printf("Access token is empty or null\n");
            }
            json_object_put(json_response);
            free(response);
            json_object_put(json_payload);
            return SUCCESS;
        } else {
            printf("Failed to find access_token in response\n");
            json_object_put(json_response);
        }
    } else {
        printf("Login failed (Status: %d)\n", status_code);
        if (response) {
            printf("Response: %s\n", response);
        }
    }
    
    if (response) free(response);
    json_object_put(json_payload);
    return FAILURE;
}

int bit_create_repo(const char *name, const char *description) {
    printf("Creating repository: %s\n", name);
    
    // Check if we have auth token
    if (strlen(g_auth_token) == 0) {
        char *token = load_auth_token();
        if (token) {
            strcpy(g_auth_token, token);
            free(token);
        } else {
            printf("Not logged in. Use 'bit login' first.\n");
            return FAILURE;
        }
    }
    
    // Build JSON payload
    struct json_object *json_payload = json_object_new_object();
    json_object_object_add(json_payload, "name", json_object_new_string(name));
    json_object_object_add(json_payload, "description", json_object_new_string(description));
    
    char *json_str = (char*)json_object_to_json_string(json_payload);
    
    // Build auth header
    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", g_auth_token);
    
    // Make HTTP request
    char *response = NULL;
    char url[512];
    snprintf(url, sizeof(url), "%s/data/repositories/", API_BASE_URL);
    
    int status_code = http_post(url, json_str, auth_header, &response);
    
    if (status_code == 201) {
        // Parse response to get repo id and share token
        struct json_object *json_response = json_tokener_parse(response);
        struct json_object *id_obj;
        if (json_object_object_get_ex(json_response, "id", &id_obj)) {
            const char *repo_id = json_object_get_string(id_obj);
            if (repo_id && strlen(repo_id) > 0) {
                save_repo_id(repo_id);
            }
        }
        struct json_object *share_links_obj, *share_link_obj, *token_obj;
        
        if (json_object_object_get_ex(json_response, "share_links", &share_links_obj) &&
            json_object_array_length(share_links_obj) > 0) {
            
            share_link_obj = json_object_array_get_idx(share_links_obj, 0);
            if (json_object_object_get_ex(share_link_obj, "token", &token_obj)) {
                const char *share_token = json_object_get_string(token_obj);
                strcpy(g_share_token, share_token);
                save_share_token(share_token);
                printf("Repository created successfully!\n");
                printf("Share token: %s\n", share_token);
                json_object_put(json_response);
                free(response);
                json_object_put(json_payload);
                return SUCCESS;
            }
        }
        
        json_object_put(json_response);
    } else {
        printf("Repository creation failed (Status: %d)\n", status_code);
        if (response) {
            printf("Response: %s\n", response);
        }
    }
    
    if (response) free(response);
    json_object_put(json_payload);
    return FAILURE;
}

int bit_generate_share_token(const char *repo_id) {
    printf("Generating new share token for repository %s...\n", repo_id);
    
    // Check if we have auth token
    if (strlen(g_auth_token) == 0) {
        char *token = load_auth_token();
        if (token) {
            strcpy(g_auth_token, token);
            free(token);
        } else {
            printf("Not logged in. Use 'bit login' first.\n");
            return FAILURE;
        }
    }
    
    // Build auth header
    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", g_auth_token);
    
    // Make HTTP request
    char *response = NULL;
    char url[512];
    snprintf(url, sizeof(url), "%s/data/repositories/%s/generate_link/", API_BASE_URL, repo_id);
    
    int status_code = http_post(url, "{}", auth_header, &response);
    
    if (status_code == 201) {
        // Parse response
        struct json_object *json_response = json_tokener_parse(response);
        struct json_object *token_obj;
        
        if (json_object_object_get_ex(json_response, "token", &token_obj)) {
            const char *share_token = json_object_get_string(token_obj);
            strcpy(g_share_token, share_token);
            save_share_token(share_token);
            printf("New share token generated!\n");
            printf("Share token: %s\n", share_token);
            json_object_put(json_response);
            free(response);
            return SUCCESS;
        }
        
        json_object_put(json_response);
    } else {
        printf("Token generation failed (Status: %d)\n", status_code);
        if (response) {
            printf("Response: %s\n", response);
        }
    }
    
    if (response) free(response);
    return FAILURE;
}

int bit_commit_to_server(const char *author, const char *email, const char *message) {
    printf("Creating commit: %s\n", message);
    
    // Check if we have share token
    if (strlen(g_share_token) == 0) {
        char *token = load_share_token();
        if (token) {
            strcpy(g_share_token, token);
            free(token);
        } else {
            printf("No share token found. Use 'bit create-repo' or 'bit share' first.\n");
            return FAILURE;
        }
    }
    
    // Load current index
    IndexEntry *current_entries;
    size_t current_count;
    if (load_entries(".bit/index", &current_entries, &current_count) != SUCCESS) {
        printf("Failed to load index.\n");
        return FAILURE;
    }
    
    printf("Auto-staging changes to tracked files...\n");
    
    // Collect current working directory files and hashes
    struct FileHash {
        char *path;
        char *hash;
    };
    struct FileHash *wd_files = NULL;
    size_t wd_count = 0;

    // Recursive function to collect files (similar to bit_status)
    int collect_files(const char *dir) {
        DIR *d = opendir(dir);
        if (!d) return FAILURE;

        struct dirent *ent;
        while ((ent = readdir(d))) {
            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
            if (strcmp(ent->d_name, BIT_DIRECTORY) == 0 && strcmp(dir, ".") == 0) continue;

            char full[MAX_PATH_LENGTH];
            snprintf(full, sizeof(full), "%s/%s", dir, ent->d_name);

            struct stat st;
            if (stat(full, &st) == -1) continue;

            if (S_ISDIR(st.st_mode)) {
                collect_files(full);
            } else {
                size_t size;
                unsigned char *data = read_file(full, &size);
                if (!data) continue;

                char hash[41];
                compute_sha1_hash(data, size, hash);
                free(data);

                struct FileHash *new_f = realloc(wd_files, (wd_count + 1) * sizeof(struct FileHash));
                if (!new_f) return FAILURE;
                wd_files = new_f;

                char *rel_path = full;
                if (strncmp(full, "./", 2) == 0) rel_path = full + 2;

                wd_files[wd_count].path = strdup(rel_path);
                wd_files[wd_count].hash = strdup(hash);
                wd_count++;
            }
        }
        closedir(d);
        return SUCCESS;
    }

    if (collect_files(".") != SUCCESS) {
        free_index(current_entries, current_count);
        for (size_t i = 0; i < wd_count; i++) {
            free(wd_files[i].path);
            free(wd_files[i].hash);
        }
        free(wd_files);
        return FAILURE;
    }

    // Update index for tracked files - start with empty new index
    bool changes_staged = false;
    size_t new_current_count = 0;
    IndexEntry *new_current_entries = NULL;

    for (size_t i = 0; i < current_count; i++) {
        bool found = false;
        char *wd_hash = NULL;
        for (size_t j = 0; j < wd_count; j++) {
            if (strcmp(current_entries[i].path, wd_files[j].path) == 0) {
                found = true;
                wd_hash = wd_files[j].hash;
                break;
            }
        }
        if (found) {
            new_current_entries = realloc(new_current_entries, (new_current_count + 1) * sizeof(IndexEntry));
            new_current_entries[new_current_count].path = strdup(current_entries[i].path);
            if (strcmp(current_entries[i].hash, wd_hash) != 0) {
                // Stage modified - create new object
                size_t file_size;
                unsigned char *file_content = read_file(current_entries[i].path, &file_size);
                if (file_content) {
                    size_t compressed_size;
                    unsigned char *compressed_data = compress_data(file_content, file_size, &compressed_size);
                    free(file_content);
                    if (compressed_data) {
                        char object_path[256];
                        get_object_path(wd_hash, object_path, sizeof(object_path));
                        char dir_path[256];
                        get_object_dir(wd_hash, dir_path, sizeof(dir_path));
                        if (make_dir(dir_path, 0755) != 0 && errno != EEXIST) {
                            fprintf(stderr, "Failed to create object dir %s\n", dir_path);
                        } else {
                            FILE *object_file = fopen(object_path, "wb");
                            if (object_file) {
                                fwrite(compressed_data, 1, compressed_size, object_file);
                                fclose(object_file);
                                changes_staged = true;
                            }
                        }
                        free(compressed_data);
                    }
                }
                new_current_entries[new_current_count].hash = strdup(wd_hash);
            } else {
                new_current_entries[new_current_count].hash = strdup(current_entries[i].hash);
            }
            new_current_count++;
        } else {
            changes_staged = true;
        }
    }

    // Save updated index if changes
    if (changes_staged) {
        save_entries(".bit/index", new_current_entries, new_current_count);
    }

    // Set current to new
    free_index(current_entries, current_count);
    current_entries = new_current_entries;
    current_count = new_current_count;

    for (size_t i = 0; i < wd_count; i++) {
        free(wd_files[i].path);
        free(wd_files[i].hash);
    }
    free(wd_files);

    // Load last committed index (if exists)
    IndexEntry *last_entries;
    size_t last_count;
    load_entries(".bit/last_index", &last_entries, &last_count);

    // Build commit struct for local hash generation
    BitCommit commit = {0};
    commit.author = strdup(author);
    commit.email = strdup(email);
    commit.message = strdup(message);
    commit.timestamp = time(NULL);
    commit.staged_files_count = current_count;
    if (current_count > 0) {
        commit.staged_files = malloc(current_count * sizeof(char*));
        commit.staged_hashes = malloc(current_count * sizeof(char*));
        for (size_t i = 0; i < current_count; i++) {
            commit.staged_files[i] = strdup(current_entries[i].path);
            commit.staged_hashes[i] = strdup(current_entries[i].hash);
        }
    }
    char *parent = get_current_head();
    commit.parent_hash = parent ? strdup(parent) : NULL;
    commit.hash = generate_commit_hash(&commit);
    
    // Build operations array
    struct json_object *operations_array = json_object_new_array();
    
    // Add UPDATE operations
    for (size_t i = 0; i < current_count; i++) {
        char obj_path[256];
        get_object_path(current_entries[i].hash, obj_path, sizeof(obj_path));
        
        size_t compressed_size;
        unsigned char *compressed_data = read_file(obj_path, &compressed_size);
        if (!compressed_data) {
            printf("Failed to read object for %s\n", current_entries[i].path);
            continue;
        }
        
        char *base64_data = base64_encode(compressed_data, compressed_size);
        free(compressed_data);
        if (!base64_data) {
            printf("Failed to encode %s\n", current_entries[i].path);
            continue;
        }
        
        struct json_object *operation = json_object_new_object();
        json_object_object_add(operation, "type", json_object_new_string("UPDATE"));
        json_object_object_add(operation, "path", json_object_new_string(current_entries[i].path));
        json_object_object_add(operation, "content", json_object_new_string(base64_data));
        
        json_object_array_add(operations_array, operation);
        free(base64_data);
    }
    
    // Add DELETE operations
    for (size_t i = 0; i < last_count; i++) {
        int found = find_index_entry(current_entries, current_count, last_entries[i].path);
        if (found == -1) {
            struct json_object *operation = json_object_new_object();
            json_object_object_add(operation, "type", json_object_new_string("DELETE"));
            json_object_object_add(operation, "path", json_object_new_string(last_entries[i].path));
            
            json_object_array_add(operations_array, operation);
        }
    }
    
    // Check if no changes
    if (json_object_array_length(operations_array) == 0) {
        printf("No changes to commit.\n");
        json_object_put(operations_array);
        free_index(current_entries, current_count);
        free_index(last_entries, last_count);
        free(commit.author);
        free(commit.email);
        free(commit.message);
        free(commit.hash);
        if (commit.parent_hash) free(commit.parent_hash);
        for (size_t i = 0; i < commit.staged_files_count; i++) {
            free(commit.staged_files[i]);
            free(commit.staged_hashes[i]);
        }
        free(commit.staged_files);
        free(commit.staged_hashes);
        if (parent) free(parent);
        return SUCCESS;
    }
    
    // Build JSON payload
    struct json_object *json_payload = json_object_new_object();
    json_object_object_add(json_payload, "share_token", json_object_new_string(g_share_token));
    json_object_object_add(json_payload, "author", json_object_new_string(author));
    json_object_object_add(json_payload, "email", json_object_new_string(email));
    json_object_object_add(json_payload, "message", json_object_new_string(message));
    json_object_object_add(json_payload, "parent_hash", json_object_new_string(parent ? parent : ""));
    json_object_object_add(json_payload, "operations", operations_array);
    
    char *json_str = (char*)json_object_to_json_string(json_payload);
    
    // Make HTTP request
    char *response = NULL;
    char url[512];
    snprintf(url, sizeof(url), "%s/data/commits/", API_BASE_URL);
    
    int status_code = http_post(url, json_str, NULL, &response);
    
    if (status_code == 201) {
        printf("Commit created successfully!\n");
        
        // Parse response to show summary and save commit id
        struct json_object *json_response = json_tokener_parse(response);
        struct json_object *operations_summary_obj, *updated_obj;
        
        if (json_object_object_get_ex(json_response, "operations_summary", &operations_summary_obj) &&
            json_object_object_get_ex(operations_summary_obj, "updated", &updated_obj)) {
            
            int updated_count = json_object_array_length(updated_obj);
            printf("Files updated: %d\n", updated_count);
        }
        
        struct json_object *id_obj;
        if (json_object_object_get_ex(json_response, "id", &id_obj)) {
            const char *commit_id = json_object_get_string(id_obj);
            if (commit_id && strlen(commit_id) > 0) {
                save_last_commit_id(commit_id);
            }
        }
        
        // Always update local state on success (even if no server hash)
        write_commit_file(&commit);
        set_head(commit.hash);
        save_entries(".bit/last_index", current_entries, current_count);
        
        // Optional: If server provides hash, override local HEAD
        struct json_object *hash_obj;
        if (json_object_object_get_ex(json_response, "hash", &hash_obj)) {
            const char *server_hash = json_object_get_string(hash_obj);
            if (server_hash && strlen(server_hash) > 0) {
                set_head(server_hash);
            }
        }
        
        json_object_put(json_response);
    } else {
        printf("Commit failed (Status: %d)\n", status_code);
        if (response) {
            printf("Response: %s\n", response);
        }
    }
    
    // Cleanup
    if (response) free(response);
    json_object_put(json_payload);
    free_index(current_entries, current_count);
    free_index(last_entries, last_count);
    free(commit.author);
    free(commit.email);
    free(commit.message);
    free(commit.hash);
    if (commit.parent_hash) free(commit.parent_hash);
    for (size_t i = 0; i < commit.staged_files_count; i++) {
        free(commit.staged_files[i]);
        free(commit.staged_hashes[i]);
    }
    free(commit.staged_files);
    free(commit.staged_hashes);
    if (parent) free(parent);
    
    return (status_code == 201) ? SUCCESS : FAILURE;
}

int bit_push() {
    char *repo_id = load_repo_id();
    if (!repo_id) {
        printf("No repository ID found. Create a repository first.\n");
        return FAILURE;
    }

    char *commit_id = load_last_commit_id();
    if (!commit_id) {
        printf("No last commit ID found. Commit changes first.\n");
        free(repo_id);
        return FAILURE;
    }

    printf("You are about to push the last commit (ID: %s) to the main project in repository %s.\n", commit_id, repo_id);
    char *input = get_input("Are you sure? (y/n): ");
    if (!input || (strcasecmp(input, "y") != 0 && strcasecmp(input, "yes") != 0)) {
        printf("Push cancelled.\n");
        free(input);
        free(repo_id);
        free(commit_id);
        return SUCCESS;
    }
    free(input);

    // Check if we have auth token
    if (strlen(g_auth_token) == 0) {
        char *token = load_auth_token();
        if (token) {
            strcpy(g_auth_token, token);
            free(token);
        } else {
            printf("Not logged in. Use 'bit login' first.\n");
            free(repo_id);
            free(commit_id);
            return FAILURE;
        }
    }

    // Build auth header
    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", g_auth_token);

    char url[512];
    snprintf(url, sizeof(url), "%s/data/repositories/%s/commits/%s/merge/", API_BASE_URL, repo_id, commit_id);

    char *response = NULL;
    int status_code = http_post(url, "{}", auth_header, &response);

    if (status_code == 200 || status_code == 201) {
        printf("Push successful!\n");
    } else {
        printf("Push failed (Status: %d)\n", status_code);
        if (response) {
            printf("Response: %s\n", response);
        }
    }

    if (response) free(response);
    free(repo_id);
    free(commit_id);

    return (status_code == 200 || status_code == 201) ? SUCCESS : FAILURE;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

char* get_input(const char *prompt) {
    printf("%s", prompt);
    char *input = malloc(256);
    if (!input) return NULL;
    
    if (fgets(input, 256, stdin)) {
        trim_whitespace(input);
        return input;
    }
    
    free(input);
    return NULL;
}

void trim_whitespace(char *str) {
    char *start = str;
    while (isspace((unsigned char)*start)) start++;
    memmove(str, start, strlen(start) + 1);
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';
}

bool is_valid_json(const char *json_str) {
    struct json_object *json = json_tokener_parse(json_str);
    if (json) {
        json_object_put(json);
        return true;
    }
    return false;
}

char* base64_encode(const unsigned char *data, size_t input_length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, input_length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    char *encoded = malloc(bufferPtr->length + 1);
    if (encoded) {
        memcpy(encoded, bufferPtr->data, bufferPtr->length);
        encoded[bufferPtr->length] = '\0';
    }
    
    BIO_free_all(bio);
    return encoded;
}

// ============================================================================
// INDEX FUNCTIONS
// ============================================================================

int load_entries(const char *file_path, IndexEntry **entries, size_t *count) {
    *entries = NULL;
    *count = 0;
    FILE *file = fopen(file_path, "r");
    if (!file) {
        return SUCCESS; // No file means empty
    }

    char line[MAX_PATH_LENGTH];
    while (fgets(line, sizeof(line), file)) {
        char *tab = strchr(line, '\t');
        if (!tab) continue;
        *tab = '\0';
        tab++;
        char *nl = strchr(tab, '\n');
        if (nl) *nl = '\0';

        IndexEntry *tmp = realloc(*entries, sizeof(IndexEntry) * (*count + 1));
        if (!tmp) {
            fclose(file);
            return FAILURE;
        }
        *entries = tmp;
        (*entries)[*count].path = strdup(line);
        (*entries)[*count].hash = strdup(tab);
        (*count)++;
    }
    fclose(file);
    return SUCCESS;
}

int save_entries(const char *file_path, const IndexEntry *entries, size_t count) {
    FILE *file = fopen(file_path, "w");
    if (!file) {
        return FAILURE;
    }
    for (size_t i = 0; i < count; i++) {
        fprintf(file, "%s\t%s\n", entries[i].path, entries[i].hash);
    }
    fclose(file);
    return SUCCESS;
}

void free_index(IndexEntry *entries, size_t count) {
    for (size_t i = 0; i < count; i++) {
        free(entries[i].path);
        free(entries[i].hash);
    }
    free(entries);
}

int find_index_entry(const IndexEntry *entries, size_t count, const char *path) {
    for (size_t i = 0; i < count; i++) {
        if (strcmp(entries[i].path, path) == 0) {
            return i;
        }
    }
    return -1;
}

// ============================================================================
// HEAD FUNCTIONS
// ============================================================================

char *get_current_head() {
    FILE *file = fopen(".bit/HEAD", "r");
    if (!file) {
        return NULL;
    }
    char *hash = malloc(41);
    if (fgets(hash, 41, file)) {
        trim_whitespace(hash);
        fclose(file);
        return hash;
    }
    fclose(file);
    free(hash);
    return NULL;
}

int set_head(const char *hash) {
    FILE *file = fopen(".bit/HEAD", "w");
    if (!file) {
        return FAILURE;
    }
    fprintf(file, "%s\n", hash);
    fclose(file);
    return SUCCESS;
}

// ============================================================================
// EXISTING FUNCTIONS (updated implementations)
// ============================================================================

void print_help() {
    printf("Bit - Version Control System\n");
    printf("Usage: bit <command> [options]\n\n");
    printf("Commands:\n");
    printf("  login [username] [password]     Login to the server\n");
    printf("  create-repo <name> [desc]       Create a new repository\n");
    printf("  share <repo_id>                 Generate new share token\n");
    printf("  share_token <token>             Set share token manually\n");
    printf("  set-repo-id <id>                Set repository ID manually\n");
    printf("  init                            Initialize local repository\n");
    printf("  add <file>                      Stage a file for commit\n");
    printf("  rm <file>                       Stage file deletion\n");
    printf("  commit -m <msg> -a <author> -e <email>  Create a commit\n");
    printf("  push                            Push the last commit to the main project\n");
    printf("  status                          Show working tree status\n");
    printf("  log                             Show commit history\n");
    printf("  sync                            Revert to last commit state\n");
    printf("  help                            Show this help\n\n");
}

int handle_error(const char *operation) {
    fprintf(stderr, "Error during %s: %s\n", operation, strerror(errno));
    return FAILURE;
}

int is_bit_initialized(const char *path) {
    struct stat statbuf;
    if (stat(path, &statbuf) == -1) {
        return 0; // Not initialized
    }
    return S_ISDIR(statbuf.st_mode) ? 1 : 0;
}

int initialize_directory(const char *path) {
    if (is_bit_initialized(path)) {
        return 1; // Already defined
    }
    
    if (make_dir(path, 0755) == -1) {
        return FAILURE;
    }
    
    return create_bit_directories();
}

int create_bit_directories() {
    const char *dirs[] = {
        BIT_DIRECTORY,
        ".bit/objects",
        ".bit/commits"
    };

    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        if (make_dir(dirs[i], 0755) != 0 && errno != EEXIST) {
            fprintf(stderr, "Failed to create directory %s: %s\n", dirs[i], strerror(errno));
            return FAILURE;
        }
    }

    // Create index file
    char index_path[256];
    snprintf(index_path, sizeof(index_path), "%s/index", BIT_DIRECTORY);
    FILE *index_file = fopen(index_path, "a");
    if (index_file) {
        fclose(index_file);
    } else {
        fprintf(stderr, "Failed to create index file\n");
        return FAILURE;
    }

    return SUCCESS;
}

char *generate_commit_hash(BitCommit *commit) {
    char hash_input[4096] = {0};
    snprintf(hash_input, sizeof(hash_input), "%s%s%" PRIdMAX "%s",
             commit->author,
             commit->message,
             (intmax_t)commit->timestamp,
             commit->parent_hash ? commit->parent_hash : "");

    // Include files in hash
    if (commit->staged_files_count > 0) {
        struct FilePair *pairs = malloc(commit->staged_files_count * sizeof(struct FilePair));
        for (size_t i = 0; i < commit->staged_files_count; i++) {
            pairs[i].path = commit->staged_files[i];
            pairs[i].hash = commit->staged_hashes[i];
        }
        qsort(pairs, commit->staged_files_count, sizeof(struct FilePair), pair_cmp);
        char tree_str[4096] = {0};
        for (size_t i = 0; i < commit->staged_files_count; i++) {
            char buf[1024];
            snprintf(buf, sizeof(buf), "%s:%s", pairs[i].path, pairs[i].hash);
            strncat(tree_str, buf, sizeof(tree_str) - strlen(tree_str) - 1);
        }
        free(pairs);
        strncat(hash_input, tree_str, sizeof(hash_input) - strlen(hash_input) - 1);
    }

    char *hash = malloc(41);
    unsigned char sha1_hash[20];
    SHA1((unsigned char*)hash_input, strlen(hash_input), sha1_hash);
    for (int i = 0; i < 20; i++) {
        sprintf(hash + (i * 2), "%02x", sha1_hash[i]);
    }
    hash[40] = '\0';

    return hash;
}

int write_commit_file(BitCommit *commit) {
    if (!commit) return FAILURE;

    if (make_dir(".bit/commits", 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "Error creating commits directory: %s\n", strerror(errno));
        return FAILURE;
    }

    char commit_filename[MAX_PATH_LENGTH];
    snprintf(commit_filename, sizeof(commit_filename), ".bit/commits/%s", commit->hash);

    FILE *commit_file = fopen(commit_filename, "wb");
    if (!commit_file) {
        fprintf(stderr, "Error creating commit file: %s\n", strerror(errno));
        return FAILURE;
    }

    fprintf(commit_file, "Author: %s\n", commit->author);
    fprintf(commit_file, "Email: %s\n", commit->email);
    fprintf(commit_file, "Date: %s", ctime(&commit->timestamp));
    fprintf(commit_file, "Message: %s\n", commit->message);

    if (commit->parent_hash) {
        fprintf(commit_file, "Parent: %s\n", commit->parent_hash);
    }

    fprintf(commit_file, "Files:\n");
    for (size_t i = 0; i < commit->staged_files_count; i++) {
        fprintf(commit_file, "  %s %s\n", commit->staged_files[i], commit->staged_hashes[i]);
    }

    fclose(commit_file);

    return SUCCESS;
}

int create_commit(const char *author, const char *email, const char *message) {
    if (!is_bit_initialized(BIT_DIRECTORY)) {
        fprintf(stderr, "Error: Repository not initialized. Run 'bit init' first.\n");
        return FAILURE;
    }

    IndexEntry *entries;
    size_t count;
    if (load_entries(".bit/index", &entries, &count) != SUCCESS) {
        fprintf(stderr, "Error: Failed to load index.\n");
        return FAILURE;
    }

    if (count == 0) {
        fprintf(stderr, "Error: No files staged for commit.\n");
        free_index(entries, count);
        return FAILURE;
    }

    BitCommit commit = {0};
    commit.author = strdup(author);
    commit.email = strdup(email);
    commit.message = strdup(message);
    commit.timestamp = time(NULL);
    commit.staged_files = malloc(count * sizeof(char*));
    commit.staged_hashes = malloc(count * sizeof(char*));
    commit.staged_files_count = count;

    for (size_t i = 0; i < count; i++) {
        commit.staged_files[i] = strdup(entries[i].path);
        commit.staged_hashes[i] = strdup(entries[i].hash);
    }

    char *parent = get_current_head();
    commit.parent_hash = parent ? strdup(parent) : NULL;
    if (parent) free(parent);

    commit.hash = generate_commit_hash(&commit);

    int result = write_commit_file(&commit);
    if (result == SUCCESS) {
        set_head(commit.hash);
    }

    free(commit.author);
    free(commit.email);
    free(commit.message);
    free(commit.hash);
    if (commit.parent_hash) free(commit.parent_hash);
    for (size_t i = 0; i < count; i++) {
        free(commit.staged_files[i]);
        free(commit.staged_hashes[i]);
    }
    free(commit.staged_files);
    free(commit.staged_hashes);
    free_index(entries, count);

    return result;
}

unsigned char *read_file(const char *filepath, size_t *file_size) {
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        fprintf(stderr, "Error opening file %s: %s\n", filepath, strerror(errno));
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *buffer = malloc(*file_size);
    if (!buffer) {
        fprintf(stderr, "Memory allocation failed for file %s\n", filepath);
        fclose(file);
        return NULL;
    }

    size_t bytes_read = fread(buffer, 1, *file_size, file);
    if (bytes_read != *file_size) {
        fprintf(stderr, "Error reading file %s\n", filepath);
        free(buffer);
        fclose(file);
        return NULL;
    }

    fclose(file);
    return buffer;
}

void compute_sha1_hash(const unsigned char *data, size_t data_size, char *hash_out) {
    unsigned char hash[20];
    SHA1(data, data_size, hash);

    for (int i = 0; i < 20; i++) {
        sprintf(hash_out + (i * 2), "%02x", hash[i]);
    }
    hash_out[40] = '\0';
}

unsigned char *compress_data(const unsigned char *data, size_t data_size, size_t *compressed_size) {
    if (!data || data_size == 0 || !compressed_size) {
        return NULL;
    }

    uLong max_compressed_size = compressBound(data_size);
    unsigned char *compressed_buffer = malloc(max_compressed_size);
    if (!compressed_buffer) {
        return NULL;
    }

    uLong dest_len = max_compressed_size;
    int compression_level = Z_BEST_COMPRESSION;

    int result = compress2(compressed_buffer, &dest_len, data, data_size, compression_level);
    if (result != Z_OK) {
        free(compressed_buffer);
        return NULL;
    }

    *compressed_size = dest_len;
    return compressed_buffer;
}

unsigned char *decompress_data(const unsigned char *compressed, size_t comp_size, size_t *dec_size) {
    uLongf dest_len = comp_size * 5; // initial guess
    unsigned char *buffer = NULL;
    int result;

    do {
        free(buffer);
        buffer = malloc(dest_len);
        if (!buffer) return NULL;
        uLongf prev_len = dest_len;
        result = uncompress(buffer, &dest_len, compressed, comp_size);
        if (result == Z_BUF_ERROR) {
            dest_len = prev_len * 2;
        }
    } while (result == Z_BUF_ERROR);

    if (result != Z_OK) {
        free(buffer);
        return NULL;
    }

    *dec_size = dest_len;
    return buffer;
}

int mkdir_p(const char *path) {
    const size_t len = strlen(path);
    char *dir_path = malloc(len + 1);
    if (!dir_path) return FAILURE;
    strcpy(dir_path, path);

    char *p;
    for (p = dir_path + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (make_dir(dir_path, 0755) != 0 && errno != EEXIST) {
                free(dir_path);
                return FAILURE;
            }
            *p = '/';
        }
    }

    if (make_dir(dir_path, 0755) != 0 && errno != EEXIST) {
        free(dir_path);
        return FAILURE;
    }

    free(dir_path);
    return SUCCESS;
}

int add_directory_recursive(const char *dirpath) {
    DIR *dir;
    struct dirent *entry;
    int success = SUCCESS;

    dir = opendir(dirpath);
    if (!dir) {
        fprintf(stderr, "Cannot open directory %s\n", dirpath);
        return FAILURE;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char full_path[MAX_PATH_LENGTH];
        snprintf(full_path, sizeof(full_path), "%s/%s", dirpath, entry->d_name);

        struct stat statbuf;
        if (stat(full_path, &statbuf) == -1) {
            continue;
        }

        if (S_ISDIR(statbuf.st_mode)) {
            int result = add_directory_recursive(full_path);
            if (result != SUCCESS) {
                success = FAILURE;
            }
        } else {
            int result = add_file(full_path);
            if (result != SUCCESS) {
                success = FAILURE;
            }
        }
    }

    closedir(dir);
    return success;
}

int add_file(const char *filepath) {
    // Check if repository is initialized
    if (!is_bit_initialized(BIT_DIRECTORY)) {
        fprintf(stderr, "Error: Repository not initialized. Run 'bit init' first.\n");
        return FAILURE;
    }

    // Create necessary directories if they don't exist
    if (create_bit_directories() != SUCCESS) {
        return FAILURE;
    }

    struct stat st;
    if (stat(filepath, &st) == -1) {
        return FAILURE;
    }
    if (S_ISDIR(st.st_mode)) {
        return add_directory_recursive(filepath);
    }

    // Read file contents
    size_t file_size;
    unsigned char *file_content = read_file(filepath, &file_size);
    if (!file_content) {
        return FAILURE;
    }

    // Compute SHA-1 hash
    char hash[41];
    compute_sha1_hash(file_content, file_size, hash);

    // Compress file content
    size_t compressed_size;
    unsigned char *compressed_data = compress_data(file_content, file_size, &compressed_size);
    free(file_content);
    if (!compressed_data) {
        fprintf(stderr, "Compression failed for %s\n", filepath);
        return FAILURE;
    }

    // Save compressed object
    char object_path[256];
    get_object_path(hash, object_path, sizeof(object_path));
    char dir_path[256];
    if (get_object_dir(hash, dir_path, sizeof(dir_path)) != SUCCESS) {
        free(compressed_data);
        fprintf(stderr, "Invalid hash\n");
        return FAILURE;
    }
    if (make_dir(dir_path, 0755) != 0 && errno != EEXIST) {
        free(compressed_data);
        fprintf(stderr, "Failed to create object dir %s\n", dir_path);
        return FAILURE;
    }

    FILE *object_file = fopen(object_path, "wb");
    if (!object_file) {
        free(compressed_data);
        fprintf(stderr, "Failed to create object file %s\n", object_path);
        return FAILURE;
    }

    fwrite(compressed_data, 1, compressed_size, object_file);
    fclose(object_file);
    free(compressed_data);

    // Update index
    IndexEntry *entries;
    size_t count;
    if (load_entries(".bit/index", &entries, &count) != SUCCESS) {
        return FAILURE;
    }

    int idx = find_index_entry(entries, count, filepath);
    if (idx != -1) {
        free(entries[idx].hash);
        entries[idx].hash = strdup(hash);
    } else {
        IndexEntry *new_entries = realloc(entries, (count + 1) * sizeof(IndexEntry));
        if (!new_entries) {
            free_index(entries, count);
            return FAILURE;
        }
        entries = new_entries;
        entries[count].path = strdup(filepath);
        entries[count].hash = strdup(hash);
        count++;
    }

    int result = save_entries(".bit/index", entries, count);
    free_index(entries, count);

    return result;
}

int bit_status() {
    if (!is_bit_initialized(BIT_DIRECTORY)) {
        printf("Repository not initialized.\n");
        return FAILURE;
    }

    IndexEntry *entries;
    size_t count;
    if (load_entries(".bit/index", &entries, &count) != SUCCESS) {
        return FAILURE;
    }

    // Collect current working directory files
    struct FileHash {
        char *path;
        char *hash;
    };
    struct FileHash *wd_files = NULL;
    size_t wd_count = 0;

    // Recursive function to collect files
    int collect_files(const char *dir) {
        DIR *d = opendir(dir);
        if (!d) return FAILURE;

        struct dirent *ent;
        while ((ent = readdir(d))) {
            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
            if (strcmp(ent->d_name, BIT_DIRECTORY) == 0 && strcmp(dir, ".") == 0) continue;

            char full[MAX_PATH_LENGTH];
            snprintf(full, sizeof(full), "%s/%s", dir, ent->d_name);

            struct stat st;
            if (stat(full, &st) == -1) continue;

            if (S_ISDIR(st.st_mode)) {
                collect_files(full);
            } else {
                size_t size;
                unsigned char *data = read_file(full, &size);
                if (!data) continue;

                char hash[41];
                compute_sha1_hash(data, size, hash);
                free(data);

                struct FileHash *new_f = realloc(wd_files, (wd_count + 1) * sizeof(struct FileHash));
                if (!new_f) return FAILURE;
                wd_files = new_f;

                char *rel_path = full;
                if (strncmp(full, "./", 2) == 0) rel_path = full + 2;

                wd_files[wd_count].path = strdup(rel_path);
                wd_files[wd_count].hash = strdup(hash);
                wd_count++;
            }
        }
        closedir(d);
        return SUCCESS;
    }

    if (collect_files(".") != SUCCESS) {
        free_index(entries, count);
        return FAILURE;
    }

    // Compare
    char **modified = NULL; size_t mod_count = 0;
    char **deleted = NULL; size_t del_count = 0;
    char **untracked = NULL; size_t unt_count = 0;

    for (size_t i = 0; i < wd_count; i++) {
        int idx = find_index_entry(entries, count, wd_files[i].path);
        if (idx == -1) {
            untracked = realloc(untracked, (unt_count + 1) * sizeof(char*));
            untracked[unt_count++] = strdup(wd_files[i].path);
        } else if (strcmp(wd_files[i].hash, entries[idx].hash) != 0) {
            modified = realloc(modified, (mod_count + 1) * sizeof(char*));
            modified[mod_count++] = strdup(wd_files[i].path);
        }
    }

    for (size_t i = 0; i < count; i++) {
        bool found = false;
        for (size_t j = 0; j < wd_count; j++) {
            if (strcmp(entries[i].path, wd_files[j].path) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            deleted = realloc(deleted, (del_count + 1) * sizeof(char*));
            deleted[del_count++] = strdup(entries[i].path);
        }
    }

    // Print status
    printf("Status:\n");
    if (mod_count > 0) {
        printf("Modified files:\n");
        for (size_t i = 0; i < mod_count; i++) printf("  %s\n", modified[i]);
    }
    if (del_count > 0) {
        printf("Deleted files:\n");
        for (size_t i = 0; i < del_count; i++) printf("  %s\n", deleted[i]);
    }
    if (unt_count > 0) {
        printf("Untracked files:\n");
        for (size_t i = 0; i < unt_count; i++) printf("  %s\n", untracked[i]);
    }
    if (mod_count + del_count + unt_count == 0) {
        printf("No changes.\n");
    }

    // Cleanup
    free_index(entries, count);
    for (size_t i = 0; i < wd_count; i++) {
        free(wd_files[i].path);
        free(wd_files[i].hash);
    }
    free(wd_files);
    for (size_t i = 0; i < mod_count; i++) free(modified[i]);
    free(modified);
    for (size_t i = 0; i < del_count; i++) free(deleted[i]);
    free(deleted);
    for (size_t i = 0; i < unt_count; i++) free(untracked[i]);
    free(untracked);

    return SUCCESS;
}

int bit_log() {
    char *head = get_current_head();
    if (!head) {
        printf("No commits yet.\n");
        return SUCCESS;
    }

    char *current = head;
    while (current) {
        char path[256];
        snprintf(path, sizeof(path), ".bit/commits/%s", current);

        FILE *f = fopen(path, "r");
        if (!f) break;

        char line[1024];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "Files:") != NULL) break;
            printf("%s", line);
        }
        fclose(f);
        printf("\n");

        // Get parent
        f = fopen(path, "r");
        char *parent = NULL;
        while (fgets(line, sizeof(line), f)) {
            trim_whitespace(line);
            if (strncmp(line, "Parent: ", 8) == 0) {
                parent = strdup(line + 8);
                break;
            }
        }
        fclose(f);

        free(current);
        current = parent;
    }

    return SUCCESS;
}

int bit_sync() {
    if (!is_bit_initialized(BIT_DIRECTORY)) {
        printf("Repository not initialized.\n");
        return FAILURE;
    }

    char *head = get_current_head();
    if (!head) {
        printf("No commits yet.\n");
        return SUCCESS;
    }

    char commit_path[256];
    snprintf(commit_path, sizeof(commit_path), ".bit/commits/%s", head);

    FILE *f = fopen(commit_path, "r");
    if (!f) {
        printf("Failed to open commit file.\n");
        free(head);
        return FAILURE;
    }

    char line[1024];
    bool in_files = false;
    struct FilePair *files = NULL;
    size_t file_count = 0;

    while (fgets(line, sizeof(line), f)) {
        trim_whitespace(line);
        if (strcmp(line, "Files:") == 0) {
            in_files = true;
            continue;
        }
        if (!in_files) continue;

        if (strlen(line) == 0) continue;

        char *space = strrchr(line, ' ');
        if (!space) continue;

        *space = '\0';
        trim_whitespace(line);
        char *path_str = line;

        char *hash_str = space + 1;
        trim_whitespace(hash_str);

        if (strlen(path_str) == 0 || strlen(hash_str) == 0) continue;

        files = realloc(files, (file_count + 1) * sizeof(struct FilePair));
        files[file_count].path = strdup(path_str);
        files[file_count].hash = strdup(hash_str);
        file_count++;
    }
    fclose(f);

    char *input = get_input("This action will revert the codebase to the last commit.\nAre you sure? (y/n): ");
    if (!input || (strcasecmp(input, "y") != 0 && strcasecmp(input, "yes") != 0)) {
        printf("Sync cancelled.\n");
        free(input);
        for (size_t i = 0; i < file_count; i++) {
            free(files[i].path);
            free(files[i].hash);
        }
        free(files);
        free(head);
        return SUCCESS;
    }
    free(input);

    for (size_t i = 0; i < file_count; i++) {
        char obj_path[256];
        get_object_path(files[i].hash, obj_path, sizeof(obj_path));

        size_t comp_size;
        unsigned char *comp_data = read_file(obj_path, &comp_size);
        if (!comp_data) {
            printf("Failed to read object for %s\n", files[i].path);
            continue;
        }

        size_t dec_size;
        unsigned char *dec_data = decompress_data(comp_data, comp_size, &dec_size);
        free(comp_data);
        if (!dec_data) {
            printf("Failed to decompress %s\n", files[i].path);
            continue;
        }

        // Create directories if needed
        char *dir = strdup(files[i].path);
        char *slash = strrchr(dir, '/');
        if (slash) {
            *slash = '\0';
            mkdir_p(dir);
        }
        free(dir);

        FILE *out = fopen(files[i].path, "wb");
        if (!out) {
            printf("Failed to write %s\n", files[i].path);
            free(dec_data);
            continue;
        }

        fwrite(dec_data, 1, dec_size, out);
        fclose(out);
        free(dec_data);

        printf("Restored %s\n", files[i].path);
    }

    for (size_t i = 0; i < file_count; i++) {
        free(files[i].path);
        free(files[i].hash);
    }
    free(files);
    free(head);

    printf("Codebase synced to last commit.\n");
    return SUCCESS;
}

int bit_push_commit(const char *author, const char *email, const char *message) {
    // Placeholder for push, if needed
    return bit_commit_to_server(author, email, message);
}

// ============================================================================
// MAIN FUNCTION
// ============================================================================

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_help();
        return SUCCESS;
    }
    
    // Initialize CURL
    curl_global_init(CURL_GLOBAL_ALL);
    
    // Load existing tokens
    char *auth_token = load_auth_token();
    if (auth_token) {
        strcpy(g_auth_token, auth_token);
        free(auth_token);
    }
    
    char *share_token = load_share_token();
    if (share_token) {
        strcpy(g_share_token, share_token);
        free(share_token);
    }
    
    // Parse commands
    if (strcmp(argv[1], "login") == 0) {
        if (argc < 4) {
            char *username = get_input("Username: ");
            char *password = get_input("Password: ");
            
            if (username && password) {
                int result = bit_login(username, password);
                free(username);
                free(password);
                curl_global_cleanup();
                return result;
            } else {
                printf("Invalid input\n");
                curl_global_cleanup();
                return FAILURE;
            }
        } else {
            int result = bit_login(argv[2], argv[3]);
            curl_global_cleanup();
            return result;
        }
    } else if (strcmp(argv[1], "create-repo") == 0) {
        if (argc < 3) {
            printf("Repository name required\n");
            printf("Usage: bit create-repo <name> [description]\n");
            curl_global_cleanup();
            return FAILURE;
        }

        const char *description = (argc > 3) ? argv[3] : "";
        int result = bit_create_repo(argv[2], description);
        curl_global_cleanup();
        return result;
    } else if (strcmp(argv[1], "share") == 0) {
        if (argc < 3) {
            printf("Repository ID required\n");
            printf("Usage: bit share <repo_id>\n");
            curl_global_cleanup();
            return FAILURE;
        }

        int result = bit_generate_share_token(argv[2]);
        curl_global_cleanup();
        return result;
    } else if (strcmp(argv[1], "share_token") == 0) {
        if (argc < 3) {
            printf("Share token required\n");
            curl_global_cleanup();
            return FAILURE;
        }

        strcpy(g_share_token, argv[2]);
        save_share_token(argv[2]);
        printf("Share token set to %s\n", argv[2]);
        curl_global_cleanup();
        return SUCCESS;
    } else if (strcmp(argv[1], "set-repo-id") == 0) {
        if (argc < 3) {
            printf("Repository ID required\n");
            curl_global_cleanup();
            return FAILURE;
        }

        int result = save_repo_id(argv[2]);
        if (result == SUCCESS) {
            printf("Repository ID set to %s\n", argv[2]);
        }
        curl_global_cleanup();
        return result;
    } else if (strcmp(argv[1], "commit") == 0) {
        // Parse commit arguments
        const char *message = NULL;
        const char *author = NULL;
        const char *email = NULL;

        for (int i = 2; i < argc; i += 2) {
            if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
                message = argv[i + 1];
            } else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
                author = argv[i + 1];
            } else if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) {
                email = argv[i + 1];
            }
        }

        if (!message || !author || !email) {
            printf("Missing required commit arguments\n");
            printf("Usage: bit commit -m \"<message>\" -a \"<author>\" -e \"<email>\"\n");
            curl_global_cleanup();
            return FAILURE;
        }

        int result = bit_commit_to_server(author, email, message);
        curl_global_cleanup();
        return result;
    } else if (strcmp(argv[1], "init") == 0) {
        int result = initialize_directory(BIT_DIRECTORY);
        curl_global_cleanup();
        return result;
    } else if (strcmp(argv[1], "add") == 0) {
        if (argc < 3) {
            printf("No files specified to add\n");
            curl_global_cleanup();
            return FAILURE;
        }

        int success = SUCCESS;
        for (int i = 2; i < argc; i++) {
            int result = add_file(argv[i]);
            if (result != SUCCESS) {
                success = FAILURE;
            }
        }
        curl_global_cleanup();
        return success;
    } else if (strcmp(argv[1], "rm") == 0) {
        if (argc < 3) {
            printf("No files specified to rm\n");
            curl_global_cleanup();
            return FAILURE;
        }

        int success = SUCCESS;
        for (int i = 2; i < argc; i++) {
            IndexEntry *entries;
            size_t count;
            if (load_entries(".bit/index", &entries, &count) != SUCCESS) {
                success = FAILURE;
                continue;
            }

            int idx = find_index_entry(entries, count, argv[i]);
            if (idx == -1) {
                printf("File not tracked: %s\n", argv[i]);
                free_index(entries, count);
                success = FAILURE;
                continue;
            }

            free(entries[idx].path);
            free(entries[idx].hash);
            if (count > 1) {
                memmove(entries + idx, entries + idx + 1, sizeof(IndexEntry) * (count - idx - 1));
            }
            count--;

            if (save_entries(".bit/index", entries, count) != SUCCESS) {
                success = FAILURE;
            }
            free_index(entries, count);
        }
        curl_global_cleanup();
        return success;
    } else if (strcmp(argv[1], "status") == 0) {
        int result = bit_status();
        curl_global_cleanup();
        return result;
    } else if (strcmp(argv[1], "log") == 0) {
        int result = bit_log();
        curl_global_cleanup();
        return result;
    } else if (strcmp(argv[1], "push") == 0) {
        int result = bit_push();
        curl_global_cleanup();
        return result;
    } else if (strcmp(argv[1], "sync") == 0) {
        int result = bit_sync();
        curl_global_cleanup();
        return result;
    } else if (strcmp(argv[1], "help") == 0) {
        print_help();
        curl_global_cleanup();
        return SUCCESS;
    } else {
        printf("Unknown command: %s\n", argv[1]);
        printf("Use 'bit help' for usage information\n");
        curl_global_cleanup();
        return FAILURE;
    }
    
    curl_global_cleanup();
    return SUCCESS;
}