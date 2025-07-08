#ifndef APP_H
#define APP_H

#include <sqlite3.h>

#include "bf.h"
#include "config.h"
#include "reader.h"
#include "SinglyLinkedList.h"
#include "uthash/uthash.h"


#define DATA_FIELD_INSERT     1
#define DATA_FIELD_STAT     2
#define DATA_FIELD_XATTR    4
#define DATA_FIELD_DELETE   8

typedef struct file_index_cache {
    char entry_id[256];
    char parent_id[256];
    char file_name[256];
    const char* file_path;
    struct entry_data ed;
    uint16_t data_field_flag;
    file_pattern_t *file_pattern;
    pthread_mutex_t file_lock;
    UT_hash_handle hh;
} file_index_cache_t;

typedef struct dir_index_cache {
    char entry_id[256];
    sqlite3 *db;
    const char *index_path;
    sqlite3_stmt *stmt_insert;
    sqlite3_stmt *stmt_update;
    sqlite3_stmt *stmt_delete;
    time_t last_commit;
    time_t last_access;
    int row_count;
    int summary_count;

    int ref_count;
    pthread_mutex_t mutex;

    file_index_cache_t *file_cache;
    UT_hash_handle hh;
} dir_index_cache_t;

typedef struct app {
    AppConfig config;

    dir_index_cache_t *index_cache;
    pthread_mutex_t index_cache_mutex;

    int listen_fd;
    int epoll_fd;

    sll_t socket_list;
    pthread_mutex_t socket_mutex;

    sll_t event_queue;
    pthread_mutex_t queue_mutex;
    pthread_cond_t queue_cond;

    pthread_t stream_listener;
    pthread_t event_flusher;
    pthread_t *event_workers;
} app_t;

void signal_handler(int signum);

void thread_join();

int init_server();

int init_app();

void uninit_app();


#endif //APP_H
