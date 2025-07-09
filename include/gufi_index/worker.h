#ifndef WORKER_H
#define WORKER_H
#include <signal.h>
#include <sqlite3.h>
#include <stdbool.h>

#include "app.h"
#include "reader.h"

#define EVENT_TYPE_MAX      (18)

extern app_t app;
extern volatile sig_atomic_t app_stop;

typedef void (*event_handler_t)(struct fs_event *event);

dir_index_cache_t *dir_cache_init(const char *entry_id, const char* dir_path);

void dir_cache_uinit(dir_index_cache_t *item);
void file_cache_uninit(file_index_cache_t *item);

dir_index_cache_t *reference_dir(const char entryId[256], const char* event_path, bool create);

void release_cached_dir(const char entryId[256]);

void cache_event(struct fs_event* event);

void dir_cache_flush(dir_index_cache_t *dir);

void delete_cache_dir(const char entryId[256], bool flush);

void clear_cache_dir();


void update_file_stat(struct file_index_cache *file);

int update_cache_data_flag(int old_flag, fs_event_type event_type);

void rmdir_iterative(const char *dir_path);

void create_dir(struct fs_event *event);

void remove_dir(struct fs_event *event);

void rename_event(struct fs_event *event);

void process_event(struct fs_event *event);

void set_nonblocking(int sockfd);

void receive_event(int socket_fd);

void *event_flusher_run(void *arg);

void *event_worker_run(void *arg);

void *stream_listener_run(void *arg);

#endif //WORKER_H
