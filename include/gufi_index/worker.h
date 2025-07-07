#ifndef WORKER_H
#define WORKER_H
#include <signal.h>
#include <sqlite3.h>
#include <stdbool.h>

#include "app.h"
#include "reader.h"

#define MAX_BUFFER_SIZE     (1024*1024*4)
#define EVENT_TYPE_MAX      (18)

extern app_t app;
extern volatile sig_atomic_t app_stop;

typedef void (*event_handler_t)(struct fs_event *event);

dir_index_cache_t *dir_cache_init(const char *entry_id);

void dir_cache_uinit(dir_index_cache_t *item);

dir_index_cache_t *reference_cached_dir(const char entryId[256], bool create);

void release_cached_dir(const char entryId[256]);

int add_event_to_cache(dir_index_cache_t *dir, const char *file_path, const char* entry_id, struct stat *stat, enum file_op op,
                       file_pattern_t *pattern);
void dir_cache_flush(dir_index_cache_t *dir);

void delete_cache_dir(const char entryId[256], bool flush);

void clear_cache_dir();

void rmdir_iterative(const char *dir_path);

void update_attr(struct fs_event *event);

void create_file(struct fs_event *event);

void create_dir(struct fs_event *event);

void remove_dir(struct fs_event *event);

void unlink_file(struct fs_event *event);

void move_file(struct fs_event *event);

void process_event(struct fs_event *event);

void set_nonblocking(int sockfd);

void receive_event(int socket_fd);

void *event_flusher_run(void *arg);

void *event_worker_run(void *arg);

void *stream_listener_run(void *arg);

#endif //WORKER_H
