#include "gufi_index/worker.h"
#include "gufi_index/index_db.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include "dbutils.h"
#include "external.h"
#include "utils.h"
#include <libgen.h>
#include <string.h>

static event_handler_t handler_table[EVENT_TYPE_MAX] = {
    [TRUNCATE] = update_attr,
    [SETATTR] = update_attr,
    [CLOSE_WRITE] = update_attr,

    [CREATE] = create_file,
    [SYMLINK] = create_file,
    [HARDLINK] = create_file,
    [MKNOD] = create_file,

    [MKDIR] = create_dir,
    [RMDIR] = remove_dir,
    [UNLINK] = unlink_file,
    [RENAME] = move_file,

    // ignore events below
    [FLUSH] = NULL,
    [OPEN_READ] = NULL,
    [OPEN_WRITE] = NULL,
    [OPEN_READ_WRITE] = NULL,
    [LAST_WRITER_CLOSED] = NULL,
    [RECORD] = NULL,
};

dir_index_cache_t *dir_cache_init(const char *entry_id) {
    dir_index_cache_t *item = calloc(1, sizeof(dir_index_cache_t));
    snprintf(item->entry_id, sizeof(item->entry_id), "%s", entry_id);
    pthread_mutex_init(&item->mutex, NULL);
    time(&item->last_access);
    time(&item->last_commit);

    item->ref_count = 0;
    item->row_count = 0;
    item->summary_count = 0;

    item->file_cache = NULL;

    return item;
}

void dir_cache_uinit(dir_index_cache_t *item) {
    if (item->stmt_insert) sqlite3_finalize(item->stmt_insert);
    if (item->stmt_update) sqlite3_finalize(item->stmt_update);
    if (item->stmt_delete) sqlite3_finalize(item->stmt_delete);
    if (item->db) sqlite3_close(item->db);
    if (item->index_path) free((char *) item->index_path);
    pthread_mutex_destroy(&item->mutex);

    file_index_cache_t *f, *tmp;
    HASH_ITER(hh, item->file_cache, f, tmp) {
        HASH_DEL(item->file_cache, f);
        if (f->file_pattern) {
            free(f->file_pattern);
        }
        free(f);
    }

    free(item);
}

dir_index_cache_t *reference_cached_dir(const char entryId[256], bool create) {
    dir_index_cache_t *found = NULL;

    pthread_mutex_lock(&app.index_cache_mutex);
    HASH_FIND_STR(app.index_cache, entryId, found);
    if (found == NULL && create) {
        found = dir_cache_init(entryId);
        HASH_ADD_STR(app.index_cache, entry_id, found);
    }
    if (found) {
        __sync_fetch_and_add(&found->ref_count, 1);
    }
    pthread_mutex_unlock(&app.index_cache_mutex);

    return found;
}

int add_event_to_cache(dir_index_cache_t *dir, const char *file_path, const char *entry_id, struct stat *stat,
                       enum file_op op,
                       file_pattern_t *pattern) {
    // check file cache exist
    pthread_mutex_lock(&dir->mutex);
    file_index_cache_t *found = NULL;
    HASH_FIND_STR(dir->file_cache, entry_id, found);
    if (found == NULL) {
        found = calloc(1, sizeof(file_index_cache_t));
        found->data_field_flag = FIELD_FLAG_ATTR;
        found->op = op;
        extract_filename(file_path, found->file_name);
        pthread_mutex_init(&found->file_lock, NULL);
        found->ed.type = S_ISREG(stat->st_mode) ? 'f' : S_ISLNK(stat->st_mode) ? 'l' : '?';
        found->ed.linkname[0] = '\0';
        found->ed.xattrs;
        found->ed.crtime = 0;
        found->ed.ossint1 = 0;
        found->ed.ossint2 = 0;
        found->ed.ossint3 = 0;
        found->ed.ossint4 = 0;
        found->ed.osstext1[0] = '\0';
        found->ed.osstext2[0] = '\0';
        HASH_ADD_STR(dir->file_cache, entry_id, found);
    }
    pthread_mutex_unlock(&dir->mutex);

    // fill pattern and stat
    if (op == MKFILE) {
        if (stat == NULL || pattern == NULL) {
            LOG_ERR("file stat or pattern should not be NULL when create file, path: %s", file_path);
            return -1;
        }
        found->data_field_flag = FIELD_FLAG_ATTR;
        found->file_pattern = pattern;
        found->ed.statuso = *stat;
    }

    if (found->op == MKFILE) {
        if (op == MKFILE) {
        } else if (op == UPDATE) {
            // update stat info and stay MKFILE
            if (stat != NULL) {
                pthread_mutex_lock(&found->file_lock);
                found->ed.statuso = *stat;
                pthread_mutex_unlock(&found->file_lock);
            }
        } else if (op == DELETE) {
            // remove this cached event
            pthread_mutex_lock(&dir->mutex);
            HASH_DEL(dir->file_cache, found);
            pthread_mutex_unlock(&dir->mutex);
            pthread_mutex_destroy(&found->file_lock);
            if (found->file_pattern) {
                free(found->file_pattern);
            }
            free(found);
        }
        goto add_end;
    }

    if (found->op == UPDATE) {
        // update stat info and stay MKFILE
        if (stat != NULL) {
            pthread_mutex_lock(&found->file_lock);
            found->ed.statuso = *stat;
            pthread_mutex_unlock(&found->file_lock);
        }
        goto add_end;
    }

    if (found->op == DELETE) {
        // no update needed
    }

add_end:

    return 0;
}

void release_cached_dir(const char entryId[256]) {
    dir_index_cache_t *found = NULL;

    pthread_mutex_lock(&app.index_cache_mutex);
    HASH_FIND_STR(app.index_cache, entryId, found);
    if (found) {
        __sync_sub_and_fetch(&found->ref_count, 1);
    }
    pthread_mutex_unlock(&app.index_cache_mutex);
}

void delete_cache_dir(const char entryId[256],bool flush) {
    pthread_mutex_lock(&app.index_cache_mutex);
    dir_index_cache_t *entry = NULL;
    HASH_FIND_STR(app.index_cache, entryId, entry);
    if (entry) {
        HASH_DEL(app.index_cache, entry);
    }
    pthread_mutex_unlock(&app.index_cache_mutex);
}

void clear_cache_dir() {
    pthread_mutex_lock(&app.index_cache_mutex);
    dir_index_cache_t *entry, *tmp;
    HASH_ITER(hh, app.index_cache, entry, tmp) {
        HASH_DEL(app.index_cache, entry);

        LOG_DBG("clearing cache dir %s", entry->entry_id);
        dir_cache_uinit(entry);
    }
    pthread_mutex_unlock(&app.index_cache_mutex);
}

void update_attr(struct fs_event *event) {
    LOG_DBG("update attr event, path %s, id %s parent id %s", event->path, event->parentEntryId, event->entryId);
    char file_path[MAXPATH];
    struct stat st;
    SNPRINTF(file_path, sizeof(file_path), "%s%s", app.config.mount_point, event->path);
    if (lstat(file_path, &st) == 0 && S_ISDIR(st.st_mode)) {
        LOG_ERR("path in create file event is actually a directory, path: %s", file_path);
    }
    /*
     * path does exist:    path is in the filesystem the index is on,
     *                     rather than in the index (e.g. db.db)
     *
     * path doesn't exist: path is a file/link name that might exist
     *                     within the index
     *
     * either way, search index at dirname(path)
     */
    else {
        dir_index_cache_t *parent = reference_cached_dir(event->parentEntryId, true);
        if (parent->index_path == NULL) {
            char tmp_path[MAXPATH];
            char parent_path[MAXPATH];
            char name[MAXPATH];
            SNPRINTF(tmp_path, sizeof(tmp_path), "%s%s", app.config.index_root, event->path);
            shortpath(tmp_path, parent_path, name);

            parent->index_path = strdup(parent_path);
            LOG_DBG("created index dir %s", parent->index_path);
        }

        add_event_to_cache(parent, file_path, event->entryId, &st, UPDATE,NULL);
    }
    release_cached_dir(event->parentEntryId);
}

void create_file(struct fs_event *event) {
    LOG_DBG("create file event, path %s, id %s parent id %s", event->path, event->parentEntryId, event->entryId);
    dir_index_cache_t *parent = reference_cached_dir(event->parentEntryId, true);

    struct stat st;
    char file_path[MAXPATH];
    SNPRINTF(file_path, sizeof(file_path), "%s%s", app.config.mount_point, event->path);
    if (lstat(file_path, &st) == 0 && S_ISDIR(st.st_mode)) {
        LOG_ERR("path in create file event is actually a directory, path: %s", file_path);
    }
    /*
     * path does exist:    path is in the filesystem the index is on,
     *                     rather than in the index (e.g. db.db)
     *
     * path doesn't exist: path is a file/link name that might exist
     *                     within the index
     *
     * either way, search index at dirname(path)
     */
    else {
        file_pattern_t *pattern = get_file_pattern(file_path, event->entryId, event->parentEntryId);
        print_file_pattern(pattern);

        char prefix[MAXPATH];
        char file_name[MAXPATH];
        shortpath(file_path, prefix, file_name);

        if (parent->index_path == NULL) {
            char tmp_path[MAXPATH];
            char parent_path[MAXPATH];
            char name[MAXPATH];
            SNPRINTF(tmp_path, sizeof(tmp_path), "%s%s", app.config.index_root, event->path);
            shortpath(tmp_path, parent_path, name);

            parent->index_path = strdup(parent_path);
            LOG_DBG("created index dir %s", parent->index_path);
        }
        add_event_to_cache(parent, file_path, event->entryId, &st, MKFILE, pattern);
    }
    release_cached_dir(parent->entry_id);
}

void create_dir(struct fs_event *event) {
    char index_dir[MAXPATH];
    char source_dir[MAXPATH];

    SNPRINTF(index_dir, sizeof(index_dir), "%s%s", app.config.index_root, event->path);
    SNPRINTF(source_dir, sizeof(source_dir), "%s%s", app.config.mount_point, event->path);

    struct stat st;
    if (lstat(source_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        LOG_ERR("event mkdir path %s is not a valid directory", source_dir);
        return;
    }

    if (mkdir(index_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) != 0) {
        LOG_ERR("Failed to create index directory \"%s\"", index_dir);
        return;
    }

    struct entry_data row_ed = {
        .type = 'd',
        .statuso = st,
        .linkname = "",
        .xattrs = NULL,
        .crtime = 0,
        .ossint1 = 0,
        .ossint2 = 0,
        .ossint3 = 0,
        .ossint4 = 0,
        .osstext1 = "",
        .osstext2 = "",
    };

    char db_file[MAXPATH];
    SNPRINTF(db_file, sizeof(db_file), "%s/%s", index_dir, DBNAME);
    LOG_DBG("new db_path: %s", db_file);

    // tables created via create_index_db_tables
    sqlite3 *db = opendb(db_file, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, 1, 0, create_index_db_tables, NULL);
    if (!db) {
        LOG_ERR("Failed to open database %s", db_file);
        return;
    }

    // insert init sum table
    struct sum summary;
    zeroit(&summary);

    char parent[MAXPATH], name[MAXPATH];
    shortpath(index_dir, parent, name);
    insertsumdb_index(db, name, &row_ed, &summary);

    closedb(db);
}

void rmdir_iterative(const char *dir_path) {
    sll_t dir_stack;
    sll_init(&dir_stack);

    sll_t delete_later;
    sll_init(&delete_later);

    sll_push(&dir_stack, strdup(dir_path));

    while (sll_get_size(&dir_stack) > 0) {
        char *path = sll_pop(&dir_stack);

        DIR *dir = opendir(path);
        if (!dir) {
            LOG_ERR("opendir failed: %s", path);
            free(path);
            continue;
        }

        struct dirent *entry;
        char full_path[MAXPATH];

        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;

            SNPRINTF(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

            struct stat st;
            if (lstat(full_path, &st) != 0) {
                LOG_ERR("lstat failed: %s", full_path);
                continue;
            }

            if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
                sll_push(&dir_stack, strdup(full_path));
            } else {
                if (remove(full_path) != 0) {
                    LOG_ERR("remove failed: %s", full_path);
                }
            }
        }

        closedir(dir);
        sll_push(&delete_later, path);
    }


    while (sll_get_size(&delete_later) > 0) {
        char *current_dir = sll_pop(&delete_later);
        if (rmdir(current_dir) != 0) {
            LOG_ERR("rmdir failed: %s", current_dir);
        }
        free(current_dir);
    }

    sll_destroy(&dir_stack, NULL);
    sll_destroy(&delete_later, NULL);
}


void remove_dir(struct fs_event *event) {
    // check cached event and sql buffer under this directory, should clear them first
    delete_cache_dir(event->entryId, false);

    char index_path[MAXPATH];
    SNPRINTF(index_path, sizeof(index_path), "%s%s", app.config.index_root, event->path);

    LOG_INFO("Removing directory %s", index_path);
    rmdir_iterative(index_path);
}

void unlink_file(struct fs_event *event) {
    LOG_DBG("update attr event, path %s, id %s parent id %s", event->path, event->parentEntryId, event->entryId);
    char file_path[MAXPATH];
    SNPRINTF(file_path, sizeof(file_path), "%s%s", app.config.mount_point, event->path);

    dir_index_cache_t *parent = reference_cached_dir(event->parentEntryId, true);
    if (parent->index_path == NULL) {
        char tmp_path[MAXPATH];
        char parent_path[MAXPATH];
        char name[MAXPATH];
        SNPRINTF(tmp_path, sizeof(tmp_path), "%s%s", app.config.index_root, event->path);
        shortpath(tmp_path, parent_path, name);

        parent->index_path = strdup(parent_path);
        LOG_DBG("created index dir %s", parent->index_path);
    }

    add_event_to_cache(parent, file_path, event->entryId, NULL, DELETE,NULL);
    release_cached_dir(event->parentEntryId);
}

void move_file(struct fs_event *event) {
}

void process_event(struct fs_event *event) {
    if (!event || event->type <= 0 || event->type >= EVENT_TYPE_MAX)
        return;

    event_handler_t handler = handler_table[event->type];
    if (handler) {
        LOG_DBG("processing event %s", event_type_string(event));
        handler(event);
    } else {
        LOG_DBG("Ignored or unknown event: %d (%s)\n", event->type, event_type_string(event));
    }
}

void set_nonblocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) {
        LOG_ERR("fcntl get failed: %s");
        return;
    }
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        LOG_ERR("fcntl set nonblocking failed: %s");
    }
}

void enqueue(struct fs_event *event) {
    pthread_mutex_lock(&app.queue_mutex);
    sll_push(&app.event_queue, event);
    pthread_cond_signal(&app.queue_cond);
    pthread_mutex_unlock(&app.queue_mutex);
}

struct fs_event *dequeue() {
    struct timespec ts;
    struct fs_event *event = NULL;

    pthread_mutex_lock(&app.queue_mutex);
    while (!app_stop && sll_get_size(&app.event_queue) == 0) {
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 1;
        pthread_cond_timedwait(&app.queue_cond, &app.queue_mutex, &ts);
    }

    if (sll_get_size(&app.event_queue) > 0) {
        event = sll_pop(&app.event_queue);
    }
    pthread_mutex_unlock(&app.queue_mutex);
    return event;
}

void receive_event(int socket_fd) {
    static char recv_buffer[RECV_BUF_CAPACITY];
    static size_t recv_buffer_len = 0;

    while (1) {
        ssize_t bytes_received = recv(socket_fd,
                                      recv_buffer + recv_buffer_len,
                                      RECV_BUF_CAPACITY - recv_buffer_len,
                                      0);

        if (bytes_received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            LOG_ERR("receive failed");
            close(socket_fd);
            break;
        }

        if (bytes_received == 0) {
            LOG_INFO("client disconnected: %d", socket_fd);
            epoll_ctl(app.epoll_fd, EPOLL_CTL_DEL, socket_fd, NULL);
            close(socket_fd);
            break;
        }

        recv_buffer_len += bytes_received;
        LOG_DBG("Received %zd bytes, total in buffer: %zu", bytes_received, recv_buffer_len);

        size_t offset = 0;

        while (recv_buffer_len - offset >= PACKET_HEADER_LEN) {
            if (memcmp(recv_buffer + offset, MAGIC_HEADER, MAGIC_HEADER_LEN) != 0) {
                LOG_ERR("Invalid magic header, skipping one byte");
                offset += 1;
                continue;
            }


            uint64_t payload_len = 0;
            memcpy(&payload_len, recv_buffer + offset + MAGIC_HEADER_LEN, LENGTH_PREFIX_LEN);

            size_t total_packet_len = PACKET_HEADER_LEN + payload_len;
            if (payload_len > RECV_BUF_CAPACITY - PACKET_HEADER_LEN) {
                LOG_ERR("payload too large, discarding");
                break;
            }

            if (recv_buffer_len - offset < total_packet_len) {
                break;
            }

            struct fs_event *event = malloc(sizeof(struct fs_event));
            if (!event) {
                LOG_ERR("malloc failed");
                break;
            }

            ReadErrorCode status = packet_to_event(recv_buffer + offset + PACKET_HEADER_LEN, payload_len, event);

            if (status == Success) {
                if (log_level >= LOG_LEVEL_DEBUG) {
                    char *event_str = event_to_str(event);
                    free(event_str);
                }
                enqueue(event);
                offset += total_packet_len;
            } else {
                free(event);
                LOG_ERR("failed to parse event");
                break;
            }
        }

        if (offset > 0) {
            recv_buffer_len -= offset;
            memmove(recv_buffer, recv_buffer + offset, recv_buffer_len);
        }

        if (recv_buffer_len == RECV_BUF_CAPACITY) {
            LOG_ERR("buffer overflow, discarding %zu bytes", recv_buffer_len);
            recv_buffer_len = 0;
        }
    }
}

void dir_cache_flush(dir_index_cache_t *dir) {
    pthread_mutex_lock(&dir->mutex);

    if (dir->db == NULL) {
        char db_path[MAXPATH];
        SNPRINTF(db_path, sizeof(db_path), "%s/" DBNAME, dir->index_path);
        dir->db = opendb(db_path, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, 1, 0, NULL, NULL);
    }

    int rc = sqlite3_prepare_v2(dir->db, ENTRIES_INSERT, -1, &dir->stmt_insert,NULL);
    if (rc != SQLITE_OK) {
        LOG_ERR("sqlite3_prepare_v2 insert entry failed: %s, path %s", sqlite3_errmsg(dir->db), dir->index_path);
    }

    rc = sqlite3_prepare_v2(dir->db, ENTRIES_UPDATE, -1, &dir->stmt_update, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERR("sqlite3_prepare_v2 update entry failed: %s", sqlite3_errmsg(dir->db));
    }
    rc = sqlite3_prepare_v2(dir->db, ENTRIES_DELETE, -1, &dir->stmt_delete, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERR("sqlite3_prepare_v2 delete entry failed: %s", sqlite3_errmsg(dir->db));
    }

    startdb(dir->db);
    file_index_cache_t *item, *tmp;
    HASH_ITER(hh, dir->file_cache, item, tmp) {
        if (item->op == MKFILE) {
            insertdbgo_index(item, dir->stmt_insert);
        } else if (item->op == UPDATE) {
            update_attr_index(item, dir->stmt_update);
        } else if (item->op == DELETE) {
            delete_index(item, dir->stmt_delete);
        }
        HASH_DEL(dir->file_cache, item);
        if (item->file_pattern) {
            free(item->file_pattern);
        }
        free(item);
    }

    stopdb(dir->db);
    time(&dir->last_commit);
    pthread_mutex_unlock(&dir->mutex);
}

void *event_flusher_run(void *arg) {
    while (!app_stop) {
        pthread_mutex_lock(&app.index_cache_mutex);
        dir_index_cache_t *entry, *tmp;
        dir_index_cache_t *still_alive = NULL;
        time_t current_time = time(NULL);
        HASH_ITER(hh, app.index_cache, entry, tmp) {
            if (difftime(current_time, entry->last_access) > 5) {
                HASH_DEL(app.index_cache, entry);
                HASH_ADD_STR(still_alive, entry_id, entry);
            }
        }
        pthread_mutex_unlock(&app.index_cache_mutex);

        HASH_ITER(hh, still_alive, entry, tmp) {
            LOG_DBG("flushing cache dir %s", entry->entry_id);
            dir_cache_flush(entry);
            if (entry->ref_count == 0) {
                LOG_DBG("removing expired cache dir %s", entry->entry_id);
                HASH_DEL(still_alive, entry);
                dir_cache_uinit(entry);
            } else {
                pthread_mutex_lock(&app.index_cache_mutex);
                HASH_ADD_STR(app.index_cache, entry_id, entry);
                pthread_mutex_unlock(&app.index_cache_mutex);
                HASH_DEL(still_alive, entry);
            }
        }

        // put ref_count > 0 item back
        if (still_alive) {
            pthread_mutex_lock(&app.index_cache_mutex);
            dir_index_cache_t *e, *tmp2;
            HASH_ITER(hh, still_alive, e, tmp2) {
                HASH_ADD_STR(app.index_cache, entry_id, e);
                HASH_DEL(still_alive, e);
            }
            pthread_mutex_unlock(&app.index_cache_mutex);
        }

        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 5;

        // TODO: replace sleep with interruptable sleep
        sleep(5);
    }
    return NULL;
}


void *event_worker_run(void *arg) {
    while (1) {
        struct fs_event *event = dequeue();

        if (!event) {
            if (app_stop) break;
            continue;
        }

        process_event(event);
        free(event);
    }

    return NULL;
}

void *stream_listener_run(void *arg) {
    struct epoll_event events[EPOLL_EVENTS_NUM];
    const int epoll_timeout = app.config.aggressive_poll ? 0 : 3000;

    while (!app_stop) {
        const int num_fds = epoll_wait(app.epoll_fd, events, EPOLL_EVENTS_NUM, epoll_timeout);
        if (num_fds < 0 && errno != EINTR) {
            LOG_ERR("epoll_wait failed");
            break;
        }

        for (int i = 0; i < num_fds; i++) {
            int fd = events[i].data.fd;

            if (fd == app.listen_fd) {
                struct sockaddr_in client_addr;
                socklen_t client_addr_len = sizeof(client_addr);

                while (1) {
                    int *accepted_socket = malloc(sizeof(int));
                    if (!accepted_socket) {
                        LOG_ERR("malloc accepted socket failed");
                        continue;
                    }

                    *accepted_socket = accept(app.listen_fd, (struct sockaddr *) &client_addr, &client_addr_len);
                    if (*accepted_socket < 0) {
                        free(accepted_socket);
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break;
                        }
                        LOG_ERR("accept connection failed");
                        break;
                    }

                    set_nonblocking(*accepted_socket);

                    struct epoll_event event;
                    event.events = EPOLLIN | EPOLLET;
                    event.data.fd = *accepted_socket;
                    epoll_ctl(app.epoll_fd, EPOLL_CTL_ADD, *accepted_socket, &event);

                    pthread_mutex_lock(&app.socket_mutex);
                    sll_push(&app.socket_list, accepted_socket);
                    pthread_mutex_unlock(&app.socket_mutex);
                }
            } else {
                receive_event(fd);
            }
        }
    }

    return NULL;
}
