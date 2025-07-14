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
#include "utils.h"

#define MAX_FLUSH_PER_ROUND 100000

static event_handler_t handler_table[EVENT_TYPE_MAX] = {
    [CREATE] = cache_event,
    [SYMLINK] = cache_event,
    [HARDLINK] = cache_event,
    [MKNOD] = cache_event,
    [TRUNCATE] = cache_event,
    [SETATTR] = cache_event,
    [CLOSE_WRITE] = cache_event,
    [UNLINK] = cache_event,

    [MKDIR] = create_dir,
    [RMDIR] = remove_dir,
    [RENAME] = rename_event,

    [FLUSH] = NULL,
    [OPEN_READ] = NULL,
    [OPEN_WRITE] = NULL,
    [OPEN_READ_WRITE] = NULL,
    [LAST_WRITER_CLOSED] = NULL,
    [RECORD] = NULL,
};

dir_index_cache_t *dir_cache_init(const char *entry_id, const char *index_path) {
    dir_index_cache_t *item = calloc(1, sizeof(dir_index_cache_t));
    snprintf(item->entry_id, sizeof(item->entry_id), "%s", entry_id);
    pthread_mutex_init(&item->mutex, NULL);
    time(&item->last_access);
    time(&item->last_commit);
    item->index_path = strdup(index_path);
    item->ref_count = 0;
    item->row_count = 0;
    item->summary_count = 0;

    char db_path[MAXPATH];
    SNPRINTF(db_path, sizeof(db_path), "%s/" DBNAME, item->index_path);
    item->db = opendb(db_path, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, 1, 0, NULL, NULL);

    int rc = sqlite3_prepare_v2(item->db, ENTRIES_INSERT, -1, &item->stmt_insert,NULL);
    if (rc != SQLITE_OK) {
        LOG_ERR("sqlite3_prepare_v2 insert entry failed: %s, index_path %s, db_path %s", sqlite3_errmsg(item->db),
                item->index_path, db_path);
    }

    rc = sqlite3_prepare_v2(item->db, ENTRIES_UPDATE, -1, &item->stmt_update, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERR("sqlite3_prepare_v2 update entry failed: %s", sqlite3_errmsg(item->db));
    }
    rc = sqlite3_prepare_v2(item->db, ENTRIES_DELETE, -1, &item->stmt_delete, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERR("sqlite3_prepare_v2 delete entry failed: %s", sqlite3_errmsg(item->db));
    }
    item->file_cache = NULL;

    return item;
}

void file_cache_uninit(file_index_cache_t *item) {
    if (item->file_pattern) free(item->file_pattern);

    if (item->file_path) free((void *) item->file_path);
}

void dir_cache_uinit(dir_index_cache_t *item) {
    stopdb(item->db);
    if (item->stmt_insert) sqlite3_finalize(item->stmt_insert);
    if (item->stmt_update) sqlite3_finalize(item->stmt_update);
    if (item->stmt_delete) sqlite3_finalize(item->stmt_delete);
    if (item->db) sqlite3_close(item->db);
    if (item->index_path) free((char *) item->index_path);
    pthread_mutex_destroy(&item->mutex);

    file_index_cache_t *f, *tmp;
    HASH_ITER(hh, item->file_cache, f, tmp) {
        HASH_DEL(item->file_cache, f);
        file_cache_uninit(f);
        free(f);
    }
}

dir_index_cache_t *reference_dir(const char entryId[256], const char *event_path, bool create) {
    dir_index_cache_t *found = NULL;
    pthread_mutex_lock(&app.index_cache_mutex);
    HASH_FIND_STR(app.index_cache, entryId, found);
    if (found == NULL && create) {
        char db_path[MAXPATH];
        SNPRINTF(db_path, sizeof(db_path), "%s%s", app.config.index_root, event_path);
        char parent[MAXPATH];
        char name[MAXPATH];
        shortpath(db_path, parent, name);
        found = dir_cache_init(entryId, parent);
        HASH_ADD_STR(app.index_cache, entry_id, found);
    }
    if (found) {
        __sync_fetch_and_add(&found->ref_count, 1);
    }
    pthread_mutex_unlock(&app.index_cache_mutex);

    return found;
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

void delete_cache_dir(const char entryId[256]) {
    pthread_mutex_lock(&app.index_cache_mutex);
    dir_index_cache_t *entry = NULL;
    HASH_FIND_STR(app.index_cache, entryId, entry);
    if (entry) {
        HASH_DEL(app.index_cache, entry);
        pthread_mutex_unlock(&app.index_cache_mutex);
        dir_cache_uinit(entry);
        free(entry);
        return;
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
        free(entry);
    }
    pthread_mutex_unlock(&app.index_cache_mutex);
}

int update_cache_data_flag(int old_flag, fs_event_type event_type) {
    if (event_type == CREATE || event_type == SYMLINK || event_type == HARDLINK || event_type == MKNOD) {
        return DATA_FIELD_INSERT;
    }
    if (event_type == SETATTR || event_type == CLOSE_WRITE || event_type == TRUNCATE) {
        if (old_flag & DATA_FIELD_INSERT) {
            return old_flag;
        }
        return old_flag | DATA_FIELD_STAT;
    }
    if (event_type == UNLINK) {
        return DATA_FIELD_DELETE;
    }
    return old_flag;
}


void cache_event(struct fs_event *event) {
    dir_index_cache_t *parent = reference_dir(event->parentEntryId, event->path, true);

    // check directory cached event size, flush before cache if too large
    pthread_mutex_lock(&parent->mutex);
    uint64_t cache_size = HASH_COUNT(parent->file_cache);
    if (cache_size >= MAX_FLUSH_PER_ROUND)
    {
        LOG_DBG("flushing cache dir %s, cache size %lld", parent->entry_id, cache_size);
        pthread_mutex_unlock(&parent->mutex);
        dir_cache_flush(parent);
        pthread_mutex_lock(&parent->mutex);
    }

    // check file cache exist
    file_index_cache_t *found = NULL;
    HASH_FIND_STR(parent->file_cache, event->entryId, found);
    if (found == NULL) {
        found = calloc(1, sizeof(file_index_cache_t));

        char tmp[MAXPATH];
        shortpath(event->path, tmp, found->file_name);
        snprintf(found->entry_id, sizeof(found->entry_id), event->entryId);
        snprintf(found->parent_id, sizeof(found->parent_id), event->parentEntryId);
        char file_path[MAXPATH];
        SNPRINTF(file_path, sizeof(file_path), "%s%s", app.config.mount_point, event->path);
        found->file_path = strdup(file_path);
        found->data_field_flag = update_cache_data_flag(0, event->type);

        pthread_mutex_init(&found->file_lock, NULL);

        HASH_ADD_STR(parent->file_cache, entry_id, found);
    } else {
        pthread_mutex_lock(&found->file_lock);
        found->data_field_flag = update_cache_data_flag(found->data_field_flag, event->type);
        pthread_mutex_unlock(&found->file_lock);
    }
    pthread_mutex_unlock(&parent->mutex);

    release_cached_dir(event->parentEntryId);
}

void update_file_stat(struct file_index_cache *file) {
    struct stat stat;

    int rc = lstat(file->file_path, &stat);
    if (rc != 0) {
        LOG_ERR("lstat %s failed: %s", strerror(errno), file->file_path);
        return;
    }
    file->ed.type = S_ISREG(stat.st_mode) ? 'f' : S_ISLNK(stat.st_mode) ? 'l' : '?';
    file->ed.linkname[0] = '\0';
    file->ed.xattrs;
    file->ed.crtime = 0;
    file->ed.ossint1 = 0;
    file->ed.ossint2 = 0;
    file->ed.ossint3 = 0;
    file->ed.ossint4 = 0;
    file->ed.osstext1[0] = '\0';
    file->ed.osstext2[0] = '\0';
    file->ed.statuso = stat;
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
        LOG_ERR("Failed to create index directory \"%s\", %s", index_dir, strerror(errno));
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
    delete_cache_dir(event->entryId);

    char index_path[MAXPATH];
    SNPRINTF(index_path, sizeof(index_path), "%s%s", app.config.index_root, event->path);

    LOG_INFO("Removing directory %s", index_path);
    rmdir_iterative(index_path);
}

void rename_event(struct fs_event *event) {
    char source_path[MAXPATH], dest_path[MAXPATH];
    char source_index_path[MAXPATH], dest_index_path[MAXPATH];
    SNPRINTF(source_index_path, sizeof(source_index_path), "%s%s", app.config.index_root, event->path);
    SNPRINTF(dest_index_path, sizeof(dest_index_path), "%s%s", app.config.index_root, event->targetPath);
    SNPRINTF(source_path, sizeof(source_path), "%s%s", app.config.mount_point, event->path);
    SNPRINTF(dest_path, sizeof(dest_path), "%s%s", app.config.mount_point, event->targetPath);
    LOG_DBG("rename event: %s -> %s\n", source_path, dest_path);

    struct stat st;
    int rc = lstat(dest_path, &st);
    if (rc != 0) {
        fprintf(stderr, "Failed to stat \"%s\": %s\n", dest_path, strerror(errno));
        return;
    }

    char old_parent[MAXPATH], new_parent[MAXPATH];
    char new_name[MAXPATH], old_name[MAXPATH];
    char old_db_prefix[MAXPATH], new_db_prefix[MAXPATH];
    char old_db_path[MAXPATH], new_db_path[MAXPATH];
    shortpath(dest_path, old_parent, new_name);
    shortpath(source_path, new_parent, old_name);
    shortpath(source_index_path, old_db_prefix, old_name);
    shortpath(dest_index_path, new_db_prefix, new_name);
    SNPRINTF(old_db_path, sizeof(old_db_path), "%s/%s", old_db_prefix, DBNAME);
    SNPRINTF(new_db_path, sizeof(new_db_path), "%s/%s", new_db_prefix, DBNAME);
    bool same_parent = strcmp(old_parent, new_parent) == 0;

    /*
     * move directory from source path to dest path
     * 1. update related summary table for their parent directory.
     * 2. do directory movement in index dir too
     */
    if (S_ISDIR(st.st_mode)) {
        rc = rename(source_index_path, dest_index_path);
        if (rc != 0) {
            fprintf(stderr, "failed to do rename in index directory, error: rc %d\n", rc);
        }
    }
    /*
     * rename file from source path to dest path
     * 1. in same directory, just rename the name in database;
     * 2. in different directory, delete the source path in database and insert the dest path in database.
     */
    else {
        if (same_parent) {
            printf("rename in the same directory\n");
            sqlite3 *db = opendb(new_db_path, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, 1, 0, NULL, NULL);
            const char *sql = "UPDATE entries SET name = ? WHERE name = ?;";
            sqlite3_stmt *stmt;

            rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
            if (rc != SQLITE_OK) {
                fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
                return;
            }

            // Bind parameters
            sqlite3_bind_text(stmt, 1, new_name, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, old_name, -1, SQLITE_STATIC);

            // Execute the statement
            rc = sqlite3_step(stmt);
            if (rc != SQLITE_DONE) {
                fprintf(stderr, "Failed to execute update: %s\n", sqlite3_errmsg(db));
            }

            // Finalize the statement
            sqlite3_finalize(stmt);
            sqlite3_close(db);
        }
        /*
         * 1. do unlink for old database
         * 2. do create for new database
         */
        else {
            struct fs_event *unlink = malloc(sizeof(struct fs_event));

            unlink->type = UNLINK;
            strcpy(unlink->path, event->path);
            strcpy(unlink->entryId, event->entryId);
            strcpy(unlink->parentEntryId, event->parentEntryId);
            cache_event(unlink);
            free(unlink);

            struct fs_event *create = malloc(sizeof(struct fs_event));
            create->type = CREATE;
            strcpy(create->path, event->targetPath);
            strcpy(create->entryId, event->entryId);
            strcpy(create->parentEntryId, event->targetParentId);
            cache_event(create);
            free(create);
        }
    }
}

void process_event(struct fs_event *event) {
    if (!event || event->type <= 0 || event->type >= EVENT_TYPE_MAX) {
        unsigned event_type = event ? event->type : 0;
        LOG_ERR("event type %d not supported", event_type);
        return;
    }

    const char *type = event_type_string(event);
    event_handler_t handler = handler_table[event->type];
    if (handler) {
        handler(event);
    } else {
        LOG_DBG("Ignored or unknown event: %d (%s)\n", event->type, type);
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

            // TODO: use mempool instead of malloc every time
            struct fs_event *event = malloc(sizeof(struct fs_event));
            if (!event) {
                LOG_ERR("malloc failed");
                break;
            }

            ReadErrorCode status = packet_to_event(recv_buffer + offset + PACKET_HEADER_LEN, payload_len, event);

            if (status == Success) {
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
    size_t flush_count = 0;
    file_index_cache_t *item, *tmp;

NEXT_ROUND:
    HASH_ITER(hh, dir->file_cache, item, tmp) {
        if (item->data_field_flag & DATA_FIELD_INSERT) {
            update_file_stat(item);
            item->file_pattern = get_file_pattern(item->file_path, item->entry_id, item->parent_id);
            int rc = insertdbgo_index(item, dir->stmt_insert);
            if (rc != SQLITE_OK) {
                LOG_ERR("insert failed: %s (rc=%d)", item->file_path, rc);
            }
        } else if (item->data_field_flag & DATA_FIELD_STAT) {
            update_file_stat(item);
            update_attr_index(item, dir->stmt_update);
        } else if (item->data_field_flag & DATA_FIELD_DELETE) {
            delete_index(item, dir->stmt_delete);
        }
        HASH_DEL(dir->file_cache, item);
        file_cache_uninit(item);
        free(item);

        flush_count++;
        if (flush_count == MAX_FLUSH_PER_ROUND) {
            stopdb(dir->db);
            startdb(dir->db);
            flush_count = 0;
            goto NEXT_ROUND;
        }
    }
    stopdb(dir->db);
    time(&dir->last_commit);
    pthread_mutex_unlock(&dir->mutex);
}

void *event_flusher_run(void *arg) {
    while (!app_stop) {
        pthread_mutex_lock(&app.index_cache_mutex);
        dir_index_cache_t *entry, *tmp;
        dir_index_cache_t *need_flush = NULL;
        time_t current_time = time(NULL);
        HASH_ITER(hh, app.index_cache, entry, tmp) {
            if (difftime(current_time, entry->last_access) > 5) {
                HASH_ADD_STR(need_flush, entry_id, entry);
            }
        }
        pthread_mutex_unlock(&app.index_cache_mutex);

        HASH_ITER(hh, need_flush, entry, tmp) {
            dir_cache_flush(entry);
            if (entry->ref_count > 0) {
                HASH_DEL(need_flush, entry);
            }
        }

        if (need_flush) {
            pthread_mutex_lock(&app.index_cache_mutex);
            HASH_ITER(hh, need_flush, entry, tmp) {
                HASH_DEL(need_flush, entry);

                if (entry->ref_count == 0) {
                    HASH_DEL(app.index_cache, entry);
                    dir_cache_uinit(entry);
                    free(entry);
                }
            }
            pthread_mutex_unlock(&app.index_cache_mutex);
        }

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
