#include <beegfs.h>
#include <bf.h>
#include <dbutils.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <external.h>
#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <utils.h>
#include <trace.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <bits/fcntl-linux.h>
#include <pthread.h>

const char ENTRIES_UPDATE[] =
        "UPDATE " ENTRIES
        " SET size = ?, blocks = ?, blksize = ?, inode = ?, nlink = ?, mode = ?, uid = ?, gid = ?, atime = ?, mtime = ?, ctime = ? WHERE name = ?;";

const char ENTRIES_DELETE[] = "DELETE FROM " ENTRIES " WHERE name = ?;";

#define MAX_EVENTS 1024
#define LISTEN_BACKLOG 128
#define NUM_WORKERS 12
#define MAX_TRANSMISSION 10000
#define SESSION_CLEAN_INTERVAL 10
#define SESSION_EXPIRE_INTERVAL 5

typedef struct app {
    int port;
    char *db_root;
    char *beegfs_root;

    int listen_fd; // socket fd for listening events from beegfs event-listener
    int epoll_fd; // listen connect request and event arrival
    sll_t socket_list;
    pthread_mutex_t socket_mutex;

    sll_t event_queue;
    pthread_mutex_t queue_mutex;

    sll_t db_sessions;
    pthread_rwlock_t session_rwlock;

    pthread_cond_t queue_cond;
    pthread_t workers[NUM_WORKERS];
} app_t;

enum session_type {
    SESSION_TYPE_NONE,
    SESSION_TYPE_INSERT,
    SESSION_TYPE_UPDATE,
    SESSION_TYPE_DELETE,
};

typedef struct db_session {
    sqlite3 *db;
    enum session_type type;
    const char *path;

    sqlite3_stmt *stmt;
    time_t last_commit;
    time_t last_access;
    int row_count;
    int summary_count;

    pthread_mutex_t mutex;
} db_session_t;

app_t app;
volatile sig_atomic_t stop_flag = 0;

struct db_session *new_db_session(const char *path, enum session_type type) {
    struct db_session *session = malloc(sizeof(struct db_session));
    session->path = path;
    session->type = type;
    session->db = opendb(path, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, 1, 0, NULL, NULL);
    session->row_count = 0;
    // if insert happens, summary_count++ and commit to summary table
    session->summary_count = 0;

    pthread_mutex_init(&session->mutex, NULL);
    time(&session->last_commit);
    time(&session->last_access);
    startdb(session->db);
    int rc;
    switch (type) {
        case SESSION_TYPE_INSERT:
            session->stmt = insertdbprep(session->db, ENTRIES_INSERT);
            break;
        case SESSION_TYPE_UPDATE:
            rc = sqlite3_prepare_v2(session->db, ENTRIES_UPDATE, -1, &session->stmt, 0);
            if (rc != SQLITE_OK) {
                perror("sqlite3_prepare_v2");
            }
            break;
        case SESSION_TYPE_DELETE:
            rc = sqlite3_prepare_v2(session->db, ENTRIES_DELETE, -1, &session->stmt, 0);
            if (rc != SQLITE_OK) {
                perror("sqlite3_prepare_v2");
            }
            break;
        default: ;
    }
    return session;
}

void add_to_session(sqlite3_stmt *stmt, struct stat *stat, const char *file_name, enum session_type type) {
    if (type == SESSION_TYPE_INSERT) {
        struct entry_data row_ed = {
            .statuso = *stat,
            .type = S_ISREG(stat->st_mode) ? 'f' : S_ISLNK(stat->st_mode) ? 'l' : '?',
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

        struct work *row = new_work_with_name("", 0, file_name, strlen(file_name));
        // FIXME: this is a hack, should set the correct values within new_work_with_name instead of set them here
        row->basename_len = strlen(file_name);
        row->name = file_name;
        row->name_len = strlen(file_name);
        insertdbgo(row, &row_ed, stmt);

        free(row);
    }

    if (type == SESSION_TYPE_UPDATE) {
        sqlite3_bind_int64(stmt, 1, stat->st_size);
        sqlite3_bind_int64(stmt, 2, stat->st_blocks);
        sqlite3_bind_int64(stmt, 3, stat->st_blksize);
        char *zino = sqlite3_mprintf("%" PRIu64, stat->st_ino);
        sqlite3_bind_text(stmt, 4, zino, -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 5, stat->st_nlink);
        sqlite3_bind_int64(stmt, 6, stat->st_mode);
        sqlite3_bind_int64(stmt, 7, stat->st_uid);
        sqlite3_bind_int64(stmt, 8, stat->st_gid);
        sqlite3_bind_int64(stmt, 9, stat->st_atime);
        sqlite3_bind_int64(stmt, 10, stat->st_mtime);
        sqlite3_bind_int64(stmt, 11, stat->st_ctime);
        sqlite3_bind_text(stmt, 12, file_name, -1,SQLITE_STATIC);

        int rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            fprintf(stderr, "sqlite3_step\n");
        }

        sqlite3_free(zino);
        sqlite3_reset(stmt);
    }

    if (type == SESSION_TYPE_DELETE) {
        sqlite3_bind_text(stmt, 1, file_name, -1, SQLITE_STATIC);
        int rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            fprintf(stderr, "deleted\n");
        }
        sqlite3_reset(stmt);
    }
}

void insert_sql_buffer(const char *file_name, struct stat *stat_buf, enum session_type type, const char *db_path) {
    // iterate session list to find the session with the same db path
    db_session_t *session = NULL;
    bool found_session = false;
    pthread_rwlock_rdlock(&app.session_rwlock);
    sll_loop(&app.db_sessions, session_item) {
        session = (struct db_session *) sll_node_data(session_item);
        if (strcmp(session->path, db_path) == 0) {
            found_session = true;
            break;
        }
    }
    pthread_rwlock_unlock(&app.session_rwlock);

    if (!found_session) {
        pthread_rwlock_wrlock(&app.session_rwlock);
        session = new_db_session(db_path, type);
        sll_push(&app.db_sessions, session);
        pthread_rwlock_unlock(&app.session_rwlock);
    } else {
        time(&session->last_access);
    }

    pthread_mutex_lock(&session->mutex);
    // check earlier session type matches new type, if not clean up the session stmt
    if (session->type != type) {
        stopdb(session->db);
        sqlite3_finalize(session->stmt);

        char sql[256];
        snprintf(sql, sizeof(sql), "UPDATE summary SET size = size + %d;", session->summary_count);
        int rc = sqlite3_exec(session->db, sql, NULL, NULL, NULL);
        if (rc != SQLITE_OK) {
            perror("sqlite3_exec");
        }
        session->summary_count = 0;

        switch (type) {
            case SESSION_TYPE_INSERT:
                session->stmt = insertdbprep(session->db, ENTRIES_INSERT);
                break;
            case SESSION_TYPE_UPDATE:
                rc = sqlite3_prepare_v2(session->db, ENTRIES_UPDATE, -1, &session->stmt, 0);
                if (rc != SQLITE_OK) {
                    perror("sqlite3_prepare_v2 SESSION_TYPE_UPDATE");
                }
                break;
            case SESSION_TYPE_DELETE:
                rc = sqlite3_prepare_v2(session->db, ENTRIES_DELETE, -1, &session->stmt, 0);
                if (rc != SQLITE_OK) {
                    perror("sqlite3_prepare_v2 SESSION_TYPE_DELETE");
                }
                printf("session type not match, change from %d to %d\n", session->type, type);
                break;
            default: ;
        }
        session->type = type;
        startdb(session->db);
    }

    // bind the values to the stmt
    add_to_session(session->stmt, stat_buf, file_name, type);

    session->row_count++;
    if (session->type == SESSION_TYPE_INSERT) {
        session->summary_count++;
    } else if (session->type == SESSION_TYPE_DELETE) {
        session->summary_count--;
    }

    // check if the session is too big, if so, commit the transaction
    if (session->row_count >= MAX_TRANSMISSION || difftime(time(NULL), session->last_commit) >=
        SESSION_EXPIRE_INTERVAL) {
        stopdb(session->db);
        startdb(session->db);
        char sql[256];
        snprintf(sql, sizeof(sql), "UPDATE summary SET size = size + %d;", session->summary_count);
        int rc = sqlite3_exec(session->db, sql, NULL, NULL, NULL);
        if (rc != SQLITE_OK) {
            perror("sqlite3_exec");
        }
        session->summary_count = 0;
        session->row_count = 0;
        time(&session->last_commit);
    }
    pthread_mutex_unlock(&session->mutex);
}

void enqueue_event(struct beegfs_event *event) {
    pthread_mutex_lock(&app.queue_mutex);
    sll_push(&app.event_queue, event);
    pthread_cond_signal(&app.queue_cond);
    pthread_mutex_unlock(&app.queue_mutex);
}

struct beegfs_event *dequeue_event() {
    struct timespec ts;
    struct beegfs_event *event = NULL;

    pthread_mutex_lock(&app.queue_mutex);
    while (!stop_flag && sll_get_size(&app.event_queue) == 0) {
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


static void process_attr_update(struct beegfs_event *event, const char *db_root, const char *beegfs_root) {
    char file_path[MAXPATH];
    char db_path[MAXPATH];
    char beegfs_path[MAXPATH];
    SNPRINTF(beegfs_path, sizeof(beegfs_path), "%s%s", beegfs_root, event->path);
    SNPRINTF(file_path, sizeof(file_path), "%s%s", db_root, event->path);
    struct stat st;
    /* path is directory */
    if (lstat(file_path, &st) == 0 && S_ISDIR(st.st_mode)) {
        fprintf(stderr, "not supported\n");
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
        if (lstat(beegfs_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            fprintf(stderr, "not supported\n");
        }

        /* remove basename from the path */
        char parent[MAXPATH];
        char name[MAXPATH];
        shortpath(file_path, parent, name);
        SNPRINTF(db_path, sizeof(db_path), "%s/" DBNAME, parent);
        insert_sql_buffer(name, &st, SESSION_TYPE_UPDATE, db_path);
    }
}

static void process_create(struct beegfs_event *event, const char *db_root, const char *beegfs_root) {
    char filePath[MAXPATH];
    char dbPath[MAXPATH];
    SNPRINTF(filePath, sizeof(filePath), "%s%s", db_root, event->path);
    struct stat st;
    /* path is directory */
    if (lstat(filePath, &st) == 0 && S_ISDIR(st.st_mode)) {
        fprintf(stderr, "not supported\n");
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
        /* remove basename from the path */
        char parent[MAXPATH];
        char name[MAXPATH];
        char beegfs_path[MAXPATH];
        SNPRINTF(beegfs_path, sizeof(beegfs_path), "%s%s", beegfs_root, event->path);
        shortpath(filePath, parent, name);
        SNPRINTF(dbPath, sizeof(dbPath), "%s/" DBNAME, parent);
        if (lstat(beegfs_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            fprintf(stderr, "not supported\n");
        }

        insert_sql_buffer(name, &st, SESSION_TYPE_INSERT, dbPath);
    }
}

static void process_unlink(struct beegfs_event *event, const char *db_root) {
    char filePath[MAXPATH];
    char dbPath[MAXPATH];
    SNPRINTF(filePath, sizeof(filePath), "%s%s", db_root, event->path);
    struct stat st;
    /* path is directory */
    if (lstat(filePath, &st) == 0 && S_ISDIR(st.st_mode)) {
        fprintf(stderr, "not supported\n");
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
        /* remove basename from the path */
        char parent[MAXPATH];
        char name[MAXPATH];
        shortpath(filePath, parent, name);
        SNPRINTF(dbPath, sizeof(dbPath), "%s/" DBNAME, parent);
        insert_sql_buffer(name, &st, SESSION_TYPE_DELETE, dbPath);
    }
}

void delete_directory_recursive(const char *path) {
    DIR *dir = opendir(path);
    if (!dir) {
        perror("opendir");
        return;
    }

    struct dirent *entry;
    char full_path[MAXPATH];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

        struct stat statbuf;
        if (stat(full_path, &statbuf) == 0) {
            if (S_ISDIR(statbuf.st_mode)) {
                delete_directory_recursive(full_path);
            } else {
                if (remove(full_path) != 0) {
                    perror("remove file");
                }
            }
        }
    }

    closedir(dir);

    if (rmdir(path) != 0) {
        perror("rmdir");
    }
}

static void process_rmdir(struct beegfs_event *event, const char *db_root, const char *beegfs_root) {
    char file_path[MAXPATH];
    char db_path[MAXPATH];
    char beegfs_path[MAXPATH];
    SNPRINTF(beegfs_path, sizeof(beegfs_path), "%s%s", beegfs_root, event->path);
    SNPRINTF(file_path, sizeof(file_path), "%s%s", db_root, event->path);
    fprintf(stderr, "process_rmdir %s\n", file_path);

    delete_directory_recursive(file_path);
}

static void process_mkdir(struct beegfs_event *event, const char *db_root, const char *beegfs_root) {
    char db_path[MAXPATH];
    SNPRINTF(db_path, sizeof(db_path), "%s%s", db_root, event->path);

    char beegfs_path[MAXPATH];
    SNPRINTF(beegfs_path, sizeof(beegfs_path), "%s%s", beegfs_root, event->path);


    struct stat st;
    lstat(beegfs_path, &st);
    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "not a directory\n");
        return;
    }

    int rc = mkdir(db_path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    if (rc != 0) {
        fprintf(stderr, "Failed to create directory \"%s\": %s\n", db_path, strerror(errno));
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

    char dbPath[MAXPATH];
    SNPRINTF(dbPath, sizeof(dbPath), "%s/%s", db_path, DBNAME);
    fprintf(stderr, "new db_path: %s\n", dbPath);
    sqlite3 *db = opendb(dbPath, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, 1, 0, create_dbdb_tables, NULL);
    if (db) {
        struct sum summary;
        zeroit(&summary);

        sll_t xattr_db_list;
        sll_init(&xattr_db_list);

        /* INSERT statement bindings into db.db */
        sqlite3_stmt *entries_res = insertdbprep(db, ENTRIES_INSERT); /* entries */
        sqlite3_stmt *xattrs_res = insertdbprep(db, XATTRS_PWD_INSERT); /* xattrs within db.db */
        sqlite3_stmt *xattr_files_res = insertdbprep(db, EXTERNAL_DBS_PWD_INSERT);
        /* per-user and per-group db file names */

        startdb(db);

        stopdb(db);
        /* write out per-user and per-group xattrs */
        sll_destroy(&xattr_db_list, destroy_xattr_db);

        /* write out the current directory's xattrs */
        insertdbgo_xattrs_avail(&row_ed, xattrs_res);

        /* write out data going into db.db */
        insertdbfin(xattr_files_res); /* per-user and per-group xattr db file names */
        insertdbfin(xattrs_res);
        insertdbfin(entries_res);

        xattrs_cleanup(&row_ed.xattrs);

        char parent[MAXPATH];
        char name[MAXPATH];
        shortpath(db_path, parent, name);
        struct work *row = new_work_with_name("", 0, name, strlen(name));
        row->basename_len = strlen(name);
        row->name = name;
        row->name_len = strlen(name);
        row->pinode = st.st_ino;
        insertsumdb(db, name, row, &row_ed, &summary);
        free(row);
        closedb(db); /* don't set to nullptr */
    }
}

static void process_rename(struct beegfs_event *event, const char *db_root, const char *beegfs_root) {
    char source_path[MAXPATH], dest_path[MAXPATH];
    char source_index_path[MAXPATH], dest_index_path[MAXPATH];
    SNPRINTF(source_index_path, sizeof(source_index_path), "%s%s", db_root, event->path);
    SNPRINTF(dest_index_path, sizeof(dest_index_path), "%s%s", db_root, event->targetPath);
    SNPRINTF(source_path, sizeof(source_path), "%s%s", beegfs_root, event->path);
    SNPRINTF(dest_path, sizeof(dest_path), "%s%s", beegfs_root, event->targetPath);
    fprintf(stderr, "rename event: %s -> %s\n", source_path, dest_path);

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
        fprintf(stdout, "source_index_path %s dest_index_path%s \n", source_index_path, dest_index_path);
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
            struct beegfs_event unlink_event = {
                .type = UNLINK,
            };
            strcpy(unlink_event.path, event->path);
            struct beegfs_event create_event = {
                .type = CREATE,
            };
            strcpy(create_event.path, event->targetPath);

            fprintf(stderr, "rename in different directory, %s %s %s, %s\n", unlink_event.path, create_event.path,
                    (&unlink_event)->path, (&create_event)->path);
            process_unlink(&unlink_event, db_root);
            process_create(&create_event, db_root, beegfs_root);
        }
    }
}

static void process_event(struct beegfs_event *event, const char *db_root, const char *beegfs_root) {
    if (event == NULL) {
        return;
    }
    switch (event->type) {
        // ignore FLUSH and READ events
        case FLUSH:
        case OPEN_READ:
        case OPEN_WRITE:
        case LAST_WRITER_CLOSED:
            break;
        // update file size and other attributes on TRUNCATE, SETATTR, and CLOSE_WRITE events
        case TRUNCATE:
        case SETATTR:
        case CLOSE_WRITE:
            process_attr_update(event, db_root, beegfs_root);
            break;
        // insert new file on CREATE, SYMLINK, HARDLINK, and MKNOD events
        case CREATE:
        case SYMLINK:
        case HARDLINK:
        case MKNOD:
            process_create(event, db_root, beegfs_root);
            break;
        case MKDIR:
            process_mkdir(event, db_root, beegfs_root);
            break;
        case RMDIR:
            process_rmdir(event, db_root, beegfs_root);
            break;
        case UNLINK:
            process_unlink(event, db_root);
            break;
        case RENAME:
            process_rename(event, db_root, beegfs_root);
            break;
        default:
            fprintf(stderr, "Unknown event type: %d\n", event->type);
    }
}

void signal_handler(int signum) {
    printf("Caught signal %d\n", signum);
    stop_flag = 1;
    pthread_mutex_lock(&app.queue_mutex);
    pthread_cond_broadcast(&app.queue_cond);
    pthread_mutex_unlock(&app.queue_mutex);
}

void set_nonblocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
}

ssize_t recv_all(int sock, char *buffer, size_t length) {
    ssize_t total_received = 0;
    ssize_t bytes_received;

    while (total_received < length) {
        if (stop_flag) {
            printf("Received stop signal, exiting recv_all()\n");
            return -1;
        }

        bytes_received = recv(sock, buffer + total_received, length - total_received, 0);

        if (bytes_received < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            perror("recv failed");
            return -1;
        }
        if (bytes_received == 0) return 0;

        total_received += bytes_received;
    }
    return total_received;
}

void handle_client(int client_fd) {
    char buffer[MAX_BUFFER_SIZE];

    while (1) {
        ssize_t bytes_received = recv(client_fd, buffer, 1024, 0);
        if (bytes_received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            perror("recv failed");
            close(client_fd);
            return;
        }
        if (bytes_received == 0) {
            printf("Client disconnected: %d\n", client_fd);
            epoll_ctl(app.epoll_fd, EPOLL_CTL_DEL, client_fd, NULL);
            close(client_fd);
            return;
        }

        struct beegfs_event *event = malloc(sizeof(struct beegfs_event));
        ReadErrorCode status = phase_body(buffer, 1024, event);
        if (status == Success) {
            print_beegfs_event(event);
            enqueue_event(event);
        } else {
            perror("Failed to parse message");
        }
    }
}

void *session_cleaner_func(void *arg) {
    while (!stop_flag) {
        if (sleep(SESSION_CLEAN_INTERVAL) != 0) {
            perror("Sleep interrupted\n");
            break; // Exit the loop if sleep was interrupted
        }

        sll_t expired_sessions, active_sessions;
        sll_init(&expired_sessions);
        sll_init(&active_sessions);

        pthread_rwlock_wrlock(&app.session_rwlock);
        // Iterate over all sessions and close them
        db_session_t *session = sll_pop(&app.db_sessions);
        while (session) {
            time_t current_time = time(NULL);
            if (difftime(current_time, session->last_access) > SESSION_CLEAN_INTERVAL) {
                // move expired session to expired_sessions
                sll_push(&expired_sessions, session);
            } else {
                sll_push(&active_sessions, session);
            }

            // Pop next session
            session = sll_pop(&app.db_sessions);
        }

        // switch the list
        session = sll_pop(&active_sessions);
        while (session) {
            sll_push(&app.db_sessions, session);
            session = sll_pop(&active_sessions);
        }

        pthread_rwlock_unlock(&app.session_rwlock);

        // close the expired sessions
        session = sll_pop(&expired_sessions);
        while (session) {
            printf("closing session %s, %d\n", session->path, session->type);

            // Stop and close the database
            if (session->row_count > 0) {
                char sql[256];
                snprintf(sql, sizeof(sql), "UPDATE summary SET size = size + %d;", session->summary_count);
                int rc = sqlite3_exec(session->db, sql, NULL, NULL, NULL);
                if (rc != SQLITE_OK) {
                    perror("sqlite3_exec");
                }
            }
            sqlite3_finalize(session->stmt);
            stopdb(session->db);
            closedb(session->db);

            // Destroy mutex and free memory
            pthread_mutex_destroy(&session->mutex);
            free(session);
            session = sll_pop(&expired_sessions);
        }

        sll_destroy(&expired_sessions, NULL);
        sll_destroy(&active_sessions, NULL);
    }

    printf("Session cleaner stopped.\n");
    return NULL;
}


void *epoll_thread_func(void *arg) {
    struct epoll_event events[MAX_EVENTS];

    while (!stop_flag) {
        int num_fds = epoll_wait(app.epoll_fd, events, MAX_EVENTS, 5000);
        if (num_fds < 0 && errno != EINTR) {
            perror("epoll_wait failed");
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
                        perror("malloc failed");
                        continue;
                    }

                    *accepted_socket = accept(app.listen_fd, (struct sockaddr *) &client_addr, &client_addr_len);
                    if (*accepted_socket < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break;
                        }
                        perror("accept failed 1");
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
                handle_client(fd);
            }
        }
    }

    return NULL;
}

int init_server() {
    struct sockaddr_in server_addr;

    app.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (app.listen_fd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    int opt = 1;
    setsockopt(app.listen_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    set_nonblocking(app.listen_fd);

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(app.port);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(app.listen_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("Binding failed");
        close(app.listen_fd);
        return -1;
    }

    if (listen(app.listen_fd, LISTEN_BACKLOG) < 0) {
        perror("Listen failed");
        close(app.listen_fd);
        return -1;
    }

    app.epoll_fd = epoll_create1(0);
    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = app.listen_fd;
    epoll_ctl(app.epoll_fd, EPOLL_CTL_ADD, app.listen_fd, &event);

    return 0;
}

void *worker_thread_func(void *arg) {
    pthread_t tid = pthread_self();
    printf("[worker %lu] started\n", (unsigned long)tid);

    while (1) {
        struct beegfs_event *event = dequeue_event();

        if (!event) {
            if (stop_flag) break;  // graceful shutdown
            continue;              // spurious wake-up
        }

        process_event(event, app.db_root, app.beegfs_root);
        free(event);
    }

    printf("[worker %lu] exiting\n", (unsigned long)tid);
    return NULL;
}

int app_init(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <port> <GUFI index root path> <BeeGFS mountpoint>\n", argv[0]);
        return 1;
    }

    app.port = atoi(argv[1]);
    app.db_root = argv[2];
    app.beegfs_root = argv[3];

    sll_init(&app.event_queue);
    sll_init(&app.db_sessions);
    sll_init(&app.socket_list);
    pthread_mutex_init(&app.socket_mutex,NULL);

    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    pthread_mutex_init(&app.queue_mutex, NULL);
    pthread_cond_init(&app.queue_cond, NULL);

    pthread_rwlock_init(&app.session_rwlock, NULL);

    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_create(&app.workers[i], NULL, worker_thread_func, NULL);
    }

    return 0;
}

void app_uinit() {
    close(app.listen_fd);
    close(app.epoll_fd);

    int *socket_fd = sll_pop(&app.socket_list);
    while (socket_fd) {
        // close accepted socket from socket list
        close(*socket_fd);
        free(socket_fd);
        socket_fd = sll_pop(&app.socket_list);
    }

    sll_destroy(&app.socket_list, free);
    pthread_mutex_destroy(&app.socket_mutex);

    pthread_mutex_lock(&app.queue_mutex);
    struct beegfs_event *event = sll_pop(&app.event_queue);
    while (event) {
        perror("still have events in the queue");
        free(event);
        event = sll_pop(&app.event_queue);
    }
    pthread_mutex_unlock(&app.queue_mutex);

    pthread_cond_destroy(&app.queue_cond);
    sll_destroy(&app.event_queue, free);
    // must destroy mutex after cond destroyed or pthread_cond_destroy will pend forever
    pthread_mutex_destroy(&app.queue_mutex);

    pthread_rwlock_wrlock(&app.session_rwlock);
    // iterate over all sessions and close them
    db_session_t *session = sll_pop(&app.db_sessions);
    while (session) {
        printf("closing session %s, %d\n", session->path, session->type);

        // Stop and close the database
        if (session->row_count > 0) {
            char sql[256];
            snprintf(sql, sizeof(sql), "UPDATE summary SET size = size + %d;", session->summary_count);
            int rc = sqlite3_exec(session->db, sql, NULL, NULL, NULL);
            if (rc != SQLITE_OK) {
                perror("sqlite3_exec");
            }
        }
        sqlite3_finalize(session->stmt);
        stopdb(session->db);
        closedb(session->db);

        // Destroy mutex and free memory
        pthread_mutex_destroy(&session->mutex);
        free(session);
        session = sll_pop(&app.db_sessions);
    }
    sll_destroy(&app.db_sessions, free);
    pthread_rwlock_unlock(&app.session_rwlock);
    pthread_rwlock_destroy(&app.session_rwlock);
}

int main(int argc, char *argv[]) {
    if (app_init(argc, argv) != 0) {
        return 1;
    }

    if (init_server() < 0) {
        return 1;
    }

    pthread_t epoll_thread;
    pthread_create(&epoll_thread, NULL, epoll_thread_func, NULL);
    pthread_t session_cleaner;
    int rc = pthread_create(&session_cleaner, NULL, session_cleaner_func, NULL);
    if (rc != 0) {
        perror("Error creating thread");
        exit(1);
    }

    pthread_join(epoll_thread, NULL);
    pthread_join(session_cleaner, NULL);

    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(app.workers[i], NULL);
    }

    printf("All threads joined.\n");

    app_uinit();
    return 0;
}
