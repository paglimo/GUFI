#include <beegfs.h>
#include <bf.h>
#include <dbutils.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <external.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <utils.h>
#include <grp.h>
#include <pwd.h>
#include <trace.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <stdbool.h>

static void process_attr_update(beegfs_event *event, const char *db_root, const char *beegfs_root) {
	char file_path[MAXPATH];
	char db_path[MAXPATH];
	char beegfs_path[MAXPATH];
	SNPRINTF(beegfs_path, sizeof(beegfs_path), "%s%s", beegfs_root, event->path);
	SNPRINTF(file_path, sizeof(file_path), "%s%s", db_root, event->path);
	struct stat st;
	/* path is directory */
	if ((lstat(file_path, &st) == 0) && S_ISDIR(st.st_mode)) {
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
		if ((lstat(beegfs_path, &st) == 0) && S_ISDIR(st.st_mode)) {
			fprintf(stderr, "not supported\n");
		}

		/* remove basename from the path */
		char parent[MAXPATH];
		char name[MAXPATH];
		shortpath(file_path, parent, name);
		SNPRINTF(db_path, sizeof(db_path), "%s/" DBNAME, parent);
		sqlite3 *db = opendb(db_path, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, 1, 0, NULL, NULL);

		sqlite3_stmt *stmt;
		const char *sql =
				"UPDATE entries SET size = ?, blocks = ?, blksize = ?, inode = ?, nlink = ?, mode = ?, uid = ?, gid = ?, atime = ?, mtime = ?, ctime = ? WHERE name = ?;";
		int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
		if (rc != SQLITE_OK) {
			fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
		}
		sqlite3_bind_int64(stmt, 1, st.st_size);
		sqlite3_bind_int64(stmt, 2, st.st_blocks);
		sqlite3_bind_int64(stmt, 3, st.st_blksize);
		char *zino = sqlite3_mprintf("%" PRIu64, st.st_ino);
		sqlite3_bind_text(stmt, 4, zino, -1, SQLITE_STATIC);
		sqlite3_bind_int64(stmt, 5, st.st_nlink);
		sqlite3_bind_int64(stmt, 6, st.st_mode);
		sqlite3_bind_int64(stmt, 7, st.st_uid);
		sqlite3_bind_int64(stmt, 8, st.st_gid);
		sqlite3_bind_int64(stmt, 9, st.st_atime);
		sqlite3_bind_int64(stmt, 10, st.st_mtime);
		sqlite3_bind_int64(stmt, 11, st.st_ctime);
		sqlite3_bind_text(stmt, 12, name, -1,SQLITE_STATIC);

		rc = sqlite3_step(stmt);
		if (rc != SQLITE_DONE) {
			fprintf(stderr, "Failed to update user name: %s\n", sqlite3_errmsg(db));
		} else {
			printf("User name updated successfully, st.st_ino %llu, %s\n", st.st_ino, zino);
		}

		sqlite3_free(zino);
		sqlite3_finalize(stmt);
		closedb(db);
	}
}

static void process_create(beegfs_event *event, const char *db_root, const char *beegfs_root) {
	printf("Create event\n");
	char filePath[MAXPATH];
	char dbPath[MAXPATH];
	SNPRINTF(filePath, sizeof(filePath), "%s%s", db_root, event->path);
	struct stat st;
	/* path is directory */
	if ((lstat(filePath, &st) == 0) && S_ISDIR(st.st_mode)) {
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
		fprintf(stdout, "should process_create %s to database: %s, parent %s\n", filePath, dbPath, parent);

		sqlite3 *db = opendb(dbPath, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, 1, 0, NULL, NULL);

		sqlite3_stmt *stmt_summary;
		const char *sql_summary = "UPDATE summary SET size = size + 1;";
		int rc = sqlite3_prepare_v2(db, sql_summary, -1, &stmt_summary, 0);
		if (rc != SQLITE_OK) {
			fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
		}

		rc = sqlite3_step(stmt_summary);
		if (rc != SQLITE_DONE) {
			fprintf(stderr, "Execution failed: %s\n", sqlite3_errmsg(db));
		} else {
			printf("Updated size in summary table successfully.\n");
		}
		sqlite3_finalize(stmt_summary);

		if ((lstat(beegfs_path, &st) == 0) && S_ISDIR(st.st_mode)) {
			fprintf(stderr, "not supported\n");
		}

		/* INSERT statement bindings into db.db */
		// TODO: only insert entries table for now
		sqlite3_stmt *entries_res = insertdbprep(db, ENTRIES_INSERT); /* entries */
		//sqlite3_stmt *xattrs_res      = insertdbprep(db, XATTRS_PWD_INSERT);        /* xattrs within db.db */
		//sqlite3_stmt *xattr_files_res = insertdbprep(db, EXTERNAL_DBS_PWD_INSERT);  /* per-user and per-group db file names */

		startdb(db);


		struct stat ds = {
			.st_ino = st.st_ino,
			.st_nlink = st.st_nlink,
			.st_uid = st.st_uid,
			.st_gid = st.st_gid,
			.st_size = st.st_size,
			.st_blksize = st.st_blksize,
			.st_blocks = st.st_blocks,
			.st_atime = st.st_atime,
			.st_mtim = st.st_mtime,
			.st_ctime = st.st_ctime,
			.st_mode = st.st_mode,
		};

		struct entry_data row_ed = {
			.statuso = ds,
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

		if (S_ISREG(st.st_mode)) {
			row_ed.type = 'f';
		}
		if (S_ISLNK(st.st_mode)) {
			row_ed.type = 'l';
		}

		struct work *row = new_work_with_name("", 0, name, strlen(name));
		// FIXME: this is a hack, should set the correct values within new_work_with_name instead of set them here
		row->basename_len = strlen(name);
		row->name = name;
		row->name_len = strlen(name);
		insertdbgo(row, &row_ed, entries_res);
		free(row);
		stopdb(db);
		closedb(db); /* don't set to nullptr */
	}
}

static void process_unlink(beegfs_event *event, const char *db_root) {
	printf("process_unlink event\n");
	char filePath[MAXPATH];
	char dbPath[MAXPATH];
	SNPRINTF(filePath, sizeof(filePath), "%s%s", db_root, event->path);
	struct stat st;
	/* path is directory */
	if ((lstat(filePath, &st) == 0) && S_ISDIR(st.st_mode)) {
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
		fprintf(stdout, "should process_unlink %s to database: %s, parent %s\n", filePath, dbPath, parent);

		sqlite3 *db = opendb(dbPath, SQLITE_OPEN_READWRITE, 0, 0, NULL, NULL);

		sqlite3_stmt *stmt;
		const char *sql = "DELETE FROM ENTRIES WHERE name = ?;";

		int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
		if (rc != SQLITE_OK) {
			fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
			return;
		}

		sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
		rc = sqlite3_step(stmt);
		if (rc != SQLITE_DONE) {
			fprintf(stderr, "Execution failed: %s\n", sqlite3_errmsg(db));
		} else {
			printf("Deleted file with name: %s\n", name);
		}

		sqlite3_finalize(stmt);

		sqlite3_stmt *stmt_summary;
		const char *sql_summary = "UPDATE summary SET size = size - 1;";
		rc = sqlite3_prepare_v2(db, sql_summary, -1, &stmt_summary, 0);
		if (rc != SQLITE_OK) {
			fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
		}

		rc = sqlite3_step(stmt_summary);
		if (rc != SQLITE_DONE) {
			fprintf(stderr, "Execution failed: %s\n", sqlite3_errmsg(db));
		} else {
			printf("Updated size in summary table successfully.\n");
		}

		sqlite3_finalize(stmt_summary);
		closedb(db); /* don't set to nullptr */
	}
}

static void process_rmdir(beegfs_event *event, const char *db_root, const char *beegfs_root) {
	char file_path[MAXPATH];
	char db_path[MAXPATH];
	char beegfs_path[MAXPATH];
	SNPRINTF(beegfs_path, sizeof(beegfs_path), "%s%s", beegfs_root, event->path);
	SNPRINTF(file_path, sizeof(file_path), "%s%s", db_root, event->path);
	fprintf(stderr, "process_rmdir %s\n", file_path);

	DIR *dir = opendir(file_path);
	if (!dir) {
		perror("Failed to open directory");
		return;
	}

	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		// Skip the current directory and parent directory entries
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
			continue;

		if (strcmp(entry->d_name, "db.db") != 0) {
			fprintf(stderr, "directory is not empty\n");
			break;
		}

		char fullpath[PATH_MAX];
		snprintf(fullpath, sizeof(fullpath), "%s/%s", file_path, entry->d_name);
		if (unlink(fullpath) == -1) {
			fprintf(stderr, "Failed to remove file \"%s\": %s\n", fullpath, strerror(errno));
		} else {
			printf("Removed file: %s\n", fullpath);
		}
	}
	closedir(dir);

	if (rmdir(file_path) == -1) {
		fprintf(stderr, "Failed to remove directory \"%s\": %s\n", file_path, strerror(errno));
		// If the directory is not empty or an error occurs, it is kept
	} else {
		printf("Removed empty directory: %s\n", file_path);
	}
}

static void process_mkdir(beegfs_event *event, const char *db_root, const char *beegfs_root) {
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

	int rc = mkdir(db_path, 0777);
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
		closedb(db); /* don't set to nullptr */
	}
}

static void process_rename(beegfs_event *event, const char *db_root, const char *beegfs_root) {
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
			} else {
				printf("Update successful: %s -> %s\n", old_name, new_name);
			}

			// Finalize the statement
			sqlite3_finalize(stmt);
			sqlite3_close(new_db_path);
		}
		/*
		 * 1. do unlink for old database
		 * 2. do create for new database
		 */
		else {
			beegfs_event unlink_event = {
				.type = UNLINK,
			};
			strcpy(unlink_event.path, event->path);
			beegfs_event create_event = {
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

static void process_event(beegfs_event *event, const char *db_root, const char *beegfs_root) {
	switch (event->type) {
		// ignore FLUSH and READ events
		case FLUSH:
		case READ:
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


int reveive_event(const char *address, int port, const char *db_root, const char *beegfs_root) {
	fprintf(stdout, "Creating GUFI Index %s with %d threads\n", db_root, 1);
	int server_fd, client_fd;
	struct sockaddr_in server_addr, client_addr;
	socklen_t client_addr_len = sizeof(client_addr);
	char buffer[MAX_BUFFER_SIZE] = {0};

	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Socket creation failed");
		return 0;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = inet_addr(address);

	int opt = 1;
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
		perror("Unable to set socket options");
		close(server_fd);
		return 0;
	}

	if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
		perror("Binding failed");
		close(server_fd);
		return 0;
	}

	if (listen(server_fd, 3) < 0) {
		perror("Listen failed");
		close(server_fd);
		return 0;
	}

	printf("Server is listening on %s:%d...\n", address, port);

	if ((client_fd = accept(server_fd, (struct sockaddr *) &client_addr, &client_addr_len)) < 0) {
		perror("Failed to accept connection");
		close(server_fd);
		return 0;
	}

	printf("Connection established with client\n");

	ssize_t bytes_received;
	while ((bytes_received = recv(client_fd, buffer, MAX_BUFFER_SIZE, 0)) > 0) {
		beegfs_event event;
		ReadErrorCode status = raw_to_packet(buffer, bytes_received, &event);

		if (status == Success) {
			process_event(&event, db_root, beegfs_root);
		} else {
			printf("Packet parsing error: %d\n", status);
		}

		memset(buffer, 0, MAX_BUFFER_SIZE);
	}

	if (bytes_received < 0) {
		perror("Failed to receive message");
	} else {
		printf("Client disconnected\n");
	}

	close(client_fd);
	close(server_fd);
	return 1;
}

int main(int argc, char *argv[]) {
	if (argc < 4) {
		fprintf(stderr, "Usage: %s <port> <GUFI index root path> <BeeGFS mountpoint>\n", argv[0]);
		return 1;
	}
	int port = argv[1] ? atoi(argv[1]) : 6000;
	const char *path = argv[2] ? argv[2] : "";
	const char *beegfs_root = argv[3] ? argv[3] : "";

	reveive_event("0.0.0.0", port, path, beegfs_root);
	return 0;
}
