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
#include <sys/time.h>

static const char DEFAULT_FORMAT[] = "  File: %N\n"
		"  Size: %-15s Blocks: %-10b IO Block: %-6o %F\n"
		"Device: %-4Dh/%-5dd    Inode: %-11i Links: %h\n"
		"Access: (0%a/%A)  Uid: (%5u/%8U)   Gid: (%5g/%8G)\n"
		"Context: %C\n"
		"Access: %x\n"
		"Modify: %y\n"
		"Change: %z\n"
		" Birth: %w\n";

struct callback_args {
	size_t found;
	const char *path;
	FILE *out;
	const char *format;
};

static int print_callback(void *args, int count, char **data, char **columns) {
	(void) count;
	(void) columns;

	struct callback_args *ca = (struct callback_args *) args;
	ca->found = 1;

	FILE *out = ca->out;
	const char *f = ca->format;

	fflush(out);

	return 0;

	const mode_t mode = atoi(data[6]);

	time_t atime = atoi(data[9]);
	struct tm atm;
	localtime_r(&atime, &atm);
	char atime_str[MAXPATH];

	time_t mtime = atoi(data[10]);
	struct tm mtm;
	localtime_r(&mtime, &mtm);
	char mtime_str[MAXPATH];

	time_t ctime = atoi(data[11]);
	struct tm ctm;
	localtime_r(&ctime, &ctm);
	char ctime_str[MAXPATH];

	while (*f) {
		if (*f != '%') {
			/* handle escape sequences */
			if (*f == '\\') {
				unsigned char escape = *f;
				switch (*++f) {
					case 'a':
						escape = '\x07';
						break;
					case 'b':
						escape = '\x08';
						break;
					case 'e':
						escape = '\x1b';
						break;
					case 'f':
						escape = '\x0c';
						break;
					case 'n':
						escape = '\x0a';
						break;
					case 'r':
						escape = '\x0d';
						break;
					case 't':
						escape = '\x09';
						break;
					case 'v':
						escape = '\x0b';
						break;
					case '\\':
						escape = '\x5c';
						break;
					case '\'':
						escape = '\x27';
						break;
					case '"':
						escape = '\x22';
						break;
					case '?':
						escape = '\x3f';
						break;
					case 'x':
						f++;
						if (('0' <= *f) && (*f <= '9')) {
							escape = *f - '0';
						} else if (('a' <= *f) && (*f <= 'f')) {
							escape = *f - 'a' + 10;
						} else if (('A' <= *f) && (*f <= 'F')) {
							escape = *f - 'A' + 10;
						} else {
							fprintf(stderr, "gufi_stat: missing hex digit for \\x\n");
							f -= 2;
							break;
						}

						f++;
						if (('0' <= *f) && (*f <= '9')) {
							escape = (escape << 4) | (*f - '0');
						} else if (('a' <= *f) && (*f <= 'f')) {
							escape = (escape << 4) | (*f - 'a' + 10);
						} else if (('A' <= *f) && (*f <= 'F')) {
							escape = (escape << 4) | (*f - 'A' + 10);
						} else {
							f--;
						}

						break;
					case '0':
					case '1':
					case '2':
					case '3':
					case '4':
					case '5':
					case '6':
					case '7':
					case '8':
					case '9':
						for (int i = 0; i < 3; i++) {
							if (!(('0' <= *f) && (*f <= '9'))) {
								break;
							}
							escape = (escape << 3) | (*f - '0');
							f++;
						}
						f--;
						break;
					default:
						fwrite("\\", sizeof(char), 1, out);
						escape = *f;
						break;
				}
				fwrite(&escape, sizeof(char), 1, out);
			} else {
				fwrite(f, sizeof(char), 1, out);
			}
		} else {
			f++;

			/* if the first character starts a number */
			int width = 0;
			if (*f && (((*f == '-') || (*f == '+') ||
							(('0' <= *f) && (*f <= '9'))))) {
				int multiplier = 1;
				if (*f == '-') {
					multiplier = -1;
					f++;
				} else if (*f == '+') {
					f++;
				}

				/* get width */
				while (*f && ('0' <= *f) && (*f <= '9')) {
					width = (width * 10) + (*f - '0');
					f++;
				}

				width *= multiplier;
			}

			char format[MAXPATH] = "%";
			if (width) {
				SNPRINTF(format, sizeof(format), "%%%d", width);
			}

			char line[MAXPATH];
			SNPRINTF(line, sizeof(line), "%ss", format); /* most columns are strings */
			switch (*f) {
				case 'a': /* access rights in octal */
					SNPRINTF(line, sizeof(line), "%so", format);
					fprintf(out, line, mode & 0777);
					break;
				case 'A': /* access rights in human readable form */
				{
					char mode_str[11];
					modetostr(mode_str, 11, mode);
					fprintf(out, line, mode_str);
				}
				break;
				case 'b': /* number of blocks allocated (see %B) */
					fprintf(out, line, data[2]);
					break;
				case 'B': /* the size in bytes of each block reported by %b */
					fprintf(out, line, data[3]);
					break;
				case 'C': /* SELinux security context string */
					if (strlen(data[13])) {
						fprintf(out, line, data[13] + 16); /* offset by "security.selinux" */
					}
					break;
				case 'd': /* device number in decimal */
					fprintf(out, line, "?");
					break;
				case 'D': /* device number in hex */
					fprintf(out, line, "?");
					break;
				case 'f': /* raw mode in hex */
					SNPRINTF(line, sizeof(line), "%sx", format);
					fprintf(out, line, mode);
					break;
				case 'F': /* file type */
					switch (data[0][0]) {
						case 'f':
							fprintf(out, line, "regular file");
							break;
						case 'l':
							fprintf(out, line, "symbolic link");
							break;
						case 'd':
							fprintf(out, line, "directory");
							break;
						default:
							break;
					}
					break;
				case 'g': /* group ID of owner */
					fprintf(out, line, data[8]);
					break;
				case 'G': /* group name of owner */
				{
					struct group *gr = getgrgid(atoi(data[8]));
					const char *group = gr ? gr->gr_name : "UNKNOWN";
					fprintf(out, line, group);
				}
				break;
				case 'h': /* number of hard links */
					fprintf(out, line, data[5]);
					break;
				case 'i': /* inode number */
					fprintf(out, line, data[4]);
					break;
				case 'm': /* mount point */
					fprintf(out, line, " ");
					break;
				case 'n': /* file name */
					fprintf(out, line, ca->path);
					break;
				case 'N': /* quoted file name with dereference if symbolic link */
				{
					char name[MAXPATH];
					switch (data[0][0]) {
						case 'l':
							SNPRINTF(name, sizeof(name), "'%s' -> '%s'", ca->path, data[12]);
							break;
						case 'f':
						case 'd':
						default:
							SNPRINTF(name, sizeof(name), "'%s'", ca->path);
							break;
					}
					fprintf(out, line, name);
				}
				break;
				case 'o': /* optimal I/O transfer size hint */
					fprintf(out, line, data[3]);
					break;
				case 's': /* total size, in bytes */
					fprintf(out, line, data[1]);
					break;
				case 't': /* major device type in hex, for character/block device special files */
					SNPRINTF(line, sizeof(line), "%sd", format);
					fprintf(out, line, 0);
					break;
				case 'T': /* minor device type in hex, for character/block device special files */
					SNPRINTF(line, sizeof(line), "%sd", format);
					fprintf(out, line, 0);
					break;
				case 'u': /* user ID of owner */
					fprintf(out, line, data[7]);
					break;
				case 'U': /* user name of owner */
				{
					struct passwd *pw = getpwuid(atoi(data[7]));
					const char *user = pw ? pw->pw_name : "UNKNOWN";
					fprintf(out, line, user);
				}
				break;
				case 'w': /* time of file birth, human-readable; - if unknown */
					fprintf(out, line, "-");
					break;
				case 'W': /* time of file birth, seconds since Epoch; 0 if unknown */
					fprintf(out, line, "0");
					break;
				case 'x': /* time of last access, human-readable */
					strftime(atime_str, MAXPATH, "%F %T %z", &atm);
					fprintf(out, line, atime_str);
					break;
				case 'X': /* time of last access, seconds since Epoch */
					SNPRINTF(atime_str, MAXPATH, "%llu", (long long unsigned int) mktime(&atm));
					fprintf(out, line, atime_str);
					break;
				case 'y': /* time of last modification, human-readable */
					strftime(mtime_str, MAXPATH, "%F %T %z", &mtm);
					fprintf(out, line, mtime_str);
					break;
				case 'Y': /* time of last modification, seconds since Epoch */
					SNPRINTF(mtime_str, MAXPATH, "%llu", (long long unsigned int) mktime(&mtm));
					fprintf(out, line, mtime_str);
					break;
				case 'z': /* time of last change, human-readable */
					strftime(ctime_str, MAXPATH, "%F %T %z", &ctm);
					fprintf(out, line, ctime_str);
					break;
				case 'Z': /* time of last change, seconds since Epoch */
					SNPRINTF(ctime_str, MAXPATH, "%llu", (long long unsigned int) mktime(&ctm));
					fprintf(out, line, ctime_str);
					break;
				default:
					fwrite("?", sizeof(char), 1, out);
					break;
			}
		}

		f++;
	}

	fflush(out);

	return 0;
}

static void processNormal(beegfs_event *event, const char *dbRoot) {
	char filePath[MAXPATH];
	char dbPath[MAXPATH];
	const char *table = NULL;
	SNPRINTF(filePath, sizeof(filePath), "%s%s", dbRoot, event->path);
	char where[MAXSQL];
	char query[MAXSQL];
	struct stat st;
	/* path is directory */
	if ((lstat(filePath, &st) == 0) && S_ISDIR(st.st_mode)) {
		SNPRINTF(dbPath, sizeof(dbPath), "%s/" DBNAME, filePath);
		table = SUMMARY;
		SNPRINTF(where, sizeof(where), "WHERE isroot == 1");
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
		table = PENTRIES;
		sqlite3_snprintf(sizeof(where), where, "WHERE name == %Q", name);
	}
	static const char QUERY_PREFIX[] =
			"SELECT type, size, blocks, blksize, inode, nlink, mode, uid, gid, atime, mtime, ctime, linkname, xattr_names FROM";

	SNPRINTF(query, sizeof(query), "%s %s %s;", QUERY_PREFIX, table, where);
	struct callback_args ca;
	ca.found = 0;
	ca.path = filePath;
	ca.out = stdout;
	ca.format = DEFAULT_FORMAT;

	int rc = 0;
	sqlite3 *db = NULL;
	if ((db = opendb(dbPath, SQLITE_OPEN_READONLY, 0, 1, NULL, NULL))) {
		/* query the database */
		char *err = NULL;
		if (sqlite3_exec(db, query, print_callback, &ca, &err) == SQLITE_OK) {
			/* if the query was successful, but nothing was found, error */
			if (!ca.found) {
				fprintf(stderr, "gufi_stat: cannot stat '%s': No such file or directory\n", filePath);
				rc = 1;
			}
		} else {
			sqlite_print_err_and_free(err, stderr, "gufi_stat: failed to query database in '%s': %s\n", filePath, err);
			rc = 1;
		}
	} else {
		fprintf(stderr, "gufi_stat: cannot stat '%s': No such file or directory\n", filePath);
		rc = 1;
	}

	/* close no matter what to avoid memory leaks */
	closedb(db);
}

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
		closedb(db_path);
	}
}

static void processCreate(beegfs_event *event, const char *db_root) {
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
		shortpath(filePath, parent, name);
		SNPRINTF(dbPath, sizeof(dbPath), "%s/" DBNAME, parent);

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


		/* INSERT statement bindings into db.db */
		// TODO: only insert entries table for now
		sqlite3_stmt *entries_res = insertdbprep(db, ENTRIES_INSERT); /* entries */
		//sqlite3_stmt *xattrs_res      = insertdbprep(db, XATTRS_PWD_INSERT);        /* xattrs within db.db */
		//sqlite3_stmt *xattr_files_res = insertdbprep(db, EXTERNAL_DBS_PWD_INSERT);  /* per-user and per-group db file names */

		startdb(db);
		struct timeval tv;
		gettimeofday(&tv, NULL);
		long long timestamp = (long long) tv.tv_sec;

		struct stat ds = {
			.st_ino = 0,
			.st_nlink = 1,
			.st_uid = 0,
			.st_gid = 0,
			.st_size = 0,
			.st_blksize = 524288,
			.st_blocks = 0,
			.st_atime = timestamp,
			.st_mtim = timestamp,
			.st_ctime = timestamp,
			.st_mode = 33188,
		};
		struct entry_data row_ed = {
			.type = 'f',
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
		struct work *row = new_work_with_name("", 0, name, strlen(name));
		// FIXME: this is a hack, should set the correct values within new_work_with_name instead of set them here
		row->basename_len = strlen(name);
		row->name = name;
		row->name_len = strlen(name);
		insertdbgo(row, &row_ed, entries_res);
		fprintf(stdout, "inserted file %s, time %lld\n", name, timestamp);
		free(row);
		stopdb(db);
		closedb(db); /* don't set to nullptr */
	}
}


static void processUnlink(beegfs_event *event, const char *db_root) {
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
		shortpath(filePath, parent, name);
		SNPRINTF(dbPath, sizeof(dbPath), "%s/" DBNAME, parent);
		fprintf(stdout, "should add %s to database: %s, parent %s\n", filePath, dbPath, parent);

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

static void processEvent(beegfs_event *event, const char *db_root, const char *beegfs_root) {
	printf("Entry ID: %s\n", event->entryId);
	printf("Parent Entry ID: %s\n", event->parentEntryId);
	printf("Path: %s\n", event->path);

	if (strlen(event->targetPath) > 0) {
		printf("Target Path: %s\n", event->targetPath);
	}

	if (strlen(event->targetParentId) > 0) {
		printf("Target Parent ID: %s\n", event->targetParentId);
	}

	switch (event->type) {
		case FLUSH:
			printf("Flush event, ignore it, change will be applied on CLOSE_WRITE\n");
			break;
		case TRUNCATE:
			printf("Truncate event\n");
			process_attr_update(event, db_root, beegfs_root);
			break;
		case SETATTR:
			printf("Set attribute event\n");
			process_attr_update(event, db_root, beegfs_root);
			break;
		case CLOSE_WRITE:
			printf("Close write event\n");
			process_attr_update(event, db_root, beegfs_root);
			break;
		case CREATE:
			return processCreate(event, db_root);
		case MKDIR:
			printf("Mkdir event\n");
			break;
		case MKNOD:
			printf("Mknod event\n");
			break;
		case SYMLINK:
			printf("Symlink event\n");
			break;
		case RMDIR:
			printf("Rmdir event\n");
			break;
		case UNLINK:
			printf("Unlink event\n");
			return processUnlink(event, db_root);
		case HARDLINK:
			printf("Hardlink event\n");
			break;
		case RENAME:
			printf("Rename event\n");
			break;
		case READ:
			printf("Read event, ignore it, change will be applied on CLOSE_WRITE\n");
			break;
		default:
			sprintf(stderr, "Unknown event type: %d\n", event->type);
	}

	return processNormal(event, db_root);
}

int startServer(const char *address, int port, const char *db_root, const char *beegfs_root) {
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
		ReadErrorCode status = rawToPacket(buffer, bytes_received, &event);

		if (status == Success) {
			processEvent(&event, db_root, beegfs_root);
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

	startServer("0.0.0.0", port, path, beegfs_root);
	return 0;
}
