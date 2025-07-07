#ifndef INDEX_DB_H
#define INDEX_DB_H

#include "bf.h"
#include <sqlite3.h>
#include "gufi_index/app.h"


#define INDEX_ENTRIES           "entries"
#define INDEX_ENTRIES_SCHEMA(name, extra_cols) \
"CREATE TABLE " name " (" \
extra_cols \
"name TEXT,\n" \
"type TEXT,\n" \
"inode TEXT,\n" \
"mode INT64,\n" \
"nlink INT64,\n" \
"uid INT64,\n" \
"gid INT64,\n" \
"size INT64,\n" \
"blksize INT64,\n" \
"blocks INT64,\n" \
"atime INT64,\n" \
"mtime INT64,\n" \
"ctime INT64,\n" \
"linkname TEXT,\n" \
"xattr_names BLOB,\n" \
"crtime INT64,\n" \
"ossint1 INT64,\n" \
"ossint2 INT64,\n" \
"ossint3 INT64,\n" \
"ossint4 INT64,\n" \
"osstext1 TEXT,\n" \
"osstext2 TEXT,\n" \
"pinode TEXT,\n" \
"ownerID INT64,\n" \
"entryID TEXT,\n" \
"parentID TEXT,\n" \
"entryType INT64,\n" \
"featureFlag INT64,\n" \
"stripe_pattern_type INT64,\n" \
"chunk_size INT64,\n" \
"num_targets INT64,\n" \
"target_info TEXT\n" \
");"

extern const char INDEX_ENTRIES_UPDATE[];
extern const char INDEX_ENTRIES_CREATE[];
extern const char INDEX_ENTRIES_INSERT[];
extern const char INDEX_ENTRIES_DELETE[];

/* directory metadata + aggregate data */
#define INDEX_SUMMARY           "summary"
#define INDEX_SUMMARY_SCHEMA(name, extra_cols) \
"CREATE TABLE " name " (" \
extra_cols \
"name TEXT,\n" \
"type TEXT,\n" \
"inode TEXT,\n" \
"mode INT64,\n" \
"nlink INT64,\n" \
"uid INT64,\n" \
"gid INT64,\n" \
"size INT64,\n" \
"blksize INT64,\n" \
"blocks INT64,\n" \
"atime INT64,\n" \
"mtime INT64,\n" \
"ctime INT64,\n" \
"linkname TEXT,\n" \
"xattr_names BLOB,\n" \
"totfiles INT64,\n" \
"totlinks INT64,\n" \
"minuid INT64,\n" \
"maxuid INT64,\n" \
"mingid INT64,\n" \
"maxgid INT64,\n" \
"minsize INT64,\n" \
"maxsize INT64,\n" \
"totzero INT64,\n" \
"totltk INT64,\n" \
"totmtk INT64,\n" \
"totltm INT64,\n" \
"totmtm INT64,\n" \
"totmtg INT64,\n" \
"totmtt INT64,\n" \
"totsize INT64,\n" \
"minctime INT64,\n" \
"maxctime INT64,\n" \
"minmtime INT64,\n" \
"maxmtime INT64,\n" \
"minatime INT64,\n" \
"maxatime INT64,\n" \
"minblocks INT64,\n" \
"maxblocks INT64,\n" \
"totxattr INT64,\n" \
"depth INT64,\n" \
"mincrtime INT64,\n" \
"maxcrtime INT64,\n" \
"minossint1 INT64,\n" \
"maxossint1 INT64,\n" \
"totossint1 INT64,\n" \
"minossint2 INT64,\n" \
"maxossint2 INT64,\n" \
"totossint2 INT64,\n" \
"minossint3 INT64,\n" \
"maxossint3 INT64,\n" \
"totossint3 INT64,\n" \
"minossint4 INT64,\n" \
"maxossint4 INT64,\n" \
"totossint4 INT64,\n" \
"rectype INT64,\n" \
"pinode TEXT,\n" \
"isroot INT64,\n" \
"rollupscore INT64\n" \
");"

int create_index_db_tables(const char *name, sqlite3 *db, void *args);

int insertsumdb_index(sqlite3 *sdb, const char *path, struct entry_data *ed, struct sum *su);

int insertdbgo_index(file_index_cache_t *item, sqlite3_stmt *res);

int update_attr_index(file_index_cache_t *item, sqlite3_stmt *res);

int delete_index(file_index_cache_t *item, sqlite3_stmt *res);
#endif //INDEX_DB_H
