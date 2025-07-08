#ifndef INDEX_DB_H
#define INDEX_DB_H

#include "bf.h"
#include <sqlite3.h>
#include "gufi_index/app.h"

int create_index_db_tables(const char *name, sqlite3 *db, void *args);

int insertsumdb_index(sqlite3 *sdb, const char *path, struct entry_data *ed, struct sum *su);

int insertdbgo_index(file_index_cache_t *item, sqlite3_stmt *res);

int update_attr_index(file_index_cache_t *item, sqlite3_stmt *res);

int delete_index(file_index_cache_t *item, sqlite3_stmt *res);
#endif //INDEX_DB_H
