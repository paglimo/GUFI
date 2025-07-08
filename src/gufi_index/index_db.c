#include "gufi_index/index_db.h"

#include <string.h>

#include "external.h"
#include "dbutils.h"

int create_index_db_tables(const char *name, sqlite3 *db, void *args) {
    return ((create_table_wrapper(name, db, ENTRIES, ENTRIES_CREATE) != SQLITE_OK) ||
            (create_table_wrapper(name, db, SUMMARY, SUMMARY_CREATE) != SQLITE_OK) ||
            (create_table_wrapper(name, db, VRSUMMARY, VRSUMMARY_CREATE) != SQLITE_OK) ||
            (create_table_wrapper(name, db, PENTRIES_ROLLUP, PENTRIES_ROLLUP_CREATE) != SQLITE_OK) ||
            (create_table_wrapper(name, db, PENTRIES, PENTRIES_CREATE) != SQLITE_OK) ||
            (create_table_wrapper(name, db, VRPENTRIES, VRPENTRIES_CREATE) != SQLITE_OK) ||
            (create_table_wrapper(name, db, "vssqldir", vssqldir) != SQLITE_OK) ||
            (create_table_wrapper(name, db, "vssqluser", vssqluser) != SQLITE_OK) ||
            (create_table_wrapper(name, db, "vssqlgroup", vssqlgroup) != SQLITE_OK) ||
            (create_table_wrapper(name, db, SUMMARYLONG, SUMMARYLONG_CREATE) != SQLITE_OK) ||
            (create_table_wrapper(name, db, VRSUMMARYLONG, VRSUMMARYLONG_CREATE) != SQLITE_OK) ||
            create_external_tables(name, db, args) ||
            create_xattr_tables(name, db, args));
}

int insertsumdb_index(sqlite3 *sdb, const char *path, struct entry_data *ed, struct sum *su) {
    sqlite3_stmt *res = insertdbprep(sdb, SUMMARY_INSERT);
    if (!res) {
        return 1;
    }

    char *zname = sqlite3_mprintf("%q", path);
    char *ztype = sqlite3_mprintf("%c", ed->type);
    char *zino = sqlite3_mprintf("%" PRIu64, ed->statuso.st_ino);
    char *zlinkname = sqlite3_mprintf("%q", ed->linkname);
    char *zpino = sqlite3_mprintf("%" PRIu64, 0);

    char xattrnames[MAXXATTR] = "\x00";
    xattr_get_names(&ed->xattrs, xattrnames, sizeof(xattrnames), XATTRDELIM);

    char *zxattrnames = sqlite3_mprintf("%q", xattrnames);

    sqlite3_bind_text(res, 1, zname, -1, SQLITE_STATIC);
    sqlite3_bind_text(res, 2, ztype, -1, SQLITE_STATIC);
    sqlite3_bind_text(res, 3, zino, -1, SQLITE_STATIC);
    sqlite3_bind_int64(res, 4, ed->statuso.st_mode);
    sqlite3_bind_int64(res, 5, ed->statuso.st_nlink);
    sqlite3_bind_int64(res, 6, ed->statuso.st_uid);
    sqlite3_bind_int64(res, 7, ed->statuso.st_gid);
    sqlite3_bind_int64(res, 8, ed->statuso.st_size);
    sqlite3_bind_int64(res, 9, ed->statuso.st_blksize);
    sqlite3_bind_int64(res, 10, ed->statuso.st_blocks);
    sqlite3_bind_int64(res, 11, ed->statuso.st_atime);
    sqlite3_bind_int64(res, 12, ed->statuso.st_mtime);
    sqlite3_bind_int64(res, 13, ed->statuso.st_ctime);
    sqlite3_bind_text(res, 14, zlinkname, -1, SQLITE_STATIC);
    sqlite3_bind_blob64(res, 15, zxattrnames, strlen(zxattrnames), SQLITE_STATIC);
    sqlite3_bind_int64(res, 16, su->totfiles);
    sqlite3_bind_int64(res, 17, su->totlinks);
    sqlite3_bind_int64(res, 18, su->minuid);
    sqlite3_bind_int64(res, 19, su->maxuid);
    sqlite3_bind_int64(res, 20, su->mingid);
    sqlite3_bind_int64(res, 21, su->maxgid);
    sqlite3_bind_int64(res, 22, su->minsize);
    sqlite3_bind_int64(res, 23, su->maxsize);
    sqlite3_bind_int64(res, 24, su->totzero);
    sqlite3_bind_int64(res, 25, su->totltk);
    sqlite3_bind_int64(res, 26, su->totmtk);
    sqlite3_bind_int64(res, 27, su->totltm);
    sqlite3_bind_int64(res, 28, su->totmtm);
    sqlite3_bind_int64(res, 29, su->totmtg);
    sqlite3_bind_int64(res, 30, su->totmtt);
    sqlite3_bind_int64(res, 31, su->totsize);
    sqlite3_bind_int64(res, 32, su->minctime);
    sqlite3_bind_int64(res, 33, su->maxctime);
    sqlite3_bind_int64(res, 34, su->minmtime);
    sqlite3_bind_int64(res, 35, su->maxmtime);
    sqlite3_bind_int64(res, 36, su->minatime);
    sqlite3_bind_int64(res, 37, su->maxatime);
    sqlite3_bind_int64(res, 38, su->minblocks);
    sqlite3_bind_int64(res, 39, su->maxblocks);
    sqlite3_bind_int64(res, 40, su->totxattr);
    sqlite3_bind_int64(res, 41, 0); /* depth */
    sqlite3_bind_int64(res, 42, su->mincrtime);
    sqlite3_bind_int64(res, 43, su->maxcrtime);
    sqlite3_bind_int64(res, 44, su->minossint1);
    sqlite3_bind_int64(res, 45, su->maxossint1);
    sqlite3_bind_int64(res, 46, su->totossint1);
    sqlite3_bind_int64(res, 47, su->minossint2);
    sqlite3_bind_int64(res, 48, su->maxossint2);
    sqlite3_bind_int64(res, 49, su->totossint2);
    sqlite3_bind_int64(res, 50, su->minossint3);
    sqlite3_bind_int64(res, 51, su->maxossint3);
    sqlite3_bind_int64(res, 52, su->totossint3);
    sqlite3_bind_int64(res, 53, su->minossint4);
    sqlite3_bind_int64(res, 54, su->maxossint4);
    sqlite3_bind_int64(res, 55, su->totossint4);
    sqlite3_bind_int64(res, 56, 0); /* rectype */
    sqlite3_bind_text(res, 57, 0, -1, SQLITE_STATIC);
    sqlite3_bind_int64(res, 58, 1); /* isroot */
    sqlite3_bind_int64(res, 59, 0); /* rollupscore */

    sqlite3_step(res);
    sqlite3_reset(res);
    sqlite3_clear_bindings(res);

    sqlite3_free(zxattrnames);
    sqlite3_free(zpino);
    sqlite3_free(zlinkname);
    sqlite3_free(zino);
    sqlite3_free(ztype);
    sqlite3_free(zname);

    insertdbfin(res);
    return 0;
}

int insertdbgo_index(file_index_cache_t *item, sqlite3_stmt *res) {
    char *zino = sqlite3_mprintf("%" PRIu64, item->ed.statuso.st_ino);
    sqlite3_bind_text(res, sqlite3_bind_parameter_index(res, "@name"), item->file_name, -1, SQLITE_STATIC);
    sqlite3_bind_text(res, sqlite3_bind_parameter_index(res, "@type"), &item->ed.type, 1, SQLITE_STATIC);
    // FIXME: wrong inode num like 1.55088371704356e+19
    sqlite3_bind_text(res, sqlite3_bind_parameter_index(res, "@inode"), zino, -1, SQLITE_STATIC);
    sqlite3_bind_int64(res, sqlite3_bind_parameter_index(res, "@mode"), item->ed.statuso.st_mode);
    sqlite3_bind_int64(res, sqlite3_bind_parameter_index(res, "@nlink"), item->ed.statuso.st_nlink);
    sqlite3_bind_int64(res, sqlite3_bind_parameter_index(res, "@uid"), item->ed.statuso.st_uid);
    sqlite3_bind_int64(res, sqlite3_bind_parameter_index(res, "@gid"), item->ed.statuso.st_gid);
    sqlite3_bind_int64(res, sqlite3_bind_parameter_index(res, "@size"), item->ed.statuso.st_size);
    sqlite3_bind_int64(res, sqlite3_bind_parameter_index(res, "@blksize"), item->ed.statuso.st_blksize);
    sqlite3_bind_int64(res, sqlite3_bind_parameter_index(res, "@blocks"), item->ed.statuso.st_blocks);
    sqlite3_bind_int64(res, sqlite3_bind_parameter_index(res, "@atime"), item->ed.statuso.st_atime);
    sqlite3_bind_int64(res, sqlite3_bind_parameter_index(res, "@mtime"), item->ed.statuso.st_mtime);
    sqlite3_bind_int64(res, sqlite3_bind_parameter_index(res, "@ctime"), item->ed.statuso.st_ctime);
    sqlite3_bind_text(res, sqlite3_bind_parameter_index(res, "@linkname"), item->ed.linkname, -1, SQLITE_STATIC);
    sqlite3_bind_null(res, sqlite3_bind_parameter_index(res, "@xattr_names"));
    sqlite3_bind_int64(res, sqlite3_bind_parameter_index(res, "@crtime"), item->ed.crtime);
    sqlite3_bind_int64(res, sqlite3_bind_parameter_index(res, "@ossint1"), item->ed.ossint1);
    sqlite3_bind_int64(res, sqlite3_bind_parameter_index(res, "@ossint2"), item->ed.ossint2);
    sqlite3_bind_int64(res, sqlite3_bind_parameter_index(res, "@ossint3"), item->ed.ossint3);
    sqlite3_bind_int64(res, sqlite3_bind_parameter_index(res, "@ossint4"), item->ed.ossint4);
    sqlite3_bind_text(res, sqlite3_bind_parameter_index(res, "@osstext1"), item->ed.osstext1, -1, SQLITE_STATIC);
    sqlite3_bind_text(res, sqlite3_bind_parameter_index(res, "@osstext2"), item->ed.osstext2, -1, SQLITE_STATIC);
    sqlite3_bind_text(res, sqlite3_bind_parameter_index(res, "@pinode"), item->ed.pinodec, -1, SQLITE_STATIC);

    sqlite3_free(zino);
    if (item->file_pattern) {
        sqlite3_bind_int64(res, sqlite3_bind_parameter_index(res, "@ownerID"), item->file_pattern->owner_id);
        sqlite3_bind_text(res, sqlite3_bind_parameter_index(res, "@entryID"), item->file_pattern->entry_id, -1,
                          SQLITE_STATIC);
        sqlite3_bind_text(res, sqlite3_bind_parameter_index(res, "@parentID"), item->file_pattern->parent_id, -1,
                          SQLITE_STATIC);
        sqlite3_bind_int(res, sqlite3_bind_parameter_index(res, "@entryType"), item->file_pattern->entry_type);
        sqlite3_bind_int64(res, sqlite3_bind_parameter_index(res, "@featureFlag"), item->file_pattern->feature_flag);
        sqlite3_bind_int(res, sqlite3_bind_parameter_index(res, "@stripe_pattern_type"),
                         item->file_pattern->pattern_type);
        sqlite3_bind_int(res, sqlite3_bind_parameter_index(res, "@chunk_size"), item->file_pattern->chunk_size);
        sqlite3_bind_int(res, sqlite3_bind_parameter_index(res, "@num_targets"), item->file_pattern->num_targets);
        sqlite3_bind_text(res, sqlite3_bind_parameter_index(res, "@target_info"), item->file_pattern->target_info, -1,
                          SQLITE_STATIC);
    } else {
        sqlite3_bind_null(res, sqlite3_bind_parameter_index(res, "@ownerID"));
        sqlite3_bind_null(res, sqlite3_bind_parameter_index(res, "@entryID"));
        sqlite3_bind_null(res, sqlite3_bind_parameter_index(res, "@parentID"));
        sqlite3_bind_null(res, sqlite3_bind_parameter_index(res, "@entryType"));
        sqlite3_bind_null(res, sqlite3_bind_parameter_index(res, "@featureFlag"));
        sqlite3_bind_null(res, sqlite3_bind_parameter_index(res, "@stripe_pattern_type"));
        sqlite3_bind_null(res, sqlite3_bind_parameter_index(res, "@chunk_size"));
        sqlite3_bind_null(res, sqlite3_bind_parameter_index(res, "@num_targets"));
        sqlite3_bind_null(res, sqlite3_bind_parameter_index(res, "@target_info"));
    }

    int rc = sqlite3_step(res);
    if (rc != SQLITE_DONE) {
        return rc;
    }

    sqlite3_reset(res);
    sqlite3_clear_bindings(res);
    return SQLITE_OK;
}

int update_attr_index(file_index_cache_t *item, sqlite3_stmt *res) {
    struct stat st = item->ed.statuso;
    sqlite3_bind_int64(res, 1, st.st_size);
    sqlite3_bind_int64(res, 2, st.st_blocks);
    sqlite3_bind_int64(res, 3, st.st_blksize);
    char *zino = sqlite3_mprintf("%" PRIu64, st.st_ino);
    sqlite3_bind_text(res, 4, zino, -1, SQLITE_STATIC);
    sqlite3_bind_int64(res, 5, st.st_nlink);
    sqlite3_bind_int64(res, 6, st.st_mode);
    sqlite3_bind_int64(res, 7, st.st_uid);
    sqlite3_bind_int64(res, 8, st.st_gid);
    sqlite3_bind_int64(res, 9, st.st_atime);
    sqlite3_bind_int64(res, 10, st.st_mtime);
    sqlite3_bind_int64(res, 11, st.st_ctime);
    sqlite3_bind_text(res, 12, item->file_name, -1,SQLITE_STATIC);
    sqlite3_bind_text(res, 13, item->entry_id, -1,SQLITE_STATIC);

    int rc = sqlite3_step(res);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "sqlite3_step\n");
    }

    sqlite3_free(zino);
    sqlite3_reset(res);
    sqlite3_clear_bindings(res);
    return SQLITE_OK;
}

int delete_index(file_index_cache_t *item, sqlite3_stmt *res) {
    sqlite3_bind_text(res, 1, item->entry_id, -1, SQLITE_STATIC);
    int rc = sqlite3_step(res);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "deleted\n");
        return rc;
    }
    sqlite3_reset(res);
    return SQLITE_OK;
}
