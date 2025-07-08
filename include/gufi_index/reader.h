#ifndef BEEGFS_H
#define BEEGFS_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <linux/limits.h>

// sizeof(fs_event) = 8992, should make sure buffer size > fs_event size
#define MAX_BUFFER_SIZE (1024*1024*4)

#define EVENT_HEADER_MAGIC "START"
#define EVENT_HEADER_SIZE 4
#define RECV_BUF_CAPACITY 65536  // 可调，根据需要
#define MAGIC_HEADER "STAR"
#define MAGIC_HEADER_LEN 4
#define LENGTH_PREFIX_LEN 8
#define PACKET_HEADER_LEN (MAGIC_HEADER_LEN + LENGTH_PREFIX_LEN)

typedef enum {
	Success,
	ReadFailed,
	VersionMismatch,
	InvalidSize
} ReadErrorCode;

typedef enum {
	FLUSH = 1,
	TRUNCATE = 2,
	SETATTR = 3,
	CLOSE_WRITE = 4,
	CREATE = 5,
	MKDIR = 6,
	MKNOD = 7,
	SYMLINK = 8,
	RMDIR = 9,
	UNLINK = 10,
	HARDLINK = 11,
	RENAME = 12,
	RECORD = 13,
	OPEN_READ = 14,
	OPEN_WRITE = 15,
	OPEN_READ_WRITE = 16,
	LAST_WRITER_CLOSED = 17
} fs_event_type;

typedef struct fs_event{
	uint16_t formatVersionMajor;
	uint32_t eventFlags;
	uint64_t linkCount;
	fs_event_type type;
	char path[PATH_MAX];
	char entryId[256];
	char parentEntryId[256];
	char targetPath[PATH_MAX];
	char targetParentId[256];
	uint32_t msgUserID;
	uint64_t timestamp;
} fs_event_t;

typedef struct {
	const char *position;
	const char *end;
} event_reader;

typedef struct file_pattern {
	int64_t owner_id;
	char entry_id[256];
	char parent_id[256];
	int8_t entry_type;
	int64_t feature_flag;
	unsigned pattern_type;
	unsigned chunk_size;
	uint16_t num_targets;
	char target_info[256];
} file_pattern_t;

ReadErrorCode packet_to_event(const char *data, size_t body_size, struct fs_event *res);
char *event_to_str(const fs_event_t *event);
void print_file_pattern(const file_pattern_t *pattern);

const char *event_type_string(const fs_event_t *event);

file_pattern_t *get_file_pattern(const char *file_path, const char* entry_id, const char* parent_entry_id);

void extract_filename(const char *file_path, char name[256]);
#endif //BEEGFS_H
