#ifndef BEEGFS_H
#define BEEGFS_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <linux/limits.h>

// sizeof(beegfs_event) = 8992, should make sure buffer size > beegfs_event size
#define MAX_BUFFER_SIZE (1024*1024*4)

#define EVENT_HEADER_SIZE 8

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
} beegfs_event_type;

typedef struct beegfs_event{
	uint16_t formatVersionMajor;
	uint32_t eventFlags;
	uint64_t linkCount;
	beegfs_event_type type;
	char path[PATH_MAX];
	char entryId[256];
	char parentEntryId[256];
	char targetPath[PATH_MAX];
	char targetParentId[256];
	uint32_t msgUserID;
	uint64_t timestamp;
} beegfs_event_t;

typedef struct {
	const char *position;
	const char *end;
} beegfs_reader;

ReadErrorCode phase_body(const char *data, size_t body_size, struct beegfs_event *res);

void print_beegfs_event(const beegfs_event_t *event);

const char *beegfs_event_to_string(const beegfs_event_t *event);
#endif //BEEGFS_H
