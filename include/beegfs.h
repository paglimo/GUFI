#ifndef BEEGFS_H
#define BEEGFS_H

#include <stddef.h>
#include <stdint.h>
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
	FLUSH = 0,
	TRUNCATE = 1,
	SETATTR = 2,
	CLOSE_WRITE = 3,
	CREATE = 4,
	MKDIR = 5,
	MKNOD = 6,
	SYMLINK = 7,
	RMDIR = 8,
	UNLINK = 9,
	HARDLINK = 10,
	RENAME = 11,
	READ = 12,
} beegfs_event_type;

typedef struct {
	uint16_t formatVersionMajor;
	uint16_t formatVersionMinor;
	uint32_t size;
	uint64_t droppedSeq;
	uint64_t missedSeq;
	beegfs_event_type type;
	char entryId[256];
	char parentEntryId[256];
	char path[PATH_MAX];
	char targetPath[PATH_MAX];
	char targetParentId[256];
} beegfs_event;

typedef struct {
	const char *position;
	const char *end;
} beegfs_reader;

ReadErrorCode phase_header(const char *data, beegfs_event *res);
ReadErrorCode phase_body(const char *data, size_t body_size, beegfs_event *res);

#endif //BEEGFS_H
