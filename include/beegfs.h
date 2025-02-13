#ifndef BEEGFS_H
#define BEEGFS_H


#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUFFER_SIZE 1024

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
} FileEventType;

typedef struct {
	uint16_t formatVersionMajor;
	uint16_t formatVersionMinor;
	uint32_t size;
	uint64_t droppedSeq;
	uint64_t missedSeq;
	FileEventType type;
	char entryId[256];
	char parentEntryId[256];
	char path[256];
	char targetPath[256];
	char targetParentId[256];
} beegfsEvent;

typedef struct {
	const char *position;
	const char *end;
} Reader;

ReadErrorCode rawToPacket(const char *data, size_t bytesRead, beegfsEvent *res);

#endif //BEEGFS_H
