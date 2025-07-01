#include "beegfs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define READ_RAW(reader, type) ({ \
type value; \
if ((reader)->position + sizeof(type) > (reader)->end) { \
fprintf(stderr, "Read past buffer end\n"); \
exit(EXIT_FAILURE); \
} \
memcpy(&value, (reader)->position, sizeof(type)); \
(reader)->position += sizeof(type); \
value; \
})

uint32_t read_u32(beegfs_reader *reader) {
	return READ_RAW(reader, uint32_t);;
}

uint64_t read_u64(beegfs_reader *reader) {
	return READ_RAW(reader, uint64_t);
}

void read_string(beegfs_reader *reader, char *buffer, size_t max_len) {
	uint32_t len = read_u32(reader);
	if (reader->position + len > reader->end || len >= max_len) {
		fprintf(stderr, "String read error: exceeds buffer\n");
		exit(EXIT_FAILURE);
	}
	memcpy(buffer, reader->position, len);
	buffer[len] = '\0';
	reader->position += len + 1;
}

ReadErrorCode phase_body(const char *data, size_t body_size, struct beegfs_event *res) {
	beegfs_reader reader = {data, data + body_size};
	res->formatVersionMajor = READ_RAW(&reader, uint16_t);

	if (res->formatVersionMajor != 2)
		return VersionMismatch;

	res->eventFlags = read_u32(&reader);
	res->linkCount = read_u64(&reader);

	res->type = READ_RAW(&reader, beegfs_event_type);

	read_string(&reader, res->entryId, sizeof(res->entryId));
	read_string(&reader, res->parentEntryId, sizeof(res->parentEntryId));

	read_string(&reader, res->path, sizeof(res->path));
	read_string(&reader, res->targetPath, sizeof(res->targetPath));
	read_string(&reader, res->targetParentId, sizeof(res->targetParentId));

	res->msgUserID = READ_RAW(&reader, uint32_t);
	res->timestamp = READ_RAW(&reader, uint64_t);
	return Success;
}

void print_beegfs_event(const beegfs_event_t *event) {
	printf("beegfs_event_t {\n");
	printf("  formatVersionMajor: %u\n", event->formatVersionMajor);
	printf("  eventFlags:         %u\n", event->eventFlags);
	printf("  linkCount:          %llu\n", (unsigned long long)event->linkCount);
	printf("  type:               %s\n", beegfs_event_to_string(event));  // 建议替换为字符串形式
	printf("  path:               %s\n", event->path);
	printf("  entryId:            %s\n", event->entryId);
	printf("  parentEntryId:      %s\n", event->parentEntryId);
	printf("  targetPath:         %s\n", event->targetPath);
	printf("  targetParentId:     %s\n", event->targetParentId);
	printf("  msgUserID:          %u\n", event->msgUserID);
	printf("  timestamp:          %llu\n", (unsigned long long)event->timestamp);
	printf("}\n");
}

const char *beegfs_event_to_string(const beegfs_event_t *event) {
	switch (event->type) {
		case FLUSH:              return "FLUSH";
		case TRUNCATE:           return "TRUNCATE";
		case SETATTR:            return "SETATTR";
		case CLOSE_WRITE:        return "CLOSE_WRITE";
		case CREATE:             return "CREATE";
		case MKDIR:              return "MKDIR";
		case MKNOD:              return "MKNOD";
		case SYMLINK:            return "SYMLINK";
		case RMDIR:              return "RMDIR";
		case UNLINK:             return "UNLINK";
		case HARDLINK:           return "HARDLINK";
		case RENAME:             return "RENAME";
		case RECORD:			 return "RECORD";
		case OPEN_READ:          return "OPEN_READ";
		case OPEN_WRITE:         return "OPEN_WRITE";
		case OPEN_READ_WRITE:    return "OPEN_READ_WRITE";
		case LAST_WRITER_CLOSED: return "LAST_WRITER_CLOSED";
		default:                 return "UNKNOWN_EVENT";
	}
}