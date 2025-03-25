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

ReadErrorCode phase_header(const char *data, struct beegfs_event *res) {
	beegfs_reader reader = {data, data + EVENT_HEADER_SIZE};
	res->formatVersionMajor = READ_RAW(&reader, uint16_t);
	res->formatVersionMinor = READ_RAW(&reader, uint16_t);

	if (res->formatVersionMajor != 1 || res->formatVersionMinor < 0)
		return VersionMismatch;
	res->size = read_u32(&reader);
	return Success;
}

ReadErrorCode phase_body(const char *data, size_t body_size, struct beegfs_event *res) {
	beegfs_reader reader = {data, data + body_size};

	res->droppedSeq = read_u64(&reader);
	res->missedSeq = read_u64(&reader);
	res->type = READ_RAW(&reader, beegfs_event_type);

	read_string(&reader, res->entryId, sizeof(res->entryId));
	read_string(&reader, res->parentEntryId, sizeof(res->parentEntryId));
	read_string(&reader, res->path, sizeof(res->path));
	read_string(&reader, res->targetPath, sizeof(res->targetPath));
	read_string(&reader, res->targetParentId, sizeof(res->targetParentId));

	return Success;
}
