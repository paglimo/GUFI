#include "beegfs.h"

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

uint32_t read_u32(Reader *reader) {
	return READ_RAW(reader, uint32_t);;
}

uint64_t read_u64(Reader *reader) {
	return READ_RAW(reader, uint64_t);
}

void read_string(Reader *reader, char *buffer, size_t max_len) {
	uint32_t len = read_u32(reader);
	if (reader->position + len > reader->end || len >= max_len) {
		fprintf(stderr, "String read error: exceeds buffer\n");
		exit(EXIT_FAILURE);
	}
	memcpy(buffer, reader->position, len);
	buffer[len] = '\0';
	reader->position += len + 1;
}

ReadErrorCode rawToPacket(const char *data, size_t bytesRead, beegfs_event *res) {
	Reader reader = {data, data + bytesRead};

	res->formatVersionMajor = READ_RAW(&reader, uint16_t);
	res->formatVersionMinor = READ_RAW(&reader, uint16_t);

	if (res->formatVersionMajor != 1 || res->formatVersionMinor < 0)
		return VersionMismatch;

	res->size = read_u32(&reader);

	if (res->size != bytesRead) {
		fprintf(stderr, "Invalid size: %u - byteRead: %lu\n", res->size, bytesRead);
		return InvalidSize;
	}

	res->droppedSeq = read_u64(&reader);
	res->missedSeq = read_u64(&reader);
	res->type = READ_RAW(&reader, FileEventType);

	read_string(&reader, res->entryId, sizeof(res->entryId));
	read_string(&reader, res->parentEntryId, sizeof(res->parentEntryId));
	read_string(&reader, res->path, sizeof(res->path));
	read_string(&reader, res->targetPath, sizeof(res->targetPath));
	read_string(&reader, res->targetParentId, sizeof(res->targetParentId));

	return Success;
}
