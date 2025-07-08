#include "gufi_index/reader.h"
#include "gufi_index/config.h"
#include "orcafs/orcafs_ioctl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>



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

uint32_t read_u32(event_reader *reader) {
	return READ_RAW(reader, uint32_t);;
}

uint64_t read_u64(event_reader *reader) {
	return READ_RAW(reader, uint64_t);
}

void read_string(event_reader *reader, char *buffer, size_t max_len) {
	uint32_t len = read_u32(reader);
	if (reader->position + len > reader->end || len >= max_len) {
		fprintf(stderr, "String read error: exceeds buffer\n");
		exit(EXIT_FAILURE);
	}
	memcpy(buffer, reader->position, len);
	buffer[len] = '\0';
	reader->position += len + 1;
}

ReadErrorCode packet_to_event(const char *data, size_t body_size, struct fs_event *res) {
	event_reader reader = {data, data + body_size};
	res->formatVersionMajor = READ_RAW(&reader, uint16_t);

	if (res->formatVersionMajor != 2)
		return VersionMismatch;

	res->eventFlags = read_u32(&reader);
	res->linkCount = read_u64(&reader);

	res->type = READ_RAW(&reader, fs_event_type);

	read_string(&reader, res->entryId, sizeof(res->entryId));
	read_string(&reader, res->parentEntryId, sizeof(res->parentEntryId));

	read_string(&reader, res->path, sizeof(res->path));
	read_string(&reader, res->targetPath, sizeof(res->targetPath));
	read_string(&reader, res->targetParentId, sizeof(res->targetParentId));

	res->msgUserID = READ_RAW(&reader, uint32_t);
	res->timestamp = READ_RAW(&reader, uint64_t);
	return Success;
}

char *event_to_str(const fs_event_t *event) {
	const char *type_str = event_type_string(event);

	size_t bufsize = 2048;
	char *buffer = malloc(bufsize);
	if (!buffer) return NULL;

	snprintf(buffer, bufsize,
	         "fs_event_t {\n"
	         "  formatVersionMajor: %u\n"
	         "  eventFlags:         %u\n"
	         "  linkCount:          %llu\n"
	         "  type:               %s\n"
	         "  path:               %s\n"
	         "  entryId:            %s\n"
	         "  parentEntryId:      %s\n"
	         "  targetPath:         %s\n"
	         "  targetParentId:     %s\n"
	         "  msgUserID:          %u\n"
	         "  timestamp:          %llu\n"
	         "}",
	         event->formatVersionMajor,
	         event->eventFlags,
	         (unsigned long long) event->linkCount,
	         type_str,
	         event->path,
	         event->entryId,
	         event->parentEntryId,
	         event->targetPath,
	         event->targetParentId,
	         event->msgUserID,
	         (unsigned long long) event->timestamp
	);

	return buffer;
}

void print_file_pattern(const file_pattern_t *pattern) {
	if (!pattern) {
		LOG_DBG("file_pattern is NULL");
		return;
	}

	LOG_DBG("file_pattern_t {");
	LOG_DBG("  owner_id: %ld", pattern->owner_id);
	LOG_DBG("  entry_id: %s", pattern->entry_id);
	LOG_DBG("  parent_id: %s", pattern->parent_id);
	LOG_DBG("  entry_type: %d", pattern->entry_type);
	LOG_DBG("  feature_flag: %ld", pattern->feature_flag);
	LOG_DBG("  pattern_type: %u", pattern->pattern_type);
	LOG_DBG("  chunk_size: %u", pattern->chunk_size);
	LOG_DBG("  num_targets: %u", pattern->num_targets);
	LOG_DBG("  target_info: %s", pattern->target_info);
	LOG_DBG("}");
}

const char *event_type_string(const fs_event_t *event) {
	switch (event->type) {
		case FLUSH: return "FLUSH";
		case TRUNCATE: return "TRUNCATE";
		case SETATTR: return "SETATTR";
		case CLOSE_WRITE: return "CLOSE_WRITE";
		case CREATE: return "CREATE";
		case MKDIR: return "MKDIR";
		case MKNOD: return "MKNOD";
		case SYMLINK: return "SYMLINK";
		case RMDIR: return "RMDIR";
		case UNLINK: return "UNLINK";
		case HARDLINK: return "HARDLINK";
		case RENAME: return "RENAME";
		case RECORD: return "RECORD";
		case OPEN_READ: return "OPEN_READ";
		case OPEN_WRITE: return "OPEN_WRITE";
		case OPEN_READ_WRITE: return "OPEN_READ_WRITE";
		case LAST_WRITER_CLOSED: return "LAST_WRITER_CLOSED";
		default: return "UNKNOWN_EVENT";
	}
}

file_pattern_t *get_file_pattern(const char *file_path, const char *entry_id, const char *parent_entry_id) {
	mode_t MODE_FLAG = S_IRWXU | S_IRGRP | S_IROTH;
	int OPEN_FLAGS = O_RDWR;
	file_pattern_t *file_pattern = calloc(1, sizeof(file_pattern_t));
	if (file_pattern == NULL) return NULL;

	// query file pattern
	int fd = open(file_path, OPEN_FLAGS, MODE_FLAG);
	if (fd == -1) {
		goto err;
	}

	if (!orcafs_testIsOrcaFS(fd)) {
		goto err;
	}

	if (!orcafs_getStripeInfo(fd, &file_pattern->pattern_type,
	                          &file_pattern->chunk_size, &file_pattern->num_targets)) {
		goto err;
	} {
		int64_t target_list[file_pattern->num_targets];
		for (int i = 0; i < file_pattern->num_targets; ++i) {
			struct OrcafsIoctl_GetStripeTargetV2_Arg target_info;
			if (!orcafs_getStripeTargetV2(fd, i, &target_info)) {
				goto err;
			}
			target_list[i] = target_info.targetOrGroup;
		}

		size_t offset = 0;
		for (int i = 0; i < file_pattern->num_targets; ++i) {
			int written = snprintf(file_pattern->target_info + offset, sizeof(file_pattern->target_info) - offset,
			                       "%s%ld",
			                       (i == 0) ? "" : ":", target_list[i]);
			if (written < 0 || (size_t) written >= sizeof(file_pattern->target_info) - offset) {
				goto err;
			}
			offset += written;
		}
	}

	strncpy(file_pattern->entry_id, entry_id, sizeof(file_pattern->entry_id) - 1);
	file_pattern->entry_id[sizeof(file_pattern->entry_id) - 1] = '\0';
	strncpy(file_pattern->parent_id, parent_entry_id, sizeof(file_pattern->parent_id) - 1);
	file_pattern->parent_id[sizeof(file_pattern->parent_id) - 1] = '\0';

	goto out;

err:
	free(file_pattern);
	file_pattern = NULL;

out:
	if (fd >0 ) close(fd);
	return file_pattern;
}
