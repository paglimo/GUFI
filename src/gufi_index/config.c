#include "gufi_index/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>

void init_config(AppConfig *config) {
    memset(config, 0, sizeof(AppConfig));

    config->num_workers = DEFAULT_NUM_WORKERS;
    config->port = DEFAULT_LISTEN_PORT;

    config->aggressive_poll = 0;
}

void free_config(AppConfig *config) {
    if (config->mount_point) free(config->mount_point);
    if (config->index_root) free(config->index_root);
    memset(config, 0, sizeof(AppConfig)); // 彻底清理
}

int load_config(AppConfig *config) {
    FILE *fp = fopen(CONFIG_FILE_PATH, "r");
    if (!fp) {
        perror("Failed to open config file");
        return -1;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = line;
        char *value = eq + 1;

        value[strcspn(value, "\r\n")] = 0;


        if (strcmp(key, "IndexRoot") == 0) {
            free(config->index_root);
            config->index_root = value ? strdup(value) : NULL;

        } else if (strcmp(key, "Mountpoint") == 0) {
            free(config->mount_point);
            config->mount_point = value ? strdup(value) : NULL;

        } else if (strcmp(key, "NumWorkers") == 0) {
            char* endptr = NULL;
            errno = 0;
            long val = strtol(value, &endptr, 10);
            if (errno != 0 || *endptr != '\0' || val < 1 || val > UINT_MAX) {
                fprintf(stderr, "Invalid NumWorkers: %s\n", value);
            } else {
                config->num_workers = (unsigned)val;
            }

        } else if (strcmp(key, "LogLevel") == 0) {
            if (strcasecmp(value, "debug") == 0) {
                log_level = LOG_LEVEL_DEBUG;
            } else {
                log_level = LOG_LEVEL_ERROR;
            }

        } else if (strcmp(key, "Port") == 0) {
            char* endptr = NULL;
            errno = 0;
            long val = strtol(value, &endptr, 10);
            if (errno != 0 || *endptr != '\0' || val < 1 || val > UINT16_MAX) {
                fprintf(stderr, "Invalid Port: %s\n", value);
            } else {
                config->port = (uint16_t)val;
            }
        } else if (strcmp(key, "AggressivePoll") == 0) {
            if (strcasecmp(value, "TRUE") == 0 || strcmp(value, "1") == 0) {
                config->aggressive_poll = 1;
            } else {
                config->aggressive_poll = 0;
            }
        }
    }

    fclose(fp);
    return 0;
}

void log_print(LogLevel level, const char *file, int line, const char *fmt, ...) {
    if (level > log_level)
        return;

    const char *level_str = (level == LOG_LEVEL_DEBUG) ? "DEBUG" : (level == LOG_LEVEL_INFO) ? "INFO" : "ERROR";

    fprintf(stderr, "[%s][%s:%d] ", level_str, file, line);

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    if (errno != 0) {
        fprintf(stderr, ": %s", strerror(errno));
    }

    fprintf(stderr, "\n");
}
