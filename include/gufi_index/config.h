#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

#define CONFIG_FILE_PATH "/etc/GUFI/config"

#define DEFAULT_NUM_WORKERS             1
#define DEFAULT_LISTEN_PORT             6000
#define SOCKET_LISTEN_BACKLOG           128
#define EPOLL_EVENTS_NUM                512 /* make it big to avoid starvation of higher FDs */

extern int log_level;

typedef enum {
    LOG_LEVEL_INFO = 0,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_DEBUG,
} LogLevel;

typedef struct {
    int8_t aggressive_poll;
    uint16_t port;
    char* mount_point;
    char* index_root;
    unsigned num_workers;
} AppConfig;

void init_config(AppConfig* config);
void free_config(AppConfig* config);
int load_config(AppConfig *config);

void log_print(LogLevel level, const char *file, int line, const char *fmt, ...);

#define STRSAFE(s) ((s) ? (s) : "(null)")

#define LOG_INFO(...)  log_print(LOG_LEVEL_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERR(...)  log_print(LOG_LEVEL_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_DBG(...)  log_print(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __VA_ARGS__)


#endif //CONFIG_H
