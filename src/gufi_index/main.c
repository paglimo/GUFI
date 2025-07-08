#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "gufi_index/app.h"
#include "gufi_index/worker.h"

int log_level;
app_t app;
volatile sig_atomic_t app_stop = 0;

void signal_handler(int signum) {
    LOG_INFO("caught signal %d, app exiting", signum);
    app_stop = 1;
    pthread_mutex_lock(&app.queue_mutex);
    pthread_cond_broadcast(&app.queue_cond);
    pthread_mutex_unlock(&app.queue_mutex);
}

void thread_join() {
    pthread_join(app.stream_listener, NULL);
    pthread_join(app.event_flusher, NULL);

    for (int i = 0; i < app.config.num_workers; i++) {
        if (app.event_workers[i]) {
            pthread_join(app.event_workers[i], NULL);
        }
    }
}

int init_server() {
    struct sockaddr_in server_addr;
    app.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (app.listen_fd < 0) {
        LOG_ERR("listen socket create failed");
        return -1;
    }

    int opt = 1;
    setsockopt(app.listen_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    set_nonblocking(app.listen_fd);

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(app.config.port);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(app.listen_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        LOG_ERR("bind for port failed");
        close(app.listen_fd);
        return -1;
    }

    if (listen(app.listen_fd, SOCKET_LISTEN_BACKLOG) < 0) {
        LOG_ERR("listen failed");
        close(app.listen_fd);
        return -1;
    }

    app.epoll_fd = epoll_create1(0);
    if (app.epoll_fd < 0) {
        LOG_ERR("epoll_create1 failed");
        close(app.listen_fd);
        return -1;
    }

    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = app.listen_fd;
    if (epoll_ctl(app.epoll_fd, EPOLL_CTL_ADD, app.listen_fd, &event) < 0) {
        LOG_ERR("epoll_ctl ADD listen_fd failed");
        close(app.listen_fd);
        return -1;
    }
    return 0;
}

int init_app() {
    init_config(&app.config);

    if (load_config(&app.config) != 0) {
        LOG_ERR("Failed to load config");
        return EXIT_FAILURE;
    }

    app.index_cache = NULL;
    pthread_mutex_init(&app.index_cache_mutex, NULL);

    sll_init(&app.socket_list);
    pthread_mutex_init(&app.socket_mutex, NULL);

    sll_init(&app.event_queue);
    pthread_mutex_init(&app.queue_mutex, NULL);
    pthread_cond_init(&app.queue_cond, NULL);

    // register signal hadler function
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    const int ret = init_server();
    if (ret != 0) {
        return ret;
    }

    // init threads
    pthread_create(&app.stream_listener, NULL, stream_listener_run, NULL);
    pthread_create(&app.event_flusher,NULL, event_flusher_run,NULL);

    app.event_workers = calloc(app.config.num_workers, sizeof(pthread_t));
    if (!app.event_workers) {
        perror("Failed to allocate worker thread array");
        return EXIT_FAILURE;
    }
    for (int i = 0; i < app.config.num_workers; i++) {
        pthread_create(&app.event_workers[i],NULL, event_worker_run,NULL);
    }

    return EXIT_SUCCESS;
}

void uninit_app() {
    sll_destroy(&app.socket_list, NULL);
    pthread_mutex_destroy(&app.socket_mutex);

    sll_destroy(&app.event_queue, NULL);
    pthread_mutex_destroy(&app.queue_mutex);
    pthread_cond_destroy(&app.queue_cond);

    if (app.event_workers) {
        free(app.event_workers);
        app.event_workers = NULL;
    }

    clear_cache_dir();
    pthread_mutex_destroy(&app.index_cache_mutex);

    free_config(&app.config);
}

int main() {
    int ret = init_app();
    if (ret != 0)
        return ret;

    thread_join();

    uninit_app();
    return 0;
}
