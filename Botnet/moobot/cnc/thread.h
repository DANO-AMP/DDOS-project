#pragma once

#include <pthread.h>
#include <stdint.h>

struct thread_data
{
    int fd;
    uint32_t time;
    uint32_t timeout;
    pthread_barrier_t *barrier;
    pthread_t *admin_thread;
};
