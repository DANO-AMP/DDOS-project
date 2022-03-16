#pragma once

#include "main.h"

enum
{
    TYPE_COMMAND = 0,
    TYPE_FLOOD = 1,
    TYPE_AUTH = 2,
    TYPE_KILL = 3
};

struct clients
{
    int fd;
    uint32_t addr;
    char connected;
    char authenticated;
    uint32_t timeout;
    char arch[64];
    uint16_t arch_len;
};

struct relay
{
    uint8_t type;
    uint16_t b1, b2, b3, b4, b5, b6;
    char buf[64];
};

struct clients *client_list;
