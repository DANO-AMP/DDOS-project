#pragma once

#include <stdint.h>

#include "def.h"

enum
{
    TRUE = 1,
    FALSE = 0,
    MAX_EVENTS = 1000000,
    TIMEOUT = 900, // was 300
    VERIFY_TIMEOUT = 15,
    ADMIN_TIMEOUT = 10,
    CLIENT_PORT = 5683,
    ADMIN_PORT = 6596
};

static int client_fd = -1;
static int admin_fd = -1;
static int efd = -1;

#define MANAGER_AUTH_KEY "!BIGREPS"
