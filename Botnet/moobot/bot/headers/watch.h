#pragma once

#define WDIOC_KEEPALIVE 0x80045705
#define WDIOC_SETOPTIONS 0x80045704

void find_watchdog_driver(char *);
void kill_watchdog_maintainer(void);
