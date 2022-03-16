#pragma once

#include <stdint.h>

#include "includes.h"

uint16_t check_sum_generic(uint16_t *, uint32_t);
uint16_t check_sum_tcp_udp(struct iphdr *, void *, uint16_t, int);
