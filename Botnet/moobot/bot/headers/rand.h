#pragma once

#include <stdint.h>

void init_rand(void);
uint32_t rand_new(void);
void rand_string(void *, int);
void rand_string_upper(void *, int);
