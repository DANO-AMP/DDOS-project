#define _GNU_SOURCE

#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#include "headers/includes.h"
#include "headers/rand.h"
#include "headers/util.h"

static uint32_t x = 0, y = 0, z = 0, w = 0;
static char set[] = "cz2isg9l8u7b5xw0mr6jhfvpkteyo3nadq14";
static char upper_set[] = "AVPNWGUZLYORESJTHQDFCXBIMK";

void init_rand(void)
{
    x = time(NULL);
    y = getpid() ^ getppid();
    z = clock();
    w = z ^ y;
}

uint32_t rand_new(void)
{
    uint32_t t = x;
    t ^= t << 11;
    t ^= t >> 8;
    x = y; y = z; z = w;
    w ^= w >> 19;
    w ^= t;
    return w;
}

void rand_string(void *buf, int len)
{
    while(len--)
    {
        *(char *)buf++ = set[rand_new() % util_strlen(set)];
    }
}

void rand_string_upper(void *buf, int len)
{
    while(len--)
    {
        *(char *)buf++ = upper_set[rand_new() % util_strlen(upper_set)];
    }
}
