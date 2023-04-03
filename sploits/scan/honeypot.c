#include <stdio.h>
#include <string.h>

#include "headers/main.h"
#include "headers/honeypot.h"

int check_honeypot(Brute *brute)
{
    if(strstr(brute->rdbuf, "richard"))
        return 1;
    return 0;
}