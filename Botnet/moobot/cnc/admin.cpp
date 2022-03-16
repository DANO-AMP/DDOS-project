#include <iostream>
#include <string.h>
#include <string>
#include <sstream>
#include <time.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "admin.h"
#include "main.h"
#include "command.h"

int admin_login(struct admin *login)
{
    char ret = FALSE;
    if(!strcmp(login->user_ptr, ADMIN_USER1) && !strcmp(login->pass_ptr, ADMIN_PASS1) || 
    !strcmp(login->user_ptr, ADMIN_USER2) && !strcmp(login->pass_ptr, ADMIN_PASS2) ||
    !strcmp(login->user_ptr, ADMIN_USER3) && !strcmp(login->pass_ptr, ADMIN_PASS3) ||
	!strcmp(login->user_ptr, ADMIN_USER4) && !strcmp(login->pass_ptr, ADMIN_PASS4))
    {
        login->username = login->user_ptr;
        login->password = login->pass_ptr;
        ret = TRUE;
    }
    return ret;
}
