#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "headers/main.h"
#include "headers/connection.h"

void *watch_time()
{
    int fake_time;

    while(1)
    {
        fake_time = time(0);

        for(int i = 0; i < maxfds + 1; i++)
        {
            if(bruter[i].fd)
            {
                if((fake_time - bruter[i].last_recv) >= TIMEOUT && bruter[i].fd != 0)
                {
                    disconnect(&bruter[i]);
                    ATOMIC_INC(&failed);
                }
            }
        }

        sleep(1);
    }
}