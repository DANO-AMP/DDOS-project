#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "headers/queue.h"
#include "headers/main.h"
#include "headers/connection.h"

void bruter_queue_ip(char *address)
{
    pthread_mutex_lock(&mutex);

    for(int i = 0; i < 999999; i++)
    {
        if(!queue[i].queued)
        {
            ATOMIC_INC(&left_in_queue);
            strcpy(queue[i].address, address);
            queue[i].queued = 1;
            break;
        }
    }

    pthread_mutex_unlock(&mutex);
}

void *handle_queued()
{
    while(1)
    {
        if(processing <= ACTUAL_MAX_CONS)
        {
            for(int i = 0; i < 999999; i++)
            {
                if(queue[i].queued)
                {
                    start_connection(queue[i].address, NULL);

                    queue[i].queued = 0;
                    memset(queue[i].address, 0, 16);
                    ATOMIC_DEC(&left_in_queue);
                }

                if(processing >= ACTUAL_MAX_CONS)
                    break;
            }
        }

        sleep(1);
    }
}
