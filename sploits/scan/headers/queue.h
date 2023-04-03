#pragma once

typedef struct 
{
    int queued;
    char address[16];
} Queue;

Queue *queue;

void *handle_queued();
void bruter_queue_ip(char *);