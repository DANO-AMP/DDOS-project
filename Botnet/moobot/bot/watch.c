#define _GNU_SOURCE

#ifdef DEBUG
	#include <stdio.h>
#endif
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>

#include "headers/includes.h"
#include "headers/util.h"
#include "headers/watch.h"

// The point of this is to scan /dev for any files with the keyword "watchdog" and try to contact the drivers ioctl interface

static void maintain_watchdog_driver(char *fn, char *dir_to_scan)
{
    watch_pid = fork();
    if(watch_pid > 0 || watch_pid == -1)
    {
        return;
    }

    int watchdog_fd = 0;
    int timeout = 1;
    char buf[256];
    BOOL watchdog_found = FALSE;

    util_strcpy(buf, dir_to_scan);
    util_strcat(buf, "/");
    util_strcat(buf, fn);

    if((watchdog_fd = open(buf, 2)) != -1)
    {
    	#ifdef DEBUG
    		printf("[watchdog] Opened potential watchdog driver %s\n", buf);
    	#endif
    	// Attempt to message the drivers ioctl interface
    	ioctl(watchdog_fd, WDIOC_SETOPTIONS, &timeout);
    	watchdog_found = TRUE;
    }

    if(!watchdog_found)
    {
    	#ifdef DEBUG
    		printf("[watchdog] Broadcasting to the watchdog driver(s) (%s) ioctl interface\n", buf);
    	#endif
        while(TRUE)
        {
        	#ifdef DEBUG
        		printf("[watchdog] Sending ioctl call to the interface (%s)...\n", buf);
        	#endif
            ioctl(watchdog_fd, WDIOC_KEEPALIVE, 0);
            sleep(5);
        }
    }
    #ifdef DEBUG
        printf("[watchdog] Failed to open the watchdog driver (%s)\n", buf);
    #endif
    exit(0);
}

void kill_watchdog_maintainer(void)
{
    kill(watch_pid, 9);
}

void find_watchdog_driver(char *dir_to_scan)
{
    watch_pid = fork();
	if(watch_pid > 0 || watch_pid == -1)
	{
		return;
	}
	//sleep(1);
	#ifdef DEBUG
	    printf("[watchdog] Scanning for watchdog driver...\n");
	#endif
	DIR *dir;
    struct dirent *file;

    if((dir = opendir(dir_to_scan)) == NULL)
    {
        #ifdef DEBUG
      	    printf("[watchdog] Failed to open /dev\n");
       	#endif
        exit(0);
    }

    while((file = readdir(dir)) != NULL)
    {
        // No such directory or file
       	if(*(file->d_name) == '.')
       	{
       	    continue;
       	}
       	#ifdef DEBUG
       	    printf("[watchdog] Scanning %s in (/dev)\n", file->d_name);
       	#endif
        // Check for string name
       	if(util_char_search(file->d_name, util_strlen(file->d_name), "watchdog", 8) != -1)
       	{
       	    #ifdef DEBUG
       			printf("[watchdog] Found file that matches the string 'watchdog' (%s)\n", file->d_name);
       		#endif
       		maintain_watchdog_driver(file->d_name, dir_to_scan);
       		break;
       	}
       	sleep(1);
    }
    closedir(dir);
    exit(0);
}
