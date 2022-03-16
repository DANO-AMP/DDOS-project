#pragma once

struct DNS_HEADER_SIMPLE
{
unsigned short id; 		// 16 bit id - assigned by program generating the query.
unsigned char rd : 1;		// 1 bit recursion - tells the server if will will be querying recursively
unsigned char tc : 1; 		// 1 bit specifies that message was truncated
unsigned char aa : 1;		// 1 bit specifying in responses if the answer is authoritative
unsigned char opcode: 4;	// 4 bits for type of query. 0 is standard query.
unsigned char qr :1;		// 1 bit specifying if this is a query (0) or response (1). 0 in our requests, 1 in responses received
unsigned char rcode : 4;	// 4 bit response code 0 no error, 1 format error ( server couldnt parse our query), 2 server failure ( problem with name server), 3 name error (only valid from authoritative server - does next exist), 4 not implemented / supported, 5 refused for policy reasons
unsigned char z  : 3;		// 3 bit reserved for future use
unsigned char ra : 1;		// 1 bit Recursion available - server tells us if they support recursive query


unsigned short qdcount;		// 16 bit number of entries in the question section. set to 1
unsigned short ancount;		// 16 bit number specifying number of answers. set to 0 on requests
unsigned short nscount;		// 16 bit number of name server resource records in authority records section. set to 0. 
unsigned short arcount;		// 16 bit integer specifying number of resource records. ignore.
};

typedef struct 
{
 unsigned short qtype;	// two octet code specifying the type of query. 0x0001 for A. 0x000f for MX 0x0002 for NS. and others..
 unsigned short qclass;	// two octet code specifying class of query. 0x0001 - specifies internet addresses.
}DNS_QUESTION;

typedef struct
{
 unsigned char* qname;
 struct DNS_QUESTION *dns_question;
} DNS_QUERY;

void changeURLtoDNS( char * dnsBufferOut, unsigned int dnsBufferOutSize,  char * url);
#ifdef DEBUG
void DumpHex( void* data, size_t size);
#endif
unsigned long getHostByName( unsigned char * host );
