#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "headers/resolve.h"
#include "headers/includes.h"

void changeURLtoDNS( char * dnsBufferOut, unsigned int dnsBufferOutSize,  char * url) {
	int curIndex= 0;
        int maxIndex = strlen(url); //
	if(!maxIndex)
	 return;
	char buffer[2];

	memset(&buffer,0,2);
	memset(dnsBufferOut, 0, dnsBufferOutSize);


    char * curPtr = url;
	int breakOut = 0;

	while(1){
		char * nxtPtr = strchr(curPtr, '.');
		if (nxtPtr == 0) {
			nxtPtr = url + maxIndex; 		// don't read nxtPtr
			breakOut = 1;
		} else {
			
		}
		buffer[0] = (char)(nxtPtr - curPtr); 		// could overflow 
		if(strlen(dnsBufferOut) + 1 >= dnsBufferOutSize)
		 return;
		strcat(dnsBufferOut, buffer); 					  
		if(strlen(dnsBufferOut) + (char)(nxtPtr - curPtr) >= dnsBufferOutSize)
		 return;
		strncat(dnsBufferOut, curPtr, (char)(nxtPtr - curPtr));       
		if(breakOut)
		  break;
    	curPtr = nxtPtr + 1;
	}

}

#ifdef DEBUG
void DumpHex( void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}
#endif

unsigned long getHostByName( unsigned char * host ){
	unsigned char buf[0xffff];
	char buffer[255];
	
	
	struct DNS_HEADER_SIMPLE simple;
	DNS_QUESTION ourQueryHeader;
	memset(buf,0,0xffff);
	memset(&ourQueryHeader,0,sizeof(DNS_QUESTION));
	memset(&simple,0,sizeof(struct DNS_HEADER_SIMPLE));


	simple.id= 0x1;
	simple.rd= 1;
	simple.qdcount= htons(1);

	unsigned char * index = buf;

	
	memcpy(buf,&simple,sizeof(struct DNS_HEADER_SIMPLE));
	index += sizeof(struct DNS_HEADER_SIMPLE);


	changeURLtoDNS(buffer,255,host);
	size_t urlSize = strlen(buffer);
	memcpy(index,buffer,urlSize);
	index += urlSize + 1; // copy + nul byte

	ourQueryHeader.qtype = htons(1); // a record
	ourQueryHeader.qclass = htons(1); // Internet addresses

	memcpy(index,&ourQueryHeader,sizeof(DNS_QUESTION));
	index += sizeof(DNS_QUESTION);
	
	struct sockaddr_in a;
	struct sockaddr_in dest;

	int tempSize = sizeof(buf);

	int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	/*
	struct in_addr myReference;
	inet_aton("4.2.2.1", &myReference);
	dest.sin_addr.s_addr = myReference.s_addr;
	*/
	dest.sin_family = AF_INET;	
	dest.sin_addr.s_addr = INET_ADDR(4,2,2,1);
	dest.sin_port = htons(53);
             //fd      buf     size  flag  sockaddr dest
	if(sendto(s, (char*)buf, index-buf, 0,(struct sockaddr*)&dest, sizeof(dest)) <= 0) {
		// send failed
		printf("send\r\n");
		return -1;
	}
 	int recvRet = recvfrom(s,buf,0xffff,0,(struct sockaddr*)&dest,(socklen_t*)&tempSize) ;
	if(recvRet < 0){
		// recv failed
		printf("recv\r\n");
		return -1;
	}
	
	//DumpHex(buf,recvRet);
	
	struct DNS_HEADER_SIMPLE* srvHeader = (struct DNS_HEADER_SIMPLE*)buf;

	unsigned char * indexPtr = (unsigned char *)srvHeader;
	indexPtr += sizeof(struct DNS_HEADER_SIMPLE);
	// should be pointing to the begginning of the data sections
	// we need to skip some sections of questions to get to answers
	for(int i = 0; i<ntohs(srvHeader->qdcount); i++){
		// for each query we need to skip a string and 4 bytres
		indexPtr += strlen(indexPtr) + 1; // skip the url encoded
		indexPtr += 4; // skip the 4 qry header bytes
	}

	//DumpHex(indexPtr,0x10);
	for(int i = 0; i<ntohs(srvHeader->ancount); i++){
			// we are left with answers only.
			// first part is a qname - which may be a pointer
			// read two bytes ptr
		unsigned char val = (*indexPtr) & 0xFF;
		unsigned char ptr = *indexPtr & 0xC0;
		for(int x = 0; x < 20; x++){
			if(ptr == 0xC0) // if two first bits are set here its a ptr type 
			{
				indexPtr++;
				unsigned short fixedVal = ((unsigned short)(val << 8)) | (*indexPtr);	// index into buffer data to read string
			//		printf("%u\n", (unsigned int)fixedVal);
				// ptr string is alsways last.
				indexPtr++; // advance to next field after cname
				break; 
			} else {
				unsigned char skipLength = *indexPtr;
				indexPtr++; 			// point to label begging
				indexPtr += skipLength; // after this check for null and bail or loop
				
			}
			if(*indexPtr == 0){
				// null label terminates.
				indexPtr++;		
				break;
			} 
				
		}
		// by the time we are here we are at the end of the cname in the answer section
		unsigned short type = ntohs( *((unsigned short *)indexPtr) ); 	// 00 01 == A record
		indexPtr += 2;
		unsigned short class = ntohs( *((unsigned short *)indexPtr) ); 	// 00 01 == AF INET / Internet address
		indexPtr += 2;
		unsigned int ttl = ntohl( *((unsigned int *)indexPtr) );	  	// seconds to cache result
		indexPtr += 4;
		unsigned short rdlength = ntohs( *((unsigned short *)indexPtr) );// rdata size
		indexPtr += 2;
		if(type == 1 && class == 1 && rdlength == 4){
			
			//printf("%s\r\n", inet_ntoa(*((struct in_addr *)indexPtr)));
			return ((struct in_addr *)indexPtr)->s_addr;
		}		else {
			return 0;
		}
		
	
	}

	return 0;	
}
