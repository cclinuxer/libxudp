/*
 * Copyright (c) 2021 Alibaba Group Holding Limited
 * Express UDP is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>


static unsigned short checksum(unsigned short *buf, int bufsz){
    	unsigned long sum = 0xffff;

    	while(bufsz > 1){
        	sum += *buf;
        	buf++;
        	bufsz -= 2;
    	}

    	if(bufsz == 1)
        	sum += *(unsigned char*)buf;

    	sum = (sum & 0xffff) + (sum >> 16);
    	sum = (sum & 0xffff) + (sum >> 16);

    	return ~sum;
}

int ping(const char *ip)
{
    	int sd;
    	struct icmphdr hdr;
    	struct sockaddr_in addr;
    	int num;
    	char buf[1024];

    	sd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    	if(sd < 0){
		return -1;
    	}

    	memset(&hdr, 0, sizeof(hdr));

    	hdr.type = ICMP_ECHO;
    	hdr.code = 0;
    	hdr.checksum = 0;
    	hdr.un.echo.id = 0;
    	hdr.un.echo.sequence = 0;

    	hdr.checksum = checksum((unsigned short*)&hdr, sizeof(hdr));

    	addr.sin_family = PF_INET; // IPv4
	addr.sin_addr.s_addr = inet_addr(ip);

    	num = sendto(sd, (char*)&hdr, sizeof(hdr), 0,
		     (struct sockaddr*)&addr, sizeof(addr));
    	if(num < 1){
		return -1;
    	}

    	memset(buf, 0, sizeof(buf));

    	num = recv(sd, buf, sizeof(buf), 0);
    	if(num < 1){
		return -1;
    	}

    	close(sd);
    	return 0;
}
