/*
 * =====================================================================================
 *
 *       Filename:  data_send.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  01/25/2013 04:19:02 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Billowkiller (bk), billowkiller@gmail.com
 *   Organization:
 *
 * =====================================================================================
 */
#include "data_send.h"

#define PSEUDO_SIZE (sizeof(struct pseudo_hdr))

inline u_short in_cksum(u_short *addr, int len)
{
    register int nleft = len;
    register u_short *w = addr;
    register int sum = 0;
    u_short answer = 0;

     /* Our algorithm is simple, using a 32 bit accumulator (sum), we add
      * sequential 16 bit words to it, and at the end, fold back all the
      * carry bits from the top 16 bits into the lower 16 bits. */

     while (nleft > 1) {
         sum += *w++;
         nleft -= 2;
     }

     /* mop up an odd byte, if necessary */
     if (nleft == 1) {
         *(u_char *)(&answer) = *(u_char *) w;
         sum += answer;
     }

     /* add back carry outs from top 16 bits to low 16 bits */
     sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
     sum += (sum >> 16); /* add carry */
     answer = ~sum; /* truncate to 16 bits */
     return(answer);
}

int _recal_cksum(char *data)
{
	struct iphdr *iph = (struct iphdr *)data;
	struct tcphdr *tcph = (struct tcphdr *)(data + IPHL(iph));
	int datalen = ntohs(iph->tot_len) - IPHL(iph) - TCPHL(tcph);

	char * pseudo = (char *)malloc(PSEUDO_SIZE + TCPHL(tcph) + datalen);

	//tcp checksum
	struct pseudo_hdr * pseudo_h = (struct pseudo_hdr *)pseudo;
	tcph->check = 0;
	pseudo_h->saddr = iph->saddr;
	pseudo_h->daddr = iph->daddr;
	pseudo_h->mbz = 0;
    pseudo_h->ptcl = IPPROTO_TCP;
    pseudo_h->tcpl = htons(ntohs(iph->tot_len) - IPHL(iph));
    memcpy(pseudo + PSEUDO_SIZE, tcph, TCPHL(tcph));
   	memcpy(pseudo + PSEUDO_SIZE + TCPHL(tcph), data+IPHL(iph)+TCPHL(tcph), datalen);

   	tcph->check = in_cksum(pseudo, PSEUDO_SIZE + TCPHL(tcph) + datalen);
   	free(pseudo);

   	//end
   	return ntohs(iph->tot_len);
}

int send_direct(char *data)
{
	_send_data(data, 0);
	return 1;
}

int send_filter(char *data)
{
	_send_data(data, 1);
	return 1;
}

int send_rst(char *data)
{
	struct iphdr *iph = (struct iphdr *)data;
	struct tcphdr *tcph = (struct tcphdr *)(data + iph->ihl * 4);

	char * pack_msg = (char *)malloc(TCPHL(tcph) + IPHL(iph));
	memcpy(pack_msg, data, TCPHL(tcph) + IPHL(iph));
	
	struct iphdr * this_iph = (struct iphdr *)pack_msg;
	struct tcphdr *this_tcph = (struct tcphdr *)(pack_msg + IPHL(iph));
	unsigned long seq = ntohl(this_tcph->seq);

	this_iph->tot_len = htons(TCPHL(tcph)+IPHL(iph));	//payload empty
	this_tcph->rst = 1;

	_send_data(pack_msg, 1);	//to server

	this_iph->saddr = iph->daddr;  //from client
	this_iph->daddr = iph->saddr;
	this_tcph->dest = tcph->source;
	this_tcph->source = tcph->dest;
	this_tcph->ack = 1;
	this_tcph->psh = 1;
	this_tcph->rst = 1;
	this_tcph->seq = this_tcph->ack_seq;
	this_tcph->ack_seq = htonl(seq+1);

	_send_data(pack_msg, 1);
	free(pack_msg);
}

int _send_data(char *data, int flag)
{
	struct iphdr *iph = (struct iphdr *)data;
	struct tcphdr *tcph = (struct tcphdr *)(data + iph->ihl * 4);
	//set dest address
	bzero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = iph->daddr;
	sa.sin_port = ntohs(tcph->dest);

	if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
		perror("create socket error!");
		return 0;
	}

	setsockopt(fd, IPPROTO_IP, IP_HDRINCL, (char*)&optval, sizeof(optval));

	if(flag)
		_recal_cksum(data);

//	printf("%d\n",ntohs(iph->tot_len));
	if(sendto(fd, data, ntohs(iph->tot_len), 0, (struct sockaddr *)&sa, sizeof(sa))<0)
	{
		perror("tcp error");
		printf("%ip packet length = d\n",ntohs(iph->tot_len));
		printf("content:%s\n", tcph + TCPHL(tcph));

		return 0;
	}
	close(fd);	
	return 1;
}

