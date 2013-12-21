/*
 * =====================================================================================
 *
 *       Filename:  test.c
 *
 *    Description:  test unit for libnids
 *                  -  input: ip package
 *                  -  output: ordered ip link
 *
 *        Version:  1.0
 *        Created:  12/14/2013 12:42:15 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  billowkiller (), billowkiller@gmail.com
 *   Organization:  
 *
 * =====================================================================================
 */

#include <pcap.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include "nids.h"
#include "ngx_queue.h" 

#define int_ntoa(x)        inet_ntoa(*((struct in_addr *)&x))

#ifndef HEADCAL
#define HEADCAL
        #define TCPH(X) ((char *)(X)+IPHL(X)) //ip jump to tcp
        #define TCPHL(X) (((struct tcphdr *)(X))->doff * 4) //tcp header length
        #define IPHL(X) (((struct iphdr *)(X))->ihl * 4)  //ip header length
        #define IPL(X) (ntohs(((struct iphdr *)(X))->tot_len)) //ip length
        #define PAYLOADL(X) (IPL(X)-IPHL(X)-TCPHL(TCPH(X))) //payload length
        #define SEQ(X) (ntohl(((struct tcphdr *)(X))->seq)) //tcp seq number
#endif

//ip packet queue structure  
typedef struct  
{  
    void* ip_tcp_header;  
    void* payload;
    int payload_len;  
} ip_pack;  

typedef struct  
{  
    ip_pack pack;  
    ngx_queue_t queue;  
} pack_queue_t;  

// struct tuple4 contains addresses and port numbers of the TCP connections
// the following auxiliary function produces a string looking like
// 10.0.0.1,1024,10.0.0.2,23
char * adres (struct tuple4 addr)
{
    static char buf[256];
    strcpy (buf, int_ntoa (addr.saddr));
    sprintf (buf + strlen (buf), ",%i,", addr.source);
    strcat (buf, int_ntoa (addr.daddr));
    sprintf (buf + strlen (buf), ",%i", addr.dest);
    return buf;
}

ngx_queue_t *ip_queue;
static int pack_num = 0;
void tcp_callback (struct tcp_stream *a_tcp, void ** this_time_not_needed)
{
    char buf[1024];
    strcpy (buf, adres (a_tcp->addr)); // we put conn params into buf
    if (a_tcp->nids_state == NIDS_JUST_EST)
    {
    // connection described by a_tcp is established
    // here we decide, if we wish to follow this stream
    // sample condition: if (a_tcp->addr.dest!=23) return;
    // in this simple app we follow each stream, so..
        a_tcp->client.collect++; // we want data received by a client
        a_tcp->server.collect++; // and by a server, too
        a_tcp->server.collect_urg++; // we want urgent data received by a
                                     // server

        printf("ip_queue set up\n");
        ip_queue = (ngx_queue_t *)malloc(sizeof(ngx_queue_t));
        ngx_queue_init(ip_queue);
        return;
    }

    if (a_tcp->nids_state == NIDS_CLOSE)
    {
        fprintf (stderr, "%s closing\n", buf);

        pack_num = 0;
        ngx_queue_t *q = ngx_queue_head(ip_queue);  
        for (; q != ngx_queue_sentinel(ip_queue); q = ngx_queue_next(q))  
        {  
            pack_queue_t *pack = ngx_queue_data(q, pack_queue_t, queue);
            printf("*****pack %d******\n%.*s\n", ++pack_num, pack->pack.payload_len, (char *)(pack->pack.payload));
        }  
        return;
    }

    if (a_tcp->nids_state == NIDS_DATA && a_tcp->client.count_new)
    {
        struct half_stream *hlf = &a_tcp->client;

        //hlf->data 
        //hlf->ip_tcp_header
        pack_queue_t * pack = (pack_queue_t *)malloc(sizeof(pack_queue_t));
        pack->pack.ip_tcp_header = malloc(IPL(hlf->ip_tcp_header));
        memcpy(pack->pack.ip_tcp_header, hlf->ip_tcp_header, IPL(hlf->ip_tcp_header));
        pack->pack.payload_len = PAYLOADL(hlf->ip_tcp_header);
        pack->pack.payload = malloc(pack->pack.payload_len);
        memcpy(pack->pack.payload, hlf->data, pack->pack.payload_len);

        ngx_queue_init(&pack->queue);
     
        //insert this point into the points queue  
        ngx_queue_insert_tail(ip_queue, &pack->queue);
        printf("pack %d into queue\n", ++pack_num);
        printf("    |- length %d\n", pack->pack.payload_len);
    }
  return ;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
        struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
        if(IPPROTO_TCP == iph->protocol)
        {
            nids_store_ip((u_char *)iph, IPL(iph));
        }
}

void monitor()
{
        char errbuf[100];
        bpf_u_int32 mask;                /* Our netmask */
        bpf_u_int32 net;                /* Our IP */
        pcap_t *handle; //Handle of the device that shall be sniffed
        struct bpf_program fp;                /* The compiled filter */
        char *devname = "eth0";

        /* Find the properties for the device */
        if (pcap_lookupnet(devname, &net, &mask, errbuf) == -1) {
                fprintf(stderr, "Couldn't get netmask for device %s: %s\n", devname, errbuf);
                net = 0;
                mask = 0;
        }
        handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);

        if (handle == NULL)
        {
                fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
                exit(1);
        }
        char filter_exp[] = "host 211.147.4";

        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
                fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
                exit(2);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
                fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
                exit(2);
        }
        printf("libpcap Done\n");

        //Put the device in sniff loop
        pcap_loop(handle , -1 , process_packet , NULL);
}

int main ()
{
  if (!nids_init ())
  {
          fprintf(stderr,"%s\n",nids_errbuf);
          exit(1);
  }
  nids_register_tcp(tcp_callback);
  monitor();
  return 0;
}
