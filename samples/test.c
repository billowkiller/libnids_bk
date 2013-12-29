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
#include <glib.h>
#include <zlib.h>
#include <nids.h>
#include "cache.h"

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

extern int inflate_init(z_stream *strm);
extern int inflate_data(z_stream *strm, int size, char *compressdata);

static GHashTable *table;
static int pack_num = 0;
static z_stream strm;

/*
 * TODO: free stream_buf when delete table key
 */
void free_value(gpointer data) 
{      
    stream_buf *stmb = (stream_buf *)data;
    free(stmb->key);
    free(stmb->eden);
    free(stmb);
}

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

static int length=0;
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

        stream_buf *stmb = (stream_buf *)malloc(sizeof(stream_buf));
        stmb_init(stmb, buf);
        g_hash_table_insert(table, buf, stmb);
        inflate_init(&strm);
        return;
    }

    if (a_tcp->nids_state == NIDS_CLOSE)
    {
        stream_buf *stmb = g_hash_table_lookup(table, buf);
        length += EDEN_DISTANCE(stmb);
        printf("length = %d\n", length);
        inflate_data(&strm, EDEN_DISTANCE(stmb), EDEN_POS(stmb));
        g_hash_table_remove(table, buf);
        fprintf (stderr, "%s closing\n", buf);
        return;
    }

    if (a_tcp->nids_state == NIDS_DATA && a_tcp->client.count_new)
    {
        pack_num++;
        stream_buf *stmb = g_hash_table_lookup(table, buf);

        struct half_stream *hlf = &a_tcp->client;

        //hlf->data 
        //hlf->ip_tcp_header
        char *payload = hlf->data;
        int payload_len = hlf->count_new;
        if(pack_num == 1)
        {
            payload =  strstr(payload, "\r\n\r\n") + 4;
            payload_len -= payload - (char *)(hlf->data);
//            printf("%.*s\n", hlf->count_new-payload_len, (char *)hlf->data);
        }
        if(stmb_memcpy(stmb, payload_len, payload))
        {
            length += EDEN_SIZE;
            inflate_data(&strm, EDEN_SIZE, EDEN_READY(stmb));
        }
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
    table = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, free_value);
    if (!nids_init ())
    {
            fprintf(stderr,"%s\n",nids_errbuf);
            exit(1);
    }
    nids_register_tcp(tcp_callback);
    monitor();
    return 0;
}
