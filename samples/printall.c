/*
Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
See the file COPYING for license details.
*/


#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include "nids.h"

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

#ifndef HEADCAL
#define HEADCAL
	#define TCPHL(X) ((X)->doff * 4)
	#define IPHL(X) ((X)->ihl * 4)
	#define IPL(X) (ntohs((X)->tot_len))
	#define DATAL(X,Y) (IPL(X)-IPHL(X)-TCPHL(Y))
	#define SEQ(X) (ntohl((X)->seq))
#endif

extern int send_direct(char *data);
extern int send_rst(char *data);
extern void ungz_initialize();
extern char* memungz(const char* buf,int length);
static int ifile = 0;
char *filen[12] = {"0","1","2","3","4","5","6","7","8","9","10","11"};
// struct tuple4 contains addresses and port numbers of the TCP connections
// the following auxiliary function produces a string looking like
// 10.0.0.1,1024,10.0.0.2,23
char *
adres (struct tuple4 addr)
{
  static char buf[256];
  strcpy (buf, int_ntoa (addr.saddr));
  sprintf (buf + strlen (buf), ",%i,", addr.source);
  strcat (buf, int_ntoa (addr.daddr));
  sprintf (buf + strlen (buf), ",%i", addr.dest);
  return buf;
}

/*	only accept status code 200
 *  relocation may affect
 * 	@return
 * 		0  do not handle
 * 		-1 continue data
 * 		1  handle data begin
 */
int http_parse(const char *data, char **split)
{
	if(strncmp(data, "HTTP", 4))
		return -1;

	if(strncmp(data+9, "200", 3))
		return 0;
	
	char * type = strstr(data, "Type");
	if(type) type += 6; else return -1;
	if(strncmp(type, "text/html", 9))
		return 0;
	
	if(type)
	{
		char * inflate = strstr(data, "Encoding");
		if(inflate) inflate += 10; else return 0;
		if(strncmp(inflate, "gzip", 4))
			return 0;
	}

	*split = strstr(type, "\r\n\r\n") + 4;

	return 1;

}

//0 discard
int nids_ip_filter(struct iphdr *ipheader, int len)
{
	struct iphdr *iph = (struct iphdr*)(ipheader);
	struct tcphdr *tcph=(struct tcphdr*)((char *)iph + IPHL(iph));
	
	if(IPPROTO_TCP != iph->protocol)
		return 0;
	
	return 1;
}

int dlength = 0;
void deal_data(struct half_stream *hlf, char *split)
{
	if(split) write(2, hlf->data, 100);
    printf("\n");
	char * payload = hlf->data;
	int length = hlf->count_new;
	if(split)
	{
		payload = split;
		length -= payload - hlf->data;
	}
	struct iphdr *iph = (struct iphdr*)(hlf->ip_tcp_header);
	struct tcphdr *tcph=(struct tcphdr*)((char *)iph + IPHL(iph));
	printf("seq = %ld, length = %d\n", ntohl(tcph->seq), length);
	dlength += length;
	
	//ungzip
	char* ungzip=memungz(payload, length);
	printf("%s\n",ungzip);
	free(ungzip);
	

//    send_direct(hlf->data);
// 	
// 	FILE *tempfile = fopen(filen[ifile++], "w");
// 	if(tempfile)
// 	{
// 		fprintf(tempfile, "%.*s\n", length, payload);
// 		//fwrite(payload, length, 1, tempfile);
// 		fclose(tempfile);
// 		printf("close\n");
// 	}
//	printf( "%.*s\n", length, payload);
	/*
	 * unzip data in another thread 
	 * return the string and then check validation
	 * resent or not
	 */
//	int i = 1;
//	if(i)
//		send_direct((char *)(node->iphdr));
//	else
//		send_rst((char *)(node->iphdr));
}

//tcp preprocessor
void tcp_filter(char * data)
{
    struct iphdr *iph = (struct iphdr*)(data);
    struct tcphdr *tcph=(struct tcphdr*)((char *)iph + IPHL(iph));
//	printf("seq = %ld\n", ntohl(tcph->seq));
//     if(!(DATAL(iph, tcph)))
// 	{
//         send_direct(data);
// 	}
}

void
tcp_callback (struct tcp_stream *a_tcp, void ** this_time_not_needed)
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
#ifdef WE_WANT_URGENT_DATA_RECEIVED_BY_A_CLIENT
      a_tcp->client.collect_urg++; // if we don't increase this value,
                                   // we won't be notified of urgent data
                                   // arrival
#endif
      return;
    }
  if (a_tcp->nids_state == NIDS_CLOSE)
    {
      // connection has been closed normally
      fprintf (stderr, "%s closing\n", buf);
	  fprintf(stderr, "dlength = %d\n", dlength);
      return;
    }

  if (a_tcp->nids_state == NIDS_DATA)
    {
      // new data has arrived; gotta determine in what direction
      // and if it's urgent or not

      struct half_stream *hlf;
	  
      if (a_tcp->client.count_new)
		{
		hlf = &a_tcp->client; // analogical

		char *split = NULL;
	  
		//printf("hlf->count_new = %d\n", hlf->count_new);
		struct iphdr *iph = (struct iphdr*)(hlf->ip_tcp_header);
 		if(hlf->count_new && !http_parse(hlf->data, &split))
		{
// 			struct iphdr *iph = (struct iphdr*)(hlf->ip_tcp_header);
// 			struct tcphdr *tcph=(struct tcphdr*)((char *)iph + IPHL(iph));
// 			char *data = (char *)malloc(IPL(iph));
// 			memcpy(data, iph, IPL(iph));
// 			memcpy(data+IPHL(iph)+TCPHL(tcph), hlf->data, DATAL(iph, tcph));
// 			
// 			send_direct(data);
 			nids_free_tcp_stream(a_tcp);
		}
 		else  //handle gzip file
        {
            strcat (buf, "(<-)");
            fprintf(stderr,"%s",buf);
 			deal_data(hlf, split);
        }
      }
    }
  return ;
}

int 
main ()
{
  // here we can alter libnids params, for instance:
//   nids_params.ip_filter=nids_ip_filter;
  nids_params.pcap_filter = "host 211.147.4 and port 80";
  if (!nids_init ())
  {
  	fprintf(stderr,"%s\n",nids_errbuf);
  	exit(1);
  }
  nids_register_tcp (tcp_callback);
  nids_register_tcp_filter(tcp_filter);
  read_kw_file("keywords");
  ungz_initialize();
  nids_run ();
  return 0;
}

