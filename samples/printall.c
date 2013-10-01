/*
Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
See the file COPYING for license details.
*/


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include "nids.h"

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

#ifndef HEADCAL
#define HEADCAL
	#define TCPHL(X) ((X)->doff * 4)
	#define IPHL(X) ((X)->ihl * 4)
	#define IPL(X) (ntohs((X)->tot_len))
	#define SEQ(X) (ntohl((X)->seq))
#endif

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

void deal_data(struct half_stream *hlf, char *split)
{
	struct iphdr *iph = (struct iphdr *)(hlf->data);
	struct tcphdr *tcph = (struct tcphdr *)(iph + IPHL(iph));
	char * payload = (char *)iph;
	int length = 0;
	if(split)
	{
		payload = split;
		length -= payload - hlf->data;
	}
// 	
// 	FILE *tempfile = fopen(filen[ifile++], "w");
// 	fwrite(payload, length, 1, tempfile);
// 	fclose(tempfile);
	printf( "%.*s\n", length, payload);
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
		struct iphdr *iph = (struct iphdr*)(hlf->data);
		printf("iph->protocol = %d\n", iph->protocol);
// 		if(hlf->count_new && !http_parse(hlf->data, &split))
// 			nids_free_tcp_stream(a_tcp);
// 		else  //handle gzip file
// 			deal_data(hlf, split);
      }
    }
  return ;
}

int 
main ()
{
  // here we can alter libnids params, for instance:
//   nids_params.ip_filter=nids_ip_filter;
//   nids_params.pcap_filter = "host 204.232.175.78";
  if (!nids_init ())
  {
  	fprintf(stderr,"%s\n",nids_errbuf);
  	exit(1);
  }
  nids_register_tcp (tcp_callback);
  nids_run ();
  return 0;
}

