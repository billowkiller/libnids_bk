#include <stdio.h>  
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "include.h"

struct pseudo_hdr { /* See RFC 793 Pseudo Header */
    u_long saddr, daddr;/* source and dest address */
    u_char mbz, ptcl;	/* zero and protocol */
    u_short tcpl;	/* tcp length */
};

static int fd;
static struct sockaddr_in sa;
static int optval=1;
