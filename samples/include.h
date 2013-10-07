//#define DEBUG   //define debug print
#define NDEBUG   //shutdown assert

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>



#define FREE(X) if((X)) {free((X)); (X)=NULL;}
#define PR(X, Y) printf(#X " = " Y "\n", X ) //i=1; PR(i, "%d")
#define PS(X) printf(#X " = %s\n", X ) //PR(str)
#define PD(X) printf(#X " = %d\n", X ) //PR(int)
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#ifndef	FALSE
#define	FALSE	(0)
#endif

#ifndef	TRUE
#define	TRUE	(!FALSE)
#endif

#ifndef TCPTYPE
#define TCPTYPE
	#define FIRSTSHARK 1
	#define SECONDSHARK 2
	#define THIRDSHARK 3
	#define FIN 4
	#define ACK 5
	#define GET 6
	#define POST 7
#endif

#ifndef HEADCAL
#define HEADCAL
	#define TCPHL(X) ((X)->doff * 4)
	#define IPHL(X) ((X)->ihl * 4)
	#define IPL(X) (ntohs((X)->tot_len))
	#define DATAL(X,Y) (IPL(X)-IPHL(X)-TCPHL(Y))
	#define SEQ(X) (ntohl((X)->seq))
#endif

#ifndef SENDTYPE
#define SENDTYPE
	#define SEND_DIRECT 0
	#define SEND_UP 1
#endif

#ifndef WEBTYPE
#define WEBTYPE
	#define FRIEND 1
	#define STATUS 2
	#define NOTE 3
	#define COMMENT 4
	#define PHOTO 5
	#define MEDIA_SET 6
	#define ADD_FRIEND 7
	#define EDIT_NOTE 8
#endif

#ifndef STRUCT
#define STRUCT

struct HTTP{
	unsigned char method;
	int head_length;
	char url[300];
	char cookie[300];
	char content[4096];
};

struct connection_info{
	char user_id[20];
	char s_id[20]; //visitor view subject's page
	int p_type; /* page type */
	char r_id[52]; /* resource id */
	char comment[100]; /* post content */
};
#endif
