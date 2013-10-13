#
# Makefile for libnids samples.
#
# Dug Song <dugsong@monkey.org>

srcdir		= .


CC		= gcc
CFLAGS		= -g -O2 -D_BSD_SOURCE
LDFLAGS		= 

PCAP_CFLAGS	= -I/usr/local/include
PCAPLIB		= -L/usr/local/lib -lpcap

LNET_CFLAGS	= -I/usr/local/include -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H
LNETLIB		= -lnet

LIBS_CFLAGS	= -I../src $(PCAP_CFLAGS) $(LNET_CFLAGS)
LIBS		= -L../src -lnids $(PCAPLIB) $(LNETLIB) -lgthread-2.0 -lnsl 
GLIB		= `pkg-config --cflags --libs glib-2.0`
.c.o:
	$(CC) -c $(CFLAGS) -I. $(LIBS_CFLAGS) $<

all: printall
static shared: all

printall: printall.o data_send.o copeungz.o copykw_match.o
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS) $(GLIB)

printall.o: printall.c
	$(CC) -c $< $(LDFLAGS) $(LIBS)
	
data_send.o: data_send.c
	$(CC) -c $< 
	
copeungz.o: copeungz.c
	$(CC) -c $< -pthread

copykw_match.o: copykw_match.c
	$(CC) -c $<  $(GLIB)

static shared install installshared:
	@true

clean:
	rm -f *.o *~ printall

# EOF
