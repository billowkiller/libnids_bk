CC = gcc 
ZIP = -lz
PCAP = -lpcap
NET = -lnet
GTHREAD = -lgthread-2.0
NIDS = -lnids $(NET) $(GTHREAD) -lnsl $(ZIP)
GLIB = `pkg-config --cflags --libs glib-2.0`
test: test.c
	$(CC) -Wall test.c -o test $(PCAP) $(NIDS) $(GLIB)
