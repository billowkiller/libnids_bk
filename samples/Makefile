CC = gcc 
ZIP = -lz
PCAP = -lpcap
NET = -lnet
GTHREAD = -lgthread-2.0
NIDS = -lnids $(NET) $(GTHREAD) -lnsl $(ZIP)
GLIB = `pkg-config --cflags --libs glib-2.0`

test: test.o gzip.o cache.o
	$(CC) -Wall $^ -o $@ $(PCAP) $(NIDS) $(GLIB)

test.o: test.c cache.o
	$(CC) -c -Wall $< $(ZIP) $(PCAP) $(NIDS) $(GLIB)

gzip.o: gzip.c
	$(CC) -c -Wall $< $(ZIP)

cache.o: cache.c
	$(CC) -c -Wall $< $(ZIP)
