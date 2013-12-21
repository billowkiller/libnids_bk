CC = gcc 
ZIP = -lz
PCAP = -lpcap
NET = -lnet
GTHREAD = -lgthread-2.0
SQLITE = -lsqlite3
NIDS = -lnids $(NET) $(GTHREAD) -lnsl $(ZIP)
test: test.c
	$(CC) -Wall test.c -o test -lpcap $(NIDS)
