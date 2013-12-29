#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EDEN_SIZE 2000
#define EDEN_DISTANCE(X) (X)->cursor - EDEN_POS(X)
#define EDEN_POS(X) ((char *)((X)->eden) + (X)->state*EDEN_SIZE)
#define EDEN_READY(X) ((char *)((X)->eden) + (!(X)->state)*EDEN_SIZE)

#define Eden0 0
#define Eden1 1
#define FULL 1
#define EMPTY 0

typedef struct 
{
    char *key;
    int state;
    int is_full;
    char *cursor;
    void *eden;
}stream_buf;

void stmb_init(stream_buf* stmb, char *buf);
int stmb_memcpy(stream_buf* stmb, int length, char *data);
