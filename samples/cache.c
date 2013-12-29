/*
 * =====================================================================================
 *
 *       Filename:  cache.c
 *
 *    Description:  cache management for gzip
 *
 *        Version:  1.0
 *        Created:  12/29/2013 05:55:39 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  billowkiller (), billowkiller@gmail.com
 *   Organization:  
 *
 * =====================================================================================
 */
#include "cache.h"

void stmb_init(stream_buf* stmb, char *buf)
{
    stmb->key = (char *)malloc(256);
    memcpy(stmb->key, buf, 256);
    stmb->state = Eden0;
    stmb->is_full = EMPTY;
    stmb->eden= malloc(2*EDEN_SIZE);
}

int stmb_memcpy(stream_buf* stmb, int length, char *data)
{
    int distance = (stmb->cursor) - EDEN_POS(stmb);
    if(distance+length < EDEN_SIZE)
    {
         memcpy(stmb->cursor, data, length); 
         stmb->cursor += length;
         return 0;
    }
    else
    {
        if(stmb->state == Eden0)
        {
            memcpy(stmb->cursor, data, length); 
            stmb->cursor += length;
            return 1;
        }
        else
        {
            int remain = EDEN_SIZE - distance;
            memcpy(stmb->cursor, data, remain);
            stmb->state = !(stmb->state);
            stmb->cursor = EDEN_POS(stmb);
            memcpy(stmb->cursor, data+remain, length-remain);
            stmb->cursor += length-remain;
            return 1;
        }
    }
}
