/*
 * =====================================================================================
 *
 *       Filename:  gzip.c
 *
 *    Description:  decompress gzip data on the fly.
 *
 *        Version:  1.0
 *        Created:  12/28/2013 10:02:32 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  billowkiller (), billowkiller@gmail.com
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zlib.h"
#include <assert.h>

int inflate_init(z_stream *strm)
{
     /* allocate inflate state */
    strm->zalloc = Z_NULL;
    strm->zfree = Z_NULL;
    strm->opaque = Z_NULL;
    strm->avail_in = 0;
    strm->next_in = Z_NULL;
    
    if (inflateInit2(strm, 16+MAX_WBITS) != Z_OK) {
        printf("error in inflate_init!!!\n");
        return 0;
    }
    return 1;
}

int inflate_data(z_stream *strm, int size, char *compressdata)
{
    int ret,chunk=size*9;
    char *out = (char *)malloc(chunk);
    
    strm->avail_in = size;
    strm->next_in = compressdata;
    strm->avail_out = chunk;
    strm->next_out = out;
    ret = inflate(strm, Z_NO_FLUSH);

    assert(ret != Z_STREAM_ERROR);  /*  state not clobbered */

    if(ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR)
    {
        printf("error when inflating!!!\n");
        (void)inflateEnd(strm);
        return ret;
    }

    printf("avail_out %d\n", strm->avail_out);
    if(chunk-strm->avail_out)
        printf("%.*s\n", chunk-strm->avail_out, out);

    if(ret == Z_STREAM_END)
    {
        (void)inflateEnd(strm);
    }
    
    return ret;
}

