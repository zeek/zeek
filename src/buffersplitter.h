#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

unsigned char PACKET_MAGIC[5] = "\1PKT";
int PACKET_MAGIC_LEN = 4;

typedef struct {
    const unsigned char *p;
    const unsigned char *end;
} buffer_splitter;

buffer_splitter *
buffer_splitter_init(const unsigned char *packet, size_t len)
{
    buffer_splitter *b = (buffer_splitter *) malloc(sizeof(buffer_splitter));
    if (b==NULL)
        return b;
    b->p = packet;
    b->end = packet+len;
    return b;
}

void
buffer_splitter_delete(buffer_splitter *b)
{
    if(b==NULL)
        return;
    free(b);
}

int
buffer_splitter_next(buffer_splitter *b, unsigned char **chunk, size_t *len, bool *is_orig)
{
    if(b->p == b->end) {
        *chunk=NULL;
        *len=0;
        return 0;
    }
        
    unsigned char *pos = (unsigned char*) memmem(
        b->p, b->end - b->p,
        PACKET_MAGIC, PACKET_MAGIC_LEN);
    if(pos==NULL)
        return -1;
    //printf("Found offset after %d bytes\n", pos - b->p);
    //Next, there should be at least one byte for is_orig, and more bytes for data
    pos += PACKET_MAGIC_LEN;
    size_t remaining_bytes = b->end - pos;
    if (remaining_bytes < 2)
        return -2;
    unsigned char orig_byte = pos[0];
    //printf("is_orig byte is: %x\n", orig_byte);
    if(orig_byte != 1 && orig_byte != 2)
        return -3;
    *is_orig = orig_byte - 1; //1 for 0, 2 for 1, to avoid null bytes
    pos += 1;
    //POS is now start of the next packet
    *chunk = pos;
    remaining_bytes = b->end - pos;
    //printf("%d bytes remaining\n", remaining_bytes);

    //Now, see if we have another packet, or if we reach the end
    unsigned char *next_pos = (unsigned char*) memmem(
        pos, remaining_bytes,
        PACKET_MAGIC, PACKET_MAGIC_LEN);

    //Set the packet pointer to either the start of the next packet
    //Or the end of the buffer
    if(next_pos == NULL) {
        b->p = b->end;
    } else {
        b->p = next_pos;
    }
    *len = b->p - pos;
    return 0;
}

int
buffer_splitter_validate(const unsigned char *packet, size_t packet_len)
{
    buffer_splitter *pp = buffer_splitter_init(packet, packet_len);
    if(pp==NULL)
        return -99;
    int err;
    unsigned char *chunk;
    size_t len;
    bool is_orig;
    while(1) {
        err = buffer_splitter_next(pp, &chunk, &len, &is_orig);
        if (err)
            break;
        if (len==0)
            break;
    }
    buffer_splitter_delete(pp);
    return err;
}
