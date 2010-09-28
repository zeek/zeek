/*
       B R O C C O L I  --  The Bro Client Communications Library

Copyright (C) 2004-2008 Christian Kreibich <christian (at) icir.org>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies of the Software and its documentation and acknowledgment shall be
given in the documentation and software packages that this Software was
used.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

#ifdef __EMX__
#include <strings.h>
#endif 

#include <bro_types.h>
#include <bro_debug.h>
#include <bro_packet.h>


static int
packet_get_link_header_size(int dl)
{
  switch (dl)
    {
    case DLT_NULL:
      return 4;
      
    case DLT_EN10MB:
      return 14;
      
    case DLT_FDDI:
      return 13 + 8;
#ifdef LINUX_HOST      
    case DLT_LINUX_SLL:
      return 16;
#endif
    case DLT_RAW:
      return 0;
    }
  
  D(("WARNING: unknown DLT type %i encountered.\n", dl));
  return -1;
}


BroPacket     *
__bro_packet_unserialize(BroConn *bc)
{
  BroPacket *packet;

  if (! (packet = calloc(1, sizeof(BroPacket))))
    return NULL;

  if (! __bro_packet_read(packet, bc))
    {
      bro_packet_free(packet);
      return NULL;
    }

  return packet;
}


int
__bro_packet_serialize(BroPacket *packet, BroConn *bc)
{
  D_ENTER;

  /* Prepare the beginning of a serialized packet.
   */
  if (! __bro_buf_write_char(bc->tx_buf, 'p'))
    D_RETURN_(FALSE);

  if (! __bro_packet_write(packet, bc))
    D_RETURN_(FALSE);

  D_RETURN_(TRUE);
}


int
__bro_packet_read(BroPacket *packet, BroConn *bc)
{
  BroString packet_data;
  BroString packet_tag;
  uint32 tv_sec, tv_usec, len, pcap_link_type;
  
  D_ENTER;
  
  if (! packet || ! bc)
    D_RETURN_(FALSE);
  
  packet->pkt_link_type = bc->pcap_link_type;
  packet->pkt_hdr_size  = packet_get_link_header_size(bc->pcap_link_type);

  if (! __bro_buf_read_int(bc->rx_buf, &tv_sec))
    D_RETURN_(FALSE);
  if (! __bro_buf_read_int(bc->rx_buf, &tv_usec))
    D_RETURN_(FALSE);
  if (! __bro_buf_read_int(bc->rx_buf, &len))
    D_RETURN_(FALSE);
  if (! __bro_buf_read_int(bc->rx_buf, &pcap_link_type))
    D_RETURN_(FALSE);
  if (! __bro_buf_read_string(bc->rx_buf, &packet_tag))
    D_RETURN_(FALSE);
  if (! __bro_buf_read_string(bc->rx_buf, &packet_data))
    D_RETURN_(FALSE);
  
  packet->pkt_pcap_hdr.ts.tv_sec = tv_sec;
  packet->pkt_pcap_hdr.ts.tv_usec = tv_usec;
  packet->pkt_pcap_hdr.len = len;
  packet->pkt_pcap_hdr.caplen = packet_data.str_len;
  packet->pkt_link_type = pcap_link_type;
  packet->pkt_data = (const u_char *) packet_data.str_val;
  packet->pkt_tag = (const char *) packet_tag.str_val;
  packet->pkt_time = bro_util_current_time();
  
  D_RETURN_(TRUE);
}

int
__bro_packet_write(BroPacket *packet, BroConn *bc)
{
  BroString packet_data;
  BroString packet_tag;
  
  D_ENTER;
  
  if (! packet || ! bc)
    D_RETURN_(FALSE);
  
  if (! __bro_buf_write_int(bc->tx_buf, (uint32)packet->pkt_pcap_hdr.ts.tv_sec))
    D_RETURN_(FALSE);
  if (! __bro_buf_write_int(bc->tx_buf, (uint32)packet->pkt_pcap_hdr.ts.tv_usec))
    D_RETURN_(FALSE);
  if (! __bro_buf_write_int(bc->tx_buf, (uint32)packet->pkt_pcap_hdr.len))
    D_RETURN_(FALSE);
  if (! __bro_buf_write_int(bc->tx_buf, (uint32)bc->pcap_link_type))
    D_RETURN_(FALSE);

  bro_string_init(&packet_tag);
  packet_tag.str_len = strlen(packet->pkt_tag);
  packet_tag.str_val = (u_char *) packet->pkt_tag;

  if (! __bro_buf_write_string(bc->tx_buf, &packet_tag))
    D_RETURN_(FALSE);

  bro_string_init(&packet_data);
  packet_data.str_len = packet->pkt_pcap_hdr.caplen;
  packet_data.str_val = (u_char *) packet->pkt_data;

  if (! __bro_buf_write_string(bc->tx_buf, &packet_data))
    D_RETURN_(FALSE);
    
  D_RETURN_(TRUE);
}


int
__bro_packet_clone(BroPacket *dst, const BroPacket *src)
{
  D_ENTER;
  
  *dst = *src;
  
  if (! (dst->pkt_tag = strdup(src->pkt_tag)))
    D_RETURN_(FALSE);

  if (! (dst->pkt_data = malloc(src->pkt_pcap_hdr.caplen)))
    D_RETURN_(FALSE);

  memcpy((u_char *) dst->pkt_data, src->pkt_data, src->pkt_pcap_hdr.caplen);
  D_RETURN_(TRUE);
}
