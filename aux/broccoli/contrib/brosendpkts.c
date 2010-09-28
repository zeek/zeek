/* NOTE: This file needs to be cleaned up to build with all
 * C compilers -- no variable definitions in the middle of
 * functions, etc. Conditional compilation depending on
 * whether we're using a Broccoli with or without pcap support
 * can be done with #ifdef BRO_PCAP_SUPPORT. --ck.
 */

#include <string.h>
#include <broccoli.h>
#include <pcap.h>

void usage() {
  fprintf(stderr, "usage: brosendpkts -r file -b host:port [-t tag]\n");
  exit(1);
} 


int main(int argc, char** argv) {
  char* filename=NULL;
  char* bro_connection=NULL;
  char* tag="";

  bro_init(NULL);

  int opt;
  while ((opt=getopt(argc, argv, "r:b:t:h?")) != -1) {
    switch(opt) {
    case 'r':
      filename=strdup(optarg);
      break;
    case 'b':
      bro_connection=strdup(optarg);
      break;
    case 't':
      tag=strdup(optarg);
      break;
    case 'h':
    case '?':
    default:
      usage();
    }
  }
  argc -= optind;
  argv += optind;


  if (filename==NULL || bro_connection==NULL) usage();

  BroConn *broccoli_p=bro_conn_new_str(bro_connection, BRO_CFLAG_NONE);
  if (!broccoli_p)
    {
	fprintf(stderr, "can't instantiate connection object\n");
	exit(1);
	}
								   
  if (! bro_conn_connect(broccoli_p)) {
    fprintf(stderr, "Bro connection to %s failed\n",
	    bro_connection);
    exit(1);
  }
  printf("connected to Bro %s\n", bro_connection);

  char pcap_errbuf[PCAP_ERRBUF_SIZE]="";
  pcap_t* pcap_p=pcap_open_offline(filename, pcap_errbuf);

  if (!pcap_p) {
    fprintf(stderr, "pcap eror: %s\n", pcap_errbuf);
    exit(1);
  }

  bro_conn_set_packet_ctxt(broccoli_p, pcap_datalink(pcap_p));

  const uchar* packet_p=NULL;
  struct pcap_pkthdr pkthdr;
  
  int pkt_cnt=0;
  while ((packet_p=pcap_next(pcap_p, &pkthdr))) {
    pkt_cnt++;
    BroPacket* broccoli_packet_p=bro_packet_new(&pkthdr, packet_p, tag);
    bro_packet_send(broccoli_p, broccoli_packet_p);
    bro_packet_free(broccoli_packet_p);
  }

  printf("sent %d packets\n",pkt_cnt);
  
  bro_conn_delete(broccoli_p);
  printf("connection to Bro %s closed\n", bro_connection);

  return 0;
}
