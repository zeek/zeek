#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "ip.h"
#include "ether.h" 
#include "ethertype.h"

pcap_t *p;

const u_char*  printEAddr(const u_char* pkt, u_char* endp){
  const struct ether_header *ep;
  int i=0;
  ep = (const struct ether_header*) pkt;

  if (pkt+ETHER_HDRLEN > endp ||
      ntohs(ep->ether_type) != ETHERTYPE_IP){
    return 0;
  }

  for (i = 0; i<ETHER_ADDR_LEN; i++){
    if (i>0) putchar(':');
    printf("%02x", ep->ether_shost[i]);
  }
  putchar (' ');
  for (i = 0; i<ETHER_ADDR_LEN; i++){
    if (i>0) putchar(':');
    printf("%02x", ep->ether_dhost[i]);
  }
  putchar(' ');
  return (pkt+ETHER_HDRLEN);
}

void printIPAddr(const u_char* pkt, u_char* endp){
  const struct ip* iph;
  if (pkt+sizeof(struct ip) > endp) return;
  iph = (const struct ip*) pkt;
  fputs ((char*) inet_ntoa(iph->ip_src), stdout);
  putchar(' ');
  puts ((char*) inet_ntoa(iph->ip_dst));
}

void handler(u_char *user, const struct pcap_pkthdr *head, const u_char *packet){
  u_char* endp;

  endp =(u_char*) packet + head->caplen;
  packet = printEAddr(packet, endp);
  if (packet)
    printIPAddr(packet, endp);
}

void usage(char *av[])
{
	fprintf(stderr,"usage: %s filename \n", av[0]);
	exit(1);
}

int main (int argc, char *argv[])
{
  char *file;
  char errbuf[PCAP_ERRBUF_SIZE];
  u_char* pkt, endp; 
  struct pcap_pkthdr *head;

  if ( argc != 2 ) 
	  usage(argv);

  file = argv[1];

  p = pcap_open_offline(file, errbuf);
  if(p==NULL){
    fprintf (stderr, "cannot open %s: %s\n", file, errbuf);
    exit(2);
  }
  
  if (pcap_datalink(p) != DLT_EN10MB){
    fputs ("sorry, currently only ethernet links supported\n", stderr);
    exit(1); //if it is not ethernet we are watching we won't have MACs
  }

  pcap_loop(p, -1, handler, NULL);
  pcap_close(p);
  return(0);
}

