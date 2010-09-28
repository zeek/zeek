/* $Id;$ */
/* Written by Bernhard Ager (2007). */

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/time.h>
#include <netinet/in.h>

#include "nfcommon.h"

void pleave (int errlvl, const char *msg) {
  perror (msg);
  exit (errlvl);
}

void usage () {
  puts ("collects NetFlow data and writes it to a file (or stdout)\n"
	"       such that Bro can read the NetFlow dump file.\n"
	"  Usage: nfcollector [-p <port>] [-o <outputfile>]\n"
	"       port defaults to 1234, outputfile defaults to stdout");
}

int main (int argc, char** argv) {
  int opt;
  int s = -1;
  char *outfile = NULL;
  int outfd = 1; // default to stdout
  struct timeval tv;
  struct sockaddr_in sa = { .sin_family = AF_INET, 
			    .sin_port = htons(1234),
			    .sin_addr = {0} };
  struct sockaddr_in from;
  socklen_t fromlen;
  FlowFilePDU ffp;

  while ((opt = getopt (argc, argv, "p:o:h")) >= 0) {
    switch (opt) {
    case 'o':
      outfile = malloc (strlen(optarg) + 1);
      strcpy (outfile, optarg);
      break;
    case 'p':
      sa.sin_port = htons(atoi(optarg));
      break;
    case 'h':
      usage();
      exit (0);
    default:
      fprintf (stderr, "Unknown option: %c\n", optopt);
    }
  }

  if ((s = socket (PF_INET, SOCK_DGRAM, 0)) < 0)
    pleave(1, "opening socket");

  if (bind (s, (struct sockaddr*) &sa, sizeof (sa)) < 0)
    pleave (1, "bind");

  if (outfile && (outfd = open (outfile, O_TRUNC|O_WRONLY|O_CREAT, 0666)) < 0)
    pleave (1, "open");

  while (1) {
    fromlen = sizeof (from);
    if ((ffp.header.pdu_length = recvfrom(s, ffp.data, MAX_PKT_SIZE, 0, (struct sockaddr*)&from, &fromlen)) < 0)
      pleave (1, "recvfrom");
    if (gettimeofday(&tv, NULL) == 0)
      ffp.header.network_time = tv.tv_sec + tv.tv_usec / 1000000.;
    else {
      ffp.header.network_time = -1.;
      perror ("gettimeofday");
    }

    ffp.header.ipaddr = from.sin_addr.s_addr;
    write (outfd, &ffp, ffp.header.pdu_length + sizeof (FlowFileSrcPDUHeader));
  }

  return 0;
}
