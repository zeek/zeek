/* $Id:$ */
/* Written by Bernhard Ager (2007). */
/* Works only with NFv5. */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "nfcommon.h"

void leave (int errlvl, const char *msg) {
  fprintf (stderr, "%s", msg);
  exit (errlvl);
}

void usage () {
  puts ("Converts NetFlow v5 files in 'wire' format to bro format.\n"
	"A flow-tools file can be converted to 'wire' format with\n"
	"        flow-export -f 4\n"
	"Note this is a hack: The network time is calculated from the\n"
        "export time and an optional offset; the exporter is set statically.\n"
	"Usage: ftwire2bro [-e <exporter_ip> [-t <offset>]\n"
	"       <exporter_ip> defaults to 0.0.0.0, <offset> defaults to 0.0\n"
	"       data is read from stdin and written to stdout");
}

size_t pdusize(NFv5Header hdr) {
  return sizeof(hdr)+ntohs(hdr.count)*V5_RECORD_SIZE;
}

int main (int argc, char** argv) {
  int opt;
  struct in_addr exporter = {0};
  double offset = 0.0;
  FlowFileSrcPDUHeader ffphdr;
  NFv5PDU v5pdu;
  unsigned short count;

  while ((opt = getopt (argc, argv, "e:t:h")) >= 0) {
    switch (opt) {
    case 'e':
      if (! inet_aton (optarg, &exporter)) {
	fprintf (stderr, "could not convert exporter_ip: '%s'\n", optarg);
	exit (1);
      }
      break;
    case 't':
      offset = atof(optarg);
      break;
    case 'h':
      usage();
      exit (0);
    default:
/*       fprintf (stderr, "Unknown option: %c\n", optopt); */
      exit(1);
    }
  }

  while (1) {
    if (fread (&(v5pdu.header), sizeof (NFv5Header), 1, stdin) == 0) {
      if (feof(stdin))
	break;
      leave (1, "Could not read header\n");
    }

    count = ntohs (v5pdu.header.count);
    if (ntohs(v5pdu.header.version) != 5)
      leave (1, "Header indicates flow not in version 5 format\n");
    if (count > V5_RECORD_MAXCOUNT) {
      fprintf (stderr, "header indicates too many records: %d\n", 
	       count);
      exit (1);
    }
    
    if (fread (v5pdu.records, sizeof(NFv5Record), count, stdin) < count)
      leave (1, "Could not read enough records from stdin\n");

    ffphdr.network_time = ntohl(v5pdu.header.unix_secs) + 
                          ntohl(v5pdu.header.unix_nsecs)/1e9 + offset;
    ffphdr.pdu_length = pdusize(v5pdu.header);
    ffphdr.ipaddr = exporter.s_addr;

    if (fwrite (&ffphdr, sizeof(ffphdr), 1, stdout) == 0)
      leave (1, "Could not write ffpheader\n");
    if (fwrite (&v5pdu, ffphdr.pdu_length, 1, stdout) == 0)
      leave (1, "Could not write netflow PDU\n");
  }

  return 0;
}
