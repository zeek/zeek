/*
       B R O C C O L I  --  The Bro Client Communications Library

Copyright (C) 2004-2007 Christian Kreibich <christian (at) icir.org>

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
#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>

#include <broccoli.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

char *host_default = "127.0.0.1";
char *port_default = "47758";
char *host_str;
char *port_str;

char *type = "enumtest::enumtype";

static void
usage(void)
{
  printf("broenum - sends enum vals to a Bro node, printing the corresponding\n"
	 "string value on the Bro side.\n"
	 "USAGE: broping [-h|-?] [-d] [-p port] [-t type] [-n num] host\n");
  exit(0);
}

int
main(int argc, char **argv)
{
  int opt, port, debugging = 0;
  BroConn *bc;
  BroEvent *ev;
  extern char *optarg;
  extern int optind;
  char hostname[512];
  int enumval;

  bro_init(NULL);

  host_str = host_default;
  port_str = port_default;

  bro_debug_calltrace = 0;
  bro_debug_messages  = 0;

  while ( (opt = getopt(argc, argv, "t:n:p:dh?")) != -1)
    {
      switch (opt)
	{
	case 'd':
	  debugging++;

	  if (debugging == 1)
	    bro_debug_messages = 1;
	  
	  if (debugging > 1)
	    bro_debug_calltrace = 1;
	  break;

	case 'h':
	case '?':
	  usage();

	case 't':
	  type = optarg;
	  break;

	case 'n':
	  enumval = strtol(optarg, NULL, 0);
	  if (errno == ERANGE)
	    {
	      printf("Please provide an integer to -n.\n");
	      exit(-1);
	    }
	  break;
	  
	case 'p':
	  port_str = optarg;
	  break;

	default:
	  usage();
	}
    }

  argc -= optind;
  argv += optind;

  if (argc > 0)
    host_str = argv[0];

  port = strtol(port_str, NULL, 0);
  if (errno == ERANGE)
    {
      printf("Please provide a port number with -p.\n");
      exit(-1);
    }

  if (!type)
    usage();

  printf("Sending enum val %i to remote peer.\n", enumval);

  snprintf(hostname, 512, "%s:%s", host_str, port_str);
  
  /* Connect to Bro */
  if (! (bc = bro_conn_new_str(hostname, BRO_CFLAG_NONE)))
    {
      printf("Could not get Bro connection handle.\n");
      exit(-1);
    }
  
  if (! bro_conn_connect(bc))
    {
      printf("Could not connect to Bro at %s:%s.\n", host_str, port_str);
      exit(-1);
    }
    
  /* Create empty "ping" event */
  if (! (ev = bro_event_new("enumtest")))
    {
      printf("Couldn't create event structure.\n");
      exit(-1);
    }

  /* We send the given number as an instance of an enum type defined
   * in the remote Bro's policy:
   */
  bro_event_add_val(ev, BRO_TYPE_ENUM, type, &enumval);
	      
  /* Ship it -- sends it if possible, queues it otherwise */
  bro_event_send(bc, ev);
  bro_event_free(ev);
  
  /* Make sure we sent the thing. */
  while (bro_event_queue_length(bc) > 0)
    bro_event_queue_flush(bc);

  /* Disconnect from Bro and release state. */
  bro_conn_delete(bc);
  
  return 0;
}
