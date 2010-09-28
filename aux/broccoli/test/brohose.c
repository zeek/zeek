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
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>

#include <broccoli.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

char *host_default = "127.0.0.1";
char *port_default = "47758";
char *host_str;
char *port_str;

int num_procs  = 10;
int num_events = 1000;
int seq;

static void
usage(void)
{
  printf("brohose - sends events to a Bro node from multiple processes in parallel.\n"
	 "USAGE: brohose [-h|-?] [-n <# processes>] [-e <# events>] [-p port] host\n"
	 "  -h|?                 this message\n"
	 "  -n  <# processes>    number of processes to use (10)\n"
	 "  -e  <# events>       number of events per process (1000)\n"
	 "  -p <port>            port to contact\n"
	 "  host                 host to contanct\n\n");
  exit(0);
}

static void
hose_away(BroConn *bc)
{
  BroEvent *ev;
  BroString str;
  int i;
  pid_t pid = getpid();
  char msg[1024];

  printf("++ child %u\n", pid);
  
  for (i = 0; i < num_events; i++)
    {
      /* Create empty "ping" event */
      if (! (ev = bro_event_new("brohose")))
	{
	  printf("**** EEEEK\n");
	  bro_conn_delete(bc);
	  return;
	}

      snprintf(msg, 1024, "%u-%i-%i", pid, i, bro_event_queue_length(bc));
      bro_string_set(&str, msg);
      bro_event_add_val(ev, BRO_TYPE_STRING, NULL, &str);
      
      /* Ship it -- sends it if possible, queues it otherwise */
      bro_event_send(bc, ev);

      bro_event_free(ev);
      bro_string_cleanup(&str);
      
      if (bro_event_queue_length(bc) > bro_event_queue_length_max(bc) / 2)
	{
	  while (bro_event_queue_length(bc) > 0)
	    bro_event_queue_flush(bc);
	}
    }

  while (bro_event_queue_length(bc) > 0)
    bro_event_queue_flush(bc);

  printf("-- child %u, %i queued\n", pid, bro_event_queue_length(bc));
  bro_conn_delete(bc);
}


int
main(int argc, char **argv)
{
  int i, opt, port, debugging = 0;
  BroConn *bc;
  extern char *optarg;
  extern int optind;
  char hostname[512];
  
  bro_init(NULL);

  host_str = host_default;
  port_str = port_default;

  bro_debug_calltrace = 0;
  bro_debug_messages  = 0;

  while ( (opt = getopt(argc, argv, "n:e:p:dh?")) != -1)
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
	  
	case 'n':
	  num_procs = strtol(optarg, NULL, 0);
	  if (errno == ERANGE || num_procs < 1 || num_procs > 100)
	    {
	      printf("Please restrict the number of processes to 1-100.\n");
	      exit(-1);
	    }
	  break;
	  
	case 'e':
	  num_events = strtol(optarg, NULL, 0);
	  if (errno == ERANGE || num_events < 1 || num_events > 10000)
	    {
	      printf("Please restrict the number of events to 1-10,000..\n");
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

  snprintf(hostname, 512, "%s:%s", host_str, port_str);

  printf("Will attempt to send %i events from %i processes, to %s\n",
	 num_events, num_procs, hostname);
  
  /* Connect to Bro */
  if (! (bc = bro_conn_new_str(hostname, BRO_CFLAG_SHAREABLE)))
    {
      printf("Couldn't get Bro connection handle.\n");
      exit(-1);
    }

  if (! bro_conn_connect(bc))
    {
      printf("Could not connect to Bro at %s:%s.\n", host_str, port_str);
      exit(-1);
    }

  for (i = 0; i < num_procs; i++)
    {
      int pid = fork();
      
      if (pid < 0)
	{
	  printf("Couldn't fork children, aborting.\n");
	  exit(-1);
	}
      
      if (pid == 0)
	{
	  hose_away(bc);
	  exit(0);
	}
    }

  while (i > 0)
    {
      int status;

      wait(&status);
      i--;
    }

  
  /* Disconnect from Bro -- this will keep the copies in the children
   * working but reduce the reference count of the underlying socket so
   * that eventually it is really closed.
   */
  bro_conn_delete(bc);
  printf("Exiting ...\n");

  return 0;
}
