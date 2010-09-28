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
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <string.h>

#include <broccoli.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

char *host_default = "127.0.0.1";
char *port_default = "47758";
char *host_str;
char *port_str;

int count = -1;
int seq;

static void
usage(void)
{
  printf("broping - sends ping events to a Bro agent, expecting pong events.\n"
	 "USAGE: broping [-h|-?] [-d] [-l] [-r] [-c num] [-p port] host\n"
	 "   -h|-?       This message.\n"
	 "   -d          Enable debugging (only useful if configured with --enable-debug).\n"
	 "   -r          Use record types to transfer data.\n"
	 "   -C          Use compact callback argument passing.\n"
	 "   -c <num>    Number of events to send.\n"
	 "   -p <port>   Port on <host> to contact.\n");

  exit(0);
}


static void
bro_pong(BroConn *conn, void *data, double *src_time, double *dst_time, uint32 *seq)
{
  double now = bro_util_current_time();

  printf("pong event from %s: seq=%i, time=%f/%f s\n",
	 host_str, *seq, *dst_time - *src_time,
	 now - *src_time);

  conn = NULL;
  data = NULL;
}

static void
bro_pong_record(BroConn *conn, void *data, BroRecord *rec)
{
  double now = bro_util_current_time();
  double *src_time, *dst_time;
  uint32 *seq;
  int type = BRO_TYPE_COUNT;

  if (! (seq = bro_record_get_nth_val(rec, 0, &type)))
    {
      printf("Error getting sequence count from event, got type %i\n", type);
      return;
    }

  type = BRO_TYPE_TIME;

  if (! (src_time = bro_record_get_nth_val(rec, 1, &type)))
    {
      printf("Error getting src time from event, got type %i.\n", type);
      return;
    }

  type = BRO_TYPE_TIME;
  
  if (! (dst_time = bro_record_get_nth_val(rec, 2, &type)))
    {
      printf("Error getting dst time from event, got type %i\n", type);
      return;
    }

  printf("pong event from %s: seq=%i, time=%f/%f s\n",
	 host_str, *seq, *dst_time - *src_time,
	 now - *src_time);
  
  conn = NULL;
  data = NULL;
}

static void
bro_pong_compact(BroConn *conn, void *data, BroEvMeta *meta)
{
  double *src_time;
  double *dst_time;
  uint32 *seq;
  
  /* Sanity-check arguments: */

  if (strcmp(meta->ev_name, "pong") != 0)
    {
      printf("Event should be 'pong', is '%s', error.\n",
	     meta->ev_name);
      return;
    }

  if (meta->ev_numargs != 3)
    {
      printf("Pong event should have 3 arguments, has %d, error.\n",
	     meta->ev_numargs);
      return;
    }

  if (meta->ev_args[0].arg_type != BRO_TYPE_TIME)
    {
      printf("Type of first argument should be %i, is %i, error.\n",
	     BRO_TYPE_TIME, meta->ev_args[0].arg_type);
      return;
    }

  if (meta->ev_args[1].arg_type != BRO_TYPE_TIME)
    {
      printf("Type of second argument should be %i, is %i, error.\n",
	     BRO_TYPE_TIME, meta->ev_args[1].arg_type);
      return;
    }

  if (meta->ev_args[2].arg_type != BRO_TYPE_COUNT)
    {
      printf("Type of third argument should be %i, is %i, error.\n",
	     BRO_TYPE_COUNT, meta->ev_args[2].arg_type);
      return;
    }

  src_time = (double *) meta->ev_args[0].arg_data;
  dst_time = (double *) meta->ev_args[1].arg_data;
  seq = (uint32 *) meta->ev_args[2].arg_data;
  
  bro_pong(conn, data, src_time, dst_time, seq);
}

static void
bro_pong_compact_record(BroConn *conn, void *data, BroEvMeta *meta)
{
  BroRecord *rec;

  /* Sanity-check argument type: */

  if (strcmp(meta->ev_name, "pong") != 0)
    {
      printf("Event should be 'pong', is '%s', error.\n",
	     meta->ev_name);
      return;
    }

  if (meta->ev_numargs != 1)
    {
      printf("Pong event should have 1 argument, has %d, error.\n",
	     meta->ev_numargs);
      return;
    }

  if (meta->ev_args[0].arg_type != BRO_TYPE_RECORD)
    {
      printf("Type of argument should be %i, is %i, error.\n",
	     BRO_TYPE_RECORD, meta->ev_args[0].arg_type);
      return;
    }
  
  rec = (BroRecord *) meta->ev_args[0].arg_data;
  
  bro_pong_record(conn, data, rec);
}

BroConn*
start_listen(int port)
{
  int fd = 0;
  struct sockaddr_in server;
  struct sockaddr_in client;
  socklen_t len = sizeof(client);
  fd_set fds;
  const int turn_on = 1;
  BroConn *bc = 0;

  fd = socket(PF_INET, SOCK_STREAM, 0);
  if ( fd < 0 )  
	{
	printf("can't create listen socket: %s\n", strerror(errno));
	exit(-1);
	}

  // Set SO_REUSEADDR.
  if ( setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &turn_on, sizeof(turn_on)) < 0 )
	{
	printf("can't set SO_REUSEADDR: %s\n", strerror(errno));
	exit(-1);
	}

  bzero(&server, sizeof(server));
  server.sin_family = AF_INET;
  server.sin_port = htons(port);
  server.sin_addr.s_addr = 0;

  if ( bind(fd, (struct sockaddr*) &server, sizeof(server)) < 0 )
	{
	printf("can't bind to port %d: %s\n", port, strerror(errno));
	exit(-1);
	}

  if ( listen(fd, 50) < 0 )
	{
	printf("can't listen: %s\n", strerror(errno));
	exit(-1);
	}

   FD_ZERO(&fds);
   FD_SET(fd, &fds);

  if ( select(fd + 1, &fds, &fds, &fds, 0) < 0 )
	{
	printf("can't select: %s\n", strerror(errno));
	exit(-1);
	}
	
  fd = accept(fd, (struct sockaddr*) &client, &len);
  if ( fd < 0 )
	{
	printf("can't accept: %s\n", strerror(errno));
	exit(-1);
	}

  bc = bro_conn_new_socket(fd, BRO_CFLAG_ALWAYS_QUEUE);
  if ( ! bc )
	{
	printf("can't create connection form fd\n");
	exit(-1);
	}

  return bc;
}

int
main(int argc, char **argv)
{
  int opt, port, use_record = 0, use_compact = 0, debugging = 0, listen = 0;
  BroConn *bc;
  extern char *optarg;
  extern int optind;
  char hostname[512];
  int fd = -1;

  bro_init(NULL);

  host_str = host_default;
  port_str = port_default;

  bro_debug_calltrace = 0;
  bro_debug_messages  = 0;

  while ( (opt = getopt(argc, argv, "Cc:p:dh?lr")) != -1)
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
	
	case 'l':
	  listen = 1;
	  break;

	case 'h':
	case '?':
	  usage();

	case 'c':
	  count = strtol(optarg, NULL, 0);
	  if (errno == ERANGE || count < 1)
	    {
	      printf("Please provide an integer to -c.\n");
	      exit(-1);
	    }
	  break;
	  
	case 'p':
	  port_str = optarg;
	  break;

	case 'r':
	  use_record = 1;
	  break;

	case 'C':
	  use_compact = 1;
	  break;

	default:
	  usage();
	}
    }

  argc -= optind;
  argv += optind;

  if (argc > 0)
    host_str = argv[0];

  /*
  if (! (host = gethostbyname(host_str)) ||
      ! (host->h_addr_list[0]))
    {
      printf("Could not resolve host %s\n", host_str);
      exit(-1);
    }
  */

  port = strtol(port_str, NULL, 0);
  if (errno == ERANGE)
    {
      printf("Please provide a port number with -p.\n");
      exit(-1);
    }

  snprintf(hostname, 512, "%s:%s", host_str, port_str);


  if ( listen )
	bc  = start_listen(port);

  /* Connect to Bro */
  else if (! (bc = bro_conn_new_str(hostname, BRO_CFLAG_RECONNECT | BRO_CFLAG_ALWAYS_QUEUE)))
    {
      printf("Could not get Bro connection handle.\n");
      exit(-1);
    }
  
  /* Request "pong" events, and have bro_pong called when they
   * arrive. The callback mechanism automatically figures out
   * the number of arguments and invokes the callback accordingly.
   * Use record-based callback if -r option was given, and compact
   * argument passing if -C was provided.
   */
  if (use_compact)
    {
      if (use_record)
	bro_event_registry_add_compact(bc, "pong", (BroCompactEventFunc)
				       bro_pong_compact_record, NULL);
      else
	bro_event_registry_add_compact(bc, "pong", (BroCompactEventFunc)
				       bro_pong_compact, NULL);
    }
  else
    {
      if (use_record)
	bro_event_registry_add(bc, "pong", (BroEventFunc) bro_pong_record, NULL);
      else
	bro_event_registry_add(bc, "pong", (BroEventFunc) bro_pong, NULL);
    }
  
  if (! bro_conn_connect(bc))
    {
      printf("Could not connect to Bro at %s:%s.\n", host_str, port_str);
      exit(-1);
    }
  
  /* Enter pinging loop */
  for ( ; ; )
    {
      BroEvent *ev;
      
      bro_conn_process_input(bc);

      if (count > 0 && seq == count)
	break;
      
      /* Create empty "ping" event */
      if ( (ev = bro_event_new("ping")))
	{
	  double timestamp = bro_util_current_time();

	  if (use_record)
	    {
	      /* Create a record with the sequence number as first
	       * element of type counter, and the second element the
	       * current time:
	       */
	      BroRecord *rec = bro_record_new();
	      
	      bro_record_add_val(rec, "seq", BRO_TYPE_COUNT, NULL, &seq);
	      bro_record_add_val(rec, "src_time", BRO_TYPE_TIME, NULL, &timestamp);
	      
	      bro_event_add_val(ev, BRO_TYPE_RECORD, NULL, rec);
	      
	      bro_record_free(rec);
	    }
	  else
	    {
	      /* Add a timestamp to it: */
	      bro_event_add_val(ev, BRO_TYPE_TIME, NULL, &timestamp);
	      
	      /* Add the sequence counter: */
	      bro_event_add_val(ev, BRO_TYPE_COUNT, NULL, &seq);
	    }

	  seq++;

	  /* Ship it -- sends it if possible, queues it otherwise */
	  bro_event_send(bc, ev);
	  bro_event_free(ev);
	}

#ifdef __MINGW32__
      sleep(1000);
#else
      sleep(1);
#endif
    }

  /* Disconnect from Bro and release state. */
  bro_conn_delete(bc);

  return 0;
}
