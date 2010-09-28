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
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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
  printf("broconn - dumps arriving connection events to console.\n"
	 "USAGE: broconn [-h|-?] [-d] [-p port] host\n");
  exit(0);
}

/* Snippet from Bro policies containing relevant record types:

type connection: record {
	id: conn_id;
	orig: endpoint;
	resp: endpoint;
	start_time: time;
	duration: interval;
	service: string;
	addl: string;
	hot: count;
};

type conn_id: record {
	orig_h: addr;
	orig_p: port;
	resp_h: addr;
	resp_p: port;
};

type endpoint: record {
	size: count;
	state: count;
};

*/

static int
services_print_cb(BroString *service, void *user_data)
{
  printf("'%s' ", service->str_val);
  
  return TRUE;
  user_data = NULL;
}

static void
conn_generic(BroConn *bc, BroRecord *conn)
{
  BroRecord *id, *orig, *resp;
  BroSet *services;
  BroString *addl;
  BroPort *port;
  uint32 *addr, *size, *state;
  double *start_time, *duration;
  struct in_addr ip;
  int type = BRO_TYPE_RECORD;

  if (! (id = bro_record_get_named_val(conn, "id", &type)))
    {
      printf("[Error obtaining 'id' member from connection record.]\n");
      return;
    }

  if (! (orig = bro_record_get_named_val(conn, "orig", &type)))
    {
      printf("[Error obtaining 'orig' member from connection record.]\n");
      return;
    }

  if (! (resp = bro_record_get_named_val(conn, "resp", &type)))
    {
      printf("[Error obtaining 'orig' member from connection record.]\n");
      return;
    }
  
  type = BRO_TYPE_IPADDR;

  if (! (addr = bro_record_get_named_val(id, "orig_h", &type)))
    {
      printf("[Error obtaining 'orig_h' member from connection ID record.]\n");
      return;
    }

  type = BRO_TYPE_PORT;

  if (! (port = bro_record_get_named_val(id, "orig_p", &type)))
    {
      printf("[Error obtaining 'orig_p' member from connection ID record.]\n");
      return;
    }

  type = BRO_TYPE_COUNT;

  if (! (size = bro_record_get_named_val(orig, "size", &type)))
    {
      printf("[Error obtaining 'size' member from orig endpoint record.]\n");
      return;
    }

  if (! (state = bro_record_get_named_val(orig, "state", &type)))
    {
      printf("[Error obtaining 'state' member from orig endpoint record.]\n");
      return;
    }

  ip.s_addr = *addr;
  printf("%s/%u [%u/%u] -> ", inet_ntoa(ip), port->port_num, *size, *state);
  type = BRO_TYPE_IPADDR;

  if (! (addr = bro_record_get_named_val(id, "resp_h", &type)))
    {
      printf("[Error obtaining 'resp_h' member from connection ID record.]\n");
      return;
    }

  type = BRO_TYPE_PORT;

  if (! (port = bro_record_get_named_val(id, "resp_p", &type)))
    {
      printf("[Error obtaining 'resp_p' member from connection ID record.]\n");
      return;
    }

  type = BRO_TYPE_COUNT;

  if (! (size = bro_record_get_named_val(resp, "size", &type)))
    {
      printf("[Error obtaining 'size' member from orig endpoint record.]\n");
      return;
    }

  if (! (state = bro_record_get_named_val(resp, "state", &type)))
    {
      printf("[Error obtaining 'state' member from orig endpoint record.]\n");
      return;
    }

  ip.s_addr = *addr;
  printf("%s/%u [%u/%u], ", inet_ntoa(ip), port->port_num, *size, *state);
  type = BRO_TYPE_TIME;

  if (! (start_time = bro_record_get_named_val(conn, "start_time", &type)))
    {
      printf("[Error obtaining 'start_time' member from connection record.]\n");
      return;
    }

  type = BRO_TYPE_INTERVAL;

  if (! (duration = bro_record_get_named_val(conn, "duration", &type)))
    {
      printf("[Error obtaining 'duration' member from connection record.]\n");
      return;
    }

  type = BRO_TYPE_SET;

  services = bro_record_get_named_val(conn, "service", &type);

  type = BRO_TYPE_STRING;
  
  if (! (addl = bro_record_get_named_val(conn, "addl", &type)))
    {
      printf("[Error obtaining 'addl' member from connection record.]\n");
      return;
    }
  
  printf("start: %f, duration: %f, addl: '%s', ",
	 *start_time, *duration, addl->str_val);
  
  if (services)
    {
      int type;

      bro_set_get_type(services, &type);

      printf("%i services (type check: %d) ",
	     bro_set_get_size(services), type);
	     
      if (bro_set_get_size(services) > 0)
	bro_set_foreach(services, (BroSetCallback) services_print_cb, NULL);
    }
  else
    printf("no services listed");
  
  printf("\n");
}

static void
conn_new(BroConn *bc, void *data, BroRecord *conn)
{
  printf("new_connection: ");
  conn_generic(bc, conn);
  data = NULL;
}

static void
conn_fin(BroConn *bc, void *data, BroRecord *conn)
{
  printf("connection_finished: ");
  conn_generic(bc, conn);
  data = NULL;
}


int
main(int argc, char **argv)
{
  int opt, port, fd, debugging = 0;
  BroConn *bc;
  extern char *optarg;
  extern int optind;
  char hostname[512];
  fd_set fd_read;

  bro_init(NULL);

  host_str = host_default;
  port_str = port_default;

  bro_debug_calltrace = 0;
  bro_debug_messages  = 0;

  while ( (opt = getopt(argc, argv, "c:p:dh?r")) != -1)
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
  
  /* Connect to Bro */
  if (! (bc = bro_conn_new_str(hostname, BRO_CFLAG_RECONNECT | BRO_CFLAG_ALWAYS_QUEUE)))
    {
      printf("Couldn't get Bro connection handle.\n");
      exit(-1);
    }
  
  /* Request a few event types and have the corresponding callbacks
   * called when they arrive. The callback mechanism automatically figures out
   * the number of arguments and invokes the callback accordingly.
   */
  bro_event_registry_add(bc, "new_connection", (BroEventFunc) conn_new, NULL);
  bro_event_registry_add(bc, "connection_finished", (BroEventFunc) conn_fin, NULL);
 
  if (! bro_conn_connect(bc))
    {
      printf("Could not connect to Bro at %s:%s.\n", host_str, port_str);
      exit(-1);
    }
  
  /* Sit and wait for events */
  fd = bro_conn_get_fd(bc);

  for ( ; ; )
    {
      FD_ZERO(&fd_read);
      FD_SET(fd, &fd_read);
      
      if (select(fd + 1, &fd_read, NULL, NULL, NULL) <= 0)
	break;
      
      bro_conn_process_input(bc);
    }
  
  /* Disconnect from Bro and release state. */
  bro_conn_delete(bc);

  return 0;
}
