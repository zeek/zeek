#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>

#include <broccoli.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

char *ip_default   = "127.0.0.1";
char *port_default = "47756";

int
main(int argc, char **argv)
{
  char *ip_str = ip_default;
  char *port_str = port_default;
  int port;
  struct in_addr ipaddr;
  BroConn *bc;
  BroEvent *ev;
  int i;

  if (argc >= 2)
    ip_str = argv[1];
  if (argc >= 3)
    port_str = argv[2];
    
  if (inet_pton(AF_INET, ip_str, &ipaddr) <= 0)
    {
      printf("Please provide an IP address to contact as first argument.\n");
      exit(-1);
    }

  port = strtol(port_str, NULL, 0);
  if (errno == ERANGE)
    {
      printf("Please provide a port number as second argument.\n");
      exit(-1);
    }

  bro_init(NULL);

  printf("Opening connection.\n");
  if (! (bc = bro_connect_remote(0x0000, &ipaddr, port)))
    {
      printf("Couldn't connect.\n");
      exit(-1);
    }
  
  sleep(1);
  bro_conn_process_input(bc);

  sleep(5);
  bro_conn_process_input(bc);

  /*
  if ( (ev = bro_event_new("bar")))
    {
      bro_event_add_string(ev, "hello world");

      if (bro_event_send(bc, ev))
	printf("Bro test event sent.\n");
      else
	printf("Bro test event queued.\n");
    }

  if ( (ev = bro_event_new("foo")))
    {
      bro_event_add_string(ev, "hello world");

      if (bro_event_send(bc, ev))
	printf("Bro test event sent.\n");
      else
	printf("Bro test event queued.\n");
    }
  */
  sleep(2);

  printf("Disconnecting.\n");
  bro_disconnect(bc);

  return 0;
}
