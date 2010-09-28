#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include <broccoli.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

using std::string;
using std::vector;
using std::cout;
using std::cin;
using std::cerr;

string default_host = "127.0.0.1";
string default_port = "47757";
string host;
string port;

int count = -1;
int seq;

void
usage(void)
	{
	cout << "broclient - sends events with string arguments from stdin to a running Bro\n"
		"USAGE: broclient [-p port=47757] [host=127.0.0.1]\n"
		"Input format (each line): event_name type=arg1 type=arg2...\n";
	exit(0);
	}

void
showtypes(void)
	{
	cout << "Legitimate event types are:\n"
		"string, int, count, double, bool, time, \n"
		"interval, port, addr, net, subnet\n\n"
		"eamples: string=foo, port=23/tcp, addr=10.10.10.10, \n"
		"net=10.10.10.0 and subnet=10.0.0.0/8\n";
	exit(0);
	}


void tokenize(const string& str, vector<string>& tokens)
	{
	int num_tokens = 0;
	char delim = '\0';

	for ( unsigned int i = 0; i < str.length(); ++i )
		{
		while ( isspace(str[i]) )
			++i;

		string next_arg;

		if (str[i] == '"' || str[i] == '\'')
			{
			delim = str[i];
			++i;
			}
		else
			delim = '\0';
			

		for ( ; str[i]; ++i )
			{
			if ( delim && str[i] == '\\' && 
			     i < str.length() && str[i+1] == delim )
				{
				++i;
				next_arg.push_back(str[i]);
				}

			else if ( delim && str[i] == delim )
				{
				++i;
				break;
				}

			else if ( ! delim && isspace(str[i]) )
				break;
			else
				next_arg.push_back(str[i]);
			}

		tokens.push_back(next_arg);
		}
	}



int
main(int argc, char **argv)
	{
	int opt, use_record = 0, debugging = 0;
	BroConn *bc;
	extern char *optarg;
	extern int optind;

	bro_init(NULL);

	bro_debug_calltrace = 0;
	bro_debug_messages  = 0;

	host = default_host;
	port = default_port;

	while ( (opt = getopt(argc, argv, "p:dh?")) != -1)
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
				port = optarg;
				break;

			default:
				usage();
			}
		}

	argc -= optind;
	argv += optind;

	if (argc > 0)
		host = argv[0];

	/* Connect to Bro */
	if (! (bc = bro_conn_new_str( (host + ":" + port).c_str(), BRO_CFLAG_NONE )))
		{
		cerr << "Could not obtain connection handle for Bro at " << 
			host.c_str() << ":" << port.c_str() << "\n";
		exit(-1);
		}

	cout << "Connecting... \n";
	if (! bro_conn_connect(bc))
		{
		cout << "Could not connect to Bro.\n";
		exit(-1);
		}
  
	cout << "Handshake Complete \n";
	/* Enter pinging loop */
	while ( ! cin.eof() )
		{
		string inp;
		vector<string> tokens;
		cout << "Calling getline .. \n";
		std::getline(cin, inp);

		tokenize(inp, tokens);
		if ( tokens.size() == 0 )
			continue;

		BroEvent *ev;

		cout << "Calling bro_conn_process_input .. \n";
		bro_conn_process_input(bc);

		cout << "Generating Bro event \n";
		if ( (ev = bro_event_new(tokens[0].c_str())) )
			{
      
			for ( unsigned int i = 1; i < tokens.size(); ++i )
				{
				// this is something of a nasty hack, but it does work

				string tkn,tkn_type,tkn_data;
				char delim = '=';

				tkn=tokens[i].c_str();
				string::size_type position = tkn.find_first_of("=",0);

				tkn_type = tkn.substr(0,position);
				tkn_data = tkn.substr(position+1,tkn.length());

				if ( tkn_type == "string" )
					{
					BroString arg;
					bro_string_init(&arg);
					bro_string_set(&arg, tkn_data.c_str());
					bro_event_add_val(ev, BRO_TYPE_STRING, NULL, &arg);
					bro_string_cleanup(&arg);
					}
				else if ( tkn_type == "int" )
					{
					int bint;
					bint = atoi(tkn_data.c_str());
					bro_event_add_val(ev, BRO_TYPE_INT, NULL, (int*)bint);
					}
				else if ( tkn_type == "count" )
					{
					uint32 buint;
					buint = atoi(tkn_data.c_str());
					bro_event_add_val(ev, BRO_TYPE_COUNT, NULL, (uint32*)buint);
					}
				else if ( tkn_type == "double" )
					{
					double bdouble;
					char* end_s;
					bdouble = strtod(tkn_data.c_str(),&end_s);
					bro_event_add_val(ev, BRO_TYPE_DOUBLE, NULL, &bdouble);
					}
				else if ( tkn_type == "bool" )
					{
					int bbool=0;

					if ( tkn_data == "T" || 
						tkn_data == "TRUE" || 
						tkn_data == "1" )
						bbool = 1;
					
					bro_event_add_val(ev, BRO_TYPE_BOOL, NULL, &bbool);
					}
				else if ( tkn_type == "time" )
					{
					double btime;
					char* end_s;
					btime = strtod(tkn_data.c_str(),&end_s);
					bro_event_add_val(ev, BRO_TYPE_TIME, NULL, &btime);
					}
				else if ( tkn_type == "interval" )
					{
					double binterval;
					char* end_s;
					binterval = strtod(tkn_data.c_str(),&end_s);
					bro_event_add_val(ev, BRO_TYPE_INTERVAL, NULL, &binterval);
					}
				else if ( tkn_type == "port" )
					{
					BroPort BP;	
					string port_value;
					string::size_type port_offset;
					int broport;
					
					//determine protocol type, start with tcp/udp do icmp
					// later since the 'ports' are not as simple...
					if ( tkn_data.find("tcp",0) <  tkn_data.length() )
						BP.port_proto = IPPROTO_TCP;
					else BP.port_proto = IPPROTO_UDP;

					// parse out the numeric values
					port_offset = tkn_data.find_first_of("/",0);
					port_value = tkn_data.substr(0,port_offset);

					broport = atoi(port_value.c_str());
					BP.port_num = broport;

					bro_event_add_val(ev, BRO_TYPE_PORT, NULL, &BP);
					
					}
				else if ( tkn_type == "addr" )
					{
					uint32 badd;
					// badd=htonl((uint32)inet_addr(tkn_data.c_str()));
					badd=(uint32)inet_addr(tkn_data.c_str());

					bro_event_add_val(ev, BRO_TYPE_IPADDR, NULL, &badd);
					}	
				else if ( tkn_type == "net" )
					{
					uint32 bnet;
					// bnet=htonl((uint32)inet_addr(tkn_data.c_str()));
					bnet=(uint32)inet_addr(tkn_data.c_str());

					bro_event_add_val(ev, BRO_TYPE_NET, NULL, &bnet);
					}
				else if ( tkn_type == "subnet" )
					{
					// this is assuming a string that looks like
					// "subnet=10.0.0.0/8"
					BroSubnet BS;
					string subnet_value;
					string subnet_width;
					string::size_type mask_offset;
					uint32 sn_net, sn_width;

					//parse out numeric values
					mask_offset = tkn_data.find_first_of("/",0);
					subnet_value = tkn_data.substr(0,mask_offset);
					subnet_width = tkn_data.substr(mask_offset+1,tkn_data.length());

					sn_net = (uint32)inet_addr(subnet_value.c_str());
					sn_width = (uint32)atol(subnet_width.c_str());

					BS.sn_net = sn_net;
					BS.sn_width = sn_width;

					bro_event_add_val(ev, BRO_TYPE_SUBNET, NULL, &BS);
					}
				else
					{
					// there is something wrong here
					cerr << "unknown data type: " << tkn_type << "\n\n";
					bro_event_free(ev);
					showtypes();
					}

				}
			
			/* Ship it -- sends it if possible, queues it otherwise */
		        cout << "Sending event to Bro \n";
			if ( ! bro_event_send(bc, ev) )
				cerr << "event could not be sent right away\n";

			bro_event_free(ev);
			}
		}


	/* Disconnect from Bro */
	bro_conn_delete(bc);
	
	return 0;
	}
