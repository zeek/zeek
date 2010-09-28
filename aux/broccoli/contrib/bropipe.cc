// $Id: bropipe.cc 6940 2009-11-14 00:38:53Z robin $
// bropipe.cc: pipe version of generic client
// 02/04/05
//
// to compile:  g++ `broccoli-config --cflags` `broccoli-config --libs` -o bropipe bropipe.cc
//


#include <vector>
#include <iostream>
#include <iomanip>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include "broccoli.h"

using std::string;
using std::vector;
using std::cout;
using std::cin;
using std::cerr;

string default_host = "127.0.0.1";
string default_port = "47757";
string default_input_file = "brocsock";
string default_log_file = "/tmp/bropipe.log";

string conn_str;
string host;
string port;
string input_file;
string log_file;
int debug;
BroConn *bc;

// The following are declarations needed for the modp_burl string decoding
// functions. They were cribbed from the stringencoders-v3.7.0 source tree.
// syc 1/20/09

/**
 * \file
 * <pre>
 * BFASTURL.c High performance URL encoder/decoder
 * http://code.google.com/p/stringencoders/
 *
 * Copyright &copy; 2006,2007  Nick Galbreath -- nickg [at] modp [dot] com
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 *   Neither the name of the modp.com nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This is the standard "new" BSD license:
 * http://www.opensource.org/licenses/bsd-license.php
 * </PRE>
 */

static const uint32_t gsHexDecodeMap[256] = {
256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
  0,   1,   2,   3,   4,   5,   6,   7,   8,   9, 256, 256,
256, 256, 256, 256, 256,  10,  11,  12,  13,  14,  15, 256,
256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
256,  10,  11,  12,  13,  14,  15, 256, 256, 256, 256, 256,
256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
256, 256, 256, 256
};


int modp_burl_decode(char* dest, const char* s, int len)
{
    uint32_t d = 0; // used for decoding %XX
    const uint8_t* src = (const uint8_t*) s;
    const char* deststart = dest;
    const uint8_t* srcend = (const uint8_t*)(src + len);
    const uint8_t* srcendloop = (const uint8_t*)(srcend - 2);

    while (src < srcendloop) {
        switch (*src) {
        case '+':
            *dest++ = ' ';
            src++;
            break;
        case '%':
            d = (gsHexDecodeMap[(uint32_t)(*(src + 1))] << 4) |
                gsHexDecodeMap[(uint32_t)(*(src + 2))];
            if (d < 256) { // if one of the hex chars is bad,  d >= 256
                *dest = (char) d;
                dest++;
                src += 3;
            } else {
                *dest++ = '%';
                src++;
            }
            break;
        default:
            *dest++ = *src++;
        }
    }

    // handle last two chars
    // dont decode "%XX"
    while (src < srcend) {
        switch (*src) {
        case '+':
            *dest++ = ' ';
            src++;
            break;
        default:
            *dest++ = *src++;
        }
    }

    *dest = '\0';
    return dest - deststart; // compute "strlen" of dest.
}

void usage(void)
	{
	cout << "bropipe - sends events with string arguments from file to a\n"
		"	running Bro\n"
		"USAGE: bropipe [-p port=47757] [-f input] [host=127.0.0.1[:port]] [-d]\n"
		"Input format (each line): event_name type=arg1 type=arg2...\n";
	exit(0);
	}

void showtypes(void)
	{
	cout << "Legitimate event types are:\n"
		"	string, urlstring, int, count, double, bool, time, \n"
		"	interval, port, addr, net, subnet\n\n"
		"	examples: string=foo, port=23/tcp, addr=10.10.10.10, \n"
		"	net=10.10.10.0, subnet=10.0.0.0/8\n"
		"	urlstring is a url encoded string type - use this when\n"
		"	whitespace can be found in the strings\n";
	exit(0);
	}

void tokenize(const string& str, vector<string>& tokens)
	{
	int num_tokens = 0;
	char delim = '\0';
 
	for ( unsigned int i = 0; i < str.length(); ++i ) {
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

void ntokenize(const string& str, vector<string>& inText)
		{
		int num_tokens = 0;
		char delim = '\n';
																											
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
				delim = '\n';
																											
				for ( ; str[i]; ++i )
						{
						if ( delim && str[i] == '\\' &&
								 i < str.length() && str[i+1] == delim )
								{
								next_arg.push_back(str[i]);
								++i;
								}
																											
						else if ( delim && str[i] == delim )
								{
								break;
								}
																											
						else if ( ! delim && isspace(str[i]) )
								break;
						else
								next_arg.push_back(str[i]);
						}
								
				inText.push_back(next_arg);
				}
		}


FILE * open_input_stream()
	{
	FILE *fp;

	if (input_file == "-") 
		{
		fp = stdin;
		if (debug)
			fprintf(stderr, "DEBUG: input is STDIN.\n");
		}
	else
		{
		if (debug)
			fprintf(stderr, "DEBUG: try opening `%s' as input\n", input_file.c_str());
		fp = fopen(input_file.c_str(),"r");
	  	if (fp == NULL)
		  	{
			if (debug)
				fprintf(stderr, "DEBUG: can't open, so creating pipe %s\n", input_file.c_str());

			mkfifo(input_file.c_str(), S_IRUSR | S_IRGRP | S_IROTH );
	  		fp = fopen(input_file.c_str(),"r");

			if (fp==NULL) 
				fprintf(stderr, "Failed to create pipe %s\n", input_file.c_str());
			else
				if (debug)
					fprintf(stderr, "DEBUG: created and opened pipe `%s'\n", input_file.c_str());

	  		}
		}

	return(fp);
	}


int make_connection()
	{
	// now connect to the bro host - on failure, try again three times
	// the flags here are telling us to block on connect, reconnect in the
	// event of a connection failure, and queue up events in the event of a
	// failure to the bro host
	//
	// the flags have been modified to allow for connect back and event queuing

	if ((bc = bro_conn_new_str(conn_str.c_str(), BRO_CFLAG_RECONNECT | BRO_CFLAG_ALWAYS_QUEUE)))
		{
		if (debug)
			fprintf(stderr, "DEBUG: got BroConn handle\n");
		}
	else
		{
		fprintf(stderr, "fatal: could not get BroConn handle.\n");
		exit(-1);
		}

        if (debug)
	    fprintf(stderr, "DEBUG: attempt to connect to %s...", conn_str.c_str());

	bro_conn_set_class(bc, "bropipe");

        while (!bro_conn_connect (bc)) {
            fprintf (stderr, "could not connect to Bro at %s:%s.\n",
                     host.c_str (), port.c_str ());
            fprintf (stderr, "Will try again in 5 seconds \n");
            sleep (5);
        }

        if (debug)
            fprintf(stderr, "DEBUG: connected\n");
                                                
	return(0);
	}

int main(int argc, char **argv)
	{
	int fd,rc,n;
	int j;
	int ecount=0;
	fd_set readfds;
	char buf[1024];
	char *urlstr = NULL;
	int urlstrsz = 0;

	struct timeval tv;
	FILE *fp;

	int opt, use_record = 0;
	extern char *optarg;
	extern int optind;

	bro_init(NULL);

	host = default_host + ":" + default_port;
	input_file = default_input_file;

	while ( (opt = getopt(argc, argv, "l:f:p:dDh?")) != -1)
	{
		switch (opt)
			{
			case 'l':
				log_file = optarg;				
				break;

			case 'f':
				input_file = optarg;				
				break;

			case 'd':
				debug++;
				break;
 
			case 'D':
				debug++; 
				debug++;
				break;

			case 'h':
			case '?':
				usage();
				break;
 
			case 'p':
				port = optarg;
				break;
 
			default:
				usage();
				break;
			}
	}
 
	argc -= optind;
	argv += optind;

	if (argc == 1) {
	  host = argv[0];
	  if (host.find(':') == string::npos)
	    host += ":" + default_port;
	}


    if (argc > 1)
        usage();
        
    // config destination connection string
    conn_str = host;
    if (port != "")
        {
        conn_str += ":"; 
        conn_str += port;
        }

	// open input 
	fp = open_input_stream();
	if (fp == NULL) {
		fprintf(stderr, "fatal: failed to get input stream\n");
		return(1);
	}

	if (!debug || debug < 2) 
		make_connection();
	else 
		if (debug)
			fprintf(stderr, "DEBUG: not connecting to Bro (debug level >1)\n");



	// socket and pipe are set up, now start processing
	if(debug)
		fprintf(stderr, "DEBUG: waiting for data on input stream...\n");

	while(fgets(buf, sizeof(buf), fp)) 
		{
		ecount++;
		string inp;
		vector<string> inText; //text inputts within the pipe
		vector<string> tokens;

		if (debug) 
			fprintf(stderr, "DEBUG: read event #%d: %s", ecount, buf);

		if(debug >1)
			continue;
		
		
		inp = buf;
		ntokenize(inp, inText);

		BroEvent *ev;
		bro_conn_process_input(bc);

		for(j=0;j<inText.size();++j) 
		{

		tokens.clear(); // make sure that the vector is clear
		tokenize(inText[j].c_str(), tokens);
	        // if this line didn't tokenize to anything, skip the rest of the block
                if ( tokens.size() == 0)
                     continue;

		if ( ev = bro_event_new(tokens[0].c_str()) )
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
					bro_string_set(&arg,tkn_data.c_str());
					bro_event_add_val(ev, BRO_TYPE_STRING, NULL, &arg);
					bro_string_cleanup(&arg);
					}
				else if (tkn_type == "urlstring")
				        {
					BroString arg;
					bro_string_init(&arg);
					int sz= strlen(tkn_data.c_str()) + 1;
					if ( sz > urlstrsz) {
					    if (urlstr)
					        free( urlstr);
					    urlstr = (char *)malloc( sz);
					    if (urlstr == NULL) {
					        fprintf( stderr,"Could not allocate %d bytes for url conversion buffer\n",sz);
						return(1);
					    }
					    urlstrsz = sz;
					}
					modp_burl_decode(urlstr,tkn_data.c_str(),strlen(tkn_data.c_str()));
					bro_string_set(&arg,urlstr);
					bro_event_add_val(ev, BRO_TYPE_STRING, NULL, &arg);
					bro_string_cleanup(&arg);
					}
					  
				else if ( tkn_type == "int" )
					{
					int bint;
					bint = atoi(tkn_data.c_str());
					bro_event_add_val(ev, BRO_TYPE_INT, NULL, &bint);
					}
				else if ( tkn_type == "count" )
					{
					uint32 buint;
					buint = atoi(tkn_data.c_str());
					bro_event_add_val(ev, BRO_TYPE_COUNT, NULL, &buint);
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
					if ( tkn_data.find("tcp",0) <tkn_data.length() )
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
					badd=(uint32)inet_addr(tkn_data.c_str());
					//badd=htonl((uint32)inet_addr(tkn_data.c_str()));
 
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
 
					bro_event_add_val(ev, BRO_TYPE_SUBNET,NULL,  &BS);
					}
				else
					{
					// there is something wrong here with the data
					// type.  since it might be binary data, don't 
					// punt it out.  Also showtypes() will just toss
					// junk to the bro, so comment out.
					cerr << "unknown data type " << tkn_type << "\n";
					//cerr << " from -|" << inText[j].c_str() << "|-\n";
					//showtypes();
					}
 
				}
			}
			/* Ship it -- sends it if possible, queues it otherwise */
			if ( !bro_conn_alive(bc) )
				{
				cerr << "connection bad, resetting\n";
				make_connection();
				}
			//else
			//	cerr << "connection ok!\n";


			//bro_event_send(bc, ev);
			if ( ! bro_event_send(bc, ev) )
				cerr << "event could not be sent right away\n";

			// now clean up after ourselves...
			bro_event_free(ev);	
		}			
	}
	fclose(fp);

	if (debug)
		fprintf(stderr, "DEBUG: End of input stream; exiting\n");
}


