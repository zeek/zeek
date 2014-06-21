// See the file "COPYING" in the main distribution directory for copyright.
//
// Written by Bernhard Ager, TU Berlin (2006/2007).

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>

#include "FlowSrc.h"
#include "Net.h"
#include "analyzer/protocol/netflow/netflow_pac.h"
#include <errno.h>

FlowSrc::FlowSrc()
	{ // TODO: v9.
	selectable_fd = -1;
	idle = false;
	data = 0;
	pdu_len = -1;
	exporter_ip = 0;
	current_timestamp = next_timestamp = 0.0;
	netflow_analyzer = new binpac::NetFlow::NetFlow_Analyzer();
	}

FlowSrc::~FlowSrc()
	{
	delete netflow_analyzer;
	}

void FlowSrc::GetFds(int* read, int* write, int* except)
	{
	if ( selectable_fd >= 0 )
		*read = selectable_fd;
	}

double FlowSrc::NextTimestamp(double* network_time)
	{
	if ( ! data && ! ExtractNextPDU() )
		return -1.0;
	else
		return next_timestamp;
	}

void FlowSrc::Process()
	{
	if ( ! data && ! ExtractNextPDU() )
		return;

	// This is normally done by calling net_packet_dispatch(),
	// but as we don't have a packet to dispatch ...
	network_time = next_timestamp;
	expire_timers();

	netflow_analyzer->downflow()->set_exporter_ip(exporter_ip);

	// We handle exceptions in NewData (might have changed w/ new binpac).
	netflow_analyzer->NewData(0, data, data + pdu_len);
	data = 0;
	}

void FlowSrc::Close()
	{
	safe_close(selectable_fd);
	}


FlowSocketSrc::~FlowSocketSrc()
	{
	}

int FlowSocketSrc::ExtractNextPDU()
	{
	sockaddr_in from;
	socklen_t fromlen = sizeof(from);
	pdu_len = recvfrom(selectable_fd, buffer, NF_MAX_PKT_SIZE, 0,
				(struct sockaddr*) &from, &fromlen);
	if ( pdu_len < 0 )
		{
		reporter->Error("problem reading NetFlow data from socket");
		data = 0;
		next_timestamp = -1.0;
		closed = 1;
		return 0;
		}

	if ( fromlen != sizeof(from) )
		{
		reporter->Error("malformed NetFlow PDU");
		return 0;
		}

	data = buffer;
	exporter_ip = from.sin_addr.s_addr;
	next_timestamp = current_time();

	if ( next_timestamp < current_timestamp )
		next_timestamp = current_timestamp;
	else
		current_timestamp = next_timestamp;

	return 1;
	}

FlowSocketSrc::FlowSocketSrc(const char* listen_parms)
	{
	int n = strlen(listen_parms) + 1;

	char laddr[n], port[n], ident[n];
	laddr[0] = port[0] = ident[0] = '\0';

	int ret = sscanf(listen_parms, "%[^:]:%[^=]=%s", laddr, port, ident);
	if ( ret < 2 )
		{
		snprintf(errbuf, BRO_FLOW_ERRBUF_SIZE,
			"parsing your listen-spec went nuts: laddr='%s', port='%s'\n",
			laddr[0] ? laddr : "", port[0] ? port : "");
		closed = 1;
		return;
		}

	const char* id = (ret == 3) ? ident : listen_parms;
	netflow_analyzer->downflow()->set_identifier(id);

	struct addrinfo aiprefs = {
		0, PF_INET, SOCK_DGRAM, IPPROTO_UDP, 0, NULL, NULL, NULL
	};
	struct addrinfo* ainfo = 0;
	if ( (ret = getaddrinfo(laddr, port, &aiprefs, &ainfo)) != 0 )
		{
		snprintf(errbuf, BRO_FLOW_ERRBUF_SIZE,
				"getaddrinfo(%s, %s, ...): %s",
				laddr, port, gai_strerror(ret));
		closed = 1;
		return;
		}

	if ( (selectable_fd = socket (PF_INET, SOCK_DGRAM, 0)) < 0 )
		{
		snprintf(errbuf, BRO_FLOW_ERRBUF_SIZE,
				"socket: %s", strerror(errno));
		closed = 1;
		goto cleanup;
		}

	if ( bind (selectable_fd, ainfo->ai_addr, ainfo->ai_addrlen) < 0 )
		{
		snprintf(errbuf, BRO_FLOW_ERRBUF_SIZE,
				"bind: %s", strerror(errno));
		closed = 1;
		goto cleanup;
		}

cleanup:
	freeaddrinfo(ainfo);
	}


FlowFileSrc::~FlowFileSrc()
	{
	delete [] readfile;
	}

int FlowFileSrc::ExtractNextPDU()
	{
	FlowFileSrcPDUHeader pdu_header;

	if ( read(selectable_fd, &pdu_header, sizeof(pdu_header)) <
	     int(sizeof(pdu_header)) )
		return Error(errno, "read header");

	if ( pdu_header.pdu_length > NF_MAX_PKT_SIZE )
		{
		reporter->Error("NetFlow packet too long");

		// Safely skip over the too-long PDU.
		if ( lseek(selectable_fd, pdu_header.pdu_length, SEEK_CUR) < 0 )
			return Error(errno, "lseek");
		return 0;
		}

	if ( read(selectable_fd, buffer, pdu_header.pdu_length) <
	     pdu_header.pdu_length )
		return Error(errno, "read data");

	if ( next_timestamp < pdu_header.network_time )
		{
		next_timestamp = pdu_header.network_time;
		current_timestamp = pdu_header.network_time;
		}
	else
		current_timestamp = next_timestamp;

	data = buffer;
	pdu_len = pdu_header.pdu_length;
	exporter_ip = pdu_header.ipaddr;

	return 1;
	}

FlowFileSrc::FlowFileSrc(const char* readfile)
	{
	int n = strlen(readfile) + 1;
	char ident[n];
	this->readfile = new char[n];

	int ret = sscanf(readfile, "%[^=]=%s", this->readfile, ident);
	const char* id = (ret == 2) ? ident : this->readfile;
	netflow_analyzer->downflow()->set_identifier(id);

	selectable_fd = open(this->readfile, O_RDONLY);
	if ( selectable_fd < 0 )
		{
		closed = 1;
		snprintf(errbuf, BRO_FLOW_ERRBUF_SIZE,
				"open: %s", strerror(errno));
		}
	}

int FlowFileSrc::Error(int errlvl, const char* errmsg)
	{
	snprintf(errbuf, BRO_FLOW_ERRBUF_SIZE,
			"%s: %s", errmsg, strerror(errlvl));
	data = 0;
	next_timestamp = -1.0;
	closed = 1;
	return 0;
	}
