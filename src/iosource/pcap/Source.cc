// See the file  in the main distribution directory for copyright.

#include <assert.h>

#include "zeek-config.h"

#include "Source.h"
#include "iosource/Packet.h"

#include "pcap.bif.h"

#ifdef HAVE_PCAP_INT_H
#include <pcap-int.h>
#endif

using namespace iosource::pcap;

PcapSource::~PcapSource()
	{
	Close();
	}

PcapSource::PcapSource(const std::string& path, bool is_live)
	{
	props.path = path;
	props.is_live = is_live;
	pd = 0;
	memset(&current_hdr, 0, sizeof(current_hdr));
	memset(&last_hdr, 0, sizeof(last_hdr));
	last_data = 0;
	}

void PcapSource::Open()
	{
	if ( props.is_live )
		OpenLive();
	else
		OpenOffline();
	}

void PcapSource::Close()
	{
	if ( ! pd )
		return;

	pcap_close(pd);
	pd = 0;
	last_data = 0;

	Closed();
	}

void PcapSource::OpenLive()
	{
	char errbuf[PCAP_ERRBUF_SIZE];
	char tmp_errbuf[PCAP_ERRBUF_SIZE];

	// Determine interface if not specified.
	if ( props.path.empty() )
		props.path = pcap_lookupdev(tmp_errbuf);

	if ( props.path.empty() )
		{
		safe_snprintf(errbuf, sizeof(errbuf),
			 "pcap_lookupdev: %s", tmp_errbuf);
		Error(errbuf);
		return;
		}

	// Determine network and netmask.
	uint32 net;
	if ( pcap_lookupnet(props.path.c_str(), &net, &props.netmask, tmp_errbuf) < 0 )
		{
		// ### The lookup can fail if no address is assigned to
		// the interface; and libpcap doesn't have any useful notion
		// of error codes, just error std::strings - how bogus - so we
		// just kludge around the error :-(.
		// sprintf(errbuf, "pcap_lookupnet %s", tmp_errbuf);
		// return;
		props.netmask = 0xffffff00;
		}

#ifdef PCAP_NETMASK_UNKNOWN
	// Defined in libpcap >= 1.1.1
	if ( props.netmask == PCAP_NETMASK_UNKNOWN )
		props.netmask = PktSrc::NETMASK_UNKNOWN;
#endif

	pd = pcap_create(props.path.c_str(), errbuf);

	if ( ! pd )
		{
		PcapError("pcap_create");
		return;
		}

	if ( pcap_set_snaplen(pd, BifConst::Pcap::snaplen) )
		{
		PcapError("pcap_set_snaplen");
		return;
		}

	if ( pcap_set_promisc(pd, 1) )
		{
		PcapError("pcap_set_promisc");
		return;
		}

	// We use the smallest time-out possible to return almost immediately
	// if no packets are available. (We can't use set_nonblocking() as
	// it's broken on FreeBSD: even when select() indicates that we can
	// read something, we may get nothing if the store buffer hasn't
	// filled up yet.)
	//
	// TODO: The comment about FreeBSD is pretty old and may not apply
	// anymore these days.
	if ( pcap_set_timeout(pd, 1) )
		{
		PcapError("pcap_set_timeout");
		return;
		}

	if ( pcap_set_buffer_size(pd, BifConst::Pcap::bufsize * 1024 * 1024) )
		{
		PcapError("pcap_set_buffer_size");
		return;
		}

	if ( pcap_activate(pd) )
		{
		PcapError("pcap_activate");
		return;
		}

#ifdef HAVE_LINUX
	if ( pcap_setnonblock(pd, 1, tmp_errbuf) < 0 )
		{
		PcapError("pcap_setnonblock");
		return;
		}
#endif

#ifdef HAVE_PCAP_INT_H
	Info(fmt("pcap bufsize = %d\n", ((struct pcap *) pd)->bufsize));
#endif

	props.selectable_fd = pcap_fileno(pd);

	SetHdrSize();

	if ( ! pd )
		// Was closed, couldn't get header size.
		return;

	props.is_live = true;

	Opened(props);
	}

void PcapSource::OpenOffline()
	{
	char errbuf[PCAP_ERRBUF_SIZE];

	pd = pcap_open_offline(props.path.c_str(), errbuf);

	if ( ! pd )
		{
		Error(errbuf);
		return;
		}

	SetHdrSize();

	if ( ! pd )
		// Was closed, unknown link layer type.
		return;

	props.selectable_fd = fileno(pcap_file(pd));

	if ( props.selectable_fd < 0 )
		InternalError("OS does not support selectable pcap fd");

	props.is_live = false;
	Opened(props);
	}

bool PcapSource::ExtractNextPacket(Packet* pkt)
	{
	if ( ! pd )
		return false;

	const u_char* data = pcap_next(pd, &current_hdr);

	if ( ! data )
		{
		// Source has gone dry.  If it's a network interface, this just means
		// it's timed out. If it's a file, though, then the file has been
		// exhausted.
		if ( ! props.is_live )
			Close();

		return false;
		}

	last_data = data;
	pkt->Init(props.link_type, &current_hdr.ts, current_hdr.caplen, current_hdr.len, data);

	if ( current_hdr.len == 0 || current_hdr.caplen == 0 )
		{
		Weird("empty_pcap_header", pkt);
		return false;
		}

	last_hdr = current_hdr;
	last_data = data;
	++stats.received;
	stats.bytes_received += current_hdr.len;

	return true;
	}

void PcapSource::DoneWithPacket()
	{
	// Nothing to do.
	}

bool PcapSource::PrecompileFilter(int index, const std::string& filter)
	{
	return PktSrc::PrecompileBPFFilter(index, filter);
	}

bool PcapSource::SetFilter(int index)
	{
	if ( ! pd )
		return true; // Prevent error message

	char errbuf[PCAP_ERRBUF_SIZE];

	BPF_Program* code = GetBPFFilter(index);

	if ( ! code )
		{
		safe_snprintf(errbuf, sizeof(errbuf),
			      "No precompiled pcap filter for index %d",
			      index);
		Error(errbuf);
		return false;
		}

	if ( LinkType() == DLT_NFLOG )
		{
		// No-op, NFLOG does not support BPF filters.
		// Raising a warning might be good, but it would also be noisy
		// since the default scripts will always attempt to compile
		// and install a default filter
		}
	else
		{
		if ( pcap_setfilter(pd, code->GetProgram()) < 0 )
			{
			PcapError();
			return false;
			}
		}

#ifndef HAVE_LINUX
	// Linux doesn't clear counters when resetting filter.
	stats.received = stats.dropped = stats.link = stats.bytes_received = 0;
#endif

	return true;
	}

void PcapSource::Statistics(Stats* s)
	{
	char errbuf[PCAP_ERRBUF_SIZE];

	if ( ! (props.is_live && pd) )
		s->received = s->dropped = s->link = s->bytes_received = 0;

	else
		{
		struct pcap_stat pstat;
		if ( pcap_stats(pd, &pstat) < 0 )
			{
			PcapError();
			s->received = s->dropped = s->link = s->bytes_received = 0;
			}

		else
			{
			s->dropped = pstat.ps_drop;
			s->link = pstat.ps_recv;
			}
		}

	s->received = stats.received;
	s->bytes_received = stats.bytes_received;

	if ( ! props.is_live )
		s->dropped = 0;
	}

void PcapSource::PcapError(const char* where)
	{
	string location;

	if ( where )
		location = fmt(" (%s)", where);

	if ( pd )
		Error(fmt("pcap_error: %s%s", pcap_geterr(pd), location.c_str()));
	else
		Error(fmt("pcap_error: not open%s", location.c_str()));

	Close();
	}

void PcapSource::SetHdrSize()
	{
	if ( ! pd )
		return;

	char errbuf[PCAP_ERRBUF_SIZE];

	props.link_type = pcap_datalink(pd);
	}

iosource::PktSrc* PcapSource::Instantiate(const std::string& path, bool is_live)
	{
	return new PcapSource(path, is_live);
	}
