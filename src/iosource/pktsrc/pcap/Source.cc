
#include <assert.h>

#include "config.h"

#include "Source.h"

#ifdef HAVE_PCAP_INT_H
#include <pcap-int.h>
#endif

using namespace iosource::pktsrc;

PcapSource::~PcapSource()
	{
	Close();
	}

PcapSource::PcapSource(const std::string& path, const std::string& filter, bool is_live)
	{
	props.path = path;
	props.filter = filter;
	props.is_live = is_live;
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

	BPF_Program* code;
	IterCookie* cookie = filters.InitForIteration();
	while ( (code = filters.NextEntry(cookie)) )
		delete code;

	filters.Clear();

	pcap_close(pd);
	pd = 0;
	last_data = 0;

	Closed();
	}

void PcapSource::OpenLive()
	{
	char errbuf[PCAP_ERRBUF_SIZE];
	char tmp_errbuf[PCAP_ERRBUF_SIZE];

#if 0
	filter_type = ft;
#endif

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
	if ( pcap_lookupnet(props.path.c_str(), &net, &netmask, tmp_errbuf) < 0 )
		{
		// ### The lookup can fail if no address is assigned to
		// the interface; and libpcap doesn't have any useful notion
		// of error codes, just error std::strings - how bogus - so we
		// just kludge around the error :-(.
		// sprintf(errbuf, "pcap_lookupnet %s", tmp_errbuf);
		// return;
		netmask = 0xffffff00;
		}

	// We use the smallest time-out possible to return almost immediately if
	// no packets are available. (We can't use set_nonblocking() as it's
	// broken on FreeBSD: even when select() indicates that we can read
	// something, we may get nothing if the store buffer hasn't filled up
	// yet.)
	pd = pcap_open_live(props.path.c_str(), SnapLen(), 1, 1, tmp_errbuf);

	if ( ! pd )
		{
		Error(tmp_errbuf);
		return;
		}

	// ### This needs autoconf'ing.
#ifdef HAVE_PCAP_INT_H
	Info("pcap bufsize = %d\n", ((struct pcap *) pd)->bufsize);
#endif

#ifdef HAVE_LINUX
	if ( pcap_setnonblock(pd, 1, tmp_errbuf) < 0 )
		{
		PcapError();
		return;
		}
#endif

	props.selectable_fd = pcap_fileno(pd);

	if ( PrecompileFilter(0, props.filter) && SetFilter(0) )
		{
		SetHdrSize();

		if ( ! pd )
			// Was closed, couldn't get header size.
			return;

		Info(fmt("listening on %s, capture length %d bytes\n", props.path.c_str(), SnapLen()));
		}
	else
		Close();

	props.is_live = true;
	Opened(props);
	}

void PcapSource::OpenOffline()
	{
	char errbuf[PCAP_ERRBUF_SIZE];

#if 0
	filter_type = ft;
#endif

	pd = pcap_open_offline(props.path.c_str(), errbuf);

	if ( ! pd )
		{
		Error(errbuf);
		return;
		}

	if ( PrecompileFilter(0, props.filter) && SetFilter(0) )
		{
		SetHdrSize();

		if ( ! pd )
			// Was closed, unknown link layer type.
			return;

		// We don't put file sources into non-blocking mode as
		// otherwise we would not be able to identify the EOF.

		props.selectable_fd = fileno(pcap_file(pd));

		if ( props.selectable_fd < 0 )
			InternalError("OS does not support selectable pcap fd");
		}

	else
		Close();

	props.is_live = false;
	Opened(props);
	}

int PcapSource::ExtractNextPacket(Packet* pkt)
	{
	if ( ! pd )
		return 0;

	const u_char* data = pcap_next(pd, &current_hdr);

	if ( ! data )
		{
		// Source has gone dry.  If it's a network interface, this just means
		// it's timed out. If it's a file, though, then the file has been
		// exhausted.
		if ( ! props.is_live )
			Close();

		return 0;
		}

	pkt->ts = current_hdr.ts.tv_sec + double(current_hdr.ts.tv_usec) / 1e6;
	pkt->hdr = &current_hdr;
	pkt->data = last_data = data;

	if ( current_hdr.len == 0 || current_hdr.caplen == 0 )
		{
		Weird("empty_pcap_header", pkt);
		return 0;
		}

	last_hdr = current_hdr;
	last_data = data;
	++stats.received;
	return 1;
	}

void PcapSource::DoneWithPacket(Packet* pkt)
	{
	// Nothing to do.
	}

int PcapSource::PrecompileFilter(int index, const std::string& filter)
	{
	if ( ! pd )
		return 1; // Prevent error message.

	char errbuf[PCAP_ERRBUF_SIZE];

	// Compile filter.
	BPF_Program* code = new BPF_Program();

	if ( ! code->Compile(pd, filter.c_str(), netmask, errbuf, sizeof(errbuf)) )
		{
		PcapError();
		delete code;
		return 0;
		}

	// Store it in hash.
	HashKey* hash = new HashKey(HashKey(bro_int_t(index)));
	BPF_Program* oldcode = filters.Lookup(hash);
	if ( oldcode )
		delete oldcode;

	filters.Insert(hash, code);
	delete hash;

	return 1;
	}

int PcapSource::SetFilter(int index)
	{
	if ( ! pd )
		return 1; // Prevent error message

	char errbuf[PCAP_ERRBUF_SIZE];

	HashKey* hash = new HashKey(HashKey(bro_int_t(index)));
	BPF_Program* code = filters.Lookup(hash);
	delete hash;

	if ( ! code )
		{
		safe_snprintf(errbuf, sizeof(errbuf),
			      "No precompiled pcap filter for index %d",
			      index);
		Error(errbuf);
		return 0;
		}

	if ( pcap_setfilter(pd, code->GetProgram()) < 0 )
		{
		PcapError();
		return 0;
		}

#ifndef HAVE_LINUX
	// Linux doesn't clear counters when resetting filter.
	stats.received = stats.dropped = stats.link = 0;
#endif

	return 1;
	}

void PcapSource::Statistics(Stats* s)
	{
	char errbuf[PCAP_ERRBUF_SIZE];

	if ( ! (props.is_live && pd) )
		s->received = s->dropped = s->link = 0;

	else
		{
		struct pcap_stat pstat;
		if ( pcap_stats(pd, &pstat) < 0 )
			{
			PcapError();
			s->received = s->dropped = s->link = 0;
			}

		else
			{
			s->dropped = pstat.ps_drop;
			s->link = pstat.ps_recv;
			}
		}

	s->received = stats.received;

	if ( ! props.is_live )
		s->dropped = 0;
	}

bool PcapSource::GetCurrentPacket(const pcap_pkthdr** hdr, const u_char** pkt)
	{
	if ( ! last_data )
		return false;

	*hdr = &last_hdr;
	*pkt = last_data;
	return true;
	}

void PcapSource::PcapError()
	{
	if ( pd )
		Error(fmt("pcap_error: %s", pcap_geterr(pd)));
	else
		Error("pcap_error: not open");

	Close();
	}

void PcapSource::SetHdrSize()
	{
	if ( ! pd )
		return;

	char errbuf[PCAP_ERRBUF_SIZE];

	props.link_type = pcap_datalink(pd);
	props.hdr_size = GetLinkHeaderSize(props.link_type);

	if ( props.hdr_size < 0 )
		{
		safe_snprintf(errbuf, sizeof(errbuf),
			 "unknown data link type 0x%x", props.link_type);
		Error(errbuf);
		Close();
		}
	}

iosource::PktSrc* PcapSource::Instantiate(const std::string& path, const std::string& filter, bool is_live)
	{
	return new PcapSource(path, filter, is_live);
	}
