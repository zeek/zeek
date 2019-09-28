#include "Source.h"

#include "util.h"
#include "Reporter.h"

using namespace iosource::pcap;

// TODO: these should be from BifConst::Pcap
const int snaplen = 9216;
const int bufsize = 128;

PcapSource::PcapSource(const std::string& path, bool is_live) : PktSrc()
	{
	props.path = path;
	props.is_live = is_live;

	memset(&current_hdr, 0, sizeof(current_hdr));
	memset(&last_hdr, 0, sizeof(last_hdr));
	}

bool PcapSource::OpenLive()
	{
	char errbuf[PCAP_ERRBUF_SIZE];

	// Determine interface if not specified.
	if ( props.path.empty() )
		{
		pcap_if_t* devs = nullptr;

		if ( pcap_findalldevs(&devs, errbuf) < 0 )
			{
			Error(fmt("pcap_findalldevs: %s\n", errbuf));
			return false;
			}

		if ( devs )
			{
			props.path = devs->name;
			pcap_freealldevs(devs);

			if ( props.path.empty() )
				{
				Error(fmt("pcap_findalldevs: empty device name\n"));
				return false;
				}
			}
		else
			{
			Error(fmt("pcap_findalldevs: no devices found\n"));
			return false;
			}
		}

	// Determine network and netmask.
	uint32_t net;
	if ( pcap_lookupnet(props.path.c_str(), &net, &props.netmask, errbuf) < 0 )
		{
		// ### The lookup can fail if no address is assigned to
		// the interface; and libpcap doesn't have any useful notion
		// of error codes, just error std::strings - how bogus - so we
		// just kludge around the error :-(.
		// sprintf(errbuf, "pcap_lookupnet %s", errbuf);
		// return false;
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
		return false;
		}

	if ( pcap_set_snaplen(pd, snaplen) )
		{
		PcapError("pcap_set_snaplen");
		return false;
		}

	if ( pcap_set_promisc(pd, 1) )
		{
		PcapError("pcap_set_promisc");
		return false;
		}

	// We use the smallest time-out possible to return false almost immediately
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
		return false;
		}

	if ( pcap_set_buffer_size(pd, bufsize * 1024 * 1024) )
		{
		PcapError("pcap_set_buffer_size");
		return false;
		}

	if ( pcap_activate(pd) )
		{
		PcapError("pcap_activate");
		return false;
		}

#ifdef HAVE_LINUX
	if ( pcap_setnonblock(pd, 1, errbuf) < 0 )
		{
		PcapError("pcap_setnonblock");
		return false;
		}
#endif

#ifdef HAVE_PCAP_INT_H
	Info(fmt("pcap bufsize = %d\n", ((struct pcap *) pd)->bufsize));
#endif

	SetHdrSize();

	if ( ! pd )
		// Was closed, couldn't get header size.
		return false;

	props.is_live = true;

	// Tell the base class to add this to the event loop
	return IOSource::Start(pcap_fileno(pd));
	}

bool PcapSource::OpenOffline()
	{
	char errbuf[PCAP_ERRBUF_SIZE];

	pd = pcap_open_offline(props.path.c_str(), errbuf);

	if ( ! pd )
		{
		Error(fmt("%s\n", errbuf));
		return false;
		}

	SetHdrSize();

	if ( ! pd )
		// Was closed, unknown link layer type.
		return false;

	props.is_live = false;

	// Tell the base class to add this to the event loop
	return IOSource::Start();
	}

void PcapSource::Open()
	{
	bool result = props.is_live ? OpenLive() : OpenOffline();
	
	if ( result )
		Opened(props);
	else
		Close();
	}

void PcapSource::HandleNewData(int fd)
	{
	if ( ! pd )
		// TODO: failure case? why are we still in the loop if the pcap is closed?
		return;

	// If we don't already have a packet, grab a new one. If we do, just pass it up to the parent
	// class to be processed.
	if ( ! have_packet )
		{
		// We didn't have an existing packet already so get one from pcap.
		const u_char* data = pcap_next(pd, &current_hdr);
		
		if ( ! data )
			{
			// Source has gone dry.  If it's a network interface, this just means
			// it's timed out. If it's a file, though, then the file has been
			// exhausted.
			if ( ! props.is_live )
				Close();
			
			return;
			}
		
		current_packet.Init(props.link_type, &current_hdr.ts, current_hdr.caplen, current_hdr.len, data);
		
		if ( current_hdr.len == 0 || current_hdr.caplen == 0 )
			{
			Weird("empty_pcap_header", &current_packet);
			return;
			}
		
		last_hdr = current_hdr;
		last_data = data;
		++stats.received;
		stats.bytes_received += current_hdr.len;
		
		have_packet = true;
		}

	PktSrc::HandleNewData(fd);
	}

void PcapSource::Close()
	{
	if ( ! pd )
		return;

	IOSource::Done();

	pcap_close(pd);
	pd = nullptr;

	Closed();
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

void PcapSource::SetHdrSize()
	{
	if ( ! pd )
		return;

	props.link_type = pcap_datalink(pd);
	}

void PcapSource::PcapError(const std::string& where)
	{
	std::string location;

	if ( ! where.empty() )
		location = fmt(" (%s)", where.c_str());

	if ( pd )
		Error(fmt("pcap_error: %s%s", pcap_geterr(pd), location.c_str()));
	else
		Error(fmt("pcap_error: not open%s", location.c_str()));

	Close();
	}

iosource::PktSrc* PcapSource::Instantiate(const std::string& path, bool is_live)
	{
	return new PcapSource(path, is_live);
	}
