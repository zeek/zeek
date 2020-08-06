// See the file  in the main distribution directory for copyright.

#include "zeek-config.h"

#include "Source.h"
#include "iosource/Packet.h"
#include "iosource/BPF_Program.h"

#include "Event.h"

#include "pcap.bif.h"

#ifdef HAVE_PCAP_INT_H
#include <pcap-int.h>
#endif

namespace zeek::iosource::pcap {

PcapSource::~PcapSource()
	{
	Close();
	}

PcapSource::PcapSource(const std::string& path, bool is_live)
	{
	props.path = path;
	props.is_live = is_live;
	pd = nullptr;
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
	pd = nullptr;

	Closed();

	if ( Pcap::file_done )
		zeek::event_mgr.Enqueue(Pcap::file_done, zeek::make_intrusive<zeek::StringVal>(props.path));
	}

void PcapSource::OpenLive()
	{
	char errbuf[PCAP_ERRBUF_SIZE];

	// Determine interface if not specified.
	if ( props.path.empty() )
		{
		pcap_if_t* devs;

		if ( pcap_findalldevs(&devs, errbuf) < 0 )
			{
			Error(zeek::util::fmt("pcap_findalldevs: %s", errbuf));
			return;
			}

		if ( devs )
			{
			props.path = devs->name;
			pcap_freealldevs(devs);

			if ( props.path.empty() )
				{
				Error("pcap_findalldevs: empty device name");
				return;
				}
			}
		else
			{
			Error("pcap_findalldevs: no devices found");
			return;
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

	if ( pcap_set_snaplen(pd, zeek::BifConst::Pcap::snaplen) )
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

	if ( pcap_set_buffer_size(pd, zeek::BifConst::Pcap::bufsize * 1024 * 1024) )
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
	if ( pcap_setnonblock(pd, 1, errbuf) < 0 )
		{
		PcapError("pcap_setnonblock");
		return;
		}
#endif

#ifdef HAVE_PCAP_INT_H
	Info(zeek::util::fmt("pcap bufsize = %d\n", ((struct pcap *) pd)->bufsize));
#endif

	props.selectable_fd = pcap_get_selectable_fd(pd);

	props.link_type = pcap_datalink(pd);
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

	props.selectable_fd = fileno(pcap_file(pd));

	if ( props.selectable_fd < 0 )
		InternalError("OS does not support selectable pcap fd");

	props.link_type = pcap_datalink(pd);
	props.is_live = false;

	Opened(props);
	}

bool PcapSource::ExtractNextPacket(zeek::Packet* pkt)
	{
	if ( ! pd )
		return false;

	const u_char* data;
	pcap_pkthdr* header;

	int res = pcap_next_ex(pd, &header, &data);

	switch ( res ) {
	case PCAP_ERROR_BREAK: // -2
		// Exhausted pcap file, no more packets to read.
		assert(! props.is_live);
		Close();
		return false;
	case PCAP_ERROR: // -1
		// Error occurred while reading the packet.
		if ( props.is_live )
			zeek::reporter->Error("failed to read a packet from %s: %s",
			                      props.path.data(), pcap_geterr(pd));
		else
			zeek::reporter->FatalError("failed to read a packet from %s: %s",
			                           props.path.data(), pcap_geterr(pd));
		return false;
	case 0:
		// Read from live interface timed out (ok).
		return false;
	case 1:
		// Read a packet without problem.
		break;
	default:
		zeek::reporter->InternalError("unhandled pcap_next_ex return value: %d", res);
		return false;
	}

	pkt->Init(props.link_type, &header->ts, header->caplen, header->len, data);

	if ( header->len == 0 || header->caplen == 0 )
		{
		Weird("empty_pcap_header", pkt);
		return false;
		}

	++stats.received;
	stats.bytes_received += header->len;

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

	zeek::iosource::detail::BPF_Program* code = GetBPFFilter(index);

	if ( ! code )
		{
		snprintf(errbuf, sizeof(errbuf),
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
	std::string location;

	if ( where )
		location = zeek::util::fmt(" (%s)", where);

	if ( pd )
		Error(zeek::util::fmt("pcap_error: %s%s", pcap_geterr(pd), location.c_str()));
	else
		Error(zeek::util::fmt("pcap_error: not open%s", location.c_str()));

	Close();
	}

iosource::PktSrc* PcapSource::Instantiate(const std::string& path, bool is_live)
	{
	return new PcapSource(path, is_live);
	}

} // namespace zeek::iosource::pcap
