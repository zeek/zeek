// See the file  in the main distribution directory for copyright.

#include "zeek/iosource/pcap/Source.h"

#include "zeek/zeek-config.h"

#include "zeek/3rdparty/doctest.h"

#ifdef HAVE_PCAP_INT_H
#include <pcap-int.h>
#endif

#include "zeek/Event.h"
#include "zeek/iosource/BPF_Program.h"
#include "zeek/iosource/Packet.h"
#include "zeek/iosource/pcap/pcap.bif.h"

namespace zeek::iosource::pcap
	{

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
		event_mgr.Enqueue(Pcap::file_done, make_intrusive<StringVal>(props.path));
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
			Error(util::fmt("pcap_findalldevs: %s", errbuf));
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
	if ( pcap_setnonblock(pd, 1, errbuf) < 0 )
		{
		PcapError("pcap_setnonblock");
		return;
		}
#endif

#ifdef HAVE_PCAP_INT_H
	Info(util::fmt("pcap bufsize = %d\n", ((struct pcap*)pd)->bufsize));
#endif

#ifndef _MSC_VER
	props.selectable_fd = pcap_get_selectable_fd(pd);
#endif

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

	// We don't register the file descriptor if we're in offline mode,
	// because libpcap's file descriptor for trace files isn't a reliable
	// way to know whether we actually have data to read.
	// See https://github.com/the-tcpdump-group/libpcap/issues/870
	props.selectable_fd = -1;

	props.link_type = pcap_datalink(pd);
	props.is_live = false;

	Opened(props);
	}

bool PcapSource::ExtractNextPacket(Packet* pkt)
	{
	if ( ! pd )
		return false;

	const u_char* data;
	pcap_pkthdr* header;

	int res = pcap_next_ex(pd, &header, &data);

	switch ( res )
		{
		case PCAP_ERROR_BREAK: // -2
			// Exhausted pcap file, no more packets to read.
			assert(! props.is_live);
			Close();
			return false;
		case PCAP_ERROR: // -1
			// Error occurred while reading the packet.
			if ( props.is_live )
				reporter->Error("failed to read a packet from %s: %s", props.path.data(),
				                pcap_geterr(pd));
			else
				reporter->FatalError("failed to read a packet from %s: %s", props.path.data(),
				                     pcap_geterr(pd));
			return false;
		case 0:
			// Read from live interface timed out (ok).
			return false;
		case 1:
			// Read a packet without problem.
			// Although, some libpcaps may claim to have read a packet, but either did
			// not really read a packet or at least provide no way to access its
			// contents, so the following check for null-data helps handle those cases.
			if ( ! data )
				{
				reporter->Weird("pcap_null_data_packet");
				return false;
				}
			break;
		default:
			reporter->InternalError("unhandled pcap_next_ex return value: %d", res);
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

	// Some versions of libpcap (myricom) are somewhat broken and will return a duplicate
	// packet if there are no more packets available. Namely, it returns the exact same
	// packet structure (including the header) out of the library without reinitializing
	// any of the values. If we set the header lengths to zero here, we can keep from
	// processing it a second time.
	header->len = 0;
	header->caplen = 0;

	return true;
	}

void PcapSource::DoneWithPacket()
	{
	// Nothing to do.
	}

detail::BPF_Program* PcapSource::CompileFilter(const std::string& filter)
	{
	auto code = std::make_unique<detail::BPF_Program>();

	if ( ! code->Compile(pd, filter.c_str(), Netmask()) )
		{
		std::string msg = util::fmt("cannot compile BPF filter \"%s\"", filter.c_str());

		std::string state_msg = code->GetStateMessage();
		if ( ! state_msg.empty() )
			msg += ": " + state_msg;

		Error(msg);
		}

	return code.release();
	}

bool PcapSource::SetFilter(int index)
	{
	if ( ! pd )
		return true; // Prevent error message

	char errbuf[PCAP_ERRBUF_SIZE];

	iosource::detail::BPF_Program* code = GetBPFFilter(index);

	if ( ! code )
		{
		snprintf(errbuf, sizeof(errbuf), "No precompiled pcap filter for index %d", index);
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
	else if ( auto program = code->GetProgram() )
		{
		if ( pcap_setfilter(pd, program) < 0 )
			{
			PcapError();
			return false;
			}
		}
	else if ( code->GetState() != FilterState::OK )
		return false;

#ifndef HAVE_LINUX
	// Linux doesn't clear counters when resetting filter.
	stats.received = stats.dropped = stats.link = stats.bytes_received = 0;
#endif

	return true;
	}

// Given two pcap_stat structures, compute the difference of linked and dropped
// and add it to the given Stats object.
static void update_pktsrc_stats(PktSrc::Stats* stats, const struct pcap_stat* now,
                                const struct pcap_stat* prev)
	{
	decltype(now->ps_drop) ps_drop_diff = 0;
	decltype(now->ps_recv) ps_recv_diff = 0;

	// This is subtraction of unsigned ints: It's not undefined
	// and results in modulo arithmetic.
	ps_recv_diff = now->ps_recv - prev->ps_recv;
	ps_drop_diff = now->ps_drop - prev->ps_drop;

	stats->link += ps_recv_diff;
	stats->dropped += ps_drop_diff;
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
			update_pktsrc_stats(&stats, &pstat, &prev_pstat);
			prev_pstat = pstat;
			}
		}

	s->link = stats.link;
	s->dropped = stats.dropped;
	s->received = stats.received;
	s->bytes_received = stats.bytes_received;

	if ( ! props.is_live )
		s->dropped = 0;
	}

void PcapSource::PcapError(const char* where)
	{
	std::string location;

	if ( where )
		location = util::fmt(" (%s)", where);

	if ( pd )
		Error(util::fmt("pcap_error: %s%s", pcap_geterr(pd), location.c_str()));
	else
		Error(util::fmt("pcap_error: not open%s", location.c_str()));

	Close();
	}

iosource::PktSrc* PcapSource::Instantiate(const std::string& path, bool is_live)
	{
	return new PcapSource(path, is_live);
	}

TEST_CASE("pcap source update_pktsrc_stats")
	{
	PktSrc::Stats stats;
	struct pcap_stat now = {0};
	struct pcap_stat prev = {0};

	SUBCASE("all zero")
		{
		update_pktsrc_stats(&stats, &now, &prev);
		CHECK(stats.link == 0);
		CHECK(stats.dropped == 0);
		}

	SUBCASE("no overflow")
		{
		now.ps_recv = 7;
		now.ps_drop = 3;
		update_pktsrc_stats(&stats, &now, &prev);
		CHECK(stats.link == 7);
		CHECK(stats.dropped == 3);
		}

	SUBCASE("no overflow prev")
		{
		stats.link = 2;
		stats.dropped = 1;
		prev.ps_recv = 2;
		prev.ps_drop = 1;
		now.ps_recv = 7;
		now.ps_drop = 3;

		update_pktsrc_stats(&stats, &now, &prev);
		CHECK(stats.link == 7);
		CHECK(stats.dropped == 3);
		}

	SUBCASE("overflow")
		{
		prev.ps_recv = 4294967295;
		prev.ps_drop = 4294967294;
		now.ps_recv = 0;
		now.ps_drop = 1;

		update_pktsrc_stats(&stats, &now, &prev);
		CHECK(stats.link == 1);
		CHECK(stats.dropped == 3);
		}

	SUBCASE("overflow 2")
		{
		stats.link = 4294967295;
		stats.dropped = 4294967294;
		prev.ps_recv = 4294967295;
		prev.ps_drop = 4294967294;
		now.ps_recv = 10;
		now.ps_drop = 3;

		update_pktsrc_stats(&stats, &now, &prev);
		CHECK(stats.link == 4294967306); // 2**32 - 1 + 11
		CHECK(stats.dropped == 4294967299); // 2**32 - 2 + 5
		}
	}

	} // namespace zeek::iosource::pcap
