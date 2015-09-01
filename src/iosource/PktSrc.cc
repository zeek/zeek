// See the file "COPYING" in the main distribution directory for copyright.

#include <errno.h>
#include <sys/stat.h>

#include "config.h"

#include "util.h"
#include "PktSrc.h"
#include "Hash.h"
#include "Net.h"
#include "Sessions.h"

using namespace iosource;

PktSrc::Properties::Properties()
	{
	selectable_fd = -1;
	link_type = -1;
	hdr_size = -1;
	netmask = NETMASK_UNKNOWN;
	is_live = false;
	}

PktSrc::PktSrc()
	{
	have_packet = false;
	errbuf = "";
	SetClosed(true);

	next_sync_point = 0;
	first_timestamp = 0.0;
	first_wallclock = current_wallclock = 0;
	}

PktSrc::~PktSrc()
	{
	BPF_Program* code;
	IterCookie* cookie = filters.InitForIteration();
	while ( (code = filters.NextEntry(cookie)) )
		delete code;
	}

const std::string& PktSrc::Path() const
	{
	static std::string not_open("not open");
	return IsOpen() ? props.path : not_open;
	}

const char* PktSrc::ErrorMsg() const
	{
	return errbuf.size() ? errbuf.c_str() : 0;
	}

int PktSrc::LinkType() const
	{
	return IsOpen() ? props.link_type : -1;
	}

uint32 PktSrc::Netmask() const
	{
	return IsOpen() ? props.netmask : NETMASK_UNKNOWN;
	}

bool PktSrc::IsError() const
	{
	return ErrorMsg();
	}

int PktSrc::HdrSize() const
	{
	return IsOpen() ? props.hdr_size : -1;
	}

int PktSrc::SnapLen() const
	{
	return snaplen; // That's a global. Change?
	}

bool PktSrc::IsLive() const
	{
	return props.is_live;
	}

double PktSrc::CurrentPacketTimestamp()
	{
	return current_pseudo;
	}

double PktSrc::CurrentPacketWallClock()
	{
	// We stop time when we are suspended.
	if ( net_is_processing_suspended() )
		current_wallclock = current_time(true);

	return current_wallclock;
	}

void PktSrc::Opened(const Properties& arg_props)
	{
	if ( arg_props.hdr_size < 0 )
		{
		char buf[512];
		safe_snprintf(buf, sizeof(buf),
			 "unknown data link type 0x%x", props.link_type);
		Error(buf);
		Close();
		return;
		}

	props = arg_props;
	SetClosed(false);

	if ( ! PrecompileFilter(0, "") || ! SetFilter(0) )
		{
		Close();
		return;
		}

	if ( props.is_live )
		Info(fmt("listening on %s, capture length %d bytes\n", props.path.c_str(), SnapLen()));

	DBG_LOG(DBG_PKTIO, "Opened source %s", props.path.c_str());
	}

void PktSrc::Closed()
	{
	SetClosed(true);

	DBG_LOG(DBG_PKTIO, "Closed source %s", props.path.c_str());
	}

void PktSrc::Error(const std::string& msg)
	{
	// We don't report this immediately, Bro will ask us for the error
	// once it notices we aren't open.
	errbuf = msg;
	DBG_LOG(DBG_PKTIO, "Error with source %s: %s",
		IsOpen() ? props.path.c_str() : "<not open>",
		msg.c_str());
	}

void PktSrc::Info(const std::string& msg)
	{
	reporter->Info("%s", msg.c_str());
	}

void PktSrc::Weird(const std::string& msg, const Packet* p)
	{
	sessions->Weird(msg.c_str(), p->hdr, p->data, 0);
	}

void PktSrc::InternalError(const std::string& msg)
	{
	reporter->InternalError("%s", msg.c_str());
	}

void PktSrc::ContinueAfterSuspend()
	{
	current_wallclock = current_time(true);
	}

int PktSrc::GetLinkHeaderSize(int link_type)
	{
	switch ( link_type ) {
	case DLT_NULL:
		return 4;

	case DLT_EN10MB:
		return 14;

	case DLT_FDDI:
		return 13 + 8;	// fddi_header + LLC

#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL:
		return 16;
#endif

	case DLT_PPP_SERIAL:	// PPP_SERIAL
		return 4;

	case DLT_RAW:
		return 0;
	}

	return -1;
	}

double PktSrc::CheckPseudoTime()
	{
	if ( ! IsOpen() )
		return 0;

	if ( ! ExtractNextPacketInternal() )
		return 0;

	if ( remote_trace_sync_interval )
		{
		if ( next_sync_point == 0 || current_packet.ts >= next_sync_point )
			{
			int n = remote_serializer->SendSyncPoint();
			next_sync_point = first_timestamp +
						n * remote_trace_sync_interval;
			remote_serializer->Log(RemoteSerializer::LogInfo,
				fmt("stopping at packet %.6f, next sync-point at %.6f",
					current_packet.ts, next_sync_point));

			return 0;
			}
		}

	double pseudo_time = current_packet.ts - first_timestamp;
	double ct = (current_time(true) - first_wallclock) * pseudo_realtime;

	return pseudo_time <= ct ? bro_start_time + pseudo_time : 0;
	}

void PktSrc::Init()
	{
	Open();
	}

void PktSrc::Done()
	{
	if ( IsOpen() )
		Close();
	}

void PktSrc::GetFds(iosource::FD_Set* read, iosource::FD_Set* write,
                    iosource::FD_Set* except)
	{
	if ( pseudo_realtime )
		{
		// Select would give erroneous results. But we simulate it
		// by setting idle accordingly.
		SetIdle(CheckPseudoTime() == 0);
		return;
		}

	if ( IsOpen() && props.selectable_fd >= 0 )
		read->Insert(props.selectable_fd);

	// TODO: This seems like a hack that should be removed, but doing so
	// causes the main run loop to spin more frequently and increase cpu usage.
	// See also commit 9cd85be308.
	if ( read->Empty() )
		read->Insert(0);

	if ( write->Empty() )
		write->Insert(0);

	if ( except->Empty() )
		except->Insert(0);
	}

double PktSrc::NextTimestamp(double* local_network_time)
	{
	if ( ! IsOpen() )
		return -1.0;

	if ( ! ExtractNextPacketInternal() )
		return -1.0;

	if ( pseudo_realtime )
		{
		// Delay packet if necessary.
		double packet_time = CheckPseudoTime();
		if ( packet_time )
			return packet_time;

		SetIdle(true);
		return -1.0;
		}

	return current_packet.ts;
	}

void PktSrc::Process()
	{
	if ( ! IsOpen() )
		return;

	if ( ! ExtractNextPacketInternal() )
		return;

	int pkt_hdr_size = props.hdr_size;

	// Unfortunately some packets on the link might have MPLS labels
	// while others don't. That means we need to ask the link-layer if
	// labels are in place.
	bool have_mpls = false;

	int protocol = 0;
	const u_char* data = current_packet.data;
	const u_char* end_of_data = data + current_packet.hdr->caplen;

	if ( data + pkt_hdr_size >= end_of_data )
		{
		Weird("truncated_link_header", &current_packet);
		goto done;
		}

	switch ( props.link_type ) {
	case DLT_NULL:
		{
		protocol = (data[3] << 24) + (data[2] << 16) + (data[1] << 8) + data[0];

		// From the Wireshark Wiki: "AF_INET6, unfortunately, has
		// different values in {NetBSD,OpenBSD,BSD/OS},
		// {FreeBSD,DragonFlyBSD}, and {Darwin/Mac OS X}, so an IPv6
		// packet might have a link-layer header with 24, 28, or 30
		// as the AF_ value." As we may be reading traces captured on
		// platforms other than what we're running on, we accept them
		// all here.
		if ( protocol != AF_INET
		     && protocol != AF_INET6
		     && protocol != 24
		     && protocol != 28
		     && protocol != 30 )
			{
			Weird("non_ip_packet_in_null_transport", &current_packet);
			goto done;
			}

		break;
		}

	case DLT_EN10MB:
		{
		// Get protocol being carried from the ethernet frame.
		protocol = (data[12] << 8) + data[13];

		switch ( protocol )
			{
			// MPLS carried over the ethernet frame.
			case 0x8847:
				// Remove the data link layer and denote a
				// header size of zero before the IP header.
				have_mpls = true;
				data += GetLinkHeaderSize(props.link_type);
				pkt_hdr_size = 0;
				break;

			// VLAN carried over the ethernet frame.
			case 0x8100:
				data += GetLinkHeaderSize(props.link_type);

				if ( data + 4 >= end_of_data )
					{
					Weird("truncated_link_header", &current_packet);
					goto done;
					}

				// Check for MPLS in VLAN.
				if ( ((data[2] << 8) + data[3]) == 0x8847 )
					have_mpls = true;

				data += 4; // Skip the vlan header
				pkt_hdr_size = 0;

				// Check for 802.1ah (Q-in-Q) containing IP.
				// Only do a second layer of vlan tag
				// stripping because there is no
				// specification that allows for deeper
				// nesting.
				if ( data + 4 >= end_of_data )
					{
					Weird("truncated_link_header", &current_packet);
					goto done;
					}

				if ( ((data[2] << 8) + data[3]) == 0x0800 )
					data += 4;

				break;

			// PPPoE carried over the ethernet frame.
			case 0x8864:
				data += GetLinkHeaderSize(props.link_type);

				if ( data + 8 >= end_of_data )
					{
					Weird("truncated_link_header", &current_packet);
					goto done;
					}

				protocol = (data[6] << 8) + data[7];
				data += 8; // Skip the PPPoE session and PPP header
				pkt_hdr_size = 0;

				if ( protocol != 0x0021 && protocol != 0x0057 )
					{
					// Neither IPv4 nor IPv6.
					Weird("non_ip_packet_in_pppoe_encapsulation", &current_packet);
					goto done;
					}
				break;
			}

		break;
		}

	case DLT_PPP_SERIAL:
		{
		// Get PPP protocol.
		// no oob-check necessary -- header size was checked before.
		protocol = (data[2] << 8) + data[3];

		if ( protocol == 0x0281 )
			{
			// MPLS Unicast. Remove the data link layer and
			// denote a header size of zero before the IP header.
			have_mpls = true;
				data += GetLinkHeaderSize(props.link_type);
			pkt_hdr_size = 0;
			}

		else if ( protocol != 0x0021 && protocol != 0x0057 )
			{
			// Neither IPv4 nor IPv6.
			Weird("non_ip_packet_in_ppp_encapsulation", &current_packet);
			goto done;
			}
		break;
		}
	}

	if ( have_mpls )
		{
		// Skip the MPLS label stack.
		bool end_of_stack = false;

		while ( ! end_of_stack )
			{
			if ( data + 4 >= end_of_data )
				{
				Weird("truncated_link_header", &current_packet);
				goto done;
				}

			end_of_stack = *(data + 2) & 0x01;
			data += 4;
			}
		}

	if ( pseudo_realtime )
		{
		current_pseudo = CheckPseudoTime();
		net_packet_dispatch(current_pseudo, current_packet.hdr, data, pkt_hdr_size, this);
		if ( ! first_wallclock )
			first_wallclock = current_time(true);
		}

	else
		net_packet_dispatch(current_packet.ts, current_packet.hdr, data, pkt_hdr_size, this);

done:
	have_packet = 0;
	DoneWithPacket();
	}

const char* PktSrc::Tag()
	{
	return "PktSrc";
	}

bool PktSrc::ExtractNextPacketInternal()
	{
	if ( have_packet )
		return true;

	have_packet = false;

	// Don't return any packets if processing is suspended (except for the
	// very first packet which we need to set up times).
	if ( net_is_processing_suspended() && first_timestamp )
		{
		SetIdle(true);
		return 0;
		}

	if ( pseudo_realtime )
		current_wallclock = current_time(true);

	if ( ExtractNextPacket(&current_packet) )
		{
		if ( ! first_timestamp )
			first_timestamp = current_packet.ts;

		SetIdle(false);
		have_packet = true;
		return 1;
		}

	if ( pseudo_realtime && using_communication && ! IsOpen() )
		{
		// Source has gone dry, we're done.
		if ( remote_trace_sync_interval )
			remote_serializer->SendFinalSyncPoint();
		else
			remote_serializer->Terminate();
		}

	SetIdle(true);
	return 0;
	}

bool PktSrc::PrecompileBPFFilter(int index, const std::string& filter)
	{
	if ( index < 0 )
		return false;

	char errbuf[PCAP_ERRBUF_SIZE];

	// Compile filter.
	BPF_Program* code = new BPF_Program();

	if ( ! code->Compile(SnapLen(), LinkType(), filter.c_str(), Netmask(), errbuf, sizeof(errbuf)) )
		{
		string msg = fmt("cannot compile BPF filter \"%s\"", filter.c_str());

		if ( *errbuf )
			msg += ": " + string(errbuf);

		Error(msg);

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

BPF_Program* PktSrc::GetBPFFilter(int index)
	{
	if ( index < 0 )
		return 0;

	HashKey* hash = new HashKey(HashKey(bro_int_t(index)));
	BPF_Program* code = filters.Lookup(hash);
	delete hash;
	return code;
	}

bool PktSrc::ApplyBPFFilter(int index, const struct pcap_pkthdr *hdr, const u_char *pkt)
	{
	BPF_Program* code = GetBPFFilter(index);

	if ( ! code )
		{
		Error(fmt("BPF filter %d not compiled", index));
		Close();
		return false;
		}

	if ( code->MatchesAnything() )
		return true;

	return pcap_offline_filter(code->GetProgram(), hdr, pkt);
	}

bool PktSrc::GetCurrentPacket(const pcap_pkthdr** hdr, const u_char** pkt)
	{
	if ( ! have_packet )
		return false;

	*hdr = current_packet.hdr;
	*pkt = current_packet.data;
	return true;
	}
