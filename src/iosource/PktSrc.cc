// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"
#include "PktSrc.h"

#include <sys/stat.h>

#include "util.h"
#include "Hash.h"
#include "Net.h"
#include "Sessions.h"
#include "broker/Manager.h"
#include "iosource/Manager.h"
#include "BPF_Program.h"

#include "pcap/pcap.bif.h"

namespace zeek::iosource {

PktSrc::Properties::Properties()
	{
	selectable_fd = -1;
	link_type = -1;
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
	current_pseudo = 0.0;
	first_wallclock = current_wallclock = 0;
	}

PktSrc::~PktSrc()
	{
	for ( auto code : filters )
		delete code;
	}

const std::string& PktSrc::Path() const
	{
	static std::string not_open("not open");
	return IsOpen() ? props.path : not_open;
	}

const char* PktSrc::ErrorMsg() const
	{
	return errbuf.size() ? errbuf.c_str() : nullptr;
	}

int PktSrc::LinkType() const
	{
	return IsOpen() ? props.link_type : -1;
	}

uint32_t PktSrc::Netmask() const
	{
	return IsOpen() ? props.netmask : NETMASK_UNKNOWN;
	}

bool PktSrc::IsError() const
	{
	return ! errbuf.empty();
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
	if ( zeek::net::net_is_processing_suspended() )
		current_wallclock = zeek::util::current_time(true);

	return current_wallclock;
	}

void PktSrc::Opened(const Properties& arg_props)
	{
	if ( zeek::Packet::GetLinkHeaderSize(arg_props.link_type) < 0 )
		{
		char buf[512];
		snprintf(buf, sizeof(buf),
			 "unknown data link type 0x%x", arg_props.link_type);
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
		{
		Info(zeek::util::fmt("listening on %s\n", props.path.c_str()));

		// We only register the file descriptor if we're in live
		// mode because libpcap's file descriptor for trace files
		// isn't a reliable way to know whether we actually have
		// data to read.
		if ( props.selectable_fd != -1 )
			if ( ! iosource_mgr->RegisterFd(props.selectable_fd, this) )
				zeek::reporter->FatalError("Failed to register pktsrc fd with iosource_mgr");
		}

	DBG_LOG(zeek::DBG_PKTIO, "Opened source %s", props.path.c_str());
	}

void PktSrc::Closed()
	{
	SetClosed(true);

	if ( props.is_live && props.selectable_fd != -1 )
		iosource_mgr->UnregisterFd(props.selectable_fd, this);

	DBG_LOG(zeek::DBG_PKTIO, "Closed source %s", props.path.c_str());
	}

void PktSrc::Error(const std::string& msg)
	{
	// We don't report this immediately, Bro will ask us for the error
	// once it notices we aren't open.
	errbuf = msg;
	DBG_LOG(zeek::DBG_PKTIO, "Error with source %s: %s",
		IsOpen() ? props.path.c_str() : "<not open>",
		msg.c_str());
	}

void PktSrc::Info(const std::string& msg)
	{
	zeek::reporter->Info("%s", msg.c_str());
	}

void PktSrc::Weird(const std::string& msg, const zeek::Packet* p)
	{
	zeek::sessions->Weird(msg.c_str(), p, nullptr);
	}

void PktSrc::InternalError(const std::string& msg)
	{
	zeek::reporter->InternalError("%s", msg.c_str());
	}

void PktSrc::ContinueAfterSuspend()
	{
	current_wallclock = zeek::util::current_time(true);
	}

double PktSrc::CheckPseudoTime()
	{
	if ( ! IsOpen() )
		return 0;

	if ( ! ExtractNextPacketInternal() )
		return 0;

	double pseudo_time = current_packet.time - first_timestamp;
	double ct = (zeek::util::current_time(true) - first_wallclock) * zeek::net::pseudo_realtime;

	return pseudo_time <= ct ? zeek::net::zeek_start_time + pseudo_time : 0;
	}

void PktSrc::InitSource()
	{
	Open();
	}

void PktSrc::Done()
	{
	if ( IsOpen() )
		Close();
	}

void PktSrc::Process()
	{
	if ( ! IsOpen() )
		return;

	if ( ! ExtractNextPacketInternal() )
		return;

	if ( current_packet.Layer2Valid() )
		{
		if ( zeek::net::pseudo_realtime )
			{
			current_pseudo = CheckPseudoTime();
			zeek::net::detail::net_packet_dispatch(current_pseudo, &current_packet, this);
			if ( ! first_wallclock )
				first_wallclock = zeek::util::current_time(true);
			}

		else
			zeek::net::detail::net_packet_dispatch(current_packet.time, &current_packet, this);
		}

	have_packet = false;
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
	if ( zeek::net::net_is_processing_suspended() && first_timestamp )
		return false;

	if ( zeek::net::pseudo_realtime )
		current_wallclock = zeek::util::current_time(true);

	if ( ExtractNextPacket(&current_packet) )
		{
		if ( current_packet.time < 0 )
			{
			Weird("negative_packet_timestamp", &current_packet);
			return false;
			}

		if ( ! first_timestamp )
			first_timestamp = current_packet.time;

		have_packet = true;
		return true;
		}

	if ( zeek::net::pseudo_realtime && ! IsOpen() )
		{
		if ( broker_mgr->Active() )
			iosource_mgr->Terminate();
		}

	return false;
	}

bool PktSrc::PrecompileBPFFilter(int index, const std::string& filter)
	{
	if ( index < 0 )
		return false;

	char errbuf[PCAP_ERRBUF_SIZE];

	// Compile filter.
	auto* code = new zeek::iosource::detail::BPF_Program();

	if ( ! code->Compile(zeek::BifConst::Pcap::snaplen, LinkType(), filter.c_str(), Netmask(), errbuf, sizeof(errbuf)) )
		{
		std::string msg = zeek::util::fmt("cannot compile BPF filter \"%s\"", filter.c_str());

		if ( *errbuf )
			msg += ": " + std::string(errbuf);

		Error(msg);

		delete code;
		return false;
		}

	// Store it in vector.
	if ( index >= static_cast<int>(filters.size()) )
		filters.resize(index + 1);

	if ( auto old = filters[index] )
		delete old;

	filters[index] = code;

	return true;
	}

zeek::iosource::detail::BPF_Program* PktSrc::GetBPFFilter(int index)
	{
	if ( index < 0 )
		return nullptr;

	return (static_cast<int>(filters.size()) > index ? filters[index] : nullptr);
	}

bool PktSrc::ApplyBPFFilter(int index, const struct pcap_pkthdr *hdr, const u_char *pkt)
	{
	zeek::iosource::detail::BPF_Program* code = GetBPFFilter(index);

	if ( ! code )
		{
		Error(zeek::util::fmt("BPF filter %d not compiled", index));
		Close();
		return false;
		}

	if ( code->MatchesAnything() )
		return true;

	return pcap_offline_filter(code->GetProgram(), hdr, pkt);
	}

bool PktSrc::GetCurrentPacket(const zeek::Packet** pkt)
	{
	if ( ! have_packet )
		return false;

	*pkt = &current_packet;
	return true;
	}

double PktSrc::GetNextTimeout()
	{
	// If there's no file descriptor for the source, which is the case for some interfaces like
	// myricom, we can't rely on the polling mechanism to wait for data to be available. As gross
	// as it is, just spin with a short timeout here so that it will continually poll the
	// interface. The old IOSource code had a 20 microsecond timeout between calls to select()
	// so just use that.
	if ( props.selectable_fd == -1 )
		return 0.00002;

	// If we're live we want poll to do what it has to with the file descriptor. If we're not live
	// but we're not in pseudo-realtime mode, let the loop just spin as fast as it can. If we're
	// in pseudo-realtime mode, find the next time that a packet is ready and have poll block until
	// then.
	if ( IsLive() || zeek::net::net_is_processing_suspended() )
		return -1;
	else if ( ! zeek::net::pseudo_realtime )
		return 0;

	if ( ! have_packet )
		ExtractNextPacketInternal();

	double pseudo_time = current_packet.time - first_timestamp;
	double ct = (zeek::util::current_time(true) - first_wallclock) * zeek::net::pseudo_realtime;
	return std::max(0.0, pseudo_time - ct);
	}

} // namespace zeek::iosource
