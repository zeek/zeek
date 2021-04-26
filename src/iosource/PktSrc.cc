// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeek-config.h"
#include "zeek/iosource/PktSrc.h"

#include <sys/stat.h>

#include "zeek/util.h"
#include "zeek/Hash.h"
#include "zeek/RunState.h"
#include "zeek/session/SessionManager.h"
#include "zeek/broker/Manager.h"
#include "zeek/iosource/Manager.h"
#include "zeek/packet_analysis/Manager.h"
#include "zeek/iosource/BPF_Program.h"

#include "zeek/iosource/pcap/pcap.bif.h"

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

void PktSrc::Opened(const Properties& arg_props)
	{
	props = arg_props;
	SetClosed(false);

	if ( ! PrecompileFilter(0, "") || ! SetFilter(0) )
		{
		Close();
		return;
		}


	if ( props.is_live )
		{
		Info(util::fmt("listening on %s\n", props.path.c_str()));

		// We only register the file descriptor if we're in live
		// mode because libpcap's file descriptor for trace files
		// isn't a reliable way to know whether we actually have
		// data to read.
		if ( props.selectable_fd != -1 )
			if ( ! iosource_mgr->RegisterFd(props.selectable_fd, this) )
				reporter->FatalError("Failed to register pktsrc fd with iosource_mgr");
		}

	DBG_LOG(DBG_PKTIO, "Opened source %s", props.path.c_str());
	}

void PktSrc::Closed()
	{
	SetClosed(true);

	if ( props.is_live && props.selectable_fd != -1 )
		iosource_mgr->UnregisterFd(props.selectable_fd, this);

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
	session_mgr->Weird(msg.c_str(), p);
	}

void PktSrc::InternalError(const std::string& msg)
	{
	reporter->InternalError("%s", msg.c_str());
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

	run_state::detail::dispatch_packet(&current_packet, this);

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
	if ( run_state::is_processing_suspended() && run_state::detail::first_timestamp )
		return false;

	if ( run_state::pseudo_realtime )
		run_state::detail::current_wallclock = util::current_time(true);

	if ( ExtractNextPacket(&current_packet) )
		{
		if ( current_packet.time < 0 )
			{
			Weird("negative_packet_timestamp", &current_packet);
			return false;
			}

		if ( ! run_state::detail::first_timestamp )
			run_state::detail::first_timestamp = current_packet.time;

		have_packet = true;
		return true;
		}

	if ( run_state::pseudo_realtime && ! IsOpen() )
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
	auto* code = new detail::BPF_Program();

	if ( ! code->Compile(BifConst::Pcap::snaplen, LinkType(), filter.c_str(), Netmask(), errbuf, sizeof(errbuf)) )
		{
		std::string msg = util::fmt("cannot compile BPF filter \"%s\"", filter.c_str());

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

detail::BPF_Program* PktSrc::GetBPFFilter(int index)
	{
	if ( index < 0 )
		return nullptr;

	return (static_cast<int>(filters.size()) > index ? filters[index] : nullptr);
	}

bool PktSrc::ApplyBPFFilter(int index, const struct pcap_pkthdr *hdr, const u_char *pkt)
	{
	detail::BPF_Program* code = GetBPFFilter(index);

	if ( ! code )
		{
		Error(util::fmt("BPF filter %d not compiled", index));
		Close();
		return false;
		}

	if ( code->MatchesAnything() )
		return true;

	return pcap_offline_filter(code->GetProgram(), hdr, pkt);
	}

bool PktSrc::GetCurrentPacket(const Packet** pkt)
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
	if ( IsLive() || run_state::is_processing_suspended() )
		return -1;
	else if ( ! run_state::pseudo_realtime )
		return 0;

	if ( ! have_packet )
		ExtractNextPacketInternal();

	// This duplicates the calculation used in run_state::check_pseudo_time().
	double pseudo_time = current_packet.time - run_state::detail::first_timestamp;
	double ct = (util::current_time(true) - run_state::detail::first_wallclock) * run_state::pseudo_realtime;
	return std::max(0.0, pseudo_time - ct);
	}

} // namespace zeek::iosource
