// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/iosource/PktSrc.h"

#include "zeek/zeek-config.h"

#include <sys/stat.h>

#include "zeek/Hash.h"
#include "zeek/RunState.h"
#include "zeek/broker/Manager.h"
#include "zeek/iosource/BPF_Program.h"
#include "zeek/iosource/Manager.h"
#include "zeek/iosource/pcap/pcap.bif.h"
#include "zeek/packet_analysis/Manager.h"
#include "zeek/session/Manager.h"
#include "zeek/util.h"

namespace zeek::iosource
	{

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
	// Small lie to make a new PktSrc look like the previous ExtractNextPacket() was successful.
	had_packet = true;
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
		Info(util::fmt("listening on %s\n", props.path.c_str()));

	if ( props.selectable_fd != -1 )
		if ( ! iosource_mgr->RegisterFd(props.selectable_fd, this) )
			reporter->FatalError("Failed to register pktsrc fd with iosource_mgr");

	DBG_LOG(DBG_PKTIO, "Opened source %s", props.path.c_str());
	}

void PktSrc::Closed()
	{
	SetClosed(true);

	if ( props.selectable_fd != -1 )
		iosource_mgr->UnregisterFd(props.selectable_fd, this);

	DBG_LOG(DBG_PKTIO, "Closed source %s", props.path.c_str());
	}

void PktSrc::Error(const std::string& msg)
	{
	// We don't report this immediately, Zeek will ask us for the error
	// once it notices we aren't open.
	errbuf = msg;
	DBG_LOG(DBG_PKTIO, "Error with source %s: %s", IsOpen() ? props.path.c_str() : "<not open>",
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

bool PktSrc::HasBeenIdleFor(double interval) const
	{
	if ( have_packet || had_packet )
		return false;

	// Take the hit of a current_time() call now.
	double now = zeek::util::current_time(true);
	return idle_at_wallclock < now - interval;
	};

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
		had_packet = true;

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
	else
		{
		// Update the idle_at timestamp the first time we've failed
		// to extract a packet. This assumes ExtractNextPacket() is
		// called regularly which is true for non-selectable PktSrc
		// instances, but even for selectable ones with an FD the
		// main-loop will call Process() on the interface regularly
		// and detect it as idle.
		if ( had_packet )
			{
			DBG_LOG(DBG_PKTIO, "source %s is idle now", props.path.c_str());
			idle_at_wallclock = zeek::util::current_time(true);
			}

		had_packet = false;
		}

	return false;
	}

detail::BPF_Program* PktSrc::CompileFilter(const std::string& filter)
	{
	auto code = std::make_unique<detail::BPF_Program>();

	if ( ! code->Compile(BifConst::Pcap::snaplen, LinkType(), filter.c_str(), Netmask()) )
		{
		std::string msg = util::fmt("cannot compile BPF filter \"%s\"", filter.c_str());

		std::string state_msg = code->GetStateMessage();
		if ( ! state_msg.empty() )
			msg += ": " + state_msg;

		Error(msg);
		}

	return code.release();
	}

bool PktSrc::PrecompileBPFFilter(int index, const std::string& filter)
	{
	if ( index < 0 )
		return false;

	// Compile filter. This will always return a pointer, but may have stored an error
	// internally.
	auto code = CompileFilter(filter);

	// Store it in vector.
	if ( index >= static_cast<int>(filters.size()) )
		filters.resize(index + 1);

	if ( auto* old = filters[index] )
		delete old;

	filters[index] = code;

	return code->GetState() != FilterState::FATAL;
	}

detail::BPF_Program* PktSrc::GetBPFFilter(int index)
	{
	if ( index < 0 )
		return nullptr;

	return (static_cast<int>(filters.size()) > index ? filters[index] : nullptr);
	}

bool PktSrc::ApplyBPFFilter(int index, const struct pcap_pkthdr* hdr, const u_char* pkt)
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
	if ( run_state::is_processing_suspended() )
		return -1;

	// If we're in pseudo-realtime mode, find the next time that a packet is ready
	// and have poll block until then.
	if ( run_state::pseudo_realtime )
		{
		ExtractNextPacketInternal();

		// This duplicates the calculation used in run_state::check_pseudo_time().
		double pseudo_time = current_packet.time - run_state::detail::first_timestamp;
		double ct = (util::current_time(true) - run_state::detail::first_wallclock) *
		            run_state::pseudo_realtime;
		return std::max(0.0, pseudo_time - ct);
		}

	// If there's no file descriptor for the source, which is the case for some interfaces
	// like myricom, we can't rely on the polling mechanism to wait for data to be
	// available. As gross as it is, just spin with a short timeout here so that it will
	// continually poll the interface. The old IOSource code had a 20 microsecond timeout
	// between calls to select() so just use that.

	// A heuristic to avoid short sleeps when a non-selectable packet source has more
	// packets queued is to return 0.0 if the source has yielded a packet on the
	// last call to ExtractNextPacket().
	if ( props.selectable_fd == -1 )
		{
		if ( have_packet || had_packet )
			return 0.0;

		return BifConst::Pcap::non_fd_timeout;
		}

	// If there's an FD (offline or live) we want poll to do what it has to with it.
	return -1.0;
	}

	} // namespace zeek::iosource
