// See the file "COPYING" in the main distribution directory for copyright.

#include <errno.h>
#include <sys/stat.h>

#include "zeek-config.h"

#include "util.h"
#include "PktSrc.h"
#include "Hash.h"
#include "Net.h"
#include "Sessions.h"
#include "broker/Manager.h"
#include "iosource/Manager.h"

#include "pcap/pcap.bif.h"

using namespace iosource;

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
	if ( Packet::GetLinkHeaderSize(arg_props.link_type) < 0 )
		{
		char buf[512];
		safe_snprintf(buf, sizeof(buf),
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
		Info(fmt("listening on %s\n", props.path.c_str()));

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
	sessions->Weird(msg.c_str(), p, 0);
	}

void PktSrc::InternalError(const std::string& msg)
	{
	reporter->InternalError("%s", msg.c_str());
	}

void PktSrc::ContinueAfterSuspend()
	{
	current_wallclock = current_time(true);
	}

double PktSrc::CheckPseudoTime()
	{
	if ( ! IsOpen() )
		return 0;

	if ( ! ExtractNextPacketInternal() )
		return 0;

	if ( remote_trace_sync_interval )
		{
		if ( next_sync_point == 0 || current_packet.time >= next_sync_point )
			{
			int n = remote_serializer->SendSyncPoint();
			next_sync_point = first_timestamp +
						n * remote_trace_sync_interval;
			remote_serializer->Log(RemoteSerializer::LogInfo,
				fmt("stopping at packet %.6f, next sync-point at %.6f",
					current_packet.time, next_sync_point));

			return 0;
			}
		}

	double pseudo_time = current_packet.time - first_timestamp;
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

	return current_packet.time;
	}

void PktSrc::Process()
	{
	if ( ! IsOpen() )
		return;

	if ( ! ExtractNextPacketInternal() )
		return;

	if ( current_packet.Layer2Valid() )
		{
		if ( pseudo_realtime )
			{
			current_pseudo = CheckPseudoTime();
			net_packet_dispatch(current_pseudo, &current_packet, this);
			if ( ! first_wallclock )
				first_wallclock = current_time(true);
			}

		else
			net_packet_dispatch(current_packet.time, &current_packet, this);
		}

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
		if ( current_packet.time < 0 )
			{
			Weird("negative_packet_timestamp", &current_packet);
			return 0;
			}

		if ( ! first_timestamp )
			first_timestamp = current_packet.time;

		SetIdle(false);
		have_packet = true;
		return 1;
		}

	if ( pseudo_realtime && ! IsOpen() )
		{
		if ( using_communication )
			{
			// Source has gone dry, we're done.
			if ( remote_trace_sync_interval )
				remote_serializer->SendFinalSyncPoint();
			else
				remote_serializer->Terminate();
			}

		if ( broker_mgr->Active() )
			iosource_mgr->Terminate();
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

	if ( ! code->Compile(BifConst::Pcap::snaplen, LinkType(), filter.c_str(), Netmask(), errbuf, sizeof(errbuf)) )
		{
		string msg = fmt("cannot compile BPF filter \"%s\"", filter.c_str());

		if ( *errbuf )
			msg += ": " + string(errbuf);

		Error(msg);

		delete code;
		return 0;
		}

	// Store it in vector.
	if ( index >= static_cast<int>(filters.size()) )
		filters.resize(index + 1);

	if ( auto old = filters[index] )
		delete old;

	filters[index] = code;

	return true;
	}

BPF_Program* PktSrc::GetBPFFilter(int index)
	{
	if ( index < 0 )
		return 0;

	return (static_cast<int>(filters.size()) > index ? filters[index] : 0);
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

bool PktSrc::GetCurrentPacket(const Packet** pkt)
	{
	if ( ! have_packet )
		return false;

	*pkt = &current_packet;
	return true;
	}
