// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeek-config.h"
#include "zeek/RunState.h"

#include <sys/types.h>
#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

extern "C" {
#include "zeek/setsignal.h"
};

#include "zeek/NetVar.h"
#include "zeek/Sessions.h"
#include "zeek/Event.h"
#include "zeek/Timer.h"
#include "zeek/ID.h"
#include "zeek/Reporter.h"
#include "zeek/Scope.h"
#include "zeek/Anon.h"
#include "zeek/iosource/Manager.h"
#include "zeek/iosource/PktSrc.h"
#include "zeek/iosource/PktDumper.h"
#include "zeek/plugin/Manager.h"
#include "zeek/broker/Manager.h"
#include "zeek/packet_analysis/Manager.h"
#include "zeek/analyzer/protocol/stepping-stone/SteppingStone.h"

extern "C" {
extern int select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
}

static double last_watchdog_proc_time = 0.0;	// value of above during last watchdog
extern int signal_val;

using namespace zeek::analyzer::stepping_stone;

namespace zeek::run_state {
namespace detail {

iosource::PktDumper* pkt_dumper = nullptr;
iosource::PktSrc* current_pktsrc = nullptr;
iosource::IOSource* current_iosrc = nullptr;
bool have_pending_timers = false;
double first_wallclock = 0.0;
double first_timestamp = 0.0;
double current_wallclock = 0.0;
double current_pseudo = 0.0;
bool zeek_init_done = false;

RETSIGTYPE watchdog(int /* signo */)
	{
	if ( processing_start_time != 0.0 )
		{
		// The signal arrived while we're processing a packet and/or
		// its corresponding event queue.  Check whether we've been
		// spending too much time, which we take to mean we've wedged.

		// Note that it's subtle how exactly to test this.  In
		// processing_start_time we have the timestamp of the packet
		// we're currently working on.  But that *doesn't* mean that
		// we began work on the packet at that time; we could have
		// begun at a much later time, depending on how long the
		// packet filter waited (to fill its buffer) before handing
		// up this packet.  So what we require is that the current
		// processing_start_time matches the processing_start_time we
		// observed last time the watchdog went off.  If so, then
		// we've been working on the current packet for at least
		// watchdog_interval seconds.

		if ( processing_start_time == last_watchdog_proc_time )
			{
			// snprintf() calls alloc/free routines if you use %f!
			// We need to avoid doing that given we're in a single
			// handler and the allocation routines are not
			// reentrant.

			double ct = util::current_time();

			int int_ct = int(ct);
			int frac_ct = int((ct - int_ct) * 1e6);

			int int_pst = int(processing_start_time);
			int frac_pst =
				int((processing_start_time - int_pst) * 1e6);

			if ( current_pkt )
				{
				if ( ! pkt_dumper )
					{
					// We aren't dumping packets; however,
					// saving the packet which caused the
					// watchdog to trigger may be helpful,
					// so we'll save that one nevertheless.
					pkt_dumper = iosource_mgr->OpenPktDumper("watchdog-pkt.pcap", false);
					if ( ! pkt_dumper || pkt_dumper->IsError() )
						{
						reporter->Error("watchdog: can't open watchdog-pkt.pcap for writing");
						pkt_dumper = nullptr;
						}
					}

				if ( pkt_dumper )
					pkt_dumper->Dump(current_pkt);

				}

			get_final_stats();
			finish_run(0);

			reporter->FatalErrorWithCore(
				"**watchdog timer expired, t = %d.%06d, start = %d.%06d, dispatched = %d",
				int_ct, frac_ct, int_pst, frac_pst,
				current_dispatched);
			}
		}

	last_watchdog_proc_time = processing_start_time;

	(void) alarm(zeek::detail::watchdog_interval);
	return RETSIGVAL;
	}

void update_network_time(double new_network_time)
	{
	network_time = new_network_time;
	PLUGIN_HOOK_VOID(HOOK_UPDATE_NETWORK_TIME, HookUpdateNetworkTime(new_network_time));
	}

void init_run(const std::optional<std::string>& interface,
              const std::optional<std::string>& pcap_input_file,
              const std::optional<std::string>& pcap_output_file,
              bool do_watchdog)
	{
	if ( pcap_input_file )
		{
		reading_live = pseudo_realtime > 0.0;
		reading_traces = true;

		iosource::PktSrc* ps = iosource_mgr->OpenPktSrc(*pcap_input_file, false);
		assert(ps);

		if ( ! ps->IsOpen() )
			reporter->FatalError("problem with trace file %s (%s)",
			                     pcap_input_file->c_str(), ps->ErrorMsg());
		}
	else if ( interface )
		{
		reading_live = true;
		reading_traces = false;

		iosource::PktSrc* ps = iosource_mgr->OpenPktSrc(*interface, true);
		assert(ps);

		if ( ! ps->IsOpen() )
			reporter->FatalError("problem with interface %s (%s)",
			                           interface->c_str(), ps->ErrorMsg());
		}

	else
		// have_pending_timers = true, possibly.  We don't set
		// that here, though, because at this point we don't know
		// whether the user's zeek_init() event will indeed set
		// a timer.
		reading_traces = reading_live = false;

	if ( pcap_output_file )
		{
		const char* writefile = pcap_output_file->data();
		pkt_dumper = iosource_mgr->OpenPktDumper(writefile, false);
		assert(pkt_dumper);

		if ( ! pkt_dumper->IsOpen() )
			reporter->FatalError("problem opening dump file %s (%s)",
			                           writefile, pkt_dumper->ErrorMsg());

		if ( const auto& id = zeek::detail::global_scope()->Find("trace_output_file") )
			id->SetVal(make_intrusive<StringVal>(writefile));
		else
			reporter->Error("trace_output_file not defined in bro.init");
		}

	zeek::detail::init_ip_addr_anonymizers();

	sessions = new NetSessions();

	// Initialize the stepping stone manager. We intentionally throw away the result here.
	SteppingStoneManager::Get();

	if ( do_watchdog )
		{
		// Set up the watchdog to make sure we don't wedge.
		(void) setsignal(SIGALRM, watchdog);
		(void) alarm(zeek::detail::watchdog_interval);
		}
	}

void expire_timers()
	{
	zeek::detail::SegmentProfiler prof(zeek::detail::segment_logger, "expiring-timers");

	current_dispatched +=
		zeek::detail::timer_mgr->Advance(network_time,
			zeek::detail::max_timer_expires - current_dispatched);
	}

void dispatch_packet(Packet* pkt, iosource::PktSrc* pkt_src)
	{
	double t = run_state::pseudo_realtime ? check_pseudo_time(pkt) : pkt->time;

	if ( ! zeek_start_network_time )
		{
		zeek_start_network_time = t;

		if ( network_time_init )
			event_mgr.Enqueue(network_time_init, Args{});
		}

	current_iosrc = pkt_src;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	current_pktsrc = pkt_src;
#pragma GCC diagnostic pop

	// network_time never goes back.
	update_network_time(zeek::detail::timer_mgr->Time() < t ? t : zeek::detail::timer_mgr->Time());
	processing_start_time = t;
	expire_timers();

	zeek::detail::SegmentProfiler* sp = nullptr;

	if ( load_sample )
		{
		static uint32_t load_freq = 0;

		if ( load_freq == 0 )
			load_freq = uint32_t(0xffffffff) / uint32_t(zeek::detail::load_sample_freq);

		if ( uint32_t(util::detail::random_number() & 0xffffffff) < load_freq )
			{
			// Drain the queued timer events so they're not
			// charged against this sample.
			event_mgr.Drain();

			zeek::detail::sample_logger = new zeek::detail::SampleLogger();
			sp = new zeek::detail::SegmentProfiler(zeek::detail::sample_logger, "load-samp");
			}
		}

	packet_mgr->ProcessPacket(pkt);
	event_mgr.Drain();

	if ( sp )
		{
		delete sp;
		delete zeek::detail::sample_logger;
		zeek::detail::sample_logger = nullptr;
		}

	processing_start_time = 0.0;	// = "we're not processing now"
	current_dispatched = 0;

	if ( pseudo_realtime && ! first_wallclock )
		first_wallclock = util::current_time(true);

	current_iosrc = nullptr;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	current_pktsrc = nullptr;
#pragma GCC diagnostic pop
	}

void run_loop()
	{
	util::detail::set_processing_status("RUNNING", "run_loop");

	std::vector<iosource::IOSource*> ready;
	ready.reserve(iosource_mgr->TotalSize());

	while ( iosource_mgr->Size() ||
		(BifConst::exit_only_after_terminate && ! terminating) )
		{
		iosource_mgr->FindReadySources(&ready);

#ifdef DEBUG
		static int loop_counter = 0;

		// If no source is ready, we log only every 100th cycle,
		// starting with the first.
		if ( ! ready.empty() || loop_counter++ % 100 == 0 )
			{
			DBG_LOG(DBG_MAINLOOP, "realtime=%.6f ready_count=%zu",
			        util::current_time(), ready.size());

			if ( ! ready.empty() )
				loop_counter = 0;
			}
#endif
		current_iosrc = nullptr;
		auto communication_enabled = broker_mgr->Active();

		if ( ! ready.empty() )
			{
			for ( auto src : ready )
				{
				DBG_LOG(DBG_MAINLOOP, "processing source %s", src->Tag());
				current_iosrc = src;
				src->Process();
				}
			}
		else if ( (have_pending_timers || communication_enabled ||
		           BifConst::exit_only_after_terminate) &&
		          ! pseudo_realtime )
			{
			// Take advantage of the lull to get up to
			// date on timers and events.  Because we only
			// have timers as sources, going to sleep here
			// doesn't risk blocking on other inputs.
			update_network_time(util::current_time());
			expire_timers();
			}

		event_mgr.Drain();

		processing_start_time = 0.0;	// = "we're not processing now"
		current_dispatched = 0;
		current_iosrc = nullptr;

		if ( ::signal_val == SIGTERM || ::signal_val == SIGINT )
			// We received a signal while processing the
			// current packet and its related events.
			// Should we put the signal handling into an IOSource?
			zeek_terminate_loop("received termination signal");

		if ( ! reading_traces )
			// Check whether we have timers scheduled for
			// the future on which we need to wait.
			have_pending_timers = zeek::detail::timer_mgr->Size() > 0;

		if ( pseudo_realtime && communication_enabled )
			{
			auto have_active_packet_source = false;

			iosource::PktSrc* ps = iosource_mgr->GetPktSrc();
			if ( ps && ps->IsOpen() )
				have_active_packet_source = true;

			if (  ! have_active_packet_source )
				// Can turn off pseudo realtime now
				pseudo_realtime = 0.0;
			}
		}

	// Get the final statistics now, and not when finish_run() is
	// called, since that might happen quite a bit in the future
	// due to expiring pending timers, and we don't want to ding
	// for any packets dropped beyond this point.
	get_final_stats();
	}

void get_final_stats()
	{
	iosource::PktSrc* ps = iosource_mgr->GetPktSrc();
	if ( ps && ps->IsLive() )
		{
		iosource::PktSrc::Stats s;
		ps->Statistics(&s);
		double dropped_pct = s.dropped > 0.0 ? ((double)s.dropped / ((double)s.received + (double)s.dropped)) * 100.0 : 0.0;
		reporter->Info("%" PRIu64 " packets received on interface %s, %" PRIu64 " (%.2f%%) dropped",
		                     s.received, ps->Path().c_str(), s.dropped, dropped_pct);
		}
	}

void finish_run(int drain_events)
	{
	util::detail::set_processing_status("TERMINATING", "finish_run");

	if ( drain_events )
		{
		if ( sessions )
			sessions->Drain();

		event_mgr.Drain();

		if ( sessions )
			sessions->Done();
		}

#ifdef DEBUG
	extern int reassem_seen_bytes, reassem_copied_bytes;
	// DEBUG_MSG("Reassembly (TCP and IP/Frag): %d bytes seen, %d bytes copied\n",
	// 	reassem_seen_bytes, reassem_copied_bytes);

	extern int num_packets_held, num_packets_cleaned;
	// DEBUG_MSG("packets clean up: %d/%d\n", num_packets_cleaned, num_packets_held);
#endif
	}

void delete_run()
	{
	util::detail::set_processing_status("TERMINATING", "delete_run");

	delete sessions;
	delete SteppingStoneManager::Get();

	for ( int i = 0; i < zeek::detail::NUM_ADDR_ANONYMIZATION_METHODS; ++i )
		delete zeek::detail::ip_anonymizer[i];
	}

double check_pseudo_time(const Packet* pkt)
	{
	double pseudo_time = pkt->time - first_timestamp;
	double ct = (util::current_time(true) - first_wallclock) * pseudo_realtime;

	current_pseudo = pseudo_time <= ct ? zeek_start_time + pseudo_time : 0;
	return current_pseudo;
	}

iosource::PktSrc* current_packet_source()
	{
	return dynamic_cast<iosource::PktSrc*>(current_iosrc);
	}

} // namespace detail

double current_packet_timestamp()
	{
	return detail::current_pseudo;
	}

double current_packet_wallclock()
	{
	// We stop time when we are suspended.
	if ( run_state::is_processing_suspended() )
		detail::current_wallclock = util::current_time(true);

	return detail::current_wallclock;
	}

bool reading_live = false;
bool reading_traces = false;
double pseudo_realtime = 0.0;
double network_time = 0.0;	// time according to last packet timestamp
                            // (or current time)
double processing_start_time = 0.0;	// time started working on current pkt
double zeek_start_time = 0.0; // time Bro started.
double zeek_start_network_time;	// timestamp of first packet
bool terminating = false;	// whether we're done reading and finishing up
bool is_parsing = false;

const Packet *current_pkt = nullptr;
int current_dispatched = 0;
double current_timestamp = 0.0;

static int _processing_suspended = 0;

void suspend_processing()
	{
	if ( _processing_suspended == 0 )
		reporter->Info("processing suspended");

	++_processing_suspended;
	}

void continue_processing()
	{
	if ( _processing_suspended == 1 )
		{
		reporter->Info("processing continued");
		detail::current_wallclock = util::current_time(true);
		}

	--_processing_suspended;
	}

bool is_processing_suspended()	{ return _processing_suspended; }

} // namespace zeek::run_state
