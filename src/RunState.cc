// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/RunState.h"

#include "zeek/zeek-config.h"

#include <sys/types.h>
#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <ctime>
#else
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <ctime>
#endif
#endif

#include <unistd.h>
#include <csignal>
#include <cstdlib>

extern "C"
	{
#include "zeek/3rdparty/setsignal.h"
	};

#include "zeek/Anon.h"
#include "zeek/Event.h"
#include "zeek/ID.h"
#include "zeek/NetVar.h"
#include "zeek/Reporter.h"
#include "zeek/Scope.h"
#include "zeek/Timer.h"
#include "zeek/broker/Manager.h"
#include "zeek/iosource/Manager.h"
#include "zeek/iosource/PktDumper.h"
#include "zeek/iosource/PktSrc.h"
#include "zeek/packet_analysis/Manager.h"
#include "zeek/plugin/Manager.h"
#include "zeek/session/Manager.h"

static double last_watchdog_proc_time = 0.0; // value of above during last watchdog
extern int signal_val;

namespace zeek::run_state
	{
namespace detail
	{

iosource::PktDumper* pkt_dumper = nullptr;
iosource::PktSrc* current_pktsrc = nullptr;
iosource::IOSource* current_iosrc = nullptr;
bool have_pending_timers = false;
double first_wallclock = 0.0;
double first_timestamp = 0.0;
double current_wallclock = 0.0;
double current_pseudo = 0.0;
bool zeek_init_done = false;
bool time_updated = false;
bool bare_mode = false;

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
			int frac_pst = int((processing_start_time - int_pst) * 1e6);

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
				"**watchdog timer expired, t = %d.%06d, start = %d.%06d, dispatched = %d", int_ct,
				frac_ct, int_pst, frac_pst, current_dispatched);
			}
		}

	last_watchdog_proc_time = processing_start_time;

	(void)alarm(zeek::detail::watchdog_interval);
	return RETSIGVAL;
	}

void update_network_time(double new_network_time)
	{
	time_updated = true;
	network_time = new_network_time;
	PLUGIN_HOOK_VOID(HOOK_UPDATE_NETWORK_TIME, HookUpdateNetworkTime(new_network_time));
	}

// Logic to decide when updating network_time is acceptable:
static bool should_forward_network_time()
	{
	// In pseudo_realtime mode, always update time once
	// we've dispatched and processed the first packet.
	// run_state::detail::first_timestamp is currently set
	// in PktSrc::ExtractNextPacketInternal()
	if ( pseudo_realtime != 0.0 && run_state::detail::first_timestamp != 0.0 )
		return true;

	if ( iosource::PktSrc* ps = iosource_mgr->GetPktSrc() )
		{
		// Offline packet sources always control network time
		// unless we're running pseudo_realtime, see above.
		if ( ! ps->IsLive() )
			return false;

		if ( ! ps->HasBeenIdleFor(BifConst::packet_source_inactivity_timeout) )
			return false;
		}

	// We determined that we don't have a packet source, or it is idle.
	// Unless it has been disabled, network_time will now be moved forward.
	return BifConst::allow_network_time_forward;
	}

static void forward_network_time_if_applicable()
	{
	if ( ! should_forward_network_time() )
		return;

	double now = util::current_time(true);
	if ( now > network_time )
		update_network_time(now);

	return;
	}

void init_run(const std::optional<std::string>& interface,
              const std::optional<std::string>& pcap_input_file,
              const std::optional<std::string>& pcap_output_file, bool do_watchdog)
	{
	if ( pcap_input_file )
		{
		reading_live = pseudo_realtime > 0.0;
		reading_traces = true;

		iosource::PktSrc* ps = iosource_mgr->OpenPktSrc(*pcap_input_file, false);
		assert(ps);

		if ( ! ps->IsOpen() )
			reporter->FatalError("problem with trace file %s (%s)", pcap_input_file->c_str(),
			                     ps->ErrorMsg());
		}
	else if ( interface )
		{
		reading_live = true;
		reading_traces = false;

		iosource::PktSrc* ps = iosource_mgr->OpenPktSrc(*interface, true);
		assert(ps);

		if ( ! ps->IsOpen() )
			reporter->FatalError("problem with interface %s (%s)", interface->c_str(),
			                     ps->ErrorMsg());
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
			reporter->FatalError("problem opening dump file %s (%s)", writefile,
			                     pkt_dumper->ErrorMsg());

		if ( const auto& id = zeek::detail::global_scope()->Find("trace_output_file") )
			id->SetVal(make_intrusive<StringVal>(writefile));
		else
			reporter->Error("trace_output_file not defined");
		}

	zeek::detail::init_ip_addr_anonymizers();

	session_mgr = new session::Manager();

	if ( do_watchdog )
		{
		// Set up the watchdog to make sure we don't wedge.
		(void)setsignal(SIGALRM, watchdog);
		(void)alarm(zeek::detail::watchdog_interval);
		}
	}

void expire_timers()
	{
	zeek::detail::SegmentProfiler prof(zeek::detail::segment_logger, "expiring-timers");

	current_dispatched += zeek::detail::timer_mgr->Advance(
		network_time, zeek::detail::max_timer_expires - current_dispatched);
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
	current_pktsrc = pkt_src;

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

			zeek::detail::sample_logger = std::make_shared<zeek::detail::SampleLogger>();
			sp = new zeek::detail::SegmentProfiler(zeek::detail::sample_logger, "load-samp");
			}
		}

	packet_mgr->ProcessPacket(pkt);
	event_mgr.Drain();

	if ( sp )
		{
		delete sp;
		zeek::detail::sample_logger = nullptr;
		}

	processing_start_time = 0.0; // = "we're not processing now"
	current_dispatched = 0;

	if ( pseudo_realtime && ! first_wallclock )
		first_wallclock = util::current_time(true);

	current_iosrc = nullptr;
	current_pktsrc = nullptr;
	}

void run_loop()
	{
	util::detail::set_processing_status("RUNNING", "run_loop");

	iosource::Manager::ReadySources ready;
	ready.reserve(iosource_mgr->TotalSize());

	while ( iosource_mgr->Size() || (BifConst::exit_only_after_terminate && ! terminating) )
		{
		time_updated = false;
		iosource_mgr->FindReadySources(&ready);

#ifdef DEBUG
		static int loop_counter = 0;

		// If no source is ready, we log only every 100th cycle,
		// starting with the first.
		if ( ! ready.empty() || loop_counter++ % 100 == 0 )
			{
			DBG_LOG(DBG_MAINLOOP, "realtime=%.6f ready_count=%zu", util::current_time(),
			        ready.size());

			if ( ! ready.empty() )
				loop_counter = 0;
			}
#endif
		current_iosrc = nullptr;
		auto communication_enabled = broker_mgr->Active();

		if ( ! ready.empty() )
			{
			for ( const auto& src : ready )
				{
				auto* iosrc = src.src;

				DBG_LOG(DBG_MAINLOOP, "processing source %s", iosrc->Tag());
				current_iosrc = iosrc;
				if ( iosrc->ImplementsProcessFd() && src.fd != -1 )
					iosrc->ProcessFd(src.fd, src.flags);
				else
					iosrc->Process();
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
			//
			// TBD: Is this actually still relevant given that the TimerMgr
			//      is an IO source now? It'll be processed once its
			//      GetNextTimeout() yields 0 and before that there's nothing
			//      to expire anyway.
			forward_network_time_if_applicable();
			expire_timers();

			// Prevent another forward_network_time_if_applicable() below
			// even if time wasn't actually updated.
			time_updated = true;
			}

		if ( ! time_updated )
			forward_network_time_if_applicable();

		event_mgr.Drain();

		processing_start_time = 0.0; // = "we're not processing now"
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

		// Terminate if we're running pseudo_realtime and
		// the interface has been closed.
		if ( pseudo_realtime && communication_enabled )
			{
			iosource::PktSrc* ps = iosource_mgr->GetPktSrc();
			if ( ps && ! ps->IsOpen() )
				iosource_mgr->Terminate();
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

		auto pct = [](uint64_t v, uint64_t received)
		{
			return (static_cast<double>(v) /
			        (static_cast<double>(v) + static_cast<double>(received))) *
			       100;
		};

		double dropped_pct = s.dropped > 0 ? pct(s.dropped, s.received) : 0.0;

		uint64_t not_processed = packet_mgr->GetUnprocessedCount();
		double unprocessed_pct = not_processed > 0
		                             ? ((double)not_processed / (double)s.received) * 100.0
		                             : 0.0;

		std::string filtered = "";
		if ( s.filtered )
			{
			double filtered_pct = s.filtered.value() > 0 ? pct(s.filtered.value(), s.received)
			                                             : 0.0;
			filtered = zeek::util::fmt(" %" PRIu64 " (%.2f%%) filtered", s.filtered.value(),
			                           filtered_pct);
			}

		reporter->Info("%" PRIu64 " packets received on interface %s, %" PRIu64
		               " (%.2f%%) dropped, %" PRIu64 " (%.2f%%) not processed%s",
		               s.received, ps->Path().c_str(), s.dropped, dropped_pct, not_processed,
		               unprocessed_pct, filtered.c_str());
		}
	}

void finish_run(int drain_events)
	{
	util::detail::set_processing_status("TERMINATING", "finish_run");

	if ( drain_events )
		{
		if ( session_mgr )
			session_mgr->Drain();

		event_mgr.Drain();

		if ( session_mgr )
			session_mgr->Done();
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
double network_time = 0.0; // time according to last packet timestamp
                           // (or current time)
double processing_start_time = 0.0; // time started working on current pkt
double zeek_start_time = 0.0; // time Zeek started.
double zeek_start_network_time; // timestamp of first packet
bool terminating = false; // whether we're done reading and finishing up
bool is_parsing = false;

const Packet* current_pkt = nullptr;
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

	if ( _processing_suspended > 0 )
		--_processing_suspended;
	}

bool is_processing_suspended()
	{
	return _processing_suspended > 0;
	}

	} // namespace zeek::run_state
