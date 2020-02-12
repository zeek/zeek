// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"
#include "Net.h"

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

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

extern "C" {
#include "setsignal.h"
};

#include "NetVar.h"
#include "Sessions.h"
#include "Event.h"
#include "Timer.h"
#include "Var.h"
#include "Reporter.h"
#include "Anon.h"
#include "PacketDumper.h"
#include "iosource/Manager.h"
#include "iosource/PktSrc.h"
#include "iosource/PktDumper.h"
#include "plugin/Manager.h"
#include "broker/Manager.h"

extern "C" {
extern int select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
}

iosource::PktDumper* pkt_dumper = nullptr;

bool reading_live = false;
bool reading_traces = false;
bool have_pending_timers = false;
double pseudo_realtime = 0.0;
double network_time = 0.0;	// time according to last packet timestamp
				// (or current time)
double processing_start_time = 0.0;	// time started working on current pkt
double bro_start_time = 0.0; // time Bro started.
double bro_start_network_time;	// timestamp of first packet
double last_watchdog_proc_time = 0.0;	// value of above during last watchdog
bool terminating = false;	// whether we're done reading and finishing up
bool is_parsing = false;

const Packet *current_pkt = nullptr;
int current_dispatched = 0;
double current_timestamp = 0.0;
iosource::PktSrc* current_pktsrc = nullptr;
iosource::IOSource* current_iosrc = nullptr;

std::list<ScannedFile> files_scanned;
std::vector<string> sig_files;

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

			double ct = current_time();

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
						pkt_dumper = 0;
						}
					}

				if ( pkt_dumper )
					pkt_dumper->Dump(current_pkt);

				}

			net_get_final_stats();
			net_finish(0);

			reporter->FatalErrorWithCore(
			          "**watchdog timer expired, t = %d.%06d, start = %d.%06d, dispatched = %d",
				      int_ct, frac_ct, int_pst, frac_pst,
					  current_dispatched);
			}
		}

	last_watchdog_proc_time = processing_start_time;

	(void) alarm(watchdog_interval);
	return RETSIGVAL;
	}

void net_update_time(double new_network_time)
	{
	network_time = new_network_time;
	PLUGIN_HOOK_VOID(HOOK_UPDATE_NETWORK_TIME, HookUpdateNetworkTime(new_network_time));
	}

void net_init(const std::optional<std::string>& interface,
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

		if ( ID* id = global_scope()->Lookup("trace_output_file") )
			id->SetVal(new StringVal(writefile));
		else
			reporter->Error("trace_output_file not defined in bro.init");
		}

	init_ip_addr_anonymizers();

	sessions = new NetSessions();

	if ( do_watchdog )
		{
		// Set up the watchdog to make sure we don't wedge.
		(void) setsignal(SIGALRM, watchdog);
		(void) alarm(watchdog_interval);
		}
	}

void expire_timers(iosource::PktSrc* src_ps)
	{
	SegmentProfiler prof(segment_logger, "expiring-timers");

	current_dispatched +=
		timer_mgr->Advance(network_time,
			max_timer_expires - current_dispatched);
	}

void net_packet_dispatch(double t, const Packet* pkt, iosource::PktSrc* src_ps)
	{
	if ( ! bro_start_network_time )
		bro_start_network_time = t;

	// network_time never goes back.
	net_update_time(timer_mgr->Time() < t ? t : timer_mgr->Time());

	current_pktsrc = src_ps;
	current_iosrc = src_ps;
	processing_start_time = t;

	expire_timers(src_ps);

	SegmentProfiler* sp = nullptr;

	if ( load_sample )
		{
		static uint32_t load_freq = 0;

		if ( load_freq == 0 )
			load_freq = uint32_t(0xffffffff) / uint32_t(load_sample_freq);

		if ( uint32_t(bro_random() & 0xffffffff) < load_freq )
			{
			// Drain the queued timer events so they're not
			// charged against this sample.
			mgr.Drain();

			sample_logger = new SampleLogger();
			sp = new SegmentProfiler(sample_logger, "load-samp");
			}
		}

	sessions->NextPacket(t, pkt);
	mgr.Drain();

	if ( sp )
		{
		delete sp;
		delete sample_logger;
		sample_logger = nullptr;
		}

	processing_start_time = 0.0;	// = "we're not processing now"
	current_dispatched = 0;
	current_iosrc = nullptr;
	current_pktsrc = nullptr;
	}

void net_run()
	{
	set_processing_status("RUNNING", "net_run");

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
			DBG_LOG(DBG_MAINLOOP, "realtime=%.6f ready_count=%ld",
				current_time(), ready.size());

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
			net_update_time(current_time());
			expire_timers();
			}

		mgr.Drain();

		processing_start_time = 0.0;	// = "we're not processing now"
		current_dispatched = 0;
		current_iosrc = nullptr;

		if ( signal_val == SIGTERM || signal_val == SIGINT )
			// We received a signal while processing the
			// current packet and its related events.
			// Should we put the signal handling into an IOSource?
			zeek_terminate_loop("received termination signal");

		if ( ! reading_traces )
			// Check whether we have timers scheduled for
			// the future on which we need to wait.
			have_pending_timers = timer_mgr->Size() > 0;

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

	// Get the final statistics now, and not when net_finish() is
	// called, since that might happen quite a bit in the future
	// due to expiring pending timers, and we don't want to ding
	// for any packets dropped beyond this point.
	net_get_final_stats();
	}

void net_get_final_stats()
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

void net_finish(int drain_events)
	{
	set_processing_status("TERMINATING", "net_finish");

	if ( drain_events )
		{
		if ( sessions )
			sessions->Drain();

		mgr.Drain();

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

void net_delete()
	{
	set_processing_status("TERMINATING", "net_delete");

	delete sessions;

	for ( int i = 0; i < NUM_ADDR_ANONYMIZATION_METHODS; ++i )
		delete ip_anonymizer[i];
	}

int _processing_suspended = 0;

void net_suspend_processing()
	{
	if ( _processing_suspended == 0 )
		reporter->Info("processing suspended");

	++_processing_suspended;
	}

void net_continue_processing()
	{
	if ( _processing_suspended == 1 )
		{
		reporter->Info("processing continued");
		if ( iosource::PktSrc* ps = iosource_mgr->GetPktSrc() )
			ps->ContinueAfterSuspend();
		}

	--_processing_suspended;
	}
