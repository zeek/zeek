// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

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

#include "NetVar.h"
#include "Sessions.h"
#include "Event.h"
#include "Timer.h"
#include "Var.h"
#include "Reporter.h"
#include "Net.h"
#include "Anon.h"
#include "Serializer.h"
#include "PacketDumper.h"

extern "C" {
#include "setsignal.h"
};

extern "C" {
extern int select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
}

PList(PktSrc) pkt_srcs;

// FIXME: We should really merge PktDumper and PacketDumper.
PktDumper* pkt_dumper = 0;

int reading_live = 0;
int reading_traces = 0;
int have_pending_timers = 0;
double pseudo_realtime = 0.0;
bool using_communication = false;

double network_time = 0.0;	// time according to last packet timestamp
				// (or current time)
double processing_start_time = 0.0;	// time started working on current pkt
double bro_start_time = 0.0; // time Bro started.
double bro_start_network_time;	// timestamp of first packet
double last_watchdog_proc_time = 0.0;	// value of above during last watchdog
bool terminating = false;	// whether we're done reading and finishing up

const struct pcap_pkthdr* current_hdr = 0;
const u_char* current_pkt = 0;
int current_dispatched = 0;
int current_hdr_size = 0;
double current_timestamp = 0.0;
PktSrc* current_pktsrc = 0;
IOSource* current_iosrc;

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

			if ( current_hdr )
				{
				if ( ! pkt_dumper )
					{
					// We aren't dumping packets; however,
					// saving the packet which caused the
					// watchdog to trigger may be helpful,
					// so we'll save that one nevertheless.
					pkt_dumper = new PktDumper("watchdog-pkt.pcap");
					if ( pkt_dumper->IsError() )
						{
						reporter->Error("watchdog: can't open watchdog-pkt.pcap for writing\n");
						delete pkt_dumper;
						pkt_dumper = 0;
						}
					}

				if ( pkt_dumper )
					pkt_dumper->Dump(current_hdr, current_pkt);
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

void net_init(name_list& interfaces, name_list& readfiles,
	      name_list& netflows, name_list& flowfiles,
	        const char* writefile, const char* filter,
			const char* secondary_filter, int do_watchdog)
	{
	init_net_var();

	if ( readfiles.length() > 0 || flowfiles.length() > 0 )
		{
		reading_live = pseudo_realtime > 0.0;
		reading_traces = 1;

		for ( int i = 0; i < readfiles.length(); ++i )
			{
			PktFileSrc* ps = new PktFileSrc(readfiles[i], filter);

			if ( ! ps->IsOpen() )
				reporter->FatalError("%s: problem with trace file %s - %s\n",
					prog, readfiles[i], ps->ErrorMsg());
			else
				{
				pkt_srcs.append(ps);
				io_sources.Register(ps);
				}

			if ( secondary_filter )
				{
				// We use a second PktFileSrc for the
				// secondary path.
				PktFileSrc* ps = new PktFileSrc(readfiles[i],
							secondary_filter,
							TYPE_FILTER_SECONDARY);

				if ( ! ps->IsOpen() )
					reporter->FatalError("%s: problem with trace file %s - %s\n",
						prog, readfiles[i],
						ps->ErrorMsg());
				else
					{
					pkt_srcs.append(ps);
					io_sources.Register(ps);
					}

				ps->AddSecondaryTablePrograms();
				}
			}

		for ( int i = 0; i < flowfiles.length(); ++i )
			{
			FlowFileSrc* fs = new FlowFileSrc(flowfiles[i]);

			if ( ! fs->IsOpen() )
				reporter->FatalError("%s: problem with netflow file %s - %s\n",
					prog, flowfiles[i], fs->ErrorMsg());
			else
				{
				io_sources.Register(fs);
				}
			}
		}

	else if ((interfaces.length() > 0 || netflows.length() > 0))
		{
		reading_live = 1;
		reading_traces = 0;

		for ( int i = 0; i < interfaces.length(); ++i )
			{
			PktSrc* ps;
			ps = new PktInterfaceSrc(interfaces[i], filter);

			if ( ! ps->IsOpen() )
				reporter->FatalError("%s: problem with interface %s - %s\n",
					prog, interfaces[i], ps->ErrorMsg());
			else
				{
				pkt_srcs.append(ps);
				io_sources.Register(ps);
				}

			if ( secondary_filter )
				{
				PktSrc* ps;
				ps = new PktInterfaceSrc(interfaces[i],
					filter, TYPE_FILTER_SECONDARY);

				if ( ! ps->IsOpen() )
					reporter->Error("%s: problem with interface %s - %s\n",
						prog, interfaces[i],
						ps->ErrorMsg());
				else
					{
					pkt_srcs.append(ps);
					io_sources.Register(ps);
					}

				ps->AddSecondaryTablePrograms();
				}
			}

		for ( int i = 0; i < netflows.length(); ++i )
			{
			FlowSocketSrc* fs = new FlowSocketSrc(netflows[i]);

			if ( ! fs->IsOpen() )
				{
				reporter->Error("%s: problem with netflow socket %s - %s\n",
					prog, netflows[i], fs->ErrorMsg());
				delete fs;
				}

			else
				io_sources.Register(fs);
			}

		}

	else
		// have_pending_timers = 1, possibly.  We don't set
		// that here, though, because at this point we don't know
		// whether the user's bro_init() event will indeed set
		// a timer.
		reading_traces = reading_live = 0;

	if ( writefile )
		{
		// ### This will fail horribly if there are multiple
		// interfaces with different-lengthed media.
		pkt_dumper = new PktDumper(writefile);
		if ( pkt_dumper->IsError() )
			reporter->FatalError("%s: can't open write file \"%s\" - %s\n",
				prog, writefile, pkt_dumper->ErrorMsg());

		ID* id = global_scope()->Lookup("trace_output_file");
		if ( ! id )
			reporter->Error("trace_output_file not defined in bro.init");
		else
			id->SetVal(new StringVal(writefile));
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

void expire_timers(PktSrc* src_ps)
	{
	SegmentProfiler(segment_logger, "expiring-timers");
	TimerMgr* tmgr =
		src_ps ? sessions->LookupTimerMgr(src_ps->GetCurrentTag())
			: timer_mgr;

	current_dispatched +=
		tmgr->Advance(network_time,
				max_timer_expires - current_dispatched);
	}

void net_packet_dispatch(double t, const struct pcap_pkthdr* hdr,
			const u_char* pkt, int hdr_size,
			PktSrc* src_ps)
	{
	if ( ! bro_start_network_time )
		bro_start_network_time = t;

	TimerMgr* tmgr =
		src_ps ? sessions->LookupTimerMgr(src_ps->GetCurrentTag())
			: timer_mgr;

	// network_time never goes back.
	network_time = tmgr->Time() < t ? t : tmgr->Time();

	current_pktsrc = src_ps;
	current_iosrc = src_ps;
	processing_start_time = t;

	expire_timers(src_ps);

	SegmentProfiler* sp = 0;

	if ( load_sample )
		{
		static uint32 load_freq = 0;

		if ( load_freq == 0 )
			load_freq = uint32(0xffffffff) / uint32(load_sample_freq);

		if ( uint32(bro_random() & 0xffffffff) < load_freq )
			{
			// Drain the queued timer events so they're not
			// charged against this sample.
			mgr.Drain();

			sample_logger = new SampleLogger();
			sp = new SegmentProfiler(sample_logger, "load-samp");
			}
		}

	sessions->DispatchPacket(t, hdr, pkt, hdr_size, src_ps);
	mgr.Drain();

	if ( sp )
		{
		delete sp;
		delete sample_logger;
		sample_logger = 0;
		}

	processing_start_time = 0.0;	// = "we're not processing now"
	current_dispatched = 0;
	current_iosrc = 0;
	current_pktsrc = 0;
	}

void net_run()
	{
	set_processing_status("RUNNING", "net_run");

	while ( io_sources.Size() ||
		(BifConst::exit_only_after_terminate && ! terminating) )
		{
		double ts;
		IOSource* src = io_sources.FindSoonest(&ts);

#ifdef DEBUG
		static int loop_counter = 0;

		// If no source is ready, we log only every 100th cycle,
		// starting with the first.
		if ( src || loop_counter++ % 100 == 0 )
			{
			DBG_LOG(DBG_MAINLOOP, "realtime=%.6f iosrc=%s ts=%.6f",
					current_time(), src ? src->Tag() : "<all dry>", src ? ts : -1);

			if ( src )
				loop_counter = 0;
			}
#endif
		current_iosrc = src;

		if ( src )
			src->Process();	// which will call net_packet_dispatch()

		else if ( reading_live && ! pseudo_realtime)
			{ // live but  no source is currently active
			double ct = current_time();
			if ( ! net_is_processing_suspended() )
				{
				// Take advantage of the lull to get up to
				// date on timers and events.
				network_time = ct;
				expire_timers();
				usleep(1); // Just yield.
				}
			}

		else if ( (have_pending_timers || using_communication) &&
			  ! pseudo_realtime )
			{
			// Take advantage of the lull to get up to
			// date on timers and events.  Because we only
			// have timers as sources, going to sleep here
			// doesn't risk blocking on other inputs.
			network_time = current_time();
			expire_timers();

			// Avoid busy-waiting - pause for 100 ms.
			// We pick a sleep value of 100 msec that buys
			// us a lot of idle time, but doesn't delay near-term
			// timers too much.  (Delaying them somewhat is okay,
			// since Bro timers are not high-precision anyway.)
			if ( ! using_communication )
				usleep(100000);
			else
				usleep(1000);

			// Flawfinder says about usleep:
			//
			// This C routine is considered obsolete (as opposed
			// to the shell command by the same name).   The
			// interaction of this function with SIGALRM and
			// other timer functions such as sleep(), alarm(),
			// setitimer(), and nanosleep() is unspecified.
			// Use nanosleep(2) or setitimer(2) instead.
			}

		mgr.Drain();

		processing_start_time = 0.0;	// = "we're not processing now"
		current_dispatched = 0;
		current_iosrc = 0;

		// Should we put the signal handling into an IOSource?
		extern void termination_signal();

		if ( signal_val == SIGTERM || signal_val == SIGINT )
			// We received a signal while processing the
			// current packet and its related events.
			termination_signal();

#ifdef DEBUG_COMMUNICATION
		if ( signal_val == SIGPROF && remote_serializer )
			remote_serializer->DumpDebugData();
#endif

		if ( ! reading_traces )
			// Check whether we have timers scheduled for
			// the future on which we need to wait.
			have_pending_timers = timer_mgr->Size() > 0;
		}

	// Get the final statistics now, and not when net_finish() is
	// called, since that might happen quite a bit in the future
	// due to expiring pending timers, and we don't want to ding
	// for any packets dropped beyond this point.
	net_get_final_stats();
	}

void net_get_final_stats()
	{
	loop_over_list(pkt_srcs, i)
		{
		PktSrc* ps = pkt_srcs[i];

		if ( ps->IsLive() )
			{
			struct PktSrc::Stats s;
			ps->Statistics(&s);
			reporter->Info("%d packets received on interface %s, %d dropped\n",
					s.received, ps->Interface(), s.dropped);
			}
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

	delete pkt_dumper;

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

// net_packet_match
//
// Description:
//  - Checks if a packet matches a filter. It just wraps up a call to
//    [pcap.h's] bpf_filter().
//
// Inputs:
//  - fp: a BPF-compiled filter
//  - pkt: a pointer to the packet
//  - len: the original packet length
//  - caplen: the captured packet length. This is pkt length
//
// Output:
//  - return: 1 if the packet matches the filter, 0 otherwise

int net_packet_match(BPF_Program* fp, const u_char* pkt,
		     u_int len, u_int caplen)
	{
	// NOTE: I don't like too much un-const'ing the pkt variable.
	return bpf_filter(fp->GetProgram()->bf_insns, (u_char*) pkt, len, caplen);
	}


int _processing_suspended = 0;

static double suspend_start = 0;

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
		loop_over_list(pkt_srcs, i)
			pkt_srcs[i]->ContinueAfterSuspend();
		}

	--_processing_suspended;
	}
