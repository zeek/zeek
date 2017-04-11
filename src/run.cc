#include <cstdio>
#include <csignal>
#include <chrono>
#include <limits>

#include <caf/actor_system.hpp>
#include <caf/actor_system_config.hpp>
#include <caf/io/middleman.hpp>

#include "run.h"
#include "Event.h"
#include "Net.h"
#include "iosource/Manager.h"
#include "iosource/PktSrc.h"
#include "threading/Manager.h"
#include "input/Manager.h"
#include "DNS_Mgr.h"

using timercheck_atom = caf::atom_constant<caf::atom("timercheck")>;
using heartbeat_atom = caf::atom_constant<caf::atom("heartbeat")>;

run_state::~run_state()
	{
	signal_handler->Shutdown();
	}

static void close(runloop_actor* runloop)
	{
	DBG_LOG(DBG_MAINLOOP, "closing CAF run loop");

	for ( auto src : iosource_mgr->GetSources() )
		src->Stop();

	runloop->quit();
	}

static void schedule_timer_expiry(runloop_actor* runloop)
	{
	if ( ! have_pending_timers )
		return;

	auto next = timer_mgr->Next();

	if ( ! next )
		return;

	if ( next->timercheck_sent )
		return;

	auto expire_time = next->Time();
	auto dt = expire_time - network_time;

	if ( dt < 0 )
		dt = 0;

	auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(
	                    std::chrono::duration<double>(dt));
	runloop->delayed_send(runloop, duration, timercheck_atom::value);
	next->timercheck_sent = true;
	DBG_LOG(DBG_MAINLOOP, "next timer check in %f (%s)", dt,
	        timer_type_to_string(next->Type()));
	}

static void schedule_heartbeat(runloop_actor* runloop)
	{
	auto dt = BifConst::Threading::heartbeat_interval;
	auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(
	                    std::chrono::duration<double>(dt));
	runloop->delayed_send(runloop, duration, heartbeat_atom::value);
	}

static void process(runloop_actor* runloop)
	{
	auto src = iosource_mgr->SoonestSource();
	current_iosrc = src;

	bool communication_enabled = using_communication;

#ifdef ENABLE_BROKER
	communication_enabled |= broker_mgr->Enabled();
#endif

	if ( src )
		{
		DBG_LOG(DBG_MAINLOOP, "process %s", src->Tag());
		src->Process();
		}
	else
		{
		DBG_LOG(DBG_MAINLOOP, "process nothing");

		if ( ! pseudo_realtime )
			{
			if ( (reading_live && ! net_is_processing_suspended()) ||
			     have_pending_timers || communication_enabled )
				{
				net_update_time(current_time());
				expire_timers();
				}
			}
		}

	mgr.Drain();
	processing_start_time = 0.0;	// = "we're not processing now"
	current_dispatched = 0;
	current_iosrc = 0;
	runloop->state.events.clear();
	iosource_mgr->RemoveDrySources();

	if ( ! reading_traces )
		// Check whether we have timers scheduled for
		// the future on which we need to wait.
		have_pending_timers = timer_mgr->Size() > 0;

	schedule_timer_expiry(runloop);

	// In case of signals, should be fine to not clear the signal flare
	// since we always just terminate.  If that becomes untrue, then
	// likely need switch to using a thread/signal-safe signaling mechanism
	// instead of a flare.
	if ( signal_val == SIGTERM || signal_val == SIGINT )
		termination_signal();

#ifdef DEBUG_COMMUNICATION
	if ( signal_val == SIGPROF && remote_serializer )
		remote_serializer->DumpDebugData();
#endif

	if ( iosource_mgr->Size() )
		return;

	if ( BifConst::exit_only_after_terminate && ! terminating )
		return;

	close(runloop);
	}

static caf::behavior run_behavior(runloop_actor* self)
	{
	bool throttle_polling = ! getenv("BRO_UNTHROTTLE_POLLING");
	auto POLL_FREQUENCY = throttle_polling ? 25 : 1;
	// Hook the source into CAF's I/O loop.
	runloop_backend(self).add_cycle_listener(self);

	for ( auto src : iosource_mgr->GetSources() )
		src->Start(self);

	self->state.signal_handler = new FdEventHandler(nullptr, self,
	                                                signal_flare->FD());
	self->state.signal_handler->EnableReadEvents();

	schedule_timer_expiry(self);

	// @todo: the heartbeat here is being used for both threading and for
	// processing standalone scripts that just call events over and over,
	// absent any pcap source (e.g. see core/recursive-event.bro unit test).
	// In the later case, the heartbeat is the tick rate at which events
	// get dispatched.  The following should probably be done:
	// 1) have a tick rate independent of the threading heartbeat rate
	//    (e.g. the old runloop uses .1 seconds for ticks and 1 second for
	//    heartbeats)
	// 2) could allow user to define the tick rate
	// 3) only actually use the tick rate when there's no pcap sources?
	// 4) like the old runloop, could consider threading::Manager ineligible
	//    for processing (i.e. don't even send the heartbeats), until it
	//    has added a thread (i.e. the idle state has been toggled off).
	//    Doubt this point really matters much, just noting differences between
	//    runloops.
	schedule_heartbeat(self);

	return {
		[=](IOEvent ev)
		    {
			self->state.events.emplace_back(ev);

			if ( ev.source == dns_mgr )
				// @todo: this is really just a stopgap to re-use existing
				// async DNS code.  Would be better to have DNS queries
				// running independently and notifying the run loop when
				// when results or timeout events are ready to process.
				dynamic_cast<DNS_Mgr*>(ev.source)->has_io = true;
			},
		[=](caf::io_cycle_atom)
		    {
			auto& events = self->state.events;
			// @todo: use proper logging for debug messages
			DBG_LOG(DBG_MAINLOOP, "IO cycle events: %d", (int)events.size());

			for ( auto& ev : events )
				{
				if ( ev.source )
					{
					DBG_LOG(DBG_MAINLOOP, "\tfd: %d, source: %s",
					        ev.fd, ev.source->Tag());
					}
				else
					{
					DBG_LOG(DBG_MAINLOOP, "\tfd: %d, source: <no source>",
					        ev.fd);
					}
				}

			for ( auto i = 0; i < POLL_FREQUENCY; ++i )
				process(self);
			},
		[=](timercheck_atom)
		    {
			DBG_LOG(DBG_MAINLOOP, "timercheck");
			// An io cycle will automatically be triggered.
			},
		[=](heartbeat_atom)
		    {
			DBG_LOG(DBG_MAINLOOP, "heartbeat");
			schedule_heartbeat(self);

			if ( self->state.events.empty() )
				// Update time now, so that threading::Manager correctly reports
				// it is in need of processing.
				net_update_time(current_time());

			// An io cycle will automatically be triggered.
			},
		[=](caf::close_atom)
		    {
			close(self);
			}
		};
	}

void run()
	{
	DBG_LOG(DBG_MAINLOOP, "starting CAF run loop");
	caf::actor_system_config config;
	config.load<caf::io::middleman>();
	caf::actor_system sys{config};
	sys.middleman().spawn_broker(run_behavior);
	sys.await_all_actors_done();
	DBG_LOG(DBG_MAINLOOP, "ended CAF run loop");
	}
