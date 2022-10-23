// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Event.h"

#include "zeek/zeek-config.h"

#include "zeek/Desc.h"
#include "zeek/Func.h"
#include "zeek/NetVar.h"
#include "zeek/RunState.h"
#include "zeek/Trigger.h"
#include "zeek/Val.h"
#include "zeek/iosource/Manager.h"
#include "zeek/iosource/PktSrc.h"
#include "zeek/plugin/Manager.h"

zeek::EventMgr zeek::event_mgr;

namespace zeek
	{

Event::Event(EventHandlerPtr arg_handler, zeek::Args arg_args, util::detail::SourceID arg_src,
             analyzer::ID arg_aid, Obj* arg_obj)
	: handler(arg_handler), args(std::move(arg_args)), src(arg_src), aid(arg_aid), obj(arg_obj),
	  next_event(nullptr)
	{
	if ( obj )
		Ref(obj);
	}

void Event::Describe(ODesc* d) const
	{
	if ( d->IsReadable() )
		d->AddSP("event");

	bool s = d->IsShort();
	d->SetShort(s);

	if ( ! d->IsBinary() )
		d->Add("(");
	describe_vals(args, d);
	if ( ! d->IsBinary() )
		d->Add("(");
	}

void Event::Dispatch(bool no_remote)
	{
	if ( src == util::detail::SOURCE_BROKER )
		no_remote = true;

	if ( handler->ErrorHandler() )
		reporter->BeginErrorHandler();

	try
		{
		handler->Call(&args, no_remote);
		}

	catch ( InterpreterException& e )
		{
		// Already reported.
		}

	if ( obj )
		// obj->EventDone();
		Unref(obj);

	if ( handler->ErrorHandler() )
		reporter->EndErrorHandler();
	}

EventMgr::EventMgr()
	{
	head = tail = nullptr;
	current_src = util::detail::SOURCE_LOCAL;
	current_aid = 0;
	src_val = nullptr;
	draining = false;
	}

EventMgr::~EventMgr()
	{
	while ( head )
		{
		Event* n = head->NextEvent();
		Unref(head);
		head = n;
		}

	Unref(src_val);
	}

void EventMgr::Enqueue(const EventHandlerPtr& h, Args vl, util::detail::SourceID src,
                       analyzer::ID aid, Obj* obj)
	{
	QueueEvent(new Event(h, std::move(vl), src, aid, obj));
	}

void EventMgr::QueueEvent(Event* event)
	{
	bool done = PLUGIN_HOOK_WITH_RESULT(HOOK_QUEUE_EVENT, HookQueueEvent(event), false);

	if ( done )
		return;

	if ( ! head )
		{
		head = tail = event;
		queue_flare.Fire();
		}
	else
		{
		tail->SetNext(event);
		tail = event;
		}

	++event_mgr.num_events_queued;
	}

void EventMgr::Dispatch(Event* event, bool no_remote)
	{
	current_src = event->Source();
	event->Dispatch(no_remote);
	Unref(event);
	}

void EventMgr::Drain()
	{
	if ( event_queue_flush_point )
		Enqueue(event_queue_flush_point, Args{});

	detail::SegmentProfiler prof(detail::segment_logger, "draining-events");

	PLUGIN_HOOK_VOID(HOOK_DRAIN_EVENTS, HookDrainEvents());

	draining = true;

	// Past Zeek versions drained as long as there events, including when
	// a handler queued new events during its execution. This could lead
	// to endless loops in case a handler kept triggering its own event.
	// We now limit this to just a couple of rounds. We do more than
	// just one round to make it less likely to break existing scripts
	// that expect the old behavior to trigger something quickly.

	for ( int round = 0; head && round < 2; round++ )
		{
		Event* current = head;
		head = nullptr;
		tail = nullptr;

		while ( current )
			{
			Event* next = current->NextEvent();

			current_src = current->Source();
			current_aid = current->Analyzer();
			current->Dispatch();
			Unref(current);

			++event_mgr.num_events_dispatched;
			current = next;
			}
		}

	// Note: we might eventually need a general way to specify things to
	// do after draining events.
	draining = false;

	// Make sure all of the triggers get processed every time the events
	// drain.
	detail::trigger_mgr->Process();
	}

void EventMgr::Describe(ODesc* d) const
	{
	int n = 0;
	Event* e;
	for ( e = head; e; e = e->NextEvent() )
		++n;

	d->AddCount(n);

	for ( e = head; e; e = e->NextEvent() )
		{
		e->Describe(d);
		d->NL();
		}
	}

void EventMgr::Process()
	{
	// If we don't have a source, or the source is closed, or we're
	// reading live (which includes pseudo-realtime), advance the time
	// here to the current time since otherwise it won't move forward.
	iosource::PktSrc* pkt_src = iosource_mgr->GetPktSrc();
	if ( ! pkt_src || ! pkt_src->IsOpen() || run_state::reading_live )
		run_state::detail::update_network_time(util::current_time());

	queue_flare.Extinguish();

	// While it semes like the most logical thing to do, we dont want
	// to call Drain() as part of this method. It will get called at
	// the end of net_run after all of the sources have been processed
	// and had the opportunity to spawn new events. We could use
	// zeek::iosource_mgr->Wakeup() instead of making EventMgr an IOSource,
	// but then we couldn't update the time above and nothing would
	// drive it forward.
	}

void EventMgr::InitPostScript()
	{
	iosource_mgr->Register(this, true, false);
	if ( ! iosource_mgr->RegisterFd(queue_flare.FD(), this) )
		reporter->FatalError("Failed to register event manager FD with iosource_mgr");
	}

	} // namespace zeek
