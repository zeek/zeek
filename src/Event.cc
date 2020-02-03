// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "Event.h"
#include "Desc.h"
#include "Func.h"
#include "NetVar.h"
#include "Trigger.h"
#include "Val.h"
#include "plugin/Manager.h"
#include "iosource/Manager.h"
#include "iosource/PktSrc.h"
#include "Net.h"

EventMgr mgr;

uint64_t num_events_queued = 0;
uint64_t num_events_dispatched = 0;

Event::Event(EventHandlerPtr arg_handler, val_list arg_args,
		SourceID arg_src, analyzer::ID arg_aid, TimerMgr* arg_mgr,
		BroObj* arg_obj)
	: handler(arg_handler),
	  args(std::move(arg_args)),
	  src(arg_src),
	  aid(arg_aid),
	  mgr(arg_mgr ? arg_mgr : timer_mgr),
	  obj(arg_obj),
	  next_event(nullptr)
	{
	if ( obj )
		Ref(obj);
	}

Event::Event(EventHandlerPtr arg_handler, val_list* arg_args,
		SourceID arg_src, analyzer::ID arg_aid, TimerMgr* arg_mgr,
		BroObj* arg_obj)
	: Event(arg_handler, std::move(*arg_args), arg_src, arg_aid, arg_mgr, arg_obj)
	{
	delete arg_args;
	}

void Event::Describe(ODesc* d) const
	{
	if ( d->IsReadable() )
		d->AddSP("event");

	int s = d->IsShort();
	d->SetShort();
//	handler->Describe(d);
	d->SetShort(s);

	if ( ! d->IsBinary() )
		d->Add("(");
	describe_vals(&args, d);
	if ( ! d->IsBinary() )
		d->Add("(");
	}

void Event::Dispatch(bool no_remote)
	{
	if ( src == SOURCE_BROKER )
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
	head = tail = 0;
	current_src = SOURCE_LOCAL;
	current_mgr = timer_mgr;
	current_aid = 0;
	src_val = 0;
	draining = 0;
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

void EventMgr::QueueEvent(const EventHandlerPtr &h, val_list vl,
			  SourceID src, analyzer::ID aid,
			  TimerMgr* mgr, BroObj* obj)
	{
	if ( h )
		QueueEvent(new Event(h, std::move(vl), src, aid, mgr, obj));
	else
		{
		for ( const auto& v : vl )
			Unref(v);
		}
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

	++num_events_queued;
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
		QueueEventFast(event_queue_flush_point, val_list{});

	SegmentProfiler prof(segment_logger, "draining-events");

	PLUGIN_HOOK_VOID(HOOK_DRAIN_EVENTS, HookDrainEvents());

	draining = true;

	// Past Bro versions drained as long as there events, including when
	// a handler queued new events during its execution. This could lead
	// to endless loops in case a handler kept triggering its own event.
	// We now limit this to just a couple of rounds. We do more than
	// just one round to make it less likley to break existing scripts
	// that expect the old behavior to trigger something quickly.

	for ( int round = 0; head && round < 2; round++ )
		{
		Event* current = head;
		head = 0;
		tail = 0;

		while ( current )
			{
			Event* next = current->NextEvent();

			current_src = current->Source();
			current_mgr = current->Mgr();
			current_aid = current->Analyzer();
			current->Dispatch();
			Unref(current);

			++num_events_dispatched;
			current = next;
			}
		}

	// Note: we might eventually need a general way to specify things to
	// do after draining events.
	draining = false;

	// Make sure all of the triggers get processed every time the events
	// drain.
	trigger_mgr->Process();
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
	if ( ! pkt_src || ! pkt_src->IsOpen() || reading_live )
		net_update_time(current_time());

	queue_flare.Extinguish();

	// While it semes like the most logical thing to do, we dont want
	// to call Drain() as part of this method. It will get called at
	// the end of net_run after all of the sources have been processed
	// and had the opportunity to spawn new events. We could use
	// iosource_mgr->Wakeup() instead of making EventMgr an IOSource,
	// but then we couldn't update the time above and nothing would
	// drive it forward.
	}

void EventMgr::InitPostScript()
	{
	iosource_mgr->Register(this, true, false);
	iosource_mgr->RegisterFd(queue_flare.FD(), this);
	}
