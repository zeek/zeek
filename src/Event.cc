// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include "Event.h"
#include "Func.h"
#include "NetVar.h"
#include "Trigger.h"

EventMgr mgr;

int num_events_queued = 0;
int num_events_dispatched = 0;

Event::Event(EventHandlerPtr arg_handler, val_list* arg_args,
		SourceID arg_src, analyzer::ID arg_aid, TimerMgr* arg_mgr,
		BroObj* arg_obj)
	{
	handler = arg_handler;
	args = arg_args;
	src = arg_src;
	mgr = arg_mgr ? arg_mgr : timer_mgr; // default is global
	aid = arg_aid;
	obj = arg_obj;

	if ( obj )
		Ref(obj);

	next_event = 0;
	}

Event::~Event()
	{
	// We don't Unref() the individual arguments by using delete_vals()
	// here, because Func::Call already did that.
	delete args;
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
	describe_vals(args, d);
	if ( ! d->IsBinary() )
		d->Add("(");
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

void EventMgr::QueueEvent(Event* event)
	{
	if ( ! head )
		head = tail = event;
	else
		{
		tail->SetNext(event);
		tail = event;
		}

	++num_events_queued;
	}

void EventMgr::Dispatch()
	{
	if ( ! head )
		reporter->InternalError("EventMgr::Dispatch underflow");

	Event* current = head;

	head = head->NextEvent();
	if ( ! head )
		tail = head;

	current_src = current->Source();
	current_mgr = current->Mgr();
	current_aid = current->Analyzer();
	current->Dispatch();
	Unref(current);

	++num_events_dispatched;
	}

void EventMgr::Drain()
	{
	if ( event_queue_flush_point )
		QueueEvent(event_queue_flush_point, new val_list());

	SegmentProfiler(segment_logger, "draining-events");

	draining = true;
	while ( head )
		Dispatch();

	// Note: we might eventually need a general way to specify things to
	// do after draining events.
	draining = false;

	// We evaluate Triggers here. While this is somewhat unrelated to event
	// processing, we ensure that it's done at a regular basis by checking
	// them here.
	Trigger::EvaluatePending();
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

RecordVal* EventMgr::GetLocalPeerVal()
	{
	if ( ! src_val )
		{
		src_val = new RecordVal(peer);
		src_val->Assign(0, new Val(0, TYPE_COUNT));
		src_val->Assign(1, new AddrVal("127.0.0.1"));
		src_val->Assign(2, new PortVal(0));
		src_val->Assign(3, new Val(true, TYPE_BOOL));

		Ref(peer_description);
		src_val->Assign(4, peer_description);
		src_val->Assign(5, 0);	// class (optional).
		}

	return src_val;
	}
