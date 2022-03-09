// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Event.h"

#include "zeek/zeek-config.h"

#include "zeek/Desc.h"
#include "zeek/Func.h"
#include "zeek/NetVar.h"
#include "zeek/RunState.h"
#include "zeek/Trace.h"
#include "zeek/Trigger.h"
#include "zeek/Val.h"
#include "zeek/iosource/Manager.h"
#include "zeek/iosource/PktSrc.h"
#include "zeek/plugin/Manager.h"

#include "opentelemetry/common/attribute_value.h"
#include "opentelemetry/trace/provider.h"

zeek::EventMgr zeek::event_mgr;
zeek::EventMgr& mgr = zeek::event_mgr;

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
	auto span = zeek::trace::StartSpanForAsync("Event::Dispatch", span_context);
	if ( span->IsRecording() )
		{
		span->SetAttribute("no_remote", no_remote);
		AddDetailsToSpan(span);
		}

	auto scope = zeek::trace::tracer->WithActiveSpan(span);

	if ( src == util::detail::SOURCE_BROKER )
		{
		no_remote = true;
		if ( span->IsRecording() )
			span->SetAttribute("no_remote_override", no_remote);
		}

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

void Event::AddDetailsToSpan(opentelemetry::nostd::shared_ptr<opentelemetry::v1::trace::Span> span)
	{
	if ( src )
		span->SetAttribute("source", (unsigned int)src); // XXX is this cast right?

	span->SetAttribute("analyzer_id",
	                   aid); // XXX is there a way to lookup the analyzer name from this?
	span->SetAttribute("handler", handler->Name());

	std::vector<opentelemetry::nostd::string_view> arg_names;
	for ( const auto& item : args )
		{
		auto name = item->GetType()->GetName();
		// Sometimes GetName() can return an empty string like with the boolean on get_file_handle
		if ( name.empty() )
			name = "(no name, tag " + std::to_string(item->GetType()->Tag()) + ")";
		arg_names.push_back(name);
		}
	span->SetAttribute("arg_types", opentelemetry::common::AttributeValue(arg_names));

	std::vector<opentelemetry::nostd::string_view> args_formatted;
	for ( const auto& item : args )
		{
		std::string* str = new std::string(item->ToJSON()->ToStdString());
		args_formatted.push_back(*str);
		}
	span->SetAttribute("args", opentelemetry::common::AttributeValue(args_formatted));
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
	assert(tracer);

	auto span = tracer->StartSpan("EventMgr::QueueEvent");
	auto scope = tracer->WithActiveSpan(span);

	event->span_context = span->GetContext();

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
	auto span = tracer->StartSpan("EventMgr::Dispatch");
	auto scope = tracer->WithActiveSpan(span);

	current_src = event->Source();
	event->Dispatch(no_remote);
	Unref(event);
	}

void EventMgr::Drain()
	{
	auto span = tracer->StartSpan("EventMgr::Drain");
	auto scope = tracer->WithActiveSpan(span);

	if ( event_queue_flush_point )
		Enqueue(event_queue_flush_point, Args{});

	detail::SegmentProfiler prof(detail::segment_logger, "draining-events");

	PLUGIN_HOOK_VOID(HOOK_DRAIN_EVENTS, HookDrainEvents());

	draining = true;

	// Past Zeek versions drained as long as there events, including when
	// a handler queued new events during its execution. This could lead
	// to endless loops in case a handler kept triggering its own event.
	// We now limit this to just a couple of rounds. We do more than
	// just one round to make it less likley to break existing scripts
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
