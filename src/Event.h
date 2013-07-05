// See the file "COPYING" in the main distribution directory for copyright.

#ifndef event_h
#define event_h

#include "EventRegistry.h"
#include "Serializer.h"

#include "analyzer/Tag.h"
#include "analyzer/Analyzer.h"

class EventMgr;

class Event : public BroObj {
public:
	Event(EventHandlerPtr handler, val_list* args,
		SourceID src = SOURCE_LOCAL, analyzer::ID aid = 0,
		TimerMgr* mgr = 0, BroObj* obj = 0);
	~Event();

	void SetNext(Event* n)		{ next_event = n; }
	Event* NextEvent() const	{ return next_event; }

	SourceID Source() const		{ return src; }
	analyzer::ID Analyzer() const	{ return aid; }
	TimerMgr* Mgr() const		{ return mgr; }

	void Describe(ODesc* d) const;

protected:
	friend class EventMgr;

	// This method is protected to make sure that everybody goes through
	// EventMgr::Dispatch().
	void Dispatch(bool no_remote = false)
		{
		if ( event_serializer )
			{
			SerialInfo info(event_serializer);
			event_serializer->Serialize(&info, handler->Name(), args);
			}

		if ( handler->ErrorHandler() )
			reporter->BeginErrorHandler();

		try
			{
			handler->Call(args, no_remote);
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

	EventHandlerPtr handler;
	val_list* args;
	SourceID src;
	analyzer::ID aid;
	TimerMgr* mgr;
	BroObj* obj;
	Event* next_event;
};

extern int num_events_queued;
extern int num_events_dispatched;

class EventMgr : public BroObj {
public:
	EventMgr();
	~EventMgr();

	void QueueEvent(EventHandlerPtr h, val_list* vl,
			SourceID src = SOURCE_LOCAL, analyzer::ID aid = 0,
			TimerMgr* mgr = 0, BroObj* obj = 0)
		{
		if ( h )
			QueueEvent(new Event(h, vl, src, aid, mgr, obj));
		else
			delete_vals(vl);
		}

	void Dispatch();

	void Dispatch(Event* event, bool no_remote = false)
		{
		current_src = event->Source();
		event->Dispatch(no_remote);
		Unref(event);
		}

	void Drain();
	bool IsDraining() const	{ return draining; }

	int HasEvents() const	{ return head != 0; }

	// Returns the source ID of last raised event.
	SourceID CurrentSource() const	{ return current_src; }

	// Returns the ID of the analyzer which raised the last event, or 0 if
	// non-analyzer event.
	analyzer::ID CurrentAnalyzer() const	{ return current_aid; }

	// Returns the timer mgr associated with the last raised event.
	TimerMgr* CurrentTimerMgr() const	{ return current_mgr; }

	int Size() const
		{ return num_events_queued - num_events_dispatched; }

	// Returns a peer record describing the local Bro.
	RecordVal* GetLocalPeerVal();

	void Describe(ODesc* d) const;

protected:
	void QueueEvent(Event* event);

	Event* head;
	Event* tail;
	SourceID current_src;
	analyzer::ID current_aid;
	TimerMgr* current_mgr;
	RecordVal* src_val;
	bool draining;
};

extern EventMgr mgr;

#endif
