// $Id: EventHandler.h 5911 2008-07-03 22:59:01Z vern $
//
// Capsulates local and remote event handlers.

#ifndef EVENTHANDLER
#define EVENTHANDLER

#include <assert.h>

#include "List.h"
#include "BroList.h"
#include "net_util.h"

class Func;
class FuncType;
class Serializer;
class SerialInfo;
class UnserialInfo;

class EventHandler {
public:
	EventHandler(const char* name);
	~EventHandler();

	const char* Name()	{ return name; }
	Func* LocalHandler()	{ return local; }
	FuncType* FType();

	void SetLocalHandler(Func* f);

	void AddRemoteHandler(SourceID peer);
	void RemoveRemoteHandler(SourceID peer);

	void Call(val_list* vl, bool no_remote = false);

	// Returns true if there is at least one local or remote handler.
	operator  bool() const
		{ return enabled && (local || receivers.length()); }

	void SetUsed()          { used = true; }
	bool Used()             { return used; }

	const char* Group()	{ return group; }
	void SetGroup(const char* arg_group)
				{ group = copy_string(arg_group); }

	void SetEnable(bool arg_enable)	{ enabled = arg_enable; }

	// We don't serialize the handler(s) itself here, but
	// just the reference to it.
	bool Serialize(SerialInfo* info) const;
	static EventHandler* Unserialize(UnserialInfo* info);

private:
	const char* name;
	const char* group;
	Func* local;
	FuncType* type;
	bool used;		// this handler is indeed used somewhere
	bool enabled;

	declare(List, SourceID);
	typedef List(SourceID) receiver_list;
	receiver_list receivers;
};

// Encapsulates a ptr to an event handler to overload the boolean operator.
class EventHandlerPtr {
public:
	EventHandlerPtr(EventHandler* p = 0)		{ handler = p; }
	EventHandlerPtr(const EventHandlerPtr& h)	{ handler = h.handler; }

	const EventHandlerPtr& operator=(EventHandler* p)
		{ handler = p; return *this; }
	const EventHandlerPtr& operator=(const EventHandlerPtr& h)
		{ handler = h.handler; return *this; }

	EventHandler* Ptr()	{ return handler; }

	operator bool() const	{ return handler && *handler; }
	EventHandler* operator->()	{ return handler; }
	const EventHandler* operator->() const	{ return handler; }

private:
	EventHandler* handler;
};

#endif
