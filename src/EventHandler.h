// Capsulates local and remote event handlers.

#pragma once

#include <unordered_set>
#include <string>

#include "zeek/ZeekList.h"
#include "zeek/ZeekArgs.h"
#include "zeek/Type.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(Func, zeek);

namespace zeek {
using FuncPtr = IntrusivePtr<Func>;

class EventHandler {
public:
	explicit EventHandler(std::string name);

	const char* Name()	{ return name.data(); }

	const FuncPtr& GetFunc()
		{ return local; }

	const FuncTypePtr& GetType(bool check_export = true);

	void SetFunc(FuncPtr f);

	void AutoPublish(std::string topic)
		{
		auto_publish.insert(std::move(topic));
		}

	void AutoUnpublish(const std::string& topic)
		{
		auto_publish.erase(topic);
		}

	void Call(zeek::Args* vl, bool no_remote = false);

	// Returns true if there is at least one local or remote handler.
	explicit operator  bool() const;

	void SetUsed()	{ used = true; }
	bool Used()	{ return used; }

	// Handlers marked as error handlers will not be called recursively to
	// avoid infinite loops if they trigger a similar error themselves.
	void SetErrorHandler()	{ error_handler = true; }
	bool ErrorHandler()	{ return error_handler; }

	void SetEnable(bool arg_enable)	{ enabled = arg_enable; }

	// Flags the event as interesting even if there is no body defined. In
	// particular, this will then still pass the event on to plugins.
	void SetGenerateAlways()	{ generate_always = true; }
	bool GenerateAlways()	{ return generate_always; }

private:
	void NewEvent(zeek::Args* vl);	// Raise new_event() meta event.

	std::string name;
	FuncPtr local;
	FuncTypePtr type;
	bool used;		// this handler is indeed used somewhere
	bool enabled;
	bool error_handler;	// this handler reports error messages.
	bool generate_always;

	std::unordered_set<std::string> auto_publish;
};

// Encapsulates a ptr to an event handler to overload the boolean operator.
class EventHandlerPtr {
public:
	EventHandlerPtr(EventHandler* p = nullptr)		{ handler = p; }
	EventHandlerPtr(const EventHandlerPtr& h)	{ handler = h.handler; }

	const EventHandlerPtr& operator=(EventHandler* p)
		{ handler = p; return *this; }
	const EventHandlerPtr& operator=(const EventHandlerPtr& h)
		{ handler = h.handler; return *this; }

	bool operator==(const EventHandlerPtr& h) const
		{ return handler == h.handler; }

	EventHandler* Ptr()	{ return handler; }

	explicit operator bool() const	{ return handler && *handler; }
	EventHandler* operator->()	{ return handler; }
	const EventHandler* operator->() const	{ return handler; }

private:
	EventHandler* handler;
};

} // namespace zeek
