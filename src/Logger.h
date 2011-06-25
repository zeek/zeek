// See the file "COPYING" in the main distribution directory for copyright.

#ifndef logger_h
#define logger_h

#include <stdarg.h>

#include <list>
#include <utility>

#include "util.h"
#include "net_util.h"
#include "EventHandler.h"

class Connection;
class Location;

class Logger {
public:
	Logger();
	~Logger();

	// Report an informational message, nothing that needs specific
	// attention.
	void Message(const char* fmt, ...);

	// Report a warning that may indicate a problem.
	void Warning(const char* fmt, ...);

	// Report a non-fatal error. Processing proceeds normally after the error
	// has been reported.
	void Error(const char* fmt, ...);

	// Returns the number of errors reported so far.
	int Errors()	{ return errors; }

	// Report a fatal error. Bro will terminate after the message has been
	// reported.
	void FatalError(const char* fmt, ...);

	// Report a fatal error. Bro will terminate after the message has been
	// reported and always generate a core dump.
	void FatalErrorWithCore(const char* fmt, ...);

	// Report a traffic weirdness, i.e., an unexpected protocol situation
	// that may lead to incorrectly processing a connnection.
	void Weird(const char* name);	// Raises net_weird().
	void Weird(Connection* conn, const char* name, const char* addl = "");	// Raises conn_weird().
	void Weird(Val* conn_val, const char* name, const char* addl = "");	// Raises conn_weird().
	void Weird(addr_type orig, addr_type resp, const char* name);	// Raises flow_weird().

	// Syslog a message. This methods does nothing if we're running offline
	// from a trace.
	void Syslog(const char* fmt, ...);

	// Report about a potential internal problem. Bro will continue normally.
	void InternalWarning(const char* fmt, ...);

	// Report an internal program error. Bro will terminate with a core dump
	// after the message has been reported.
	void InternalError(const char* fmt, ...);

	// Toggle whether non-fatal messages should be reported through the
	// scripting layer rather on standard output. Fatal errors are always
	// reported via stderr.
	void ReportViaEvents(bool arg_via_events)	 { via_events = arg_via_events; }

	// Associates the given location with subsequent output. We create a
	// stack of location so that the most recent is always the one that will
	// be assumed to be the current one. The pointer must remain valid until
	// the location is popped.
	void PushLocation(const Location* location)
		{ locations.push_back(std::pair<const Location*, const Location*>(location, 0)); }
	
	void PushLocation(const Location* loc1, const Location* loc2)
		{ locations.push_back(std::pair<const Location*, const Location*>(loc1, loc2)); }

	// Removes the top-most location information from stack.
	void PopLocation()
		{ locations.pop_back(); }

private:
	void DoLog(const char* prefix, EventHandlerPtr event, FILE* out, Connection* conn, val_list* addl, bool location, bool time, const char* fmt, va_list ap);

	void WeirdHelper(EventHandlerPtr event, Val* conn_val, const char* name, const char* addl, ...);
	void WeirdFlowHelper(addr_type orig, addr_type resp, const char* name, ...);

	int errors;
	bool via_events;

	std::list<std::pair<const Location*, const Location*> > locations;
};

extern Logger* bro_logger;

#endif

