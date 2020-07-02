// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <stdarg.h>

#include <list>
#include <utility>
#include <string>
#include <tuple>
#include <map>
#include <unordered_set>
#include <unordered_map>

#include "BroList.h"
#include "net_util.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(Analyzer, zeek, analyzer);
namespace file_analysis { class File; }
class Connection;
class Reporter;
class EventHandlerPtr;
ZEEK_FORWARD_DECLARE_NAMESPACED(RecordVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(StringVal, zeek);

namespace zeek {
template <class T> class IntrusivePtr;
using RecordValPtr = zeek::IntrusivePtr<RecordVal>;
using StringValPtr = zeek::IntrusivePtr<StringVal>;
}

ZEEK_FORWARD_DECLARE_NAMESPACED(Location, zeek::detail);

// One cannot raise this exception directly, go through the
// Reporter's methods instead.

class ReporterException {
protected:
	friend class Reporter;
	ReporterException()	{}
};

class InterpreterException : public ReporterException {
protected:
	friend class Reporter;
	InterpreterException()	{}
};

class IPAddr;

ZEEK_FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);

#define FMT_ATTR __attribute__((format(printf, 2, 3))) // sic! 1st is "this" I guess.

class Reporter {
public:
	using IPPair = std::pair<IPAddr, IPAddr>;
	using ConnTuple = std::tuple<IPAddr, IPAddr, uint32_t, uint32_t, TransportProto>;
	using WeirdCountMap = std::unordered_map<std::string, uint64_t>;
	using WeirdFlowMap = std::map<IPPair, WeirdCountMap>;
	using WeirdConnTupleMap = std::map<ConnTuple, WeirdCountMap>;
	using WeirdSet = std::unordered_set<std::string>;

	Reporter(bool abort_on_scripting_errors);
	~Reporter();

	// Initialize reporter-sepcific options	that are defined in script-layer.
	void InitOptions();

	// Report an informational message, nothing that needs specific
	// attention.
	void Info(const char* fmt, ...) FMT_ATTR;

	// Report a warning that may indicate a problem.
	void Warning(const char* fmt, ...) FMT_ATTR;

	// Report a non-fatal error. Processing proceeds normally after the error
	// has been reported.
	void Error(const char* fmt, ...) FMT_ATTR;

	// Returns the number of errors reported so far.
	int Errors()	{ return errors; }

	// Report a fatal error. Bro will terminate after the message has been
	// reported.
	[[noreturn]] void FatalError(const char* fmt, ...) FMT_ATTR;

	// Report a fatal error. Bro will terminate after the message has been
	// reported and always generate a core dump.
	[[noreturn]] void FatalErrorWithCore(const char* fmt, ...) FMT_ATTR;

	// Report a runtime error in evaluating a Bro script expression. This
	// function will not return but raise an InterpreterException.
	[[noreturn]] void ExprRuntimeError(const zeek::detail::Expr* expr, const char* fmt, ...) __attribute__((format(printf, 3, 4)));

	// Report a runtime error in evaluating a Bro script expression. This
	// function will not return but raise an InterpreterException.
	[[noreturn]] void RuntimeError(const zeek::detail::Location* location, const char* fmt, ...) __attribute__((format(printf, 3, 4)));

	// Report a traffic weirdness, i.e., an unexpected protocol situation
	// that may lead to incorrectly processing a connnection.
	void Weird(const char* name, const char* addl = "");	// Raises net_weird().
	void Weird(file_analysis::File* f, const char* name, const char* addl = "");	// Raises file_weird().
	void Weird(Connection* conn, const char* name, const char* addl = "");	// Raises conn_weird().
	void Weird(zeek::RecordValPtr conn_id, zeek::StringValPtr uid,
	           const char* name, const char* addl = "");	// Raises expired_conn_weird().
	void Weird(const IPAddr& orig, const IPAddr& resp, const char* name, const char* addl = "");	// Raises flow_weird().

	// Syslog a message. This methods does nothing if we're running
	// offline from a trace.
	void Syslog(const char* fmt, ...) FMT_ATTR;

	// Report about a potential internal problem. Bro will continue
	// normally.
	void InternalWarning(const char* fmt, ...) FMT_ATTR;

	// Report an internal program error. Bro will terminate with a core
	// dump after the message has been reported.
	[[noreturn]] void InternalError(const char* fmt, ...) FMT_ATTR;

	// Report an analyzer error. That analyzer will be set to not process
	// any further input, but Bro otherwise continues normally.
	void AnalyzerError(zeek::analyzer::Analyzer* a, const char* fmt, ...) __attribute__((format(printf, 3, 4)));;

	// Toggle whether non-fatal messages should be reported through the
	// scripting layer rather on standard output. Fatal errors are always
	// reported via stderr.
	void ReportViaEvents(bool arg_via_events)	 { via_events = arg_via_events; }

	// Associates the given location with subsequent output. We create a
	// stack of location so that the most recent is always the one that
	// will be assumed to be the current one. The pointer must remain
	// valid until the location is popped.
	void PushLocation(const zeek::detail::Location* location)
		{ locations.push_back(std::pair<const zeek::detail::Location*, const zeek::detail::Location*>(location, 0)); }

	void PushLocation(const zeek::detail::Location* loc1, const zeek::detail::Location* loc2)
		{ locations.push_back(std::pair<const zeek::detail::Location*, const zeek::detail::Location*>(loc1, loc2)); }

	// Removes the top-most location information from stack.
	void PopLocation()
		{ locations.pop_back(); }

	// Signals that we're entering processing an error handler event.
	void BeginErrorHandler()	{ ++in_error_handler; }

	// Signals that we're done processing an error handler event.
	void EndErrorHandler()	{ --in_error_handler; }

	/**
	 * Reset/cleanup state tracking for a "net" weird.
	 */
	void ResetNetWeird(const std::string& name);

	/**
	 * Reset/cleanup state tracking for a "flow" weird.
	 */
	void ResetFlowWeird(const IPAddr& orig, const IPAddr& resp);

	/**
	 * Reset/cleanup state tracking for a "expired conn" weird.
	 */
	void ResetExpiredConnWeird(const ConnTuple& id);

	/**
	 * Return the total number of weirds generated (counts weirds before
	 * any rate-limiting occurs).
	 */
	uint64_t GetWeirdCount() const
		{ return weird_count; }

	/**
	 * Return number of weirds generated per weird type/name (counts weirds
	 * before any rate-limiting occurs).
	 */
	const WeirdCountMap& GetWeirdsByType() const
		{ return weird_count_by_type; }

	/**
	 * Gets the weird sampling whitelist.
	 */
	WeirdSet GetWeirdSamplingWhitelist() const
		{
		return weird_sampling_whitelist;
		}

	/**
	 * Sets the weird sampling whitelist.
	 *
	 * @param weird_sampling_whitelist New weird sampling whitelist.
	 */
	void SetWeirdSamplingWhitelist(const WeirdSet& weird_sampling_whitelist)
		{
		this->weird_sampling_whitelist = weird_sampling_whitelist;
		}

	/**
	 * Gets the current weird sampling threshold.
	 *
	 * @return weird sampling threshold.
	 */
	uint64_t GetWeirdSamplingThreshold() const
		{
		return weird_sampling_threshold;
		}

	/**
	 * Sets the current weird sampling threshold.
	 *
	 * @param weird_sampling_threshold New weird sampling threshold.
	 */
	void SetWeirdSamplingThreshold(uint64_t weird_sampling_threshold)
		{
		this->weird_sampling_threshold = weird_sampling_threshold;
		}

	/**
	 * Gets the current weird sampling rate.
	 *
	 * @return weird sampling rate.
	 */
	uint64_t GetWeirdSamplingRate() const
		{
		return weird_sampling_rate;
		}

	/**
	 * Sets the weird sampling rate.
	 *
	 * @param weird_sampling_rate New weird sampling rate.
	 */
	void SetWeirdSamplingRate(uint64_t weird_sampling_rate)
		{
		this->weird_sampling_rate = weird_sampling_rate;
		}

	/**
	 * Gets the current weird sampling duration.
	 *
	 * @return weird sampling duration.
	 */
	double GetWeirdSamplingDuration() const
		{
		return weird_sampling_duration;
		}

	/**
	 * Sets the current weird sampling duration. Please note that
	 * this will not delete already running timers.
	 *
	 * @param weird_sampling_duration New weird sampling duration.
	 */
	void SetWeirdSamplingDuration(double weird_sampling_duration)
		{
		this->weird_sampling_duration = weird_sampling_duration;
		}

	/**
	 * Called after zeek_init() and toggles whether messages may stop being
	 * emitted to stderr.
	 */
	void ZeekInitDone()
		{ after_zeek_init = true; }

private:
	void DoLog(const char* prefix, EventHandlerPtr event, FILE* out,
		   Connection* conn, val_list* addl, bool location, bool time,
		   const char* postfix, const char* fmt, va_list ap) __attribute__((format(printf, 10, 0)));

	// WeirdHelper doesn't really have to be variadic, but it calls DoLog
	// and that takes va_list anyway.
	void WeirdHelper(EventHandlerPtr event, val_list vl, const char* fmt_name, ...) __attribute__((format(printf, 4, 5)));;
	void UpdateWeirdStats(const char* name);
	inline bool WeirdOnSamplingWhiteList(const char* name)
		{ return weird_sampling_whitelist.find(name) != weird_sampling_whitelist.end(); }
	bool PermitNetWeird(const char* name);
	bool PermitFlowWeird(const char* name, const IPAddr& o, const IPAddr& r);
	bool PermitExpiredConnWeird(const char* name, const zeek::RecordVal& conn_id);

	bool EmitToStderr(bool flag)
		{ return flag || ! after_zeek_init; }

	int errors;
	bool via_events;
	int in_error_handler;
	bool info_to_stderr;
	bool warnings_to_stderr;
	bool errors_to_stderr;
	bool after_zeek_init;
	bool abort_on_scripting_errors = false;

	std::list<std::pair<const zeek::detail::Location*, const zeek::detail::Location*> > locations;

	uint64_t weird_count;
	WeirdCountMap weird_count_by_type;
	WeirdCountMap net_weird_state;
	WeirdFlowMap flow_weird_state;
	WeirdConnTupleMap expired_conn_weird_state;

	WeirdSet weird_sampling_whitelist;
	uint64_t weird_sampling_threshold;
	uint64_t weird_sampling_rate;
	double weird_sampling_duration;

};

extern Reporter* reporter;
