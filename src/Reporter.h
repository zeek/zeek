// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <stdarg.h>
#include <unistd.h>

#include <list>
#include <utility>
#include <string>
#include <map>
#include <unordered_set>
#include <unordered_map>

#include "IPAddr.h"
#include "Expr.h"
#include "Desc.h"

namespace analyzer { class Analyzer; }
namespace file_analysis { class File; }
class Connection;
class Location;
class Reporter;
class EventHandlerPtr;

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

extern EventHandlerPtr reporter_info;
extern EventHandlerPtr reporter_warning;
extern EventHandlerPtr reporter_error;
extern bool reading_traces;
extern double bro_start_network_time;

class Reporter {
public:
	using IPPair = std::pair<IPAddr, IPAddr>;
	using WeirdCountMap = std::unordered_map<std::string, uint64_t>;
	using WeirdFlowMap = std::map<IPPair, WeirdCountMap>;
	using WeirdSet = std::unordered_set<std::string>;

	Reporter();
	~Reporter();

	// Initialize reporter-sepcific options	that are defined in script-layer.
	void InitOptions();

	// Report an informational message, nothing that needs specific
	// attention.
	template <typename... Args>
	void Info(const char* fmt, Args&&... args)
		{
		FILE* out = EmitToStderr(info_to_stderr) ? stderr : 0;
		DoLog("", reporter_info, out, 0, 0, true, true, 0, fmt, args...);
		}

	// Report a warning that may indicate a problem.
	template <typename... Args>
	void Warning(const char* fmt, Args&&... args)
		{
		FILE* out = EmitToStderr(warnings_to_stderr) ? stderr : 0;
		DoLog("warning", reporter_warning, out, 0, 0, true, true, 0, fmt, args...);
		}

	// Report a non-fatal error. Processing proceeds normally after the error
	// has been reported.
	template <typename... Args>
	void Error(const char* fmt, Args&&... args)
		{
		++errors;
		FILE* out = EmitToStderr(errors_to_stderr) ? stderr : 0;
		DoLog("error", reporter_error, out, 0, 0, true, true, 0, fmt, args...);
		}

	// Returns the number of errors reported so far.
	int Errors()	{ return errors; }

	// Report a fatal error. Bro will terminate after the message has been
	// reported.
	template <typename... Args>
	void FatalError(const char* fmt, Args&&... args)
		{
		// Always log to stderr.
		DoLog("fatal error", 0, stderr, 0, 0, true, false, 0, fmt, args...);
		set_processing_status("TERMINATED", "fatal_error");
		fflush(stderr);
		fflush(stdout);
		_exit(1);
		}

	// Report a fatal error. Bro will terminate after the message has been
	// reported and always generate a core dump.
	template <typename... Args>
	void FatalErrorWithCore(const char* fmt, Args&&... args)
		{
		// Always log to stderr.
		DoLog("fatal error", 0, stderr, 0, 0, true, false, 0, fmt, args...);
		set_processing_status("TERMINATED", "fatal_error");
		abort();
		}

	// Report a runtime error in evaluating a Bro script expression. This
	// function will not return but raise an InterpreterException.
	template <typename... Args>
	void ExprRuntimeError(const Expr* expr, const char* fmt, Args&&... args)
		{
		++errors;

		ODesc d;
		expr->Describe(&d);

		PushLocation(expr->GetLocationInfo());
		FILE* out = EmitToStderr(errors_to_stderr) ? stderr : 0;
		DoLog("expression error", reporter_error, out, 0, 0, true, true,
			d.Description(), fmt, args...);
		PopLocation();
		throw InterpreterException();
		}

	// Report a runtime error in evaluating a Bro script expression. This
	// function will not return but raise an InterpreterException.
	template <typename... Args>
	void RuntimeError(const Location* location, const char* fmt, Args&&... args)
		{
		++errors;
		PushLocation(location);
		FILE* out = EmitToStderr(errors_to_stderr) ? stderr : 0;
		DoLog("runtime error", reporter_error, out, 0, 0, true, true, "", fmt, args...);
		PopLocation();
		throw InterpreterException();
		}

	// Report a traffic weirdness, i.e., an unexpected protocol situation
	// that may lead to incorrectly processing a connnection.
	void Weird(const char* name, const char* addl = "");	// Raises net_weird().
	void Weird(file_analysis::File* f, const char* name, const char* addl = "");	// Raises file_weird().
	void Weird(Connection* conn, const char* name, const char* addl = "");	// Raises conn_weird().
	void Weird(const IPAddr& orig, const IPAddr& resp, const char* name, const char* addl = "");	// Raises flow_weird().

	// Syslog a message. This method does nothing if we're running
	// offline from a trace.
	template <typename... Args>
	void Syslog(const char* fmt, Args&&... args)
		{
		if ( ! reading_traces )
			{
			char* buf;
			asprintf(&buf, fmt, std::forward<Args>(args)...);
			DoSyslog(buf);
			free(buf);
			}
		}

	// Report about a potential internal problem. Bro will continue
	// normally.
	template <typename... Args>
	void InternalWarning(const char* fmt, Args&&... args)
		{
		FILE* out = EmitToStderr(warnings_to_stderr) ? stderr : 0;
		// TODO: would be nice to also log a call stack.
		DoLog("internal warning", reporter_warning, out, 0, 0, true, true, 0, fmt, args...);
		}

	// Report an internal program error. Bro will terminate with a core
	// dump after the message has been reported.
	template <typename... Args>
	void InternalError(const char* fmt, Args&&... args)
		{
		// Always log to stderr.
		DoLog("internal error", 0, stderr, 0, 0, true, false, 0, fmt, args...);
		set_processing_status("TERMINATED", "internal_error");
		abort();
		}

	// Report an analyzer error. That analyzer will be set to not process
	// any further input, but Bro otherwise continues normally.
	template <typename... Args>
	void AnalyzerError(analyzer::Analyzer* a, const char* fmt, Args&&... args)
		{
		SetAnalyzerSkip(a);

		// Always log to stderr.
		// TODO: would be nice to also log a call stack.
		DoLog("analyzer error", reporter_error, stderr, 0, 0, true, true, 0, fmt, args...);
		}

	// Toggle whether non-fatal messages should be reported through the
	// scripting layer rather on standard output. Fatal errors are always
	// reported via stderr.
	void ReportViaEvents(bool arg_via_events)	 { via_events = arg_via_events; }

	// Associates the given location with subsequent output. We create a
	// stack of location so that the most recent is always the one that
	// will be assumed to be the current one. The pointer must remain
	// valid until the location is popped.
	void PushLocation(const Location* location)
		{ locations.push_back(std::pair<const Location*, const Location*>(location, 0)); }

	void PushLocation(const Location* loc1, const Location* loc2)
		{ locations.push_back(std::pair<const Location*, const Location*>(loc1, loc2)); }

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

	void SetAnalyzerSkip(analyzer::Analyzer* a);

	void DoSyslog(const char* msg);

	std::string BuildLogLocationString(bool location);
	void DoLogEvents(const char* prefix, EventHandlerPtr event, Connection* conn,
	                 val_list* addl, bool location, bool time, char* buffer,
	                 const string& loc_str);

	template <typename... Args>
	void DoLog(const char* prefix, EventHandlerPtr event, FILE* out,
		Connection* conn, val_list* addl, bool location, bool time,
		const char* postfix, const char* fmt, Args&&... args)
		{
		static char tmp[512];

		int size = sizeof(tmp);
		char* buffer  = tmp;
		char* alloced = 0;

		string loc_str = BuildLogLocationString(location);

		while ( true )
			{
			int n;

			if constexpr ( sizeof...(args) > 0 )
				n = snprintf(buffer, size, fmt, std::forward<Args>(args)...);
			else
				n = snprintf(buffer, size, "%s", fmt);

			if ( postfix )
				n += strlen(postfix) + 10; // Add a bit of slack.

			if ( n > -1 && n < size )
				// We had enough space;
				break;

			// Enlarge buffer;
			size *= 2;
			buffer = alloced = (char *)realloc(alloced, size);

			if ( ! buffer )
				FatalError("out of memory in Reporter");
			}

		if ( postfix && *postfix )
			// Note, if you change this fmt string, adjust the additional
			// buffer size above.
			snprintf(buffer + strlen(buffer), size - strlen(buffer), " (%s)", postfix);

		DoLogEvents(prefix, event, conn, addl, location, time, buffer, loc_str);

		if ( out )
			{
			string s = "";

			if ( bro_start_network_time != 0.0 )
				{
				char tmp[32];
				snprintf(tmp, 32, "%.6f", network_time);
				s += string(tmp) + " ";
				}

			if ( prefix && *prefix )
				{
				if ( ! loc_str.empty() )
					s += string(prefix) + " in " + loc_str + ": ";
				else
					s += string(prefix) + ": ";
				}

			else
				{
				if ( ! loc_str.empty() )
					s += loc_str + ": ";
				}

			s += buffer;
			s += "\n";

			if ( out )
				fprintf(out, "%s", s.c_str());
			}

		if ( alloced )
			free(alloced);
		}

	// WeirdHelper doesn't really have to be variadic, but it calls DoLog and that's
	// variadic anyway.
	template <typename... Args>
	void WeirdHelper(EventHandlerPtr event, val_list vl, const char* fmt_name, Args&&... args)
		{
		DoLog("weird", event, 0, 0, &vl, false, false, 0, fmt_name, args...);
		}

	void UpdateWeirdStats(const char* name);
	inline bool WeirdOnSamplingWhiteList(const char* name)
		{ return weird_sampling_whitelist.find(name) != weird_sampling_whitelist.end(); }
	bool PermitNetWeird(const char* name);
	bool PermitFlowWeird(const char* name, const IPAddr& o, const IPAddr& r);

	bool EmitToStderr(bool flag)
		{ return flag || ! after_zeek_init; }

	int errors;
	bool via_events;
	int in_error_handler;
	bool info_to_stderr;
	bool warnings_to_stderr;
	bool errors_to_stderr;
	bool after_zeek_init;

	std::list<std::pair<const Location*, const Location*> > locations;

	uint64_t weird_count;
	WeirdCountMap weird_count_by_type;
	WeirdCountMap net_weird_state;
	WeirdFlowMap flow_weird_state;

	WeirdSet weird_sampling_whitelist;
	uint64_t weird_sampling_threshold;
	uint64_t weird_sampling_rate;
	double weird_sampling_duration;

};

extern Reporter* reporter;
