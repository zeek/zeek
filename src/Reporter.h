// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <stdio.h>
#include <list>
#include <map>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/RunState.h"
#include "zeek/ZeekList.h"
#include "zeek/net_util.h"

extern zeek::EventHandlerPtr reporter_info;
extern zeek::EventHandlerPtr reporter_warning;
extern zeek::EventHandlerPtr reporter_error;

namespace zeek
	{

class Connection;
class RecordVal;
class StringVal;
class IPAddr;
class Reporter;

template <class T> class IntrusivePtr;
using RecordValPtr = IntrusivePtr<RecordVal>;
using StringValPtr = IntrusivePtr<StringVal>;

namespace detail
	{

class AssertStmt;
class Location;
class Expr;

	} // namespace detail

namespace analyzer
	{
class Analyzer;
	}
namespace file_analysis
	{
class File;
	}

// One cannot raise this exception directly, go through the
// Reporter's methods instead.

class ReporterException
	{
protected:
	friend class Reporter;
	ReporterException() { }
	};

class InterpreterException : public ReporterException
	{
protected:
	friend class Reporter;
	friend class detail::AssertStmt;
	InterpreterException() { }
	};

#define FMT_ATTR __attribute__((format(printf, 2, 3))) // sic! 1st is "this" I guess.

class Reporter
	{
public:
	using IPPair = std::pair<IPAddr, IPAddr>;
	using ConnTuple = std::tuple<IPAddr, IPAddr, uint32_t, uint32_t, TransportProto>;
	using WeirdCountMap = std::unordered_map<std::string, uint64_t>;
	using WeirdFlowMap = std::map<IPPair, WeirdCountMap>;
	using WeirdConnTupleMap = std::map<ConnTuple, WeirdCountMap>;
	using WeirdSet = std::unordered_set<std::string>;

	Reporter(bool abort_on_scripting_errors);
	~Reporter();

	// Initialize reporter-specific options	that are defined in script-layer.
	void InitOptions();

	// Report an informational message, nothing that needs specific
	// attention.
	template <typename... Args> void Info(const char* fmt, Args&&... args)
		{
		FILE* out = EmitToStderr(info_to_stderr) ? stderr : nullptr;
		DoLog("", reporter_info, out, nullptr, nullptr, true, true, "", fmt, args...);
		}

	// Report a warning that may indicate a problem.
	template <typename... Args> void Warning(const char* fmt, Args&&... args)
		{
		FILE* out = EmitToStderr(info_to_stderr) ? stderr : nullptr;
		DoLog("warning", reporter_warning, out, nullptr, nullptr, true, true, "", fmt, args...);
		}

	// Report a non-fatal error. Processing proceeds normally after the error
	// has been reported.
	template <typename... Args> void Error(const char* fmt, Args&&... args)
		{
		++errors;
		FILE* out = EmitToStderr(info_to_stderr) ? stderr : nullptr;
		DoLog("error", reporter_error, out, nullptr, nullptr, true, true, "", fmt, args...);
		}

	// Returns the number of errors reported so far.
	int Errors() { return errors; }

	// Report a fatal error. Zeek will terminate after the message has been
	// reported.
	template <typename... Args> [[noreturn]] void FatalError(const char* fmt, Args&&... args)
		{
		// Always log to stderr.
		DoLog("fatal error", nullptr, stderr, nullptr, nullptr, true, false, "", fmt, args...);
		util::detail::set_processing_status("TERMINATED", "fatal_error");
		fflush(stderr);
		fflush(stdout);
		_exit(1);
		}

	// Report a fatal error. Zeek will terminate after the message has been
	// reported and always generate a core dump.
	template <typename... Args>
	[[noreturn]] void FatalErrorWithCore(const char* fmt, Args&&... args)
		{
		// Always log to stderr.
		DoLog("fatal error", nullptr, stderr, nullptr, nullptr, true, false, "", fmt, args...);
		util::detail::set_processing_status("TERMINATED", "fatal_error");
		abort();
		}

	// Report a runtime error in evaluating a Zeek script expression. This
	// function will not return but raise an InterpreterException.
	template <typename... Args>
	[[noreturn]] void ExprRuntimeError(const detail::Expr* expr, const char* fmt, Args&&... args)
		{
		++errors;

		ODesc d;
		DescribeExpr(expr, d);
		FILE* out = EmitToStderr(errors_to_stderr) ? stderr : nullptr;
		DoLog("expression error", reporter_error, out, nullptr, nullptr, true, true,
		      d.Description(), fmt, args...);
		PopLocation();
		throw InterpreterException();
		}

	// Report a runtime error in evaluating a Zeek script expression. This
	// function will not return but raise an InterpreterException.
	template <typename... Args>
	[[noreturn]] void RuntimeError(const detail::Location* location, const char* fmt,
	                               Args&&... args)
		{
		++errors;
		PushLocation(location);
		FILE* out = EmitToStderr(errors_to_stderr) ? stderr : nullptr;
		DoLog("runtime error", reporter_error, out, nullptr, nullptr, true, true, "", fmt, args...);
		PopLocation();
		throw InterpreterException();
		}

	// Report a rutnime warning in evaluating a Zeek script expression.
	template <typename... Args>
	void ExprRuntimeWarning(const detail::Expr* expr, const char* fmt, Args&&... args)
		{
		ODesc d;
		DescribeExpr(expr, d);
		FILE* out = EmitToStderr(warnings_to_stderr) ? stderr : nullptr;
		DoLog("expression warning", reporter_warning, out, nullptr, nullptr, true, true,
		      d.Description(), fmt, args...);
		PopLocation();
		}

	// Report a runtime error in executing a compiled script. This
	// function will not return but raise an InterpreterException.
	template <typename... Args> [[noreturn]] void CPPRuntimeError(const char* fmt, Args&&... args)
		{
		++errors;
		FILE* out = EmitToStderr(errors_to_stderr) ? stderr : nullptr;
		DoLog("runtime error in compiled code", reporter_error, out, nullptr, nullptr, true, true,
		      "", fmt, args...);

		if ( abort_on_scripting_errors )
			abort();

		throw InterpreterException();
		}

	// Report a traffic weirdness, i.e., an unexpected protocol situation
	// that may lead to incorrectly processing a connection.
	void Weird(const char* name, const char* addl = "",
	           const char* source = ""); // Raises net_weird().
	void Weird(file_analysis::File* f, const char* name, const char* addl = "",
	           const char* source = ""); // Raises file_weird().
	void Weird(Connection* conn, const char* name, const char* addl = "",
	           const char* source = ""); // Raises conn_weird().
	void Weird(RecordValPtr conn_id, StringValPtr uid, const char* name, const char* addl = "",
	           const char* source = ""); // Raises expired_conn_weird().
	void Weird(const IPAddr& orig, const IPAddr& resp, const char* name, const char* addl = "",
	           const char* source = ""); // Raises flow_weird().

	// Report a deprecation. The message should contain a version.
	void Deprecation(std::string_view msg, const detail::Location* loc1 = nullptr,
	                 const detail::Location* loc2 = nullptr);

	// Whether or not deprecations are logged when calling Deprecation()
	void SetIgnoreDeprecations(bool arg) { ignore_deprecations = arg; }

	// Syslog a message. This methods does nothing if we're running
	// offline from a trace.
	template <typename... Args> void Syslog(const char* fmt, Args&&... args)
		{
		if ( run_state::reading_traces )
			return;

		char* buf;
#ifdef HAVE_ASPRINTF
		asprintf(&buf, fmt, std::forward<Args>(args)...);
#else
		util::asprintf(&buf, fmt, std::forward<Args>(args)...);
#endif
		DoSyslog(buf);
		free(buf);
		}

	// Report about a potential internal problem. Zeek will continue
	// normally.
	template <typename... Args> void InternalWarning(const char* fmt, Args&&... args)
		{
		FILE* out = EmitToStderr(warnings_to_stderr) ? stderr : nullptr;
		// TODO: would be nice to also log a call stack.
		DoLog("internal warning", reporter_warning, out, nullptr, nullptr, true, true, "", fmt,
		      args...);
		}

	// Report an internal program error. Zeek will terminate with a core
	// dump after the message has been reported.
	template <typename... Args> [[noreturn]] void InternalError(const char* fmt, Args&&... args)
		{
		// Always log to stderr.
		DoLog("internal error", nullptr, stderr, nullptr, nullptr, true, false, "", fmt, args...);
		util::detail::set_processing_status("TERMINATED", "internal_error");
		abort();
		}

	// Report an analyzer error. That analyzer will be set to not process
	// any further input, but Zeek otherwise continues normally.
	template <typename... Args>
	void AnalyzerError(analyzer::Analyzer* a, const char* fmt, Args&&... args)
		{
		SetAnalyzerSkip(a);

		// Always log to stderr.
		// TODO: would be nice to also log a call stack.
		DoLog("analyzer error", reporter_error, stderr, nullptr, nullptr, true, true, "", fmt,
		      args...);
		}

	// Toggle whether non-fatal messages should be reported through the
	// scripting layer rather on standard output. Fatal errors are always
	// reported via stderr.
	void ReportViaEvents(bool arg_via_events) { via_events = arg_via_events; }

	// Associates the given location with subsequent output. We create a
	// stack of location so that the most recent is always the one that
	// will be assumed to be the current one. The pointer must remain
	// valid until the location is popped.
	void PushLocation(const detail::Location* location)
		{
		locations.push_back(
			std::pair<const detail::Location*, const detail::Location*>(location, nullptr));
		}

	void PushLocation(const detail::Location* loc1, const detail::Location* loc2)
		{
		locations.push_back(
			std::pair<const detail::Location*, const detail::Location*>(loc1, loc2));
		}

	// Removes the top-most location information from stack.
	void PopLocation() { locations.pop_back(); }

	// Signals that we're entering processing an error handler event.
	void BeginErrorHandler() { ++in_error_handler; }

	// Signals that we're done processing an error handler event.
	void EndErrorHandler() { --in_error_handler; }

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
	uint64_t GetWeirdCount() const { return weird_count; }

	/**
	 * Return number of weirds generated per weird type/name (counts weirds
	 * before any rate-limiting occurs).
	 */
	const WeirdCountMap& GetWeirdsByType() const { return weird_count_by_type; }

	/**
	 * Gets the weird sampling whitelist.
	 */
	const WeirdSet& GetWeirdSamplingWhitelist() const { return weird_sampling_whitelist; }

	/**
	 * Sets the weird sampling whitelist.
	 *
	 * @param weird_sampling_whitelist New weird sampling whitelist.
	 */
	void SetWeirdSamplingWhitelist(WeirdSet weird_sampling_whitelist)
		{
		this->weird_sampling_whitelist = std::move(weird_sampling_whitelist);
		}

	/**
	 * Gets the weird sampling global list.
	 */
	const WeirdSet& GetWeirdSamplingGlobalList() const { return weird_sampling_global_list; }

	/**
	 * Sets the weird sampling global list.
	 *
	 * @param weird_sampling_global list New weird sampling global list.
	 */
	void SetWeirdSamplingGlobalList(WeirdSet weird_sampling_global_list)
		{
		this->weird_sampling_global_list = std::move(weird_sampling_global_list);
		}

	/**
	 * Gets the current weird sampling threshold.
	 *
	 * @return weird sampling threshold.
	 */
	uint64_t GetWeirdSamplingThreshold() const { return weird_sampling_threshold; }

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
	uint64_t GetWeirdSamplingRate() const { return weird_sampling_rate; }

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
	double GetWeirdSamplingDuration() const { return weird_sampling_duration; }

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

private:
	void SetAnalyzerSkip(analyzer::Analyzer* a) const;

	void DoSyslog(std::string_view msg);

	std::string BuildLogLocationString() const;

	void DoLogEvents(std::string_view prefix, EventHandlerPtr event, Connection* conn,
	                 ValPList* addl, bool location, bool time, std::string_view buffer,
	                 std::string_view loc_str) const;

	void DescribeExpr(const detail::Expr* expr, ODesc& d);

	template <typename... Args>
	void DoLog(std::string_view prefix, EventHandlerPtr event, FILE* out, Connection* conn,
	           ValPList* addl, bool location, bool time, std::string_view postfix,
	           std::string_view fmt, Args&&... args)
		{
		static char tmp[512];
		int size = sizeof(tmp);
		char* buffer = tmp;
		char* allocated = nullptr;

		std::string loc_str;
		if ( location )
			loc_str = BuildLogLocationString();

		while ( true )
			{
			int n;

			if constexpr ( sizeof...(args) > 0 )
				n = snprintf(buffer, size, fmt.data(), std::forward<Args>(args)...);
			else
				n = snprintf(buffer, size, "%s", fmt.data());

			if ( ! postfix.empty() )
				n += postfix.size() + 10;

			if ( n > -1 && n < size )
				// We had enough space;
				break;

			// Enlarge buffer;
			size *= 2;
			buffer = allocated = (char*)realloc(allocated, size);

			if ( ! buffer )
				FatalError("out of memory in Reporter");
			}

		if ( ! postfix.empty() )
			// Note, if you change this fmt string, adjust the additional
			// buffer size above.
			snprintf(buffer + strlen(buffer), size - strlen(buffer), " (%s)", postfix.data());

		DoLogEvents(prefix, event, conn, addl, location, time, buffer, loc_str);

		if ( out )
			{
			std::string s = "";

			if ( run_state::zeek_start_network_time != 0.0 )
				{
				char tmp[32];
				snprintf(tmp, 32, "%.6f", run_state::network_time);
				s += std::string(tmp) + " ";
				}

			if ( ! prefix.empty() )
				{
				if ( loc_str != "" )
					s += std::string(prefix) + " in " + loc_str + ": ";
				else
					s += std::string(prefix) + ": ";
				}

			else
				{
				if ( loc_str != "" )
					s += loc_str + ": ";
				}

			s += buffer;

#ifdef ENABLE_ZEEK_UNIT_TESTS
			if ( doctest::is_running_in_test )
				{
				try
					{
					MESSAGE(s);
					}
				catch ( const doctest::detail::TestFailureException& e )
					{
					// If doctest throws an exception, just write the string out to stdout
					// like normal, just so it's captured somewhere.
					fprintf(out, "%s\n", s.c_str());
					}
				}
			else
				{
#endif
				s += "\n";
				fprintf(out, "%s", s.c_str());
#ifdef ENABLE_ZEEK_UNIT_TESTS
				}
#endif
			}

		if ( allocated )
			free(allocated);
		}

	// WeirdHelper doesn't really have to be variadic, but it calls DoLog and that's variadic
	// anyway.
	template <typename... Args>
	void WeirdHelper(EventHandlerPtr event, ValPList vl, const char* fmt_name, Args&&... args)
		{
		DoLog("weird", event, nullptr, nullptr, &vl, false, false, "", fmt_name, args...);
		}

	void UpdateWeirdStats(const char* name);
	inline bool WeirdOnSamplingWhiteList(const char* name)
		{
		return weird_sampling_whitelist.find(name) != weird_sampling_whitelist.end();
		}
	inline bool WeirdOnGlobalList(const char* name)
		{
		return weird_sampling_global_list.find(name) != weird_sampling_global_list.end();
		}
	bool PermitNetWeird(const char* name);
	bool PermitFlowWeird(const char* name, const IPAddr& o, const IPAddr& r);
	bool PermitExpiredConnWeird(const char* name, const RecordVal& conn_id);

	enum class PermitWeird
		{
		Allow,
		Deny,
		Unknown
		};
	PermitWeird CheckGlobalWeirdLists(const char* name);

	bool EmitToStderr(bool flag);

	int errors;
	bool via_events;
	bool syslog_open;
	int in_error_handler;
	bool info_to_stderr;
	bool warnings_to_stderr;
	bool errors_to_stderr;
	bool abort_on_scripting_errors = false;

	std::list<std::pair<const detail::Location*, const detail::Location*>> locations;

	uint64_t weird_count;
	WeirdCountMap weird_count_by_type;
	WeirdCountMap net_weird_state;
	WeirdFlowMap flow_weird_state;
	WeirdConnTupleMap expired_conn_weird_state;

	WeirdSet weird_sampling_whitelist;
	WeirdSet weird_sampling_global_list;
	uint64_t weird_sampling_threshold;
	uint64_t weird_sampling_rate;
	double weird_sampling_duration;

	bool ignore_deprecations;
	};

extern Reporter* reporter;

	} // namespace zeek
