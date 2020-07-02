//
// See the file "COPYING" in the main distribution directory for copyright.
//

#include "zeek-config.h"
#include "Reporter.h"

#include <unistd.h>
#include <syslog.h>

#include "Desc.h"
#include "Event.h"
#include "Expr.h"
#include "NetVar.h"
#include "Net.h"
#include "Conn.h"
#include "Timer.h"
#include "ID.h"
#include "EventHandler.h"
#include "plugin/Plugin.h"
#include "plugin/Manager.h"
#include "input.h"
#include "file_analysis/File.h"

#ifdef SYSLOG_INT
extern "C" {
int openlog(const char* ident, int logopt, int facility);
int syslog(int priority, const char* message_fmt, ...);
int closelog();
}
#endif

Reporter* reporter = nullptr;

Reporter::Reporter(bool arg_abort_on_scripting_errors)
	{
	abort_on_scripting_errors = arg_abort_on_scripting_errors;
	errors = 0;
	via_events = false;
	in_error_handler = 0;

	// Always use stderr at startup/init before scripts have been fully parsed
	// and zeek_init() processed.
	// Messages may otherwise be missed if an error occurs that prevents events
	// from ever being dispatched.
	info_to_stderr = true;
	warnings_to_stderr = true;
	errors_to_stderr = true;
	after_zeek_init = false;

	weird_count = 0;
	weird_sampling_rate = 0;
	weird_sampling_duration = 0;
	weird_sampling_threshold = 0;

	openlog("bro", 0, LOG_LOCAL5);
	}

Reporter::~Reporter()
	{
	closelog();
	}

void Reporter::InitOptions()
	{
	info_to_stderr = zeek::id::find_val("Reporter::info_to_stderr")->AsBool();
	warnings_to_stderr = zeek::id::find_val("Reporter::warnings_to_stderr")->AsBool();
	errors_to_stderr = zeek::id::find_val("Reporter::errors_to_stderr")->AsBool();
	weird_sampling_rate = zeek::id::find_val("Weird::sampling_rate")->AsCount();
	weird_sampling_threshold = zeek::id::find_val("Weird::sampling_threshold")->AsCount();
	weird_sampling_duration = zeek::id::find_val("Weird::sampling_duration")->AsInterval();
	auto wl_val = zeek::id::find_val("Weird::sampling_whitelist")->AsTableVal();
	auto wl_table = wl_val->AsTable();

	HashKey* k;
	zeek::IterCookie* c = wl_table->InitForIteration();
	zeek::TableEntryVal* v;

	while ( (v = wl_table->NextEntry(k, c)) )
		{
		auto index = wl_val->RecreateIndex(*k);
		std::string key = index->Idx(0)->AsString()->CheckString();
		weird_sampling_whitelist.emplace(move(key));
		delete k;
		}
	}

void Reporter::Info(const char* fmt, ...)
	{
	va_list ap;
	va_start(ap, fmt);
	FILE* out = EmitToStderr(info_to_stderr) ? stderr : nullptr;
	DoLog("", reporter_info, out, nullptr, nullptr, true, true, nullptr, fmt, ap);
	va_end(ap);
	}

void Reporter::Warning(const char* fmt, ...)
	{
	va_list ap;
	va_start(ap, fmt);
	FILE* out = EmitToStderr(warnings_to_stderr) ? stderr : nullptr;
	DoLog("warning", reporter_warning, out, nullptr, nullptr, true, true, nullptr, fmt, ap);
	va_end(ap);
	}

void Reporter::Error(const char* fmt, ...)
	{
	++errors;
	va_list ap;
	va_start(ap, fmt);
	FILE* out = EmitToStderr(errors_to_stderr) ? stderr : nullptr;
	DoLog("error", reporter_error, out, nullptr, nullptr, true, true, nullptr, fmt, ap);
	va_end(ap);
	}

void Reporter::FatalError(const char* fmt, ...)
	{
	va_list ap;
	va_start(ap, fmt);

	// Always log to stderr.
	DoLog("fatal error", nullptr, stderr, nullptr, nullptr, true, false, nullptr, fmt, ap);

	va_end(ap);

	set_processing_status("TERMINATED", "fatal_error");
	fflush(stderr);
	fflush(stdout);
	_exit(1);
	}

void Reporter::FatalErrorWithCore(const char* fmt, ...)
	{
	va_list ap;
	va_start(ap, fmt);

	// Always log to stderr.
	DoLog("fatal error", nullptr, stderr, nullptr, nullptr, true, false, nullptr, fmt, ap);

	va_end(ap);

	set_processing_status("TERMINATED", "fatal_error");
	abort();
	}

void Reporter::ExprRuntimeError(const zeek::detail::Expr* expr, const char* fmt, ...)
	{
	++errors;

	ODesc d;
	expr->Describe(&d);

	PushLocation(expr->GetLocationInfo());
	va_list ap;
	va_start(ap, fmt);
	FILE* out = EmitToStderr(errors_to_stderr) ? stderr : nullptr;
	DoLog("expression error", reporter_error, out, nullptr, nullptr, true, true,
	      d.Description(), fmt, ap);
	va_end(ap);
	PopLocation();

	if ( abort_on_scripting_errors )
		abort();

	throw InterpreterException();
	}

void Reporter::RuntimeError(const zeek::detail::Location* location, const char* fmt, ...)
	{
	++errors;
	PushLocation(location);
	va_list ap;
	va_start(ap, fmt);
	FILE* out = EmitToStderr(errors_to_stderr) ? stderr : nullptr;
	DoLog("runtime error", reporter_error, out, nullptr, nullptr, true, true, "", fmt, ap);
	va_end(ap);
	PopLocation();

	if ( abort_on_scripting_errors )
		abort();

	throw InterpreterException();
	}

void Reporter::InternalError(const char* fmt, ...)
	{
	va_list ap;
	va_start(ap, fmt);

	// Always log to stderr.
	DoLog("internal error", nullptr, stderr, nullptr, nullptr, true, false, nullptr, fmt, ap);

	va_end(ap);

	set_processing_status("TERMINATED", "internal_error");
	abort();
	}

void Reporter::AnalyzerError(zeek::analyzer::Analyzer* a, const char* fmt, ...)
	{
	if ( a )
		a->SetSkip(true);

	va_list ap;
	va_start(ap, fmt);
	// Always log to stderr.
	// TODO: would be nice to also log a call stack.
	DoLog("analyzer error", reporter_error, stderr, nullptr, nullptr, true, true, nullptr, fmt,
	      ap);
	va_end(ap);
	}

void Reporter::InternalWarning(const char* fmt, ...)
	{
	va_list ap;
	va_start(ap, fmt);
	FILE* out = EmitToStderr(warnings_to_stderr) ? stderr : nullptr;
	// TODO: would be nice to also log a call stack.
	DoLog("internal warning", reporter_warning, out, nullptr, nullptr, true, true, nullptr, fmt,
	      ap);
	va_end(ap);
	}

void Reporter::Syslog(const char* fmt, ...)
	{
	if ( reading_traces )
		return;

	va_list ap;
	va_start(ap, fmt);
	vsyslog(LOG_NOTICE, fmt, ap);
	va_end(ap);
	}

void Reporter::WeirdHelper(EventHandlerPtr event, val_list vl, const char* fmt_name, ...)
	{
	va_list ap;
	va_start(ap, fmt_name);
	DoLog("weird", event, nullptr, nullptr, &vl, false, false, nullptr, fmt_name, ap);
	va_end(ap);
	}

void Reporter::UpdateWeirdStats(const char* name)
	{
	++weird_count;
	++weird_count_by_type[name];
	}

class NetWeirdTimer final : public Timer {
public:
	NetWeirdTimer(double t, const char* name, double timeout)
	: Timer(t + timeout, TIMER_NET_WEIRD_EXPIRE), weird_name(name)
		{}

	void Dispatch(double t, bool is_expire) override
		{ reporter->ResetNetWeird(weird_name); }

	std::string weird_name;
};

class FlowWeirdTimer final : public Timer {
public:
	using IPPair = std::pair<IPAddr, IPAddr>;

	FlowWeirdTimer(double t, IPPair p, double timeout)
		: Timer(t + timeout, TIMER_FLOW_WEIRD_EXPIRE), endpoints(std::move(p))
		{}

	void Dispatch(double t, bool is_expire) override
		{ reporter->ResetFlowWeird(endpoints.first, endpoints.second); }

	IPPair endpoints;
};

class ConnTupleWeirdTimer final : public Timer {
public:
	using ConnTuple = Reporter::ConnTuple;

	ConnTupleWeirdTimer(double t, ConnTuple id, double timeout)
		: Timer(t + timeout, TIMER_CONN_TUPLE_WEIRD_EXPIRE),
		  conn_id(std::move(id))
		{}

	void Dispatch(double t, bool is_expire) override
		{ reporter->ResetExpiredConnWeird(conn_id); }

	ConnTuple conn_id;
};

void Reporter::ResetNetWeird(const std::string& name)
	{
	net_weird_state.erase(name);
	}

void Reporter::ResetFlowWeird(const IPAddr& orig, const IPAddr& resp)
	{
	flow_weird_state.erase(std::make_pair(orig, resp));
	}

void Reporter::ResetExpiredConnWeird(const ConnTuple& id)
	{
	expired_conn_weird_state.erase(id);
	}

bool Reporter::PermitNetWeird(const char* name)
	{
	auto& count = net_weird_state[name];
	++count;

	if ( count == 1 )
		timer_mgr->Add(new NetWeirdTimer(network_time, name,
		                                 weird_sampling_duration));

	if ( count <= weird_sampling_threshold )
		return true;

	auto num_above_threshold = count - weird_sampling_threshold;
	if ( weird_sampling_rate )
		return num_above_threshold % weird_sampling_rate == 0;
	else
		return false;
	}

bool Reporter::PermitFlowWeird(const char* name,
                               const IPAddr& orig, const IPAddr& resp)
	{
	auto endpoints = std::make_pair(orig, resp);
	auto& map = flow_weird_state[endpoints];

	if ( map.empty() )
		timer_mgr->Add(new FlowWeirdTimer(network_time, endpoints,
		                                  weird_sampling_duration));

	auto& count = map[name];
	++count;

	if ( count <= weird_sampling_threshold )
		return true;

	auto num_above_threshold = count - weird_sampling_threshold;
	if ( weird_sampling_rate )
		return num_above_threshold % weird_sampling_rate == 0;
	else
		return false;
	}

bool Reporter::PermitExpiredConnWeird(const char* name, const zeek::RecordVal& conn_id)
	{
	auto conn_tuple = std::make_tuple(conn_id.GetField("orig_h")->AsAddr(),
	                                  conn_id.GetField("resp_h")->AsAddr(),
	                                  conn_id.GetField("orig_p")->AsPortVal()->Port(),
	                                  conn_id.GetField("resp_p")->AsPortVal()->Port(),
	                                  conn_id.GetField("resp_p")->AsPortVal()->PortType());

	auto& map = expired_conn_weird_state[conn_tuple];

	if ( map.empty() )
		timer_mgr->Add(new ConnTupleWeirdTimer(network_time,
		                                       std::move(conn_tuple),
		                                       weird_sampling_duration));

	auto& count = map[name];
	++count;

	if ( count <= weird_sampling_threshold )
		return true;

	auto num_above_threshold = count - weird_sampling_threshold;

	if ( weird_sampling_rate )
		return num_above_threshold % weird_sampling_rate == 0;
	else
		return false;
	}

void Reporter::Weird(const char* name, const char* addl)
	{
	UpdateWeirdStats(name);

	if ( ! WeirdOnSamplingWhiteList(name) )
		{
		if ( ! PermitNetWeird(name) )
			return;
		}

	WeirdHelper(net_weird, {new zeek::StringVal(addl)}, "%s", name);
	}

void Reporter::Weird(file_analysis::File* f, const char* name, const char* addl)
	{
	UpdateWeirdStats(name);

	if ( ! WeirdOnSamplingWhiteList(name) )
		{
		if ( ! f->PermitWeird(name, weird_sampling_threshold,
		                      weird_sampling_rate, weird_sampling_duration) )
			return;
		}

	WeirdHelper(file_weird, {f->ToVal()->Ref(), new zeek::StringVal(addl)},
	            "%s", name);
	}

void Reporter::Weird(Connection* conn, const char* name, const char* addl)
	{
	UpdateWeirdStats(name);

	if ( ! WeirdOnSamplingWhiteList(name) )
		{
		if ( ! conn->PermitWeird(name, weird_sampling_threshold,
		                         weird_sampling_rate, weird_sampling_duration) )
			return;
		}

	WeirdHelper(conn_weird, {conn->ConnVal()->Ref(), new zeek::StringVal(addl)},
	            "%s", name);
	}

void Reporter::Weird(zeek::RecordValPtr conn_id, zeek::StringValPtr uid,
                     const char* name, const char* addl)
	{
	UpdateWeirdStats(name);

	if ( ! WeirdOnSamplingWhiteList(name) )
		{
		if ( ! PermitExpiredConnWeird(name, *conn_id) )
			return;
		}

	WeirdHelper(expired_conn_weird,
	            {conn_id.release(), uid.release(), new zeek::StringVal(addl)},
	            "%s", name);
	}

void Reporter::Weird(const IPAddr& orig, const IPAddr& resp, const char* name, const char* addl)
	{
	UpdateWeirdStats(name);

	if ( ! WeirdOnSamplingWhiteList(name) )
		{
		if ( ! PermitFlowWeird(name, orig, resp) )
			 return;
		}

	WeirdHelper(flow_weird,
	            {new zeek::AddrVal(orig), new zeek::AddrVal(resp), new zeek::StringVal(addl)},
	            "%s", name);
	}

void Reporter::DoLog(const char* prefix, EventHandlerPtr event, FILE* out,
                     Connection* conn, val_list* addl, bool location, bool time,
                     const char* postfix, const char* fmt, va_list ap)
	{
	static char tmp[512];

	int size = sizeof(tmp);
	char* buffer  = tmp;
	char* alloced = nullptr;

	std::string loc_str;

	if ( location )
		{
		std::string loc_file = "";
		int loc_line = 0;

		if ( locations.size() )
			{
			ODesc d;

			std::pair<const zeek::detail::Location*, const zeek::detail::Location*> locs = locations.back();

			if ( locs.first )
				{
				if ( locs.first != &zeek::detail::no_location )
					locs.first->Describe(&d);

				else
					d.Add("<no location>");

				if ( locs.second )
					{
					d.Add(" and ");

					if ( locs.second != &zeek::detail::no_location )
						locs.second->Describe(&d);

					else
						d.Add("<no location>");

					}
				}

			loc_str = d.Description();
			}

		else if ( filename && *filename )
			{
			// Take from globals.
			loc_str = filename;
			char tmp[32];
			snprintf(tmp, 32, "%d", line_number);
			loc_str += std::string(", line ") + std::string(tmp);
			}
		}

	while ( true )
		{
		va_list aq;
		va_copy(aq, ap);
		int n = vsnprintf(buffer, size, fmt, aq);
		va_end(aq);

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

	bool raise_event = true;

	if ( via_events && ! in_error_handler )
		{
		if ( locations.size() )
			{
			auto locs = locations.back();
			raise_event = PLUGIN_HOOK_WITH_RESULT(HOOK_REPORTER,
							      HookReporter(prefix, event, conn, addl, location,
									   locs.first, locs.second, time, buffer), true);
			}
		else
			raise_event = PLUGIN_HOOK_WITH_RESULT(HOOK_REPORTER,
							      HookReporter(prefix, event, conn, addl, location,
									   nullptr, nullptr, time, buffer), true);
		}

	if ( raise_event && event && via_events && ! in_error_handler )
		{
		auto vl_size = 1 + (bool)time + (bool)location + (bool)conn +
		               (addl ? addl->length() : 0);

		zeek::Args vl;
		vl.reserve(vl_size);

		if ( time )
			vl.emplace_back(zeek::make_intrusive<zeek::TimeVal>(network_time ? network_time : current_time()));

		vl.emplace_back(zeek::make_intrusive<zeek::StringVal>(buffer));

		if ( location )
			vl.emplace_back(zeek::make_intrusive<zeek::StringVal>(loc_str.c_str()));

		if ( conn )
			vl.emplace_back(conn->ConnVal());

		if ( addl )
			for ( auto v : *addl )
				vl.emplace_back(zeek::AdoptRef{}, v);

		if ( conn )
			conn->EnqueueEvent(event, nullptr, std::move(vl));
		else
			mgr.Enqueue(event, std::move(vl));
		}
	else
		{
		if ( addl )
			{
			for ( const auto& av : *addl )
				Unref(av);
			}
		}

	if ( out )
		{
		std::string s = "";

		if ( bro_start_network_time != 0.0 )
			{
			char tmp[32];
			snprintf(tmp, 32, "%.6f", network_time);
			s += std::string(tmp) + " ";
			}

		if ( prefix && *prefix )
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
		s += "\n";

		if ( out )
			fprintf(out, "%s", s.c_str());
		}

	if ( alloced )
		free(alloced);
	}
