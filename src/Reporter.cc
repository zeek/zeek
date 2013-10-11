//
// See the file "COPYING" in the main distribution directory for copyright.
//

#include <syslog.h>

#include "config.h"
#include "Reporter.h"
#include "Event.h"
#include "NetVar.h"
#include "Net.h"
#include "Conn.h"

#ifdef SYSLOG_INT
extern "C" {
int openlog(const char* ident, int logopt, int facility);
int syslog(int priority, const char* message_fmt, ...);
int closelog();
}
#endif

Reporter* reporter = 0;

Reporter::Reporter()
	{
	errors = 0;
	via_events = false;
	in_error_handler = 0;

	// Always use stderr at startup/init before scripts have been fully parsed.
	// Messages may otherwise be missed if an error occurs that prevents events
	// from ever being dispatched.
	info_to_stderr = true;
	warnings_to_stderr = true;
	errors_to_stderr = true;

	openlog("bro", 0, LOG_LOCAL5);
	}

Reporter::~Reporter()
	{
	closelog();
	}

void Reporter::InitOptions()
	{
	info_to_stderr = internal_const_val("Reporter::info_to_stderr")->AsBool();
	warnings_to_stderr = internal_const_val("Reporter::warnings_to_stderr")->AsBool();
	errors_to_stderr = internal_const_val("Reporter::errors_to_stderr")->AsBool();
	}

void Reporter::Info(const char* fmt, ...)
	{
	va_list ap;
	va_start(ap, fmt);
	FILE* out = info_to_stderr ? stderr : 0;
	DoLog("", reporter_info, out, 0, 0, true, true, 0, fmt, ap);
	va_end(ap);
	}

void Reporter::Warning(const char* fmt, ...)
	{
	va_list ap;
	va_start(ap, fmt);
	FILE* out = warnings_to_stderr ? stderr : 0;
	DoLog("warning", reporter_warning, out, 0, 0, true, true, 0, fmt, ap);
	va_end(ap);
	}

void Reporter::Error(const char* fmt, ...)
	{
	++errors;
	va_list ap;
	va_start(ap, fmt);
	FILE* out = errors_to_stderr ? stderr : 0;
	DoLog("error", reporter_error, out, 0, 0, true, true, 0, fmt, ap);
	va_end(ap);
	}

void Reporter::FatalError(const char* fmt, ...)
	{
	va_list ap;
	va_start(ap, fmt);

	// Always log to stderr.
	DoLog("fatal error", 0, stderr, 0, 0, true, false, 0, fmt, ap);

	va_end(ap);

	set_processing_status("TERMINATED", "fatal_error");
	exit(1);
	}

void Reporter::FatalErrorWithCore(const char* fmt, ...)
	{
	va_list ap;
	va_start(ap, fmt);

	// Always log to stderr.
	DoLog("fatal error", 0, stderr, 0, 0, true, false, 0, fmt, ap);

	va_end(ap);

	set_processing_status("TERMINATED", "fatal_error");
	abort();
	}

void Reporter::ExprRuntimeError(const Expr* expr, const char* fmt, ...)
	{
	++errors;

	ODesc d;
	expr->Describe(&d);

	PushLocation(expr->GetLocationInfo());
	va_list ap;
	va_start(ap, fmt);
	FILE* out = errors_to_stderr ? stderr : 0;
	DoLog("expression error", reporter_error, out, 0, 0, true, true,
	      d.Description(), fmt, ap);
	va_end(ap);
	PopLocation();
	throw InterpreterException();
	}

void Reporter::InternalError(const char* fmt, ...)
	{
	va_list ap;
	va_start(ap, fmt);

	// Always log to stderr.
	DoLog("internal error", 0, stderr, 0, 0, true, false, 0, fmt, ap);

	va_end(ap);

	set_processing_status("TERMINATED", "internal_error");
	abort();
	}

void Reporter::AnalyzerError(analyzer::Analyzer* a, const char* fmt,
                                     ...)
	{
	if ( a )
		a->SetSkip(true);

	va_list ap;
	va_start(ap, fmt);
	// Always log to stderr.
	// TODO: would be nice to also log a call stack.
	DoLog("analyzer error", reporter_error, stderr, 0, 0, true, true, 0, fmt,
	      ap);
	va_end(ap);
	}

void Reporter::InternalWarning(const char* fmt, ...)
	{
	va_list ap;
	va_start(ap, fmt);
	FILE* out = warnings_to_stderr ? stderr : 0;
	// TODO: would be nice to also log a call stack.
	DoLog("internal warning", reporter_warning, out, 0, 0, true, true, 0, fmt,
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

void Reporter::WeirdHelper(EventHandlerPtr event, Val* conn_val, const char* addl, const char* fmt_name, ...)
	{
	val_list* vl = new val_list(1);

	if ( conn_val )
		vl->append(conn_val);

	if ( addl )
		vl->append(new StringVal(addl));

	va_list ap;
	va_start(ap, fmt_name);
	DoLog("weird", event, 0, 0, vl, false, false, 0, fmt_name, ap);
	va_end(ap);

	delete vl;
	}

void Reporter::WeirdFlowHelper(const IPAddr& orig, const IPAddr& resp, const char* fmt_name, ...)
	{
	val_list* vl = new val_list(2);
	vl->append(new AddrVal(orig));
	vl->append(new AddrVal(resp));

	va_list ap;
	va_start(ap, fmt_name);
	DoLog("weird", flow_weird, 0, 0, vl, false, false, 0, fmt_name, ap);
	va_end(ap);

	delete vl;
	}

void Reporter::Weird(const char* name)
	{
	WeirdHelper(net_weird, 0, 0, name);
	}

void Reporter::Weird(Connection* conn, const char* name, const char* addl)
	{
	WeirdHelper(conn_weird, conn->BuildConnVal(), addl, "%s", name);
	}

void Reporter::Weird(Val* conn_val, const char* name, const char* addl)
	{
	WeirdHelper(conn_weird, conn_val, addl, "%s", name);
	}

void Reporter::Weird(const IPAddr& orig, const IPAddr& resp, const char* name)
	{
	WeirdFlowHelper(orig, resp, "%s", name);
	}

void Reporter::DoLog(const char* prefix, EventHandlerPtr event, FILE* out,
                     Connection* conn, val_list* addl, bool location, bool time,
                     const char* postfix, const char* fmt, va_list ap)
	{
	static char tmp[512];

	int size = sizeof(tmp);
	char* buffer  = tmp;
	char* alloced = 0;

	string loc_str;

	if ( location )
		{
		string loc_file = "";
		int loc_line = 0;

		if ( locations.size() )
			{
			ODesc d;

			std::pair<const Location*, const Location*> locs = locations.back();

			if ( locs.first )
				{
				if ( locs.first != &no_location )
					locs.first->Describe(&d);

				else
					d.Add("<no location>");

				if ( locs.second )
					{
					d.Add(" and ");

					if ( locs.second != &no_location )
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
			loc_str += string(", line ") + string(tmp);
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

	if ( postfix )
		// Note, if you change this fmt string, adjust the additional
		// buffer size above.
		sprintf(buffer + strlen(buffer), " [%s]", postfix);

	if ( event && via_events && ! in_error_handler )
		{
		val_list* vl = new val_list;

		if ( time )
			vl->append(new Val((bro_start_network_time != 0.0) ? network_time : 0, TYPE_TIME));

		vl->append(new StringVal(buffer));

		if ( location )
			vl->append(new StringVal(loc_str.c_str()));

		if ( conn )
			vl->append(conn->BuildConnVal());

		if ( addl )
			{
			loop_over_list(*addl, i)
				vl->append((*addl)[i]);
			}

		if ( conn )
			conn->ConnectionEvent(event, 0, vl);
		else
			mgr.QueueEvent(event, vl);
		}
	else
		{
		if ( addl )
			{
			loop_over_list(*addl, i)
				Unref((*addl)[i]);
			}
		}

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
			if ( loc_str != "" )
				s += string(prefix) + " in " + loc_str + ": ";
			else
				s += string(prefix) + ": ";
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

