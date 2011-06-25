// $Id: Logger.cc 6916 2009-09-24 20:48:36Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#include <syslog.h>

#include "config.h"
#include "Logger.h"
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

Logger* bro_logger = 0;

Logger::Logger()
	{
	errors = 0;
	via_events = false;

	openlog("bro", 0, LOG_LOCAL5);
	}

Logger::~Logger()
	{
	closelog();
	}

void Logger::Message(const char* fmt, ...)
	{
	va_list ap;
	va_start(ap, fmt);
	DoLog("", log_message, stdout, 0, 0, true, true, fmt, ap);
	va_end(ap);
	}

void Logger::Warning(const char* fmt, ...)
	{
	va_list ap;
	va_start(ap, fmt);
	DoLog("warning", log_warning, stdout, 0, 0, true, true, fmt, ap);
	va_end(ap);
	}

void Logger::Error(const char* fmt, ...)
	{
	++errors;
	va_list ap;
	va_start(ap, fmt);
	DoLog("error", log_error, stdout, 0, 0, true, true, fmt, ap);
	va_end(ap);
	}

void Logger::FatalError(const char* fmt, ...)
	{
	va_list ap;
	va_start(ap, fmt);

	// Always log to stderr.
	DoLog("fatal error", 0, stderr, 0, 0, true, false, fmt, ap);

	va_end(ap);

	set_processing_status("TERMINATED", "fatal_error");
	exit(1);
	}

void Logger::FatalErrorWithCore(const char* fmt, ...)
	{
	va_list ap;
	va_start(ap, fmt);

	// Always log to stderr.
	DoLog("fatal error", 0, stderr, 0, 0, true, false, fmt, ap);

	va_end(ap);

	set_processing_status("TERMINATED", "fatal_error");
	abort();
	}

void Logger::InternalError(const char* fmt, ...)
	{
	va_list ap;
	va_start(ap, fmt);

	// Always log to stderr.
	DoLog("internal error", 0, stderr, 0, 0, true, false, fmt, ap);

	va_end(ap);

	set_processing_status("TERMINATED", "internal_error");
	abort();
	}

void Logger::InternalWarning(const char* fmt, ...)
	{
	va_list ap;
	va_start(ap, fmt);
	DoLog("internal warning", log_warning, stdout, 0, 0, true, true, fmt, ap);
	va_end(ap);
	}

void Logger::Syslog(const char* fmt, ...)
	{
	if ( reading_traces )
		return;

	va_list ap;
	va_start(ap, fmt);
	vsyslog(LOG_NOTICE, fmt, ap);
	va_end(ap);
	}

void Logger::WeirdHelper(EventHandlerPtr event, Val* conn_val, const char* name, const char* addl, ...)
	{
	val_list* vl = new val_list(1);

	if ( conn_val )
		vl->append(conn_val);

	if ( addl )
		vl->append(new StringVal(addl));

	va_list ap;
	va_start(ap, addl);
	DoLog("weird", event, stdout, 0, vl, false, false, name, ap);
	va_end(ap);

	delete vl;
	}

void Logger::WeirdFlowHelper(addr_type orig, addr_type resp, const char* name, ...)
	{
	val_list* vl = new val_list(2);
	vl->append(new AddrVal(orig));
	vl->append(new AddrVal(resp));

	va_list ap;
	va_start(ap, name);
	DoLog("weird", flow_weird, stdout, 0, vl, false, false, name, ap);
	va_end(ap);

	delete vl;
	}

void Logger::Weird(const char* name)
	{
	WeirdHelper(net_weird, 0, name, 0);
	}

void Logger::Weird(Connection* conn, const char* name, const char* addl)
	{
	WeirdHelper(conn_weird, conn->BuildConnVal(), name, addl);
	}

void Logger::Weird(Val* conn_val, const char* name, const char* addl)
	{
	WeirdHelper(conn_weird, conn_val, name, addl);
	}

void Logger::Weird(addr_type orig, addr_type resp, const char* name)
	{
	WeirdFlowHelper(orig, resp, name);
	}

void Logger::DoLog(const char* prefix, EventHandlerPtr event, FILE* out, Connection* conn, val_list* addl, bool location, bool time, const char* fmt, va_list ap)
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

		if ( n > -1 && n < size )
			// We had enough space;
			break;

		// Enlarge buffer;
		size *= 2;
		buffer = alloced = (char *)realloc(alloced, size);

		if ( ! buffer )
			FatalError("out of memory in logger");
		}

	if ( event && via_events )
		{
		val_list* vl = new val_list;

		if ( time )
			vl->append(new Val(network_time, TYPE_TIME));

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
		string s = "";

		if ( network_time )
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

		fprintf(out, s.c_str());
		}



	if ( alloced )
		free(alloced);
	}

