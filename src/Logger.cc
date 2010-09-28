// $Id: Logger.cc 6916 2009-09-24 20:48:36Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#include <stdlib.h>
#include <math.h>
#include <ctype.h>
#include <syslog.h>

#include "config.h"
#include "File.h"
#include "Logger.h"

#ifdef SYSLOG_INT
extern "C" {
int openlog(const char* ident, int logopt, int facility);
int syslog(int priority, const char* message_fmt, ...);
int closelog();
}
#endif

Logger::Logger(const char* name, BroFile* arg_f)
	{
	openlog(name, 0, LOG_LOCAL5);
	f = arg_f;
	enabled = 1;
	}

Logger::~Logger()
	{
	closelog();
	Unref(f);
	}

void Logger::Log(const char* msg)
	{
	int has_timestamp =
		(fabs(atof(msg) - network_time) <= 30.0) ||
		(msg[0] == 't' && msg[1] == '=' && isdigit(msg[2]));

	if ( enabled )
		{
		const char* sub_msg = msg;
		if ( has_timestamp )
			{
			// Don't include the timestamp in the logging,
			// as it gets tacked on by syslog anyway.
			sub_msg = strchr(sub_msg, ' ');
			if ( sub_msg )
				++sub_msg;	// skip over ' '
			else
				sub_msg = msg;
			}

		syslog(LOG_NOTICE, "%s", sub_msg);
		}

	if ( f )
		{
		if ( has_timestamp )
			f->Write(fmt("%s\n", msg));
		else
			f->Write(fmt("%.6f %s\n", network_time, msg));

		f->Flush();
		}
	}

void Logger::Describe(ODesc* d) const
	{
	d->AddSP("logger");
	f->Describe(d);
	}
