// See the file "COPYING" in the main distribution directory for copyright.

#include "util.h"
#include "LogWriter.h"

LogWriter::LogWriter()
	{
	buf = 0;
	buf_len = 1024;
	buffering = true;
	disabled = false;
	}

LogWriter::~LogWriter()
	{
	if ( buf )
		free(buf);

	for(int i = 0; i < num_fields; ++i)
		delete fields[i];

	delete [] fields;
	}

bool LogWriter::Init(string arg_path, int arg_num_fields,
		     const LogField* const * arg_fields)
	{
	path = arg_path;
	num_fields = arg_num_fields;
	fields = arg_fields;

	if ( ! DoInit(arg_path, arg_num_fields, arg_fields) )
		{
		disabled = true;
		return false;
		}

	return true;
	}

bool LogWriter::Write(int arg_num_fields, LogVal** vals)
	{
	// Double-check that the arguments match. If we get this from remote,
	// something might be mixed up.
	if ( num_fields != arg_num_fields )
		{
		DBG_LOG(DBG_LOGGING, "Number of fields don't match in LogWriter::Write() (%d vs. %d)",
			arg_num_fields, num_fields);

		DeleteVals(vals);
		return false;
		}

	for ( int i = 0; i < num_fields; ++i )
		{
		if ( vals[i]->type != fields[i]->type )
			{
			DBG_LOG(DBG_LOGGING, "Field type doesn't match in LogWriter::Write() (%d vs. %d)",
				vals[i]->type, fields[i]->type);
			DeleteVals(vals);
			return false;
			}
		}

	bool result = DoWrite(num_fields, fields, vals);

	DeleteVals(vals);

	if ( ! result )
		disabled = true;

	return result;
	}

bool LogWriter::SetBuf(bool enabled)
	{
	if ( enabled == buffering )
		// No change.
		return true;

	buffering = enabled;

	if ( ! DoSetBuf(enabled) )
		{
		disabled = true;
		return false;
		}

	return true;
	}

bool LogWriter::Rotate(string rotated_path, double open,
		       double close, bool terminating)
	{
	if ( ! DoRotate(rotated_path, open, close, terminating) )
		{
		disabled = true;
		return false;
		}

	return true;
	}

bool LogWriter::Flush()
	{
	if ( ! DoFlush() )
		{
		disabled = true;
		return false;
		}

	return true;
	}

void LogWriter::Finish()
	{
	DoFinish();
	}

const char* LogWriter::Fmt(const char* format, ...)
	{
	if ( ! buf )
		buf = (char*) malloc(buf_len);

	va_list al;
	va_start(al, format);
	int n = safe_vsnprintf(buf, buf_len, format, al);
	va_end(al);

	if ( (unsigned int) n >= buf_len )
		{ // Not enough room, grow the buffer.
		buf_len = n + 32;
		buf = (char*) realloc(buf, buf_len);

		// Is it portable to restart?
		va_start(al, format);
		n = safe_vsnprintf(buf, buf_len, format, al);
		va_end(al);
		}

	return buf;
	}

void LogWriter::Error(const char *msg)
	{
	log_mgr->Error(this, msg);
	}

void LogWriter::DeleteVals(LogVal** vals)
	{
	log_mgr->DeleteVals(num_fields, vals);
	}

bool LogWriter::FinishedRotation(string new_name, string old_name, double open,
				 double close, bool terminating)
	{
	return log_mgr->FinishedRotation(this, new_name, old_name, open, close, terminating);
	}
