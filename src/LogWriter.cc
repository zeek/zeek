
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

	delete [] fields;
	}

bool LogWriter::Init(string arg_path, int arg_num_fields, LogField** arg_fields)
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
		return false;

	for ( int i = 0; i < num_fields; ++i )
		if ( vals[i]->type != fields[i]->type )
			return false;

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
	for ( int i = 0; i < num_fields; i++ )
		delete vals[i];
	}


