
#include "util.h"
#include "LogWriter.h"

LogWriter::LogWriter()
	{
	buf = 0;
	buf_len = 1024;
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
	DoInit(arg_path, arg_num_fields, arg_fields);
	return true;
	}

bool LogWriter::Write(LogVal** vals)
	{
	bool result = DoWrite(num_fields, fields, vals);
	DeleteVals(vals);
	return result;
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
	run_time(msg);
	}

void LogWriter::DeleteVals(LogVal** vals)
	{
	for ( int i = 0; i < num_fields; i++ )
		delete vals[i];
	}


