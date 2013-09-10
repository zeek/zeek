#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>

#include "pac_utils.h"
#include "pac_output.h"

OutputException::OutputException(const char* arg_msg)
	{
	msg = arg_msg;
	}

OutputException::~OutputException()
	{
	}

Output::Output(const char* filename)
	{
	fp = fopen(filename, "w");
	if ( ! fp )
		throw OutputException(strerror(errno));
	indent_ = 0;
	}

Output::~Output()
	{
	if ( fp )
		fclose(fp);
	}

int Output::print(const char* fmt, va_list ap)
	{
	int r = vfprintf(fp, fmt, ap);
	if ( r == -1 )
		throw OutputException(strerror(errno));
	return r;
	}

int Output::print(const char* fmt, ...)
	{
	va_list ap;
	va_start(ap, fmt);
	int r = -1;

	try
		{
		r = print(fmt, ap);
		}

	catch ( ... )
		{
		va_end(ap);
		throw;
		}

	va_end(ap);
	return r;
	}

int Output::println(const char* fmt, ...)
	{
	for ( int i = 0; i < indent(); ++i )
		fprintf(fp, "\t");

	va_list ap;
	va_start(ap, fmt);
	int r = -1;

	try
		{
		r = print(fmt, ap);
		}

	catch ( ... )
		{
		va_end(ap);
		throw;
		}

	va_end(ap);
	fprintf(fp, "\n");
	return r;
	}
