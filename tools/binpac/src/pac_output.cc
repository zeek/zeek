// $Id: pac_output.cc 3225 2006-06-08 00:00:01Z vern $

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
	return print(fmt, ap);
	}

int Output::println(const char* fmt, ...)
	{
	for ( int i = 0; i < indent(); ++i )
		fprintf(fp, "\t");

	int r;
	va_list ap;
	va_start(ap, fmt);
	r = print(fmt, ap);

	fprintf(fp, "\n");
	return r;
	}
