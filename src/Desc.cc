// $Id: Desc.cc 6245 2008-10-07 00:56:59Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include <stdlib.h>
#include <errno.h>

#include "Desc.h"
#include "File.h"

#define DEFAULT_SIZE 128
#define SLOP 10

ODesc::ODesc(desc_type t, BroFile* arg_f)
	{
	type = t;
	style = STANDARD_STYLE;
	f = arg_f;

	if ( f == 0 )
		{
		size = DEFAULT_SIZE;
		base = safe_malloc(size);
		((char*) base)[0] = '\0';

		offset = 0;

		if ( ! base )
			OutOfMemory();
		}
	else
		{
		offset = size = 0;
		base = 0;
		}

	indent_level = 0;
	is_short = 0;
	want_quotes = 0;
	do_flush = 1;
	include_stats = 0;
	}

ODesc::~ODesc()
	{
	if ( f )
		{
		if ( do_flush )
			f->Flush();
		}
	else if ( base )
		free(base);
	}

void ODesc::PushIndent()
	{
	++indent_level;
	NL();
	}

void ODesc::PopIndent()
	{
	if ( --indent_level < 0 )
		internal_error("ODesc::PopIndent underflow");
	NL();
	}

void ODesc::Add(const char* s, int do_indent)
	{
	unsigned int n = strlen(s);

	if ( do_indent && IsReadable() && offset > 0 &&
	     ((const char*) base)[offset - 1] == '\n' )
		Indent();

	if ( IsBinary() )
		AddBytes(s, n+1);
	else
		AddBytes(s, n);
	}

void ODesc::Add(int i)
	{
	if ( IsBinary() )
		AddBytes(&i, sizeof(i));
	else
		{
		char tmp[256];
		sprintf(tmp, "%d", i);
		Add(tmp);
		}
	}

void ODesc::Add(uint32 u)
	{
	if ( IsBinary() )
		AddBytes(&u, sizeof(u));
	else
		{
		char tmp[256];
		sprintf(tmp, "%u", u);
		Add(tmp);
		}
	}

#ifdef USE_INT64
void ODesc::Add(int64 i)
	{
	if ( IsBinary() )
		AddBytes(&i, sizeof(i));
	else
		{
		char tmp[256];
		sprintf(tmp, "%lld", i);
		Add(tmp);
		}
	}

void ODesc::Add(uint64 u)
	{
	if ( IsBinary() )
		AddBytes(&u, sizeof(u));
	else
		{
		char tmp[256];
		sprintf(tmp, "%llu", u);
		Add(tmp);
		}
	}
#endif

void ODesc::Add(double d)
	{
	if ( IsBinary() )
		AddBytes(&d, sizeof(d));
	else
		{
		char tmp[256];
		sprintf(tmp, IsReadable() ? "%.15g" : "%.17g", d);
		Add(tmp);

		if ( d == double(int(d)) )
			// disambiguate from integer
			Add(".0");
		}
	}

void ODesc::AddCS(const char* s)
	{
	int n = strlen(s);
	Add(n);
	if ( ! IsBinary() )
		Add(" ");
	Add(s);
	}

void ODesc::AddBytes(const BroString* s)
	{
	if ( IsReadable() )
		{
		int render_style = BroString::EXPANDED_STRING;
		if ( Style() == ALTERNATIVE_STYLE )
			// Only change NULs, since we can't in any case
			// cope with them.
			render_style = BroString::ESC_NULL;

		const char* str = s->Render(render_style);
		Add(str);
		delete [] str;
		}
	else
		{
		Add(s->Len());
		if ( ! IsBinary() )
			Add(" ");
		AddBytes(s->Bytes(), s->Len());
		}
	}

void ODesc::Indent()
	{
	for ( int i = 0; i < indent_level; ++i )
		Add("\t", 0);
	}


void ODesc::AddBytes(const void* bytes, unsigned int n)
	{
	if ( n == 0 )
		return;

	if ( f )
		{
		static bool write_failed = false;

		if ( ! f->Write((const char*) bytes, n) )
			{
			if ( ! write_failed )
				// Most likely it's a "disk full" so report
				// subsequent failures only once.
				run_time(fmt("error writing to %s: %s", f->Name(), strerror(errno)));

			write_failed = true;
			return;
			}

		write_failed = false;
		}

	else
		{
		Grow(n);

		// The following casting contortions are necessary because
		// simply using &base[offset] generates complaints about
		// using a void* for pointer arithemtic.
		memcpy((void*) &((char*) base)[offset], bytes, n);
		offset += n;

		((char*) base)[offset] = '\0';	// ensure that always NUL-term.
		}
	}

void ODesc::Grow(unsigned int n)
	{
	while ( offset + n + SLOP >= size )
		{
		size *= 2;
		base = safe_realloc(base, size);
		if ( ! base )
			OutOfMemory();
		}
	}

void ODesc::OutOfMemory()
	{
	internal_error("out of memory");
	}
