// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include <stdlib.h>
#include <errno.h>

#include "Desc.h"
#include "File.h"
#include "Reporter.h"

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
	indent_with_spaces = 0;
	escape = false;
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

void ODesc::EnableEscaping()
	{
	escape = true;
	}

void ODesc::PushIndent()
	{
	++indent_level;
	NL();
	}

void ODesc::PopIndent()
	{
	if ( --indent_level < 0 )
		reporter->InternalError("ODesc::PopIndent underflow");

	NL();
	}

void ODesc::PopIndentNoNL()
	{
	if ( --indent_level < 0 )
		reporter->InternalError("ODesc::PopIndent underflow");
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
		modp_litoa10(i, tmp);
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
		modp_ulitoa10(u, tmp);
		Add(tmp);
		}
	}

void ODesc::Add(int64 i)
	{
	if ( IsBinary() )
		AddBytes(&i, sizeof(i));
	else
		{
		char tmp[256];
		modp_litoa10(i, tmp);
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
		modp_ulitoa10(u, tmp);
		Add(tmp);
		}
	}

void ODesc::Add(double d)
	{
	if ( IsBinary() )
		AddBytes(&d, sizeof(d));
	else
		{
		char tmp[256];
		modp_dtoa2(d, tmp, IsReadable() ? 6 : 8);
		Add(tmp);

		if ( d == double(int(d)) )
			// disambiguate from integer
			Add(".0");
		}
	}

void ODesc::Add(const IPAddr& addr)
	{
	Add(addr.AsString());
	}

void ODesc::Add(const IPPrefix& prefix)
	{
	Add(prefix.AsString());
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
		if ( Style() == RAW_STYLE )
			AddBytes(reinterpret_cast<const char*>(s->Bytes()), s->Len());
		else
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
	if ( indent_with_spaces > 0 )
		{
		for ( int i = 0; i < indent_level; ++i )
			for ( int j = 0; j < indent_with_spaces; ++j )
				Add(" ", 0);
		}
	else
		{
		for ( int i = 0; i < indent_level; ++i )
			Add("\t", 0);
		}
	}

static const char hex_chars[] = "0123456789abcdef";

static const char* find_first_unprintable(ODesc* d, const char* bytes, unsigned int n)
	{
	if ( d->IsBinary() )
		return 0;

	while ( n-- )
		{
		if ( ! isprint(*bytes) )
			return bytes;
		++bytes;
		}

	return 0;
	}

pair<const char*, size_t> ODesc::FirstEscapeLoc(const char* bytes, size_t n)
	{
	pair<const char*, size_t> p(find_first_unprintable(this, bytes, n), 1);

	string str(bytes, n);
	list<string>::const_iterator it;
	for ( it = escape_sequences.begin(); it != escape_sequences.end(); ++it )
		{
		size_t pos = str.find(*it);
		if ( pos != string::npos && (p.first == 0 || bytes + pos < p.first) )
			{
			p.first = bytes + pos;
			p.second = it->size();
			}
		}

	return p;
	}

void ODesc::AddBytes(const void* bytes, unsigned int n)
	{
	if ( ! escape )
	    {
	    AddBytesRaw(bytes, n);
	    return;
	    }

	const char* s = (const char*) bytes;
	const char* e = (const char*) bytes + n;

	while ( s < e )
		{
		pair<const char*, size_t> p = FirstEscapeLoc(s, e - s);
		if ( p.first )
			{
			AddBytesRaw(s, p.first - s);
			if ( p.second == 1 )
				{
				char hex[6] = "\\x00";
				hex[2] = hex_chars[((*p.first) & 0xf0) >> 4];
				hex[3] = hex_chars[(*p.first) & 0x0f];
				AddBytesRaw(hex, 4);
				}
			else
				{
				string esc_str = get_escaped_string(string(p.first, p.second), true);
				AddBytesRaw(esc_str.c_str(), esc_str.size());
				}
			s = p.first + p.second;
			}
		else
			{
			AddBytesRaw(s, e - s);
			break;
			}
		}
	}

void ODesc::AddBytesRaw(const void* bytes, unsigned int n)
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
				reporter->Error("error writing to %s: %s", f->Name(), strerror(errno));

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
		}
	}

void ODesc::Clear()
	{
	offset = 0;

	// If we've allocated an exceedingly large amount of space, free it.
	if ( size > 10 * 1024 * 1024 )
		{
		free(base);
		size = DEFAULT_SIZE;
		base = safe_malloc(size);
		((char*) base)[0] = '\0';
		}
	}

