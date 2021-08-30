// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeek-config.h"
#include "zeek/Desc.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <math.h>

#include "zeek/File.h"
#include "zeek/Reporter.h"
#include "zeek/ConvertUTF.h"
#include "zeek/IPAddr.h"

#define DEFAULT_SIZE 128
#define SLOP 10

namespace zeek {

ODesc::ODesc(DescType t, File* arg_f)
	{
	type = t;
	style = STANDARD_STYLE;
	f = arg_f;

	if ( f == nullptr )
		{
		size = DEFAULT_SIZE;
		base = util::safe_malloc(size);
		((char*) base)[0] = '\0';
		offset = 0;
		}
	else
		{
		offset = size = 0;
		base = nullptr;
		}

	indent_level = 0;
	is_short = false;
	want_quotes = false;
	want_determinism = false;
	do_flush = true;
	include_stats = false;
	indent_with_spaces = 0;
	escape = false;
	utf8 = false;
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

void ODesc::EnableUTF8 ()
	{
	utf8 = true;
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

void ODesc::Add(uint32_t u)
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

void ODesc::Add(int64_t i)
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

void ODesc::Add(uint64_t u)
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

void ODesc::Add(double d, bool no_exp)
	{
	if ( IsBinary() )
		AddBytes(&d, sizeof(d));
	else
		{
		// Buffer needs enough chars to store max. possible "double" value
		// of 1.79e308 without using scientific notation.
		char tmp[350];

		if ( no_exp )
			modp_dtoa3(d, tmp, sizeof(tmp), IsReadable() ? 6 : 8);
		else
			modp_dtoa2(d, tmp, IsReadable() ? 6 : 8);

		Add(tmp);

		auto approx_equal = [](double a, double b, double tolerance = 1e-6) -> bool
			{
			auto v = a - b;
			return v < 0 ? -v < tolerance : v < tolerance;
			};

		if ( approx_equal(d, nearbyint(d), 1e-9) &&
		     isfinite(d) && ! strchr(tmp, 'e') )
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

void ODesc::AddBytes(const String* s)
	{
	if ( IsReadable() )
		{
		if ( Style() == RAW_STYLE )
			AddBytes(reinterpret_cast<const char*>(s->Bytes()), s->Len());
		else
			{
			const char* str = s->Render(String::EXPANDED_STRING);
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

static bool starts_with(const char* str1, const char* str2, size_t len)
	{
	for ( size_t i = 0; i < len; ++i )
		if ( str1[i] != str2[i] )
			return false;

	return true;
	}

size_t ODesc::StartsWithEscapeSequence(const char* start, const char* end)
	{
	if ( escape_sequences.empty() )
		return 0;

	for ( const auto& esc_str : escape_sequences )
		{
		size_t esc_len = esc_str.length();

		if ( start + esc_len > end )
			continue;

		if ( starts_with(start, esc_str.c_str(), esc_len) )
			return esc_len;
		}

	return 0;
	}

std::pair<const char*, size_t> ODesc::FirstEscapeLoc(const char* bytes, size_t n)
	{
	typedef std::pair<const char*, size_t> escape_pos;

	if ( IsBinary() )
		return escape_pos(0, 0);

	for ( size_t i = 0; i < n; ++i )
		{
		auto printable = isprint(bytes[i]);

		if ( ! printable && ! utf8 )
			return escape_pos(bytes + i, 1);

		if ( bytes[i] == '\\' )
			return escape_pos(bytes + i, 1);

		size_t len = StartsWithEscapeSequence(bytes + i, bytes + n);

		if ( len )
			return escape_pos(bytes + i, len);
		}

	return escape_pos(nullptr, 0);
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
		auto [ esc_start, esc_len ] = FirstEscapeLoc(s, e - s);

		if ( esc_start != nullptr )
			{
			if ( utf8 )
				{
				std::string result = util::json_escape_utf8(s, esc_start - s, false);
				AddBytesRaw(result.c_str(), result.size());
				}
			else
				AddBytesRaw(s, esc_start - s);

			util::get_escaped_string(this, esc_start, esc_len, true);
			s = esc_start + esc_len;
			}
		else
			{
			if ( utf8 )
				{
				std::string result = util::json_escape_utf8(s, e - s, false);
				AddBytesRaw(result.c_str(), result.size());
				}
			else
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
		size *= 2;

	base = util::safe_realloc(base, size);
	}

void ODesc::Clear()
	{
	offset = 0;

	// If we've allocated an exceedingly large amount of space, free it.
	if ( size > 10 * 1024 * 1024 )
		{
		free(base);
		size = DEFAULT_SIZE;
		base = util::safe_malloc(size);
		((char*) base)[0] = '\0';
		}
	}

bool ODesc::PushType(const Type* type)
	{
	auto res = encountered_types.insert(type);
	return std::get<1>(res);
	}

bool ODesc::PopType(const Type* type)
	{
	size_t res = encountered_types.erase(type);
	return (res == 1);
	}

bool ODesc::FindType(const Type* type)
	{
	auto res = encountered_types.find(type);

	if ( res != encountered_types.end() )
		return true;

	return false;
	}


std::string obj_desc(const Obj* o)
	{
	static ODesc d;

	d.Clear();
	o->Describe(&d);
	d.SP();
	o->GetLocationInfo()->Describe(&d);

	return std::string(d.Description());
	}

} // namespace zeek
