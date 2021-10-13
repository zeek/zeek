// See the file "COPYING" in the main distribution directory for copyright.

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "zeek/script_opt/CPP/Compile.h"

namespace zeek::detail
	{

using namespace std;

void CPPCompile::StartBlock()
	{
	++block_level;
	Emit("{");
	}

void CPPCompile::EndBlock(bool needs_semi)
	{
	Emit("}%s", needs_semi ? ";" : "");
	--block_level;
	}

string CPPCompile::GenString(const char* b, int len) const
	{
	return string("make_intrusive<StringVal>(") + Fmt(len) + ", " + CPPEscape(b, len) + ")";
	}

string CPPCompile::CPPEscape(const char* b, int len) const
	{
	string res = "\"";

	for ( int i = 0; i < len; ++i )
		{
		unsigned char c = b[i];

		switch ( c )
			{
			case '\a':
				res += "\\a";
				break;
			case '\b':
				res += "\\b";
				break;
			case '\f':
				res += "\\f";
				break;
			case '\n':
				res += "\\n";
				break;
			case '\r':
				res += "\\r";
				break;
			case '\t':
				res += "\\t";
				break;
			case '\v':
				res += "\\v";
				break;

			case '\\':
				res += "\\\\";
				break;
			case '"':
				res += "\\\"";
				break;

			default:
				if ( isprint(c) )
					res += c;
				else
					{
					char buf[8192];
					snprintf(buf, sizeof buf, "%03o", c);
					res += "\\";
					res += buf;
					}
				break;
			}
		}

	return res + "\"";
	}

void CPPCompile::Indent() const
	{
	for ( auto i = 0; i < block_level; ++i )
		fprintf(write_file, "%s", "\t");
	}

	} // zeek::detail
