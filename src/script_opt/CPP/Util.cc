// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/CPP/Util.h"

#include <sys/file.h>
#include <unistd.h>
#include <cerrno>

#include "zeek/script_opt/StmtOptInfo.h"

namespace zeek::detail
	{

using namespace std;

string Fmt(double d)
	{
	// Special hack to preserve the signed-ness of the magic -0.0.
	if ( d == 0.0 && signbit(d) )
		return "-0.0";

	// Unfortunately, to_string(double) is hardwired to use %f with
	// default of 6 digits precision.
	char buf[8192];
	snprintf(buf, sizeof buf, "%.17g", d);
	return buf;
	}

string scope_prefix(const string& scope)
	{
	return "zeek::detail::CPP_" + scope;
	}

string scope_prefix(int scope)
	{
	return scope_prefix(to_string(scope));
	}

bool is_CPP_compilable(const ProfileFunc* pf, const char** reason)
	{
	if ( analysis_options.allow_cond )
		return true;

	auto body = pf->ProfiledBody();
	if ( body && ! body->GetOptInfo()->is_free_of_conditionals )
		{
		if ( reason )
			*reason = "body may be affected by @if conditional";
		return false;
		}

	return true;
	}

void lock_file(const string& fname, FILE* f)
	{
	if ( flock(fileno(f), LOCK_EX) < 0 )
		{
		char buf[256];
		util::zeek_strerror_r(errno, buf, sizeof(buf));
		reporter->Error("flock failed on %s: %s", fname.c_str(), buf);
		exit(1);
		}
	}

void unlock_file(const string& fname, FILE* f)
	{
	if ( flock(fileno(f), LOCK_UN) < 0 )
		{
		char buf[256];
		util::zeek_strerror_r(errno, buf, sizeof(buf));
		reporter->Error("un-flock failed on %s: %s", fname.c_str(), buf);
		exit(1);
		}
	}

string CPPEscape(const char* b, int len)
	{
	string res;

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

	return res;
	}

	} // zeek::detail
