// See the file "COPYING" in the main distribution directory for copyright.

// Low-level support utilities/globals for ZAM compilation.

#include "zeek/Reporter.h"
#include "zeek/Desc.h"
#include "zeek/ZeekString.h"
#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/script_opt/ZAM/Support.h"

namespace zeek::detail {

const Stmt* curr_stmt;
TypePtr log_ID_enum_type;
TypePtr any_base_type;
bool ZAM_error = false;

bool is_ZAM_compilable(const ProfileFunc* pf, const char** reason)
	{
	if ( pf->NumLambdas() > 0 )
		{
		if ( reason )
			*reason = "use of lambda";
		return false;
		}

	if ( pf->NumWhenStmts() > 0 )
		{
		if ( reason )
			*reason = "use of \"when\"";
		return false;
		}

	return true;
	}

bool IsAny(const Type* t)
	{
	return t->Tag() == TYPE_ANY;
	}


StringVal* ZAM_to_lower(const StringVal* sv)
	{
	auto bs = sv->AsString();
	const u_char* s = bs->Bytes();
	int n = bs->Len();
	u_char* lower_s = new u_char[n + 1];
	u_char* ls = lower_s;

	for ( int i = 0; i < n; ++i )
		{
		if ( isascii(s[i]) && isupper(s[i]) )
			*ls++ = tolower(s[i]);
		else
			*ls++ = s[i];
		}

	*ls++ = '\0';
		
	return new StringVal(new String(1, lower_s, n));
	}

StringVal* ZAM_sub_bytes(const StringVal* s, bro_uint_t start, bro_int_t n)
	{
	if ( start > 0 )
		--start;        // make it 0-based

	auto ss = s->AsString()->GetSubstring(start, n);

	return new StringVal(ss ? ss : new String(""));
	}

void ZAM_run_time_error(const char* msg)
	{
	fprintf(stderr, "%s\n", msg);
	ZAM_error = true;
	}

void ZAM_run_time_error(const Location* loc, const char* msg)
	{
	reporter->RuntimeError(loc, "%s", msg);
	ZAM_error = true;
	}

void ZAM_run_time_error(const char* msg, const Obj* o)
	{
	fprintf(stderr, "%s: %s\n", msg, obj_desc(o).c_str());
	ZAM_error = true;
	}

void ZAM_run_time_error(const Location* loc, const char* msg, const Obj* o)
	{
	reporter->RuntimeError(loc, "%s (%s)", msg, obj_desc(o).c_str());
	ZAM_error = true;
	}

void ZAM_run_time_warning(const Location* loc, const char* msg)
	{
	ODesc d;
	loc->Describe(&d);

	reporter->Warning("%s: %s", d.Description(), msg);
	}

} // namespace zeek::detail
