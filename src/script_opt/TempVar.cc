// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/TempVar.h"
#include "zeek/Reporter.h"


namespace zeek::detail {

TempVar::TempVar(int num, const TypePtr& t, ExprPtr _rhs) : type(t)
	{
	char buf[8192];
	snprintf(buf, sizeof buf, "#%d", num);
	name = buf;
	rhs = std::move(_rhs);
	}

void TempVar::SetAlias(IDPtr _alias)
	{
	if ( alias )
		reporter->InternalError("Re-aliasing a temporary");

	if ( alias == id )
		reporter->InternalError("Creating alias loop");

	alias = std::move(_alias);
	}

} // zeek::detail
