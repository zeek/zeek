// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/TempVar.h"
#include "zeek/Reporter.h"


namespace zeek::detail {

TempVar::TempVar(int num, const TypePtr& t, ExprPtr _rhs) : type(t)
	{
	char buf[8192];
	snprintf(buf, sizeof buf, "#%d", num);
	name = util::copy_string(buf);
	id = nullptr;
	}

} // zeek::detail
