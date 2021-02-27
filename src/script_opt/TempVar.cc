// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/TempVar.h"
#include "zeek/Reporter.h"


namespace zeek::detail {

TempVar::TempVar(int num, const TypePtr& t, ExprPtr _rhs) : type(t)
	{
	char buf[8192];
	snprintf(buf, sizeof buf, "#%d", num);
	name = buf;
	rhs = _rhs;
	}

void TempVar::SetAlias(IDPtr _alias, const DefPoints* _dps)
	{
	if ( alias )
		reporter->InternalError("Re-aliasing a temporary");

	if ( ! _dps )
		{
		printf("trying to alias %s to %s\n", name.c_str(), _alias->Name());
		reporter->InternalError("Empty dps for alias");
		}

	if ( alias == id )
		reporter->InternalError("Creating alias loop");

	alias = _alias;
	dps = _dps;
	}

void TempVar::SetDPs(const DefPoints* _dps)
	{
	ASSERT(_dps->length() == 1);
	dps = _dps;
	}

} // zeek::detail
