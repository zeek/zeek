// See the file "COPYING" in the main distribution directory for copyright.

#include "TempVar.h"
#include "Reporter.h"


namespace zeek::detail {


TempVar::TempVar(int num, const TypePtr& t, ExprPtr _rhs) : type(t)
	{
	char buf[8192];
	snprintf(buf, sizeof buf, "#%d", num);
	name = util::copy_string(buf);
	id = nullptr;

#ifdef NOT_YET
	rhs = _rhs;
	const_expr = nullptr;
	alias = nullptr;
	max_rds = nullptr;
	dps = nullptr;
#endif
	}

#ifdef NOT_YET
void TempVar::SetAlias(IDPtr _alias, const DefPoints* _dps)
	{
	if ( alias )
		reporter->InternalError("Re-aliasing a temporary");

	if ( ! _dps )
		{
		printf("trying to alias %s to %s\n", name, _alias->Name());
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
#endif


} // zeek::detail
