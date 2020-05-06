// See the file "COPYING" in the main distribution directory for copyright.

#include "TempVar.h"
#include "Reporter.h"


TempVar::TempVar(int num, const IntrusivePtr<BroType>& t,
			IntrusivePtr<Expr> _rhs) : type(t), dps(nullptr)
	{
	char buf[8192];
	snprintf(buf, sizeof buf, "#%d", num);
	name = copy_string(buf);
	id = nullptr;
	rhs = _rhs;
	const_expr = nullptr;
	alias = nullptr;
	dps = nullptr;
	max_rds = nullptr;
	}

void TempVar::SetAlias(IntrusivePtr<ID> _alias, const DefPoints* _dps)
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
