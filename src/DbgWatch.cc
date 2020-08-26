// Implementation of watches

#include "zeek-config.h"

#include "Debug.h"
#include "DbgWatch.h"
#include "Reporter.h"

namespace zeek::detail {

// Support classes
DbgWatch::DbgWatch(zeek::Obj* var_to_watch)
	{
	reporter->InternalError("DbgWatch unimplemented");
	}

DbgWatch::DbgWatch(Expr* expr_to_watch)
	{
	reporter->InternalError("DbgWatch unimplemented");
	}

} // namespace zeek::detail
