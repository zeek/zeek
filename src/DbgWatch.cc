// Implementation of watches

#include "zeek-config.h"

#include "Debug.h"
#include "DbgWatch.h"
#include "Reporter.h"

// Support classes
zeek::detail::DbgWatch::DbgWatch(zeek::Obj* var_to_watch)
	{
	reporter->InternalError("DbgWatch unimplemented");
	}

zeek::detail::DbgWatch::DbgWatch(zeek::detail::Expr* expr_to_watch)
	{
	reporter->InternalError("DbgWatch unimplemented");
	}
