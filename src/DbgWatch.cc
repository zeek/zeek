// See the file "COPYING" in the main distribution directory for copyright.

// Implementation of watches

#include "zeek/DbgWatch.h"

#include "zeek/Debug.h"
#include "zeek/Reporter.h"

namespace zeek::detail {

// Support classes
DbgWatch::DbgWatch(zeek::Obj* var_to_watch) { reporter->InternalError("DbgWatch unimplemented"); }

DbgWatch::DbgWatch(Expr* expr_to_watch) { reporter->InternalError("DbgWatch unimplemented"); }

} // namespace zeek::detail
