// Structures and methods for implementing watches in the Bro debugger.

#pragma once

#include "util.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);
namespace zeek { class Obj; }
using BroObj [[deprecated("Remove in v4.1. Use zeek:Obj instead.")]] = zeek::Obj;

namespace zeek::detail {

class DbgWatch {
public:
	explicit DbgWatch(zeek::Obj* var_to_watch);
	explicit DbgWatch(zeek::detail::Expr* expr_to_watch);
	~DbgWatch() = default;

protected:
	zeek::Obj* var;
	zeek::detail::Expr* expr;
};

} // namespace zeek::detail

using DbgWatch [[deprecated("Remove in v4.1. Using zeek::detail::DbgWatch.")]] = zeek::detail::DbgWatch;
