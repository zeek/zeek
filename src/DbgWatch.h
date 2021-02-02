// Structures and methods for implementing watches in the Bro debugger.

#pragma once

#include "zeek/util.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);
namespace zeek { class Obj; }

namespace zeek::detail {

class DbgWatch {
public:
	explicit DbgWatch(Obj* var_to_watch);
	explicit DbgWatch(Expr* expr_to_watch);
	~DbgWatch() = default;

protected:
	Obj* var;
	Expr* expr;
};

} // namespace zeek::detail
