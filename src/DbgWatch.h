// Structures and methods for implementing watches in the Bro debugger.

#pragma once

#include "util.h"

class BroObj;

FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);

class DbgWatch {
public:
	explicit DbgWatch(BroObj* var_to_watch);
	explicit DbgWatch(zeek::detail::Expr* expr_to_watch);
	~DbgWatch();

protected:
	BroObj* var;
	zeek::detail::Expr* expr;
};
