// Structures and methods for implementing watches in the Bro debugger.

#pragma once

#include "util.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(BroObj, zeek);

class DbgWatch {
public:
	explicit DbgWatch(zeek::BroObj* var_to_watch);
	explicit DbgWatch(zeek::detail::Expr* expr_to_watch);
	~DbgWatch();

protected:
	zeek::BroObj* var;
	zeek::detail::Expr* expr;
};
