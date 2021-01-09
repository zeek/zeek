// Structures and methods for implementing watches in the Bro debugger.

#pragma once

#include "zeek/util.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);
namespace zeek
{
class Obj;
}
using BroObj [[deprecated("Remove in v4.1. Use zeek:Obj instead.")]] = zeek::Obj;

namespace zeek::detail
{

class DbgWatch
	{
public:
	explicit DbgWatch(Obj* var_to_watch);
	explicit DbgWatch(Expr* expr_to_watch);
	~DbgWatch() = default;

protected:
	Obj* var;
	Expr* expr;
	};

} // namespace zeek::detail

using DbgWatch [[deprecated("Remove in v4.1. Using zeek::detail::DbgWatch.")]] =
	zeek::detail::DbgWatch;
