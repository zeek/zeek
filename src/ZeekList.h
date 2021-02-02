// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/List.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(Val, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(ID, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Stmt, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Attr, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Timer, zeek::detail);

namespace zeek {

class Type;

using ValPList = PList<Val>;
using ExprPList = PList<detail::Expr>;
using IDPList = PList<detail::ID>;
using StmtPList = PList<detail::Stmt>;
using TypePList = PList<Type>;
using AttrPList = PList<detail::Attr>;
using TimerPList = PList<detail::Timer, ListOrder::UNORDERED>;

} // namespace zeek
