// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "List.h"

class Val;
using val_list = PList<Val>;

FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);
using expr_list = PList<zeek::detail::Expr>;

FORWARD_DECLARE_NAMESPACED(ID, zeek::detail);
using id_list = PList<zeek::detail::ID>;

FORWARD_DECLARE_NAMESPACED(Stmt, zeek::detail);
using stmt_list = PList<zeek::detail::Stmt>;

class BroType;
using type_list = PList<BroType>;

FORWARD_DECLARE_NAMESPACED(Attr, zeek::detail);
using attr_list = PList<zeek::detail::Attr>;

class Timer;
using timer_list = PList<Timer, ListOrder::UNORDERED>;
