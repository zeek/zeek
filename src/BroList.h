// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "List.h"

FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);
typedef PList<zeek::detail::Expr> expr_list;

class ID;
typedef PList<ID> id_list;

class Val;
typedef PList<Val> val_list;

FORWARD_DECLARE_NAMESPACED(Stmt, zeek::detail);
typedef PList<zeek::detail::Stmt> stmt_list;

class BroType;
typedef PList<BroType> type_list;

class Attr;
typedef PList<Attr> attr_list;

class Timer;
typedef PList<Timer, ListOrder::UNORDERED> timer_list;
