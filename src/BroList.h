// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "List.h"

class Val;
using val_list = PList<Val>;

ZEEK_FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);
using expr_list = PList<zeek::detail::Expr>;

ZEEK_FORWARD_DECLARE_NAMESPACED(ID, zeek::detail);
using id_list = PList<zeek::detail::ID>;

ZEEK_FORWARD_DECLARE_NAMESPACED(Stmt, zeek::detail);
using stmt_list = PList<zeek::detail::Stmt>;

namespace zeek { class Type; }
using BroType [[deprecated("Remove in v4.1. Use zeek::Type instead.")]] = zeek::Type;
using type_list = PList<zeek::Type>;

ZEEK_FORWARD_DECLARE_NAMESPACED(Attr, zeek::detail);
using attr_list = PList<zeek::detail::Attr>;

class Timer;
using timer_list = PList<Timer, ListOrder::UNORDERED>;
