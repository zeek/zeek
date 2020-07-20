// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "List.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(Val, zeek);
using val_list = zeek::PList<zeek::Val>;

ZEEK_FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);
using expr_list = zeek::PList<zeek::detail::Expr>;

ZEEK_FORWARD_DECLARE_NAMESPACED(ID, zeek::detail);
using id_list = zeek::PList<zeek::detail::ID>;

ZEEK_FORWARD_DECLARE_NAMESPACED(Stmt, zeek::detail);
using stmt_list = zeek::PList<zeek::detail::Stmt>;

namespace zeek { class Type; }
using BroType [[deprecated("Remove in v4.1. Use zeek::Type instead.")]] = zeek::Type;
using type_list = zeek::PList<zeek::Type>;

ZEEK_FORWARD_DECLARE_NAMESPACED(Attr, zeek::detail);
using attr_list = zeek::PList<zeek::detail::Attr>;

ZEEK_FORWARD_DECLARE_NAMESPACED(Timer, zeek::detail);
using timer_list = zeek::PList<zeek::detail::Timer, zeek::ListOrder::UNORDERED>;
