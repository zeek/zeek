// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "List.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(Val, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(ID, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Stmt, zeek::detail);
namespace zeek { class Type; }
using BroType [[deprecated("Remove in v4.1. Use zeek::Type instead.")]] = zeek::Type;
ZEEK_FORWARD_DECLARE_NAMESPACED(Attr, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Timer, zeek::detail);

namespace zeek {

using val_list = PList<Val>;
using expr_list = PList<detail::Expr>;
using id_list = PList<detail::ID>;
using stmt_list = PList<detail::Stmt>;
using type_list = PList<Type>;
using attr_list = PList<detail::Attr>;
using timer_list = PList<detail::Timer, ListOrder::UNORDERED>;

} // namespace zeek

using val_list [[deprecated("Remove in v4.1. Use zeek::val_list.")]] = zeek::val_list;
using expr_list [[deprecated("Remove in v4.1. Use zeek::expr_list.")]] = zeek::expr_list;
using id_list [[deprecated("Remove in v4.1. Use zeek::id_list.")]] = zeek::id_list;
using stmt_list [[deprecated("Remove in v4.1. Use zeek::stmt_list.")]] = zeek::stmt_list;
using type_list [[deprecated("Remove in v4.1. Use zeek::type_list.")]] = zeek::type_list;
using attr_list [[deprecated("Remove in v4.1. Use zeek::attr_list.")]] = zeek::attr_list;
using timer_list [[deprecated("Remove in v4.1. Use zeek::timer_list.")]] = zeek::timer_list;
