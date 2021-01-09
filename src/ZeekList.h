// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/List.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(Val, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(ID, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Stmt, zeek::detail);
namespace zeek
{
class Type;
}
using BroType [[deprecated("Remove in v4.1. Use zeek::Type instead.")]] = zeek::Type;
ZEEK_FORWARD_DECLARE_NAMESPACED(Attr, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Timer, zeek::detail);

namespace zeek
{

using ValPList = PList<Val>;
using ExprPList = PList<detail::Expr>;
using IDPList = PList<detail::ID>;
using StmtPList = PList<detail::Stmt>;
using TypePList = PList<Type>;
using AttrPList = PList<detail::Attr>;
using TimerPList = PList<detail::Timer, ListOrder::UNORDERED>;

} // namespace zeek

using val_list [[deprecated("Remove in v4.1. Use zeek::ValPList.")]] = zeek::ValPList;
using expr_list [[deprecated("Remove in v4.1. Use zeek::ExprPList.")]] = zeek::ExprPList;
using id_list [[deprecated("Remove in v4.1. Use zeek::IDPList.")]] = zeek::IDPList;
using stmt_list [[deprecated("Remove in v4.1. Use zeek::StmtPList.")]] = zeek::StmtPList;
using type_list [[deprecated("Remove in v4.1. Use zeek::TypePList.")]] = zeek::TypePList;
using attr_list [[deprecated("Remove in v4.1. Use zeek::AttrPList.")]] = zeek::AttrPList;
using timer_list [[deprecated("Remove in v4.1. Use zeek::TimerPList.")]] = zeek::TimerPList;
