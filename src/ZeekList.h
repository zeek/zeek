// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/List.h"

namespace zeek {
namespace detail {

class Expr;
class ID;
class Stmt;
class Attr;
class Timer;

} // namespace detail

class Val;
class Type;

using ValPList = PList<Val>;
using ExprPList = PList<detail::Expr>;
using IDPList = PList<detail::ID>;
using StmtPList = PList<detail::Stmt>;
using TypePList = PList<Type>;
using AttrPList = PList<detail::Attr>;
using TimerPList = PList<detail::Timer, ListOrder::UNORDERED>;

} // namespace zeek
