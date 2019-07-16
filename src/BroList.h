// See the file "COPYING" in the main distribution directory for copyright.

#ifndef brolist_h
#define brolist_h

#include "List.h"

class Expr;
typedef PList<Expr> expr_list;

class ID;
typedef PList<ID> id_list;

class Val;
typedef PList<Val> val_list;

class Stmt;
typedef PList<Stmt> stmt_list;

class BroType;
typedef PList<BroType> type_list;

class Attr;
typedef PList<Attr> attr_list;

class Timer;
typedef PList<Timer> timer_list;

#endif
