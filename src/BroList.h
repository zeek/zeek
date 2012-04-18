// See the file "COPYING" in the main distribution directory for copyright.

#ifndef brolist_h
#define brolist_h

#include "List.h"

class Expr;
declare(PList,Expr);
typedef PList(Expr) expr_list;

class ID;
declare(PList,ID);
typedef PList(ID) id_list;

class HashKey;
declare(PList,HashKey);
typedef PList(HashKey) hash_key_list;

class Val;
declare(PList,Val);
typedef PList(Val) val_list;

class Stmt;
declare(PList,Stmt);
typedef PList(Stmt) stmt_list;

class BroType;
declare(PList,BroType);
typedef PList(BroType) type_list;

class TypeDecl;
declare(PList,TypeDecl);
typedef PList(TypeDecl) type_decl_list;

class Case;
declare(PList,Case);
typedef PList(Case) case_list;

class Attr;
declare(PList,Attr);
typedef PList(Attr) attr_list;

class Scope;
declare(PList,Scope);
typedef PList(Scope) scope_list;

class Timer;
declare(PList,Timer);
typedef PList(Timer) timer_list;

class DNS_Mgr_Request;
declare(PList,DNS_Mgr_Request);
typedef PList(DNS_Mgr_Request) DNS_mgr_request_list;

#endif
