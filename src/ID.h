// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "IntrusivePtr.h"
#include "Obj.h"
#include "Attr.h"
#include "Notifier.h"
#include "TraverseTypes.h"

#include <map>
#include <string>
#include <vector>

class Val;
class Expr;
class Func;
class BroType;
class Attributes;

typedef enum { INIT_NONE, INIT_FULL, INIT_EXTRA, INIT_REMOVE, } init_class;
typedef enum { SCOPE_FUNCTION, SCOPE_MODULE, SCOPE_GLOBAL } IDScope;

class ID : public BroObj, public notifier::Modifiable {
public:
	ID(const char* name, IDScope arg_scope, bool arg_is_export);
	~ID() override;

	const char* Name() const	{ return name; }

	int Scope() const		{ return scope; }
	bool IsGlobal() const           { return scope != SCOPE_FUNCTION; }

	bool IsExport() const           { return is_export; }
	void SetExport()                { is_export = true; }

	std::string ModuleName() const;

	void SetType(IntrusivePtr<BroType> t);
	BroType* Type()			{ return type.get(); }
	const BroType* Type() const	{ return type.get(); }

	void MakeType()			{ is_type = true; }
	BroType* AsType()		{ return is_type ? Type() : 0; }
	const BroType* AsType() const	{ return is_type ? Type() : 0; }

	// If weak_ref is false, the Val is assumed to be already ref'ed
	// and will be deref'ed when the ID is deleted.
	//
	// If weak_ref is true, we store the Val but don't ref/deref it.
	// That means that when the ID becomes the only one holding a
	// reference to the Val, the Val will be destroyed (naturally,
	// you have to take care that it will not be accessed via
	// the ID afterwards).
	void SetVal(IntrusivePtr<Val> v, bool weak_ref = false);

	void SetVal(IntrusivePtr<Val> v, init_class c);
	void SetVal(IntrusivePtr<Expr> ev, init_class c);

	bool HasVal() const		{ return val != 0; }
	Val* ID_Val()			{ return val; }
	const Val* ID_Val() const	{ return val; }
	void ClearVal();

	void SetConst()			{ is_const = true; }
	bool IsConst() const		{ return is_const; }

	void SetOption();
	bool IsOption() const		{ return is_option; }

	void SetEnumConst()		{ is_enum_const = true; }
	bool IsEnumConst() const		{ return is_enum_const; }

	void SetOffset(int arg_offset)	{ offset = arg_offset; }
	int Offset() const		{ return offset; }

	bool IsRedefinable() const;

	void SetAttrs(IntrusivePtr<Attributes> attr);
	void AddAttrs(IntrusivePtr<Attributes> attr);
	void RemoveAttr(attr_tag a);
	void UpdateValAttrs();
	Attributes* Attrs() const	{ return attrs.get(); }

	Attr* FindAttr(attr_tag t) const;

	bool IsDeprecated() const;

	void MakeDeprecated(IntrusivePtr<Expr> deprecation);

	std::string GetDeprecationWarning() const;

	void Error(const char* msg, const BroObj* o2 = 0);

	void Describe(ODesc* d) const override;
	// Adds type and value to description.
	void DescribeExtended(ODesc* d) const;
	// Produces a description that's reST-ready.
	void DescribeReST(ODesc* d, bool roles_only = false) const;
	void DescribeReSTShort(ODesc* d) const;

	bool DoInferReturnType() const
		{ return infer_return_type; }
	void SetInferReturnType(bool infer)
		{ infer_return_type = infer; }

	virtual TraversalCode Traverse(TraversalCallback* cb) const;

	bool HasOptionHandlers() const
		{ return !option_handlers.empty(); }

	void AddOptionHandler(IntrusivePtr<Func> callback, int priority);
	std::vector<Func*> GetOptionHandlers() const;

protected:
	void EvalFunc(IntrusivePtr<Expr> ef, IntrusivePtr<Expr> ev);

#ifdef DEBUG
	void UpdateValID();
#endif

	const char* name;
	IDScope scope;
	bool is_export;
	IntrusivePtr<BroType> type;
	bool is_const, is_enum_const, is_type, is_option;
	int offset;
	Val* val;
	IntrusivePtr<Attributes> attrs;
	// contains list of functions that are called when an option changes
	std::multimap<int, IntrusivePtr<Func>> option_handlers;

	bool infer_return_type;
	bool weak_ref;
};
