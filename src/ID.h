// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "IntrusivePtr.h"
#include "Obj.h"
#include "Attr.h"
#include "Notifier.h"
#include "TraverseTypes.h"

#include <map>
#include <string>
#include <string_view>
#include <vector>

class Val;
class Expr;
class Func;
class BroType;
class RecordType;
class TableType;
class VectorType;
class EnumType;
class Attributes;

typedef enum { INIT_NONE, INIT_FULL, INIT_EXTRA, INIT_REMOVE, } init_class;
typedef enum { SCOPE_FUNCTION, SCOPE_MODULE, SCOPE_GLOBAL } IDScope;

class ID final : public BroObj, public notifier::Modifiable {
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

	[[deprecated("Remove in v4.1.  Use GetType().")]]
	BroType* Type()			{ return type.get(); }
	[[deprecated("Remove in v4.1.  Use GetType().")]]
	const BroType* Type() const	{ return type.get(); }

	const IntrusivePtr<BroType>& GetType() const
		{ return type; }

	[[deprecated("Remove in v4.1.  Use IsType() and GetType().")]]
	BroType* AsType()		{ return is_type ? GetType().get() : nullptr; }
	[[deprecated("Remove in v4.1.  Use IsType() and GetType().")]]
	const BroType* AsType() const	{ return is_type ? GetType().get() : nullptr; }

	bool IsType() const
		{ return is_type; }

	void MakeType()			{ is_type = true; }

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

	bool HasVal() const		{ return val != nullptr; }

	[[deprecated("Remove in v4.1.  Use GetVal().")]]
	Val* ID_Val()			{ return val.get(); }
	[[deprecated("Remove in v4.1.  Use GetVal().")]]
	const Val* ID_Val() const	{ return val.get(); }

	const IntrusivePtr<Val>& GetVal() const
		{ return val; }

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

	void Error(const char* msg, const BroObj* o2 = nullptr);

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
	bool infer_return_type;
	bool weak_ref;
	IntrusivePtr<BroType> type;
	bool is_const, is_enum_const, is_type, is_option;
	int offset;
	IntrusivePtr<Val> val;
	IntrusivePtr<Attributes> attrs;
	// contains list of functions that are called when an option changes
	std::multimap<int, IntrusivePtr<Func>> option_handlers;

};

namespace zeek { namespace id {

/**
 * Lookup an ID in the global module and return it, if one exists;
 * @param name  The identifier name to lookup.
 * @return  The identifier, which may reference a nil object if no such
 * name exists.
 */
const IntrusivePtr<ID>& lookup(std::string_view name);

/**
 * Lookup an ID by its name and return its type.  A fatal occurs if the ID
 * does not exist.
 * @param name  The identifier name to lookup
 * @return  The type of the identifier.
 */
const IntrusivePtr<BroType>& lookup_type(std::string_view name);

/**
 * Lookup an ID by its name and return its type (as cast to @c T).
 * A fatal occurs if the ID does not exist.
 * @param name  The identifier name to lookup
 * @return  The type of the identifier.
 */
template<class T>
IntrusivePtr<T> lookup_type(std::string_view name)
	{ return cast_intrusive<T>(lookup_type(name)); }

/**
 * Lookup an ID by its name and return its value.  A fatal occurs if the ID
 * does not exist.
 * @param name  The identifier name to lookup
 * @return  The current value of the identifier
 */
const IntrusivePtr<Val>& lookup_val(std::string_view name);

/**
 * Lookup an ID by its name and return its value (as cast to @c T).
 * A fatal occurs if the ID does not exist.
 * @param name  The identifier name to lookup
 * @return  The current value of the identifier.
 */
template<class T>
IntrusivePtr<T> lookup_val(std::string_view name)
	{ return cast_intrusive<T>(lookup_val(name)); }

/**
 * Lookup an ID by its name and return its value.  A fatal occurs if the ID
 * does not exist or if it is not "const".
 * @param name  The identifier name to lookup
 * @return  The current value of the identifier
 */
const IntrusivePtr<Val>& lookup_const(std::string_view name);

/**
 * Lookup an ID by its name and return the function it references.
 * A fatal occurs if the ID does not exist or if it is not a function.
 * @param name  The identifier name to lookup
 * @return  The current function value the identifier references.
 */
IntrusivePtr<Func> lookup_func(std::string_view name);

extern IntrusivePtr<RecordType> conn_id;
extern IntrusivePtr<RecordType> endpoint;
extern IntrusivePtr<RecordType> connection;
extern IntrusivePtr<RecordType> fa_file;
extern IntrusivePtr<RecordType> fa_metadata;
extern IntrusivePtr<EnumType> transport_proto;
extern IntrusivePtr<TableType> string_set;
extern IntrusivePtr<TableType> string_array;
extern IntrusivePtr<TableType> count_set;
extern IntrusivePtr<VectorType> string_vec;
extern IntrusivePtr<VectorType> index_vec;

namespace detail {

void init();

} // namespace zeek::id::detail

}} // namespace zeek::id
