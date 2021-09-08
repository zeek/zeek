// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "zeek/Obj.h"
#include "zeek/Attr.h"
#include "zeek/Notifier.h"
#include "zeek/TraverseTypes.h"

namespace zeek {

class Func;
class Val;
class RecordType;
class TableType;
class VectorType;
class EnumType;
class Type;
using TypePtr = IntrusivePtr<Type>;
using RecordTypePtr = IntrusivePtr<RecordType>;
using TableTypePtr = IntrusivePtr<TableType>;
using VectorTypePtr = IntrusivePtr<VectorType>;
using EnumTypePtr = IntrusivePtr<EnumType>;
using ValPtr = IntrusivePtr<Val>;
using FuncPtr = IntrusivePtr<Func>;

}

namespace zeek::detail {

class Attributes;
class Expr;
using ExprPtr = IntrusivePtr<Expr>;

enum InitClass { INIT_NONE, INIT_FULL, INIT_EXTRA, INIT_REMOVE, };
enum IDScope { SCOPE_FUNCTION, SCOPE_MODULE, SCOPE_GLOBAL };

class ID;
using IDPtr = IntrusivePtr<ID>;

class IDOptInfo;

class ID final : public Obj, public notifier::detail::Modifiable {
public:
	static inline const IDPtr nil;

	ID(const char* name, IDScope arg_scope, bool arg_is_export);

	~ID() override;

	const char* Name() const	{ return name; }

	int Scope() const		{ return scope; }
	bool IsGlobal() const           { return scope != SCOPE_FUNCTION; }

	bool IsExport() const           { return is_export; }
	void SetExport()                { is_export = true; }

	std::string ModuleName() const;

	void SetType(TypePtr t);

	const TypePtr& GetType() const
		{ return type; }

	template <class T>
	IntrusivePtr<T> GetType() const
		{ return cast_intrusive<T>(type); }

	bool IsType() const
		{ return is_type; }

	void MakeType()			{ is_type = true; }

	void SetVal(ValPtr v);

	void SetVal(ValPtr v, InitClass c);
	void SetVal(ExprPtr ev, InitClass c);

	bool HasVal() const		{ return val != nullptr; }

	const ValPtr& GetVal() const
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

	void SetAttrs(AttributesPtr attr);
	void AddAttrs(AttributesPtr attr, bool is_redef = false);
	void RemoveAttr(AttrTag a);
	void UpdateValAttrs();

	const AttributesPtr& GetAttrs() const
		{ return attrs; }

	const AttrPtr& GetAttr(AttrTag t) const;

	bool IsDeprecated() const;

	void MakeDeprecated(ExprPtr deprecation);

	std::string GetDeprecationWarning() const;

	void Error(const char* msg, const Obj* o2 = nullptr);

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

	void AddOptionHandler(FuncPtr callback, int priority);
	std::vector<Func*> GetOptionHandlers() const;

	IDOptInfo* GetOptInfo() const			{ return opt_info; }

protected:
	void EvalFunc(ExprPtr ef, ExprPtr ev);

#ifdef DEBUG
	void UpdateValID();
#endif

	const char* name;
	IDScope scope;
	bool is_export;
	bool infer_return_type;
	TypePtr type;
	bool is_const, is_enum_const, is_type, is_option;
	int offset;
	ValPtr val;
	AttributesPtr attrs;

	// contains list of functions that are called when an option changes
	std::multimap<int, FuncPtr> option_handlers;

	// Information managed by script optimization.  We package this
	// up into a separate object for purposes of modularity, and,
	// via the associated pointer, to allow it to be modified in
	// contexts where the ID is itself "const".
	IDOptInfo* opt_info;

};

} // namespace zeek::detail

namespace zeek::id {

/**
 * Lookup an ID in the global module and return it, if one exists;
 * @param name  The identifier name to lookup.
 * @return  The identifier, which may reference a nil object if no such
 * name exists.
 */
const detail::IDPtr& find(std::string_view name);

/**
 * Lookup an ID by its name and return its type.  A fatal occurs if the ID
 * does not exist.
 * @param name  The identifier name to lookup
 * @return  The type of the identifier.
 */
const TypePtr& find_type(std::string_view name);

/**
 * Lookup an ID by its name and return its type (as cast to @c T).
 * A fatal occurs if the ID does not exist.
 * @param name  The identifier name to lookup
 * @return  The type of the identifier.
 */
template<class T>
IntrusivePtr<T> find_type(std::string_view name)
	{ return cast_intrusive<T>(find_type(name)); }

/**
 * Lookup an ID by its name and return its value.  A fatal occurs if the ID
 * does not exist.
 * @param name  The identifier name to lookup
 * @return  The current value of the identifier
 */
const ValPtr& find_val(std::string_view name);

/**
 * Lookup an ID by its name and return its value (as cast to @c T).
 * A fatal occurs if the ID does not exist.
 * @param name  The identifier name to lookup
 * @return  The current value of the identifier.
 */
template<class T>
IntrusivePtr<T> find_val(std::string_view name)
	{ return cast_intrusive<T>(find_val(name)); }

/**
 * Lookup an ID by its name and return its value.  A fatal occurs if the ID
 * does not exist or if it is not "const".
 * @param name  The identifier name to lookup
 * @return  The current value of the identifier
 */
const ValPtr& find_const(std::string_view name);

/**
 * Lookup an ID by its name and return its value (as cast to @c T).
 * A fatal occurs if the ID does not exist.
 * @param name  The identifier name to lookup
 * @return  The current value of the identifier.
 */
template<class T>
IntrusivePtr<T> find_const(std::string_view name)
	{ return cast_intrusive<T>(find_const(name)); }

/**
 * Lookup an ID by its name and return the function it references.
 * A fatal occurs if the ID does not exist or if it is not a function.
 * @param name  The identifier name to lookup
 * @return  The current function value the identifier references.
 */
FuncPtr find_func(std::string_view name);

extern RecordTypePtr conn_id;
extern RecordTypePtr endpoint;
extern RecordTypePtr connection;
extern RecordTypePtr fa_file;
extern RecordTypePtr fa_metadata;
extern EnumTypePtr transport_proto;
extern TableTypePtr string_set;
extern TableTypePtr string_array;
extern TableTypePtr count_set;
extern VectorTypePtr string_vec;
extern VectorTypePtr index_vec;

namespace detail {

void init_types();

} // namespace detail
} // namespace zeek::id
