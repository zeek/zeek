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

ZEEK_FORWARD_DECLARE_NAMESPACED(Func, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Val, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(RecordType, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(TableType, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(VectorType, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(EnumType, zeek);

namespace zeek {
class Type;
using TypePtr = zeek::IntrusivePtr<zeek::Type>;
using RecordTypePtr = zeek::IntrusivePtr<zeek::RecordType>;
using TableTypePtr = zeek::IntrusivePtr<zeek::TableType>;
using VectorTypePtr = zeek::IntrusivePtr<zeek::VectorType>;
using EnumTypePtr = zeek::IntrusivePtr<zeek::EnumType>;
using ValPtr = zeek::IntrusivePtr<zeek::Val>;
using FuncPtr = zeek::IntrusivePtr<zeek::Func>;
}

using BroType [[deprecated("Remove in v4.1. Use zeek::Type instead.")]] = zeek::Type;

namespace zeek::detail {

class Attributes;
class Expr;
using ExprPtr = zeek::IntrusivePtr<Expr>;

enum InitClass { INIT_NONE, INIT_FULL, INIT_EXTRA, INIT_REMOVE, };
enum IDScope { SCOPE_FUNCTION, SCOPE_MODULE, SCOPE_GLOBAL };

class ID;
using IDPtr = zeek::IntrusivePtr<ID>;

class ID final : public Obj, public zeek::notifier::detail::Modifiable {
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

	void SetType(zeek::TypePtr t);
	[[deprecated("Remove in v4.1.  Use version that takes IntrusivePtr.")]]
	void SetType(zeek::Type* t);

	[[deprecated("Remove in v4.1.  Use GetType().")]]
	zeek::Type* Type()			{ return type.get(); }
	[[deprecated("Remove in v4.1.  Use GetType().")]]
	const zeek::Type* Type() const	{ return type.get(); }

	const TypePtr& GetType() const
		{ return type; }

	template <class T>
	zeek::IntrusivePtr<T> GetType() const
		{ return zeek::cast_intrusive<T>(type); }

	[[deprecated("Remove in v4.1.  Use IsType() and GetType().")]]
	zeek::Type* AsType()		{ return is_type ? GetType().get() : nullptr; }
	[[deprecated("Remove in v4.1.  Use IsType() and GetType().")]]
	const zeek::Type* AsType() const	{ return is_type ? GetType().get() : nullptr; }

	bool IsType() const
		{ return is_type; }

	void MakeType()			{ is_type = true; }

	void SetVal(ValPtr v);

	void SetVal(ValPtr v, InitClass c);
	void SetVal(ExprPtr ev, InitClass c);

	bool HasVal() const		{ return val != nullptr; }

	[[deprecated("Remove in v4.1.  Use GetVal().")]]
	Val* ID_Val()			{ return val.get(); }
	[[deprecated("Remove in v4.1.  Use GetVal().")]]
	const Val* ID_Val() const	{ return val.get(); }

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
	void AddAttrs(AttributesPtr attr);
	void RemoveAttr(AttrTag a);
	void UpdateValAttrs();

	const AttributesPtr& GetAttrs() const
		{ return attrs; }

	[[deprecated("Remove in 4.1.  Use GetAttrs().")]]
	Attributes* Attrs() const	{ return attrs.get(); }

	const AttrPtr& GetAttr(zeek::detail::AttrTag t) const;

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

	void AddOptionHandler(zeek::FuncPtr callback, int priority);
	std::vector<Func*> GetOptionHandlers() const;

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
	std::multimap<int, zeek::FuncPtr> option_handlers;

};

}

using ID [[deprecated("Remove in v4.1. Use zeek::detail::ID instead.")]] = zeek::detail::ID;

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
zeek::IntrusivePtr<T> find_type(std::string_view name)
	{ return zeek::cast_intrusive<T>(find_type(name)); }

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
zeek::IntrusivePtr<T> find_val(std::string_view name)
	{ return zeek::cast_intrusive<T>(find_val(name)); }

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
zeek::IntrusivePtr<T> find_const(std::string_view name)
	{ return zeek::cast_intrusive<T>(find_const(name)); }

/**
 * Lookup an ID by its name and return the function it references.
 * A fatal occurs if the ID does not exist or if it is not a function.
 * @param name  The identifier name to lookup
 * @return  The current function value the identifier references.
 */
zeek::FuncPtr find_func(std::string_view name);

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

void init();

} // namespace zeek::id::detail

} // namespace zeek::id

using ID [[deprecated("Remove in v4.1 Use zeek::detail::ID instead.")]] = zeek::detail::ID;

using init_class [[deprecated("Remove in v4.1. Use zeek::detail::InitClass instead.")]] = zeek::detail::InitClass;
[[deprecated("Remove in v4.1. Use zeek::detail::INIT_NONE instead.")]]
constexpr auto INIT_NONE = zeek::detail::INIT_NONE;
[[deprecated("Remove in v4.1. Use zeek::detail::INIT_FULL instead.")]]
constexpr auto INIT_FULL = zeek::detail::INIT_FULL;
[[deprecated("Remove in v4.1. Use zeek::detail::INIT_EXTRA instead.")]]
constexpr auto INIT_EXTRA = zeek::detail::INIT_EXTRA;
[[deprecated("Remove in v4.1. Use zeek::detail::INIT_REMOVE instead.")]]
constexpr auto INIT_REMOVE = zeek::detail::INIT_REMOVE;

using IDScope [[deprecated("Remove in v4.1. Use zeek::detail::IDScope instead.")]] = zeek::detail::IDScope;
[[deprecated("Remove in v4.1. Use zeek::detail::SCOPE_FUNCTION instead.")]]
constexpr auto SCOPE_FUNCTION = zeek::detail::SCOPE_FUNCTION;
[[deprecated("Remove in v4.1. Use zeek::detail::SCOPE_MODULE instead.")]]
constexpr auto SCOPE_MODULE = zeek::detail::SCOPE_MODULE;
[[deprecated("Remove in v4.1. Use zeek::detail::SCOPE_GLOBAL instead.")]]
constexpr auto SCOPE_GLOBAL = zeek::detail::SCOPE_GLOBAL;
