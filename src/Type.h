// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>
#include <set>
#include <unordered_map>
#include <map>
#include <list>
#include <optional>

#include "zeek/Obj.h"
#include "zeek/ID.h"
#include "zeek/Attr.h"
#include "zeek/ZeekList.h"
#include "zeek/IntrusivePtr.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(Val, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(EnumVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(TableVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(ListExpr, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Attributes, zeek::detail);

namespace zeek {

using ValPtr = IntrusivePtr<Val>;
using EnumValPtr = IntrusivePtr<EnumVal>;
using TableValPtr = IntrusivePtr<TableVal>;

namespace detail {
using ListExprPtr = IntrusivePtr<ListExpr>;
}

// BRO types.
enum TypeTag {
	TYPE_VOID,      // 0
	TYPE_BOOL,      // 1
	TYPE_INT,       // 2
	TYPE_COUNT,     // 3
	TYPE_DOUBLE,    // 5
	TYPE_TIME,      // 6
	TYPE_INTERVAL,  // 7
	TYPE_STRING,    // 8
	TYPE_PATTERN,   // 9
	TYPE_ENUM,      // 10
	TYPE_TIMER,     // 11
	TYPE_PORT,      // 12
	TYPE_ADDR,      // 13
	TYPE_SUBNET,    // 14
	TYPE_ANY,       // 15
	TYPE_TABLE,     // 16
	TYPE_UNION,     // 17
	TYPE_RECORD,    // 18
	TYPE_LIST,      // 19
	TYPE_FUNC,      // 20
	TYPE_FILE,      // 21
	TYPE_VECTOR,    // 22
	TYPE_OPAQUE,    // 23
	TYPE_TYPE,      // 24
	TYPE_ERROR      // 25
#define NUM_TYPES (int(TYPE_ERROR) + 1)
};

// Returns the name of the type.
extern const char* type_name(TypeTag t);

constexpr bool is_network_order(TypeTag tag) noexcept
	{
	return tag == TYPE_PORT;
	}

enum FunctionFlavor {
	FUNC_FLAVOR_FUNCTION,
	FUNC_FLAVOR_EVENT,
	FUNC_FLAVOR_HOOK
};

enum InternalTypeTag : uint16_t {
	TYPE_INTERNAL_VOID,
	TYPE_INTERNAL_INT, TYPE_INTERNAL_UNSIGNED, TYPE_INTERNAL_DOUBLE,
	TYPE_INTERNAL_STRING, TYPE_INTERNAL_ADDR, TYPE_INTERNAL_SUBNET,
	TYPE_INTERNAL_OTHER, TYPE_INTERNAL_ERROR
};

constexpr InternalTypeTag to_internal_type_tag(TypeTag tag) noexcept
	{
	switch ( tag ) {
	case TYPE_VOID:
		return TYPE_INTERNAL_VOID;

	case TYPE_BOOL:
	case TYPE_INT:
	case TYPE_ENUM:
		return TYPE_INTERNAL_INT;

	case TYPE_COUNT:
	case TYPE_PORT:
		return TYPE_INTERNAL_UNSIGNED;

	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
		return TYPE_INTERNAL_DOUBLE;

	case TYPE_STRING:
		return TYPE_INTERNAL_STRING;

	case TYPE_ADDR:
		return TYPE_INTERNAL_ADDR;

	case TYPE_SUBNET:
		return TYPE_INTERNAL_SUBNET;

	case TYPE_PATTERN:
	case TYPE_TIMER:
	case TYPE_ANY:
	case TYPE_TABLE:
	case TYPE_UNION:
	case TYPE_RECORD:
	case TYPE_LIST:
	case TYPE_FUNC:
	case TYPE_FILE:
	case TYPE_OPAQUE:
	case TYPE_VECTOR:
	case TYPE_TYPE:
		return TYPE_INTERNAL_OTHER;

	case TYPE_ERROR:
		return TYPE_INTERNAL_ERROR;
	}

	/* this should be unreachable */
	return TYPE_INTERNAL_VOID;
	}

class Type;
class TypeList;
class TableType;
class SetType;
class RecordType;
class SubNetType;
class FuncType;
class EnumType;
class VectorType;
class TypeType;
class OpaqueType;
class FileType;

using TypePtr = IntrusivePtr<Type>;
using TypeListPtr = IntrusivePtr<TypeList>;
using TableTypePtr = IntrusivePtr<TableType>;
using SetTypePtr = IntrusivePtr<SetType>;
using RecordTypePtr = IntrusivePtr<RecordType>;
using SubNetTypePtr = IntrusivePtr<SubNetType>;
using FuncTypePtr = IntrusivePtr<FuncType>;
using EnumTypePtr = IntrusivePtr<EnumType>;
using VectorTypePtr = IntrusivePtr<VectorType>;
using TypeTypePtr = IntrusivePtr<TypeType>;
using OpaqueTypePtr = IntrusivePtr<OpaqueType>;
using FileTypePtr = IntrusivePtr<FileType>;

constexpr int DOES_NOT_MATCH_INDEX = 0;
constexpr int MATCHES_INDEX_SCALAR = 1;
constexpr int MATCHES_INDEX_VECTOR = 2;

class Type : public Obj {
public:
	static inline const TypePtr nil;

	explicit Type(TypeTag tag, bool base_type = false);

	// Performs a shallow clone operation of the Bro type.
	// This especially means that especially for tables the types
	// are not recursively cloned; altering one type will in this case
	// alter one of them.
	// The main use for this is alias tracking.
	// Clone operations will mostly be implemented in the derived classes;
	// in addition cloning will be limited to classes that can be reached by
	// the script-level.
	virtual TypePtr ShallowClone();

	TypeTag Tag() const		{ return tag; }
	InternalTypeTag InternalType() const	{ return internal_tag; }

	// Whether it's stored in network order.
	bool IsNetworkOrder() const	{ return is_network_order; }

	// Type-checks the given expression list, returning
	// MATCHES_INDEX_SCALAR = 1 if it matches this type's index
	// and produces a scalar result (and promoting its
	// subexpressions as necessary); MATCHES_INDEX_VECTOR = 2
	// if it matches and produces a vector result; and
	// DOES_NOT_MATCH_INDEX = 0 if it can't match (or the type
	// is not an indexable type).
	virtual int MatchesIndex(detail::ListExpr* index) const;

	// Returns the type yielded by this type.  For example, if
	// this type is a table[string] of port, then returns the "port"
	// type.  Returns nil if this is not an index type.
	virtual const TypePtr& Yield() const;

	const TypeList* AsTypeList() const;
	TypeList* AsTypeList();

	const TableType* AsTableType() const;
	TableType* AsTableType();

	const SetType* AsSetType() const;
	SetType* AsSetType();

	const RecordType* AsRecordType() const;
	RecordType* AsRecordType();

	const SubNetType* AsSubNetType() const;
	SubNetType* AsSubNetType();

	const FuncType* AsFuncType() const;
	FuncType* AsFuncType();

	const EnumType* AsEnumType() const;
	EnumType* AsEnumType();

	const VectorType* AsVectorType() const;
	VectorType* AsVectorType();

	const OpaqueType* AsOpaqueType() const;
	OpaqueType* AsOpaqueType();

	const TypeType* AsTypeType() const;
	TypeType* AsTypeType();

	bool IsSet() const
		{
		return tag == TYPE_TABLE && ! Yield();
		}

	bool IsTable() const
		{
		return tag == TYPE_TABLE && Yield();
		}

	Type* Ref()		{ ::zeek::Ref(this); return this; }

	void Describe(ODesc* d) const override;
	virtual void DescribeReST(ODesc* d, bool roles_only = false) const;

	virtual unsigned MemoryAllocation() const;

	void SetName(const std::string& arg_name) { name = arg_name; }
	const std::string& GetName() const { return name; }

	struct TypePtrComparer {
		bool operator()(const TypePtr& a, const TypePtr& b) const
			{ return a.get() < b.get(); }
	};
	using TypePtrSet = std::set<TypePtr, TypePtrComparer>;
	using TypeAliasMap = std::map<std::string, TypePtrSet, std::less<>>;

	/**
	 * Returns a mapping of type-name to all other type names declared as
	 * an alias to it.
	 */
	static const TypeAliasMap& GetAliasMap()
		{ return type_aliases; }

	/**
	 * Returns true if the given type name has any declared aliases
	 */
	static bool HasAliases(std::string_view type_name)
		{ return Type::type_aliases.find(type_name) != Type::type_aliases.end(); }

	/**
	 * Returns the set of all type names declared as an aliases to the given
	 * type name.  A static empty set is returned if there are no aliases.
	 */
	static const TypePtrSet& Aliases(std::string_view type_name)
		{
		static TypePtrSet empty;
		auto it = Type::type_aliases.find(type_name);
		return it == Type::type_aliases.end() ? empty : it->second;
		}

	/**
	 * Registers a new type alias.
	 * @param type_name  the name of the type to register a new alias for.
	 * @param type  the associated alias type of *type_name*.
	 * @return  true if the alias is now registered or false if the alias was
	 * already previously registered.
	 */
	static bool RegisterAlias(std::string_view type_name, TypePtr type)
		{
		auto it = Type::type_aliases.find(type_name);
		if ( it == Type::type_aliases.end() )
			it = Type::type_aliases.emplace(std::string{type_name}, TypePtrSet{}).first;
		return it->second.emplace(std::move(type)).second;
		}

protected:
	Type() = default;

	void SetError();

private:
	TypeTag tag;
	InternalTypeTag internal_tag;
	bool is_network_order;
	bool base_type;
	std::string name;

	static TypeAliasMap type_aliases;
};

class TypeList final : public Type {
public:
	explicit TypeList(TypePtr arg_pure_type = nullptr)
		: Type(TYPE_LIST), pure_type(std::move(arg_pure_type))
		{
		}

	~TypeList() override = default;

	const std::vector<TypePtr>& GetTypes() const
		{ return types; }

	bool IsPure() const		{ return pure_type != nullptr; }

	// Returns the underlying pure type, or nil if the list
	// is not pure or is empty.
	const TypePtr& GetPureType() const
		{ return pure_type; }

	// True if all of the types match t, false otherwise.  If
	// is_init is true, then the matching is done in the context
	// of an initialization.
	bool AllMatch(const Type* t, bool is_init) const;
	bool AllMatch(const TypePtr& t, bool is_init) const
		{ return AllMatch(t.get(), is_init); }

	void Append(TypePtr t);
	void AppendEvenIfNotPure(TypePtr t);

	void Describe(ODesc* d) const override;

	unsigned int MemoryAllocation() const override;

protected:
	TypePtr pure_type;
	std::vector<TypePtr> types;
};

class IndexType : public Type {
public:

	int MatchesIndex(detail::ListExpr* index) const override;

	const TypeListPtr& GetIndices() const
		{ return indices; }

	const std::vector<TypePtr>& GetIndexTypes() const
		{ return indices->GetTypes(); }

	const TypePtr& Yield() const override
		{ return yield_type; }

	void Describe(ODesc* d) const override;
	void DescribeReST(ODesc* d, bool roles_only = false) const override;

	// Returns true if this table is solely indexed by subnet.
	bool IsSubNetIndex() const;

protected:
	IndexType(TypeTag t, TypeListPtr arg_indices,
	          TypePtr arg_yield_type)
		: Type(t), indices(std::move(arg_indices)),
		  yield_type(std::move(arg_yield_type))
		{
		}

	~IndexType() override = default;

	TypeListPtr indices;
	TypePtr yield_type;
};

class TableType : public IndexType {
public:
	TableType(TypeListPtr ind, TypePtr yield);

	TypePtr ShallowClone() override;

	// Returns true if this table type is "unspecified", which is
	// what one gets using an empty "set()" or "table()" constructor.
	bool IsUnspecifiedTable() const;
};

class SetType final : public TableType {
public:
	SetType(TypeListPtr ind, detail::ListExprPtr arg_elements);
	~SetType() override;

	TypePtr ShallowClone() override;

	const detail::ListExprPtr& Elements() const
		{ return elements; }

protected:
	detail::ListExprPtr elements;
};

class FuncType final : public Type {
public:
	static inline const FuncTypePtr nil;

	/**
	 * Prototype is only currently used for events and hooks which declare
	 * multiple signature prototypes that allow users to have handlers
	 * with various argument permutations.
	 */
	struct Prototype {
		bool deprecated;
		std::string deprecation_msg;
		RecordTypePtr args;
		// Maps from parameter index in canonical prototype to
		// parameter index in this alternate prorotype.
		std::map<int, int> offsets;
	};

	FuncType(RecordTypePtr args, TypePtr yield,
	         FunctionFlavor f);

	TypePtr ShallowClone() override;

	const RecordTypePtr& Params() const
		{ return args; }

	const TypePtr& Yield() const override
		{ return yield; }

	void SetYieldType(TypePtr arg_yield)	{ yield = std::move(arg_yield); }
	FunctionFlavor Flavor() const { return flavor; }
	std::string FlavorString() const;

	// Used to convert a function type to an event or hook type.
	void ClearYieldType(FunctionFlavor arg_flav)
		{ yield = nullptr; flavor = arg_flav; }

	int MatchesIndex(detail::ListExpr* index) const override;
	bool CheckArgs(const TypePList* args, bool is_init = false) const;
	bool CheckArgs(const std::vector<TypePtr>& args,
	               bool is_init = false) const;

	const TypeListPtr& ParamList() const
		{ return arg_types; }

	void Describe(ODesc* d) const override;
	void DescribeReST(ODesc* d, bool roles_only = false) const override;

	/**
	 * Adds a new event/hook signature allowed for use in handlers.
	 */
	void AddPrototype(Prototype s);

	/**
	 * Returns a prototype signature that matches the desired argument types.
	 */
	std::optional<Prototype> FindPrototype(const RecordType& args) const;

	/**
	 * Returns all allowed function prototypes.
	 */
	const std::vector<Prototype>& Prototypes() const
		{ return prototypes; }

	/**
	 * A single lambda "capture" (outer variable used in a lambda's body).
	 */
	struct Capture {
		detail::IDPtr id;
		bool deep_copy;
	};

	using CaptureList = std::vector<Capture>;

	/**
	 * Sets this function's set of captures.  Only valid for lambdas.
	 *
	 * @param captures  if non-nil, a list of the lambda's captures
	 */
	void SetCaptures(std::optional<CaptureList> captures);

	/**
	 * Returns the captures declared for this function, or nil if none.
	 *
	 * @return a vector giving the captures
	 */
	const std::optional<CaptureList>& GetCaptures() const
		{ return captures; }

protected:
	friend FuncTypePtr make_intrusive<FuncType>();

	FuncType() : Type(TYPE_FUNC) { flavor = FUNC_FLAVOR_FUNCTION; }
	RecordTypePtr args;
	TypeListPtr arg_types;
	TypePtr yield;
	FunctionFlavor flavor;
	std::vector<Prototype> prototypes;

	std::optional<CaptureList> captures; // if nil then no captures specified
};

class TypeType final : public Type {
public:
	explicit TypeType(TypePtr t) : zeek::Type(TYPE_TYPE), type(std::move(t)) {}
	TypePtr ShallowClone() override { return make_intrusive<TypeType>(type); }

	const TypePtr& GetType() const
		{ return type; }

	template <class T>
	IntrusivePtr<T> GetType() const
		{ return cast_intrusive<T>(type); }

protected:
	TypePtr type;
};

class TypeDecl final {
public:
	TypeDecl() = default;
	TypeDecl(const char* i, TypePtr t, detail::AttributesPtr attrs = nullptr);
	TypeDecl(const TypeDecl& other);
	~TypeDecl();

	const detail::AttrPtr& GetAttr(detail::AttrTag a) const
		{ return attrs ? attrs->Find(a) : detail::Attr::nil; }

	void DescribeReST(ODesc* d, bool roles_only = false) const;

	TypePtr type;
	detail::AttributesPtr attrs;
	const char* id = nullptr;
};

using type_decl_list = PList<TypeDecl>;

class RecordType final : public Type {
public:
	explicit RecordType(type_decl_list* types);
	TypePtr ShallowClone() override;

	~RecordType() override;

	bool HasField(const char* field) const;

	/**
	 * Looks up a field by name and returns its type.  No check for invalid
	 * field name is performed.
	 */
	const TypePtr& GetFieldType(const char* field_name) const
		{ return GetFieldType(FieldOffset(field_name)); }

	/**
	 * Looks up a field by name and returns its type as cast to @c T.
	 * No check for invalid field name is performed.
	 */
	template <class T>
	IntrusivePtr<T> GetFieldType(const char* field_name) const
		{ return cast_intrusive<T>(GetFieldType(field_name)); }

	/**
	 * Looks up a field by its index and returns its type.  No check for
	 * invalid field offset is performed.
	 */
	const TypePtr& GetFieldType(int field_index) const
		{ return (*types)[field_index]->type; }

	/**
	 * Looks up a field by its index and returns its type as cast to @c T.
	 * No check for invalid field offset is performed.
	 */
	template <class T>
	IntrusivePtr<T> GetFieldType(int field_index) const
		{ return cast_intrusive<T>((*types)[field_index]->type); }

	ValPtr FieldDefault(int field) const;

	// A field's offset is its position in the type_decl_list,
	// starting at 0.  Returns negative if the field doesn't exist.
	int FieldOffset(const char* field) const;

	// Given an offset, returns the field's name.
	const char* FieldName(int field) const;

	type_decl_list* Types() { return types; }

	// Given an offset, returns the field's TypeDecl.
	const TypeDecl* FieldDecl(int field) const;
	TypeDecl* FieldDecl(int field);

	int NumFields() const			{ return num_fields; }

	/**
	 * Returns a "record_field_table" value for introspection purposes.
	 * @param rv  an optional record value, if given the values of
	 * all fields will be provided in the returned table.
	 */
	TableValPtr GetRecordFieldsVal(const RecordVal* rv = nullptr) const;

	// Returns null if all is ok, otherwise a pointer to an error message.
	const char* AddFields(const type_decl_list& types,
	                      bool add_log_attr = false);

	void Describe(ODesc* d) const override;
	void DescribeReST(ODesc* d, bool roles_only = false) const override;
	void DescribeFields(ODesc* d) const;
	void DescribeFieldsReST(ODesc* d, bool func_args) const;

	bool IsFieldDeprecated(int field) const
		{
		const TypeDecl* decl = FieldDecl(field);
		return decl && decl->GetAttr(detail::ATTR_DEPRECATED) != nullptr;
		}

	bool FieldHasAttr(int field, detail::AttrTag at) const
		{
		const TypeDecl* decl = FieldDecl(field);
		return decl && decl->GetAttr(at) != nullptr;
		}

	std::string GetFieldDeprecationWarning(int field, bool has_check) const;

protected:
	RecordType() { types = nullptr; }

	int num_fields;
	type_decl_list* types;
};

class SubNetType final : public Type {
public:
	SubNetType();
	void Describe(ODesc* d) const override;
};

class FileType final : public Type {
public:
	explicit FileType(TypePtr yield_type);
	TypePtr ShallowClone() override { return make_intrusive<FileType>(yield); }
	~FileType() override;

	const TypePtr& Yield() const override
		{ return yield; }

	void Describe(ODesc* d) const override;

protected:
	TypePtr yield;
};

class OpaqueType final : public Type {
public:
	explicit OpaqueType(const std::string& name);
	TypePtr ShallowClone() override { return make_intrusive<OpaqueType>(name); }
	~OpaqueType() override { };

	const std::string& Name() const { return name; }

	void Describe(ODesc* d) const override;
	void DescribeReST(ODesc* d, bool roles_only = false) const override;

protected:
	OpaqueType() { }

	std::string name;
};

class EnumType final : public Type {
public:
	typedef std::list<std::pair<std::string, bro_int_t> > enum_name_list;

	explicit EnumType(const EnumType* e);
	explicit EnumType(const std::string& arg_name);
	TypePtr ShallowClone() override;
	~EnumType() override;

	// The value of this name is next internal counter value, starting
	// with zero. The internal counter is incremented.
	void AddName(const std::string& module_name, const char* name, bool is_export, detail::Expr* deprecation = nullptr, bool from_redef = false);

	// The value of this name is set to val. Once a value has been
	// explicitly assigned using this method, no further names can be
	// added that aren't likewise explicitly initalized.
	void AddName(const std::string& module_name, const char* name, bro_int_t val, bool is_export, detail::Expr* deprecation = nullptr, bool from_redef = false);

	// -1 indicates not found.
	bro_int_t Lookup(const std::string& module_name, const char* name) const;
	const char* Lookup(bro_int_t value) const; // Returns 0 if not found

	// Returns the list of defined names with their values. The names
	// will be fully qualified with their module name.
	enum_name_list Names() const;

	void DescribeReST(ODesc* d, bool roles_only = false) const override;

	const EnumValPtr& GetEnumVal(bro_int_t i);

protected:
	void AddNameInternal(const std::string& module_name,
			const char* name, bro_int_t val, bool is_export);

	void CheckAndAddName(const std::string& module_name,
	                     const char* name, bro_int_t val, bool is_export,
	                     detail::Expr* deprecation = nullptr,
	                     bool from_redef = false);

	typedef std::map<std::string, bro_int_t> NameMap;
	NameMap names;

	using ValMap = std::unordered_map<bro_int_t, EnumValPtr>;
	ValMap vals;

	// The counter is initialized to 0 and incremented on every implicit
	// auto-increment name that gets added (thus its > 0 if
	// auto-increment is used).  Once an explicit value has been
	// specified, the counter is set to -1. This way counter can be used
	// as a flag to prevent mixing of auto-increment and explicit
	// enumerator specifications.
	bro_int_t counter;
};

class VectorType final : public Type {
public:
	explicit VectorType(TypePtr t);
	TypePtr ShallowClone() override;
	~VectorType() override;

	const TypePtr& Yield() const override;

	int MatchesIndex(detail::ListExpr* index) const override;

	// Returns true if this table type is "unspecified", which is what one
	// gets using an empty "vector()" constructor.
	bool IsUnspecifiedVector() const;

	void Describe(ODesc* d) const override;
	void DescribeReST(ODesc* d, bool roles_only = false) const override;

protected:
	TypePtr yield_type;
};

// True if the two types are equivalent.  If is_init is true then the test is
// done in the context of an initialization. If match_record_field_names is
// true then for record types the field names have to match, too.
extern bool same_type(const Type& t1, const Type& t2,
                      bool is_init=false, bool match_record_field_names=true);
inline bool same_type(const TypePtr& t1, const TypePtr& t2,
                      bool is_init=false, bool match_record_field_names=true)
    { return same_type(*t1, *t2, is_init, match_record_field_names); }
inline bool same_type(const Type* t1, const Type* t2,
                      bool is_init=false, bool match_record_field_names=true)
    { return same_type(*t1, *t2, is_init, match_record_field_names); }
inline bool same_type(const TypePtr& t1, const Type* t2,
                      bool is_init=false, bool match_record_field_names=true)
    { return same_type(*t1, *t2, is_init, match_record_field_names); }
inline bool same_type(const Type* t1, const TypePtr& t2,
                      bool is_init=false, bool match_record_field_names=true)
    { return same_type(*t1, *t2, is_init, match_record_field_names); }

// True if the two attribute lists are equivalent.
extern bool same_attrs(const detail::Attributes* a1, const detail::Attributes* a2);

// Returns true if the record sub_rec can be promoted to the record
// super_rec.
extern bool record_promotion_compatible(const RecordType* super_rec,
					const RecordType* sub_rec);

// If the given Type is a TypeList with just one element, returns
// that element, otherwise returns the type.
extern const Type* flatten_type(const Type* t);
extern Type* flatten_type(Type* t);

// Returns the "maximum" of two type tags, in a type-promotion sense.
extern TypeTag max_type(TypeTag t1, TypeTag t2);

// Given two types, returns the "merge", in which promotable types
// are promoted to the maximum of the two.  Returns nil (and generates
// an error message) if the types are incompatible.
TypePtr merge_types(const TypePtr& t1, const TypePtr& t2);

// Given a list of expressions, returns a (ref'd) type reflecting
// a merged type consistent across all of them, or nil if this
// cannot be done.
TypePtr merge_type_list(detail::ListExpr* elements);

// Given an expression, infer its type when used for an initialization.
TypePtr init_type(detail::Expr* init);

// Returns true if argument is an atomic type.
bool is_atomic_type(const Type& t);
inline bool is_atomic_type(const Type* t)
	{ return is_atomic_type(*t); }
inline bool is_atomic_type(const TypePtr& t)
	{ return is_atomic_type(*t); }

// True if the given type tag corresponds to type that can be assigned to.
extern bool is_assignable(TypeTag t);
inline bool is_assignable(Type* t)
	{ return is_assignable(t->Tag()); }

// True if the given type tag corresponds to an integral type.
inline bool IsIntegral(TypeTag t) { return (t == TYPE_INT || t == TYPE_COUNT ); }

// True if the given type tag corresponds to an arithmetic type.
inline bool IsArithmetic(TypeTag t)	{ return (IsIntegral(t) || t == TYPE_DOUBLE); }

// True if the given type tag corresponds to a boolean type.
inline bool IsBool(TypeTag t)	{ return (t == TYPE_BOOL); }

// True if the given type tag corresponds to an interval type.
inline bool IsInterval(TypeTag t)	{ return (t == TYPE_INTERVAL); }

// True if the given type tag corresponds to a record type.
inline bool IsRecord(TypeTag t)	{ return (t == TYPE_RECORD || t == TYPE_UNION); }

// True if the given type tag corresponds to a function type.
inline bool IsFunc(TypeTag t)	{ return (t == TYPE_FUNC); }

// True if the given type type is a vector.
inline bool IsVector(TypeTag t)	{ return (t == TYPE_VECTOR); }

// True if the given type type is a string.
inline bool IsString(TypeTag t)	{ return (t == TYPE_STRING); }

// True if the given type tag corresponds to the error type.
inline bool IsErrorType(TypeTag t)	{ return (t == TYPE_ERROR); }

// True if both tags are integral types.
inline bool BothIntegral(TypeTag t1, TypeTag t2) { return (IsIntegral(t1) && IsIntegral(t2)); }

// True if both tags are arithmetic types.
inline bool BothArithmetic(TypeTag t1, TypeTag t2) { return (IsArithmetic(t1) && IsArithmetic(t2)); }

// True if either tags is an arithmetic type.
inline bool EitherArithmetic(TypeTag t1, TypeTag t2) { return (IsArithmetic(t1) || IsArithmetic(t2)); }

// True if both tags are boolean types.
inline bool BothBool(TypeTag t1, TypeTag t2) { return (IsBool(t1) && IsBool(t2)); }

// True if both tags are interval types.
inline bool BothInterval(TypeTag t1, TypeTag t2) { return (IsInterval(t1) && IsInterval(t2)); }

// True if both tags are string types.
inline bool BothString(TypeTag t1, TypeTag t2) { return (IsString(t1) && IsString(t2)); }

// True if either tag is the error type.
inline bool EitherError(TypeTag t1, TypeTag t2) { return (IsErrorType(t1) || IsErrorType(t2)); }

// Returns the basic (non-parameterized) type with the given type.
const TypePtr& base_type(TypeTag tag);

// Returns the basic error type.
inline const TypePtr& error_type()       { return base_type(TYPE_ERROR); }

} // namespace zeek

extern zeek::OpaqueTypePtr md5_type;
extern zeek::OpaqueTypePtr sha1_type;
extern zeek::OpaqueTypePtr sha256_type;
extern zeek::OpaqueTypePtr entropy_type;
extern zeek::OpaqueTypePtr cardinality_type;
extern zeek::OpaqueTypePtr topk_type;
extern zeek::OpaqueTypePtr bloomfilter_type;
extern zeek::OpaqueTypePtr x509_opaque_type;
extern zeek::OpaqueTypePtr ocsp_resp_opaque_type;
extern zeek::OpaqueTypePtr paraglob_type;
