// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>
#include <set>
#include <unordered_map>
#include <map>
#include <list>

#include "Obj.h"
#include "Attr.h"
#include "BroList.h"
#include "Dict.h"

// BRO types.

typedef enum {
	TYPE_VOID,      // 0
	TYPE_BOOL,      // 1
	TYPE_INT,       // 2
	TYPE_COUNT,     // 3
	TYPE_COUNTER,   // 4
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
} TypeTag;

typedef enum {
	FUNC_FLAVOR_FUNCTION,
	FUNC_FLAVOR_EVENT,
	FUNC_FLAVOR_HOOK
} function_flavor;

typedef enum {
	TYPE_INTERNAL_VOID,
	TYPE_INTERNAL_INT, TYPE_INTERNAL_UNSIGNED, TYPE_INTERNAL_DOUBLE,
	TYPE_INTERNAL_STRING, TYPE_INTERNAL_ADDR, TYPE_INTERNAL_SUBNET,
	TYPE_INTERNAL_OTHER, TYPE_INTERNAL_ERROR
} InternalTypeTag;

// Returns the name of the type.
extern const char* type_name(TypeTag t);

class Expr;
class Attributes;
class TypeList;
class TableType;
class SetType;
class RecordType;
class SubNetType;
class FuncType;
class ListExpr;
class EnumType;
class VectorType;
class TypeType;
class OpaqueType;
class EnumVal;
class TableVal;

const int DOES_NOT_MATCH_INDEX = 0;
const int MATCHES_INDEX_SCALAR = 1;
const int MATCHES_INDEX_VECTOR = 2;

class BroType : public BroObj {
public:
	explicit BroType(TypeTag tag, bool base_type = false);
	~BroType() override { }

	// Performs a shallow clone operation of the Bro type.
	// This especially means that especially for tables the types
	// are not recursively cloned; altering one type will in this case
	// alter one of them.
	// The main use for this is alias tracking.
	// Clone operations will mostly be implemented in the derived classes;
	// in addition cloning will be limited to classes that can be reached by
	// the script-level.
	virtual BroType* ShallowClone();

	TypeTag Tag() const		{ return tag; }
	InternalTypeTag InternalType() const	{ return internal_tag; }

	// Whether it's stored in network order.
	int IsNetworkOrder() const	{ return is_network_order; }

	// Type-checks the given expression list, returning
	// MATCHES_INDEX_SCALAR = 1 if it matches this type's index
	// and produces a scalar result (and promoting its
	// subexpressions as necessary); MATCHES_INDEX_VECTOR = 2
	// if it matches and produces a vector result; and
	// DOES_NOT_MATCH_INDEX = 0 if it can't match (or the type
	// is not an indexable type).
	virtual int MatchesIndex(ListExpr*& index) const;

	// Returns the type yielded by this type.  For example, if
	// this type is a table[string] of port, then returns the "port"
	// type.  Returns nil if this is not an index type.
	virtual BroType* YieldType();
	virtual const BroType* YieldType() const
		{ return ((BroType*) this)->YieldType(); }

	// Returns true if this type is a record and contains the
	// given field, false otherwise.
	virtual int HasField(const char* field) const;

	// Returns the type of the given field, or nil if no such field.
	virtual BroType* FieldType(const char* field) const;

#define CHECK_TYPE_TAG(tag_type, func_name) \
	CHECK_TAG(tag, tag_type, func_name, type_name)

	const TypeList* AsTypeList() const
		{
		CHECK_TYPE_TAG(TYPE_LIST, "BroType::AsTypeList");
		return (const TypeList*) this;
		}
	TypeList* AsTypeList()
		{
		CHECK_TYPE_TAG(TYPE_LIST, "BroType::AsTypeList");
		return (TypeList*) this;
		}

	const TableType* AsTableType() const
		{
		CHECK_TYPE_TAG(TYPE_TABLE, "BroType::AsTableType");
		return (const TableType*) this;
		}
	TableType* AsTableType()
		{
		CHECK_TYPE_TAG(TYPE_TABLE, "BroType::AsTableType");
		return (TableType*) this;
		}

	SetType* AsSetType()
		{
		if ( ! IsSet() )
			BadTag("BroType::AsSetType", type_name(tag));
		return (SetType*) this;
		}
	const SetType* AsSetType() const
		{
		if ( ! IsSet() )
			BadTag("BroType::AsSetType", type_name(tag));
		return (const SetType*) this;
		}

	const RecordType* AsRecordType() const
		{
		CHECK_TYPE_TAG(TYPE_RECORD, "BroType::AsRecordType");
		return (const RecordType*) this;
		}
	RecordType* AsRecordType()
		{
		CHECK_TYPE_TAG(TYPE_RECORD, "BroType::AsRecordType");
		return (RecordType*) this;
		}

	const SubNetType* AsSubNetType() const
		{
		CHECK_TYPE_TAG(TYPE_SUBNET, "BroType::AsSubNetType");
		return (const SubNetType*) this;
		}

	SubNetType* AsSubNetType()
		{
		CHECK_TYPE_TAG(TYPE_SUBNET, "BroType::AsSubNetType");
		return (SubNetType*) this;
		}

	const FuncType* AsFuncType() const
		{
		CHECK_TYPE_TAG(TYPE_FUNC, "BroType::AsFuncType");
		return (const FuncType*) this;
		}

	FuncType* AsFuncType()
		{
		CHECK_TYPE_TAG(TYPE_FUNC, "BroType::AsFuncType");
		return (FuncType*) this;
		}

	const EnumType* AsEnumType() const
		{
		CHECK_TYPE_TAG(TYPE_ENUM, "BroType::AsEnumType");
		return (EnumType*) this;
		}

	EnumType* AsEnumType()
		{
		CHECK_TYPE_TAG(TYPE_ENUM, "BroType::AsEnumType");
		return (EnumType*) this;
		}

	const VectorType* AsVectorType() const
		{
		CHECK_TYPE_TAG(TYPE_VECTOR, "BroType::AsVectorType");
		return (VectorType*) this;
		}

	OpaqueType* AsOpaqueType()
		{
		CHECK_TYPE_TAG(TYPE_OPAQUE, "BroType::AsOpaqueType");
		return (OpaqueType*) this;
		}

	const OpaqueType* AsOpaqueType() const
		{
		CHECK_TYPE_TAG(TYPE_OPAQUE, "BroType::AsOpaqueType");
		return (OpaqueType*) this;
		}

	VectorType* AsVectorType()
		{
		CHECK_TYPE_TAG(TYPE_VECTOR, "BroType::AsVectorType");
		return (VectorType*) this;
		}

	const TypeType* AsTypeType() const
		{
		CHECK_TYPE_TAG(TYPE_TYPE, "BroType::AsTypeType");
		return (TypeType*) this;
		}

	TypeType* AsTypeType()
		{
		CHECK_TYPE_TAG(TYPE_TYPE, "BroType::AsTypeType");
		return (TypeType*) this;
		}

	int IsSet() const
		{
		return tag == TYPE_TABLE && (YieldType() == 0);
		}

	int IsTable() const
		{
		return tag == TYPE_TABLE && (YieldType() != 0);
		}

	BroType* Ref()		{ ::Ref(this); return this; }

	void Describe(ODesc* d) const override;
	virtual void DescribeReST(ODesc* d, bool roles_only = false) const;

	virtual unsigned MemoryAllocation() const;

	void SetName(const std::string& arg_name) { name = arg_name; }
	const std::string& GetName() const { return name; }

	typedef std::map<std::string, std::set<BroType*> > TypeAliasMap;

	static std::set<BroType*> GetAliases(const std::string& type_name)
		{ return BroType::type_aliases[type_name]; }

	static void AddAlias(const std::string &type_name, BroType* type)
		{ BroType::type_aliases[type_name].insert(type); }

protected:
	BroType()	{ }

	void SetError();

private:
	TypeTag tag;
	InternalTypeTag internal_tag;
	bool is_network_order;
	bool base_type;
	std::string name;

	static TypeAliasMap type_aliases;
};

class TypeList : public BroType {
public:
	explicit TypeList(BroType* arg_pure_type = 0) : BroType(TYPE_LIST)
		{
		pure_type = arg_pure_type;
		if ( pure_type )
			pure_type->Ref();
		}
	~TypeList() override;

	const type_list* Types() const	{ return &types; }
	type_list* Types()		{ return &types; }

	int IsPure() const		{ return pure_type != 0; }

	// Returns the underlying pure type, or nil if the list
	// is not pure or is empty.
	BroType* PureType()		{ return pure_type; }
	const BroType* PureType() const	{ return pure_type; }

	// True if all of the types match t, false otherwise.  If
	// is_init is true, then the matching is done in the context
	// of an initialization.
	int AllMatch(const BroType* t, int is_init) const;

	void Append(BroType* t);
	void AppendEvenIfNotPure(BroType* t);

	void Describe(ODesc* d) const override;

	unsigned int MemoryAllocation() const override
		{
		return BroType::MemoryAllocation()
			+ padded_sizeof(*this) - padded_sizeof(BroType)
			+ types.MemoryAllocation() - padded_sizeof(types);
		}

protected:
	BroType* pure_type;
	type_list types;
};

class IndexType : public BroType {
public:
	int MatchesIndex(ListExpr*& index) const override;

	TypeList* Indices() const		{ return indices; }
	const type_list* IndexTypes() const	{ return indices->Types(); }
	BroType* YieldType() override;
	const BroType* YieldType() const override;

	void Describe(ODesc* d) const override;
	void DescribeReST(ODesc* d, bool roles_only = false) const override;

	// Returns true if this table is solely indexed by subnet.
	bool IsSubNetIndex() const;

protected:
	IndexType(){ indices = 0; yield_type = 0; }
	IndexType(TypeTag t, TypeList* arg_indices, BroType* arg_yield_type) :
		BroType(t)
		{
		indices = arg_indices;
		yield_type = arg_yield_type;
		}
	~IndexType() override;

	TypeList* indices;
	BroType* yield_type;
};

class TableType : public IndexType {
public:
	TableType(TypeList* ind, BroType* yield);

	TableType* ShallowClone() override;

	// Returns true if this table type is "unspecified", which is
	// what one gets using an empty "set()" or "table()" constructor.
	bool IsUnspecifiedTable() const;

protected:
	TableType()	{}

	TypeList* ExpandRecordIndex(RecordType* rt) const;
};

class SetType : public TableType {
public:
	SetType(TypeList* ind, ListExpr* arg_elements);
	~SetType() override;

	SetType* ShallowClone() override;

	ListExpr* SetElements() const	{ return elements; }

protected:
	SetType()	{}

	ListExpr* elements;
};

class FuncType : public BroType {
public:
	FuncType(RecordType* args, BroType* yield, function_flavor f);
	FuncType* ShallowClone() override;

	~FuncType() override;

	RecordType* Args() const	{ return args; }
	BroType* YieldType() override;
	const BroType* YieldType() const override;
	void SetYieldType(BroType* arg_yield)	{ yield = arg_yield; }
	function_flavor Flavor() const { return flavor; }
	std::string FlavorString() const;

	// Used to convert a function type to an event or hook type.
	void ClearYieldType(function_flavor arg_flav)
		{ Unref(yield); yield = 0; flavor = arg_flav; }

	int MatchesIndex(ListExpr*& index) const override;
	int CheckArgs(const type_list* args, bool is_init = false) const;

	TypeList* ArgTypes() const	{ return arg_types; }

	void Describe(ODesc* d) const override;
	void DescribeReST(ODesc* d, bool roles_only = false) const override;

protected:
	FuncType() : BroType(TYPE_FUNC) { args = 0; arg_types = 0; yield = 0; flavor = FUNC_FLAVOR_FUNCTION; }
	RecordType* args;
	TypeList* arg_types;
	BroType* yield;
	function_flavor flavor;
};

class TypeType : public BroType {
public:
	explicit TypeType(BroType* t) : BroType(TYPE_TYPE)	{ type = t->Ref(); }
	TypeType* ShallowClone() override { return new TypeType(type); }
	~TypeType() override { Unref(type); }

	BroType* Type()	{ return type; }

protected:
	TypeType()	{}

	BroType* type;
};

class TypeDecl {
public:
	TypeDecl(BroType* t, const char* i, attr_list* attrs = 0, bool in_record = false);
	TypeDecl(const TypeDecl& other);
	virtual ~TypeDecl();

	const Attr* FindAttr(attr_tag a) const
		{ return attrs ? attrs->FindAttr(a) : 0; }

	virtual void DescribeReST(ODesc* d, bool roles_only = false) const;

	BroType* type;
	Attributes* attrs;
	const char* id;
};

typedef PList<TypeDecl> type_decl_list;

class RecordType : public BroType {
public:
	explicit RecordType(type_decl_list* types);
	RecordType* ShallowClone() override;

	~RecordType() override;

	int HasField(const char* field) const override;
	BroType* FieldType(const char* field) const override;
	BroType* FieldType(int field) const;
	Val* FieldDefault(int field) const; // Ref's the returned value; 0 if none.

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
	TableVal* GetRecordFieldsVal(const RecordVal* rv = nullptr) const;

	// Returns 0 if all is ok, otherwise a pointer to an error message.
	// Takes ownership of list.
	const char* AddFields(type_decl_list* types, attr_list* attr);

	void Describe(ODesc* d) const override;
	void DescribeReST(ODesc* d, bool roles_only = false) const override;
	void DescribeFields(ODesc* d) const;
	void DescribeFieldsReST(ODesc* d, bool func_args) const;

	bool IsFieldDeprecated(int field) const
		{
		const TypeDecl* decl = FieldDecl(field);
		return decl && decl->FindAttr(ATTR_DEPRECATED) != 0;
		}

	bool FieldHasAttr(int field, attr_tag at) const
		{
		const TypeDecl* decl = FieldDecl(field);
		return decl && decl->FindAttr(at) != 0;
		}

	std::string GetFieldDeprecationWarning(int field, bool has_check) const;

protected:
	RecordType() { types = 0; }

	int num_fields;
	type_decl_list* types;
};

class SubNetType : public BroType {
public:
	SubNetType();
	void Describe(ODesc* d) const override;
};

class FileType : public BroType {
public:
	explicit FileType(BroType* yield_type);
	FileType* ShallowClone() override { return new FileType(yield->Ref()); }
	~FileType() override;

	BroType* YieldType() override;

	void Describe(ODesc* d) const override;

protected:
	FileType()	{ yield = 0; }

	BroType* yield;
};

class OpaqueType : public BroType {
public:
	explicit OpaqueType(const std::string& name);
	OpaqueType* ShallowClone() override { return new OpaqueType(name); }
	~OpaqueType() override { };

	const std::string& Name() const { return name; }

	void Describe(ODesc* d) const override;
	void DescribeReST(ODesc* d, bool roles_only = false) const override;

protected:
	OpaqueType() { }

	std::string name;
};

class EnumType : public BroType {
public:
	typedef std::list<std::pair<std::string, bro_int_t> > enum_name_list;

	explicit EnumType(const EnumType* e);
	explicit EnumType(const std::string& arg_name);
	EnumType* ShallowClone() override;
	~EnumType() override;

	// The value of this name is next internal counter value, starting
	// with zero. The internal counter is incremented.
	void AddName(const std::string& module_name, const char* name, bool is_export, Expr* deprecation = nullptr);

	// The value of this name is set to val. Once a value has been
	// explicitly assigned using this method, no further names can be
	// added that aren't likewise explicitly initalized.
	void AddName(const std::string& module_name, const char* name, bro_int_t val, bool is_export, Expr* deprecation = nullptr);

	// -1 indicates not found.
	bro_int_t Lookup(const std::string& module_name, const char* name) const;
	const char* Lookup(bro_int_t value) const; // Returns 0 if not found

	// Returns the list of defined names with their values. The names
	// will be fully qualified with their module name.
	enum_name_list Names() const;

	void DescribeReST(ODesc* d, bool roles_only = false) const override;

	EnumVal* GetVal(bro_int_t i);

protected:
	EnumType() { counter = 0; }

	void AddNameInternal(const std::string& module_name,
			const char* name, bro_int_t val, bool is_export);

	void CheckAndAddName(const std::string& module_name,
	                     const char* name, bro_int_t val, bool is_export,
	                     Expr* deprecation = nullptr);

	typedef std::map<std::string, bro_int_t> NameMap;
	NameMap names;

	using ValMap = std::unordered_map<bro_int_t, EnumVal*>;
	ValMap vals;

	// The counter is initialized to 0 and incremented on every implicit
	// auto-increment name that gets added (thus its > 0 if
	// auto-increment is used).  Once an explicit value has been
	// specified, the counter is set to -1. This way counter can be used
	// as a flag to prevent mixing of auto-increment and explicit
	// enumerator specifications.
	bro_int_t counter;
};

class VectorType : public BroType {
public:
	explicit VectorType(BroType* t);
	VectorType* ShallowClone() override;
	~VectorType() override;
	BroType* YieldType() override;
	const BroType* YieldType() const override;

	int MatchesIndex(ListExpr*& index) const override;

	// Returns true if this table type is "unspecified", which is what one
	// gets using an empty "vector()" constructor.
	bool IsUnspecifiedVector() const;

	void Describe(ODesc* d) const override;
	void DescribeReST(ODesc* d, bool roles_only = false) const override;

protected:
	VectorType()	{ yield_type = 0; }

	BroType* yield_type;
};

extern OpaqueType* md5_type;
extern OpaqueType* sha1_type;
extern OpaqueType* sha256_type;
extern OpaqueType* entropy_type;
extern OpaqueType* cardinality_type;
extern OpaqueType* topk_type;
extern OpaqueType* bloomfilter_type;
extern OpaqueType* x509_opaque_type;
extern OpaqueType* ocsp_resp_opaque_type;
extern OpaqueType* paraglob_type;

// Returns the Bro basic (non-parameterized) type with the given type.
// The reference count of the type is not increased.
BroType* base_type_no_ref(TypeTag tag);

// Returns the BRO basic (non-parameterized) type with the given type.
// The caller assumes responsibility for a reference to the type.
inline BroType* base_type(TypeTag tag)
	{ return base_type_no_ref(tag)->Ref(); }

// Returns the BRO basic error type.
inline BroType* error_type()	{ return base_type(TYPE_ERROR); }

// True if the two types are equivalent.  If is_init is true then the test is
// done in the context of an initialization. If match_record_field_names is
// true then for record types the field names have to match, too.
extern int same_type(const BroType* t1, const BroType* t2, int is_init=0, bool match_record_field_names=true);

// True if the two attribute lists are equivalent.
extern int same_attrs(const Attributes* a1, const Attributes* a2);

// Returns true if the record sub_rec can be promoted to the record
// super_rec.
extern int record_promotion_compatible(const RecordType* super_rec,
					const RecordType* sub_rec);

// If the given BroType is a TypeList with just one element, returns
// that element, otherwise returns the type.
extern const BroType* flatten_type(const BroType* t);
extern BroType* flatten_type(BroType* t);

// Returns the "maximum" of two type tags, in a type-promotion sense.
extern TypeTag max_type(TypeTag t1, TypeTag t2);

// Given two types, returns the "merge", in which promotable types
// are promoted to the maximum of the two.  Returns nil (and generates
// an error message) if the types are incompatible.
extern BroType* merge_types(const BroType* t1, const BroType* t2);

// Given a list of expressions, returns a (ref'd) type reflecting
// a merged type consistent across all of them, or nil if this
// cannot be done.
BroType* merge_type_list(ListExpr* elements);

// Given an expression, infer its type when used for an initialization.
extern BroType* init_type(Expr* init);

// Returns true if argument is an atomic type.
bool is_atomic_type(const BroType* t);

// True if the given type tag corresponds to type that can be assigned to.
extern int is_assignable(BroType* t);

// True if the given type tag corresponds to an integral type.
inline bool IsIntegral(TypeTag t) { return (t == TYPE_INT || t == TYPE_COUNT || t == TYPE_COUNTER); }

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
