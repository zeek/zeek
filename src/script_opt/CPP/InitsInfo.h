// See the file "COPYING" in the main distribution directory for copyright.

// Classes for tracking information for initializing C++ values used by the
// generated code.

// Initialization is probably the most complex part of the entire compiler,
// as there are a lot of considerations.  There are two basic parts: (1) the
// generation of C++ code for doing run-time initialization, which is covered
// by the classes in this file, and (2) the execution of that code to do the
// actual initialization, which is covered by the classes in RuntimeInits.h.
//
// There are two fundamental types of initialization, those that create values
// (such as Zeek Type and Val objects) that will be used during the execution
// of compiled scripts, and those that perform actions such as registering
// the presence of a global or a lambda.  In addition, for the former (values
// used at run-time), some are grouped together into vectors, with the compiled
// code using a hardwired index to get to a particular value; and some have
// standalone globals (for example, one for each BiF that a compiled script
// may call).
//
// For each of these types of initialization, our general approach is to a
// class that manages a single instance of that type, and an an object that
// manages all of those instances collectively.  The latter object will, for
// example, attend to determining the offset into the run-time vector associated
// with a particular initialized value.
//
// An additional complexity is that often the initialization of a particular
// value will depend on *other* values having already been initialized.  For
// example, a record type might have a field that is a table, and thus the
// type corresponding to the table needs to be available before we can create
// the record type.  However, the table might have a set of attributes
// associated with it, which have to be initialized before we can create the
// table type, those in turn requiring the initialization of each of the
// individual attributes in the set.  One of those attributes might specify
// a &default function for the table, requiring initializing *that* value
// (not just the type, but also a way to refer to the particular instance of
// the function) before initializing the attribute, etc.  Worse, record types
// can be *indirectly recursive*, which requires first initializing a "stub"
// for the record type before doing the final initialization.
//
// The general strategy for dealing with all of these dependencies is to
// compute for each initialization its "cohort".  An initialization that
// doesn't depend on any others is in cohort 0.  An initialization X that
// depends on an initialization Y will have cohort(X) = cohort(Y) + 1; or,
// in general, one more than the highest cohort of any initialization it
// depends on.  (We cut a corner in that, due to how initialization information
// is constructed, if X and Y are for the same type of object then we can
// safely use cohort(X) = cohort(Y).)  We then execute run-time initialization
// in waves, one cohort at a time.
//
// Because C++ compilers can struggle when trying to optimize large quantities
// of code - clang in particular could take many CPU *hours* back when our
// compiler just generated C++ code snippets for each initialization - rather
// than producing code that directly executes each given initialization, we
// instead employ a table-driven approach.  The C++ initializers for the
// tables contain simple values - often just vectors of integers - that compile
// quickly.  At run-time we then spin through the elements of the tables (one
// cohort at a time) to obtain the information needed to initialize any given
// item.
//
// Many forms of initialization are specified in terms of indices into globals
// that hold items of various types.  Thus, the most common initialization
// information is a vector of integers/indices.  These data structures can
// be recursive, too, namely we sometimes associate an index with a vector
// of integers/indices and then we can track multiple such vectors using
// another vector of integers/indices.

#include "zeek/File.h"
#include "zeek/Val.h"
#include "zeek/script_opt/ProfileFunc.h"

#pragma once

namespace zeek::detail
	{

class CPPCompile;

// Abstract class for tracking information about a single initialization item.
class CPP_InitInfo;

// Abstract class for tracking information about a collection of initialization
// items.
class CPP_InitsInfo
	{
public:
	CPP_InitsInfo(std::string _tag, std::string type) : tag(std::move(_tag))
		{
		base_name = std::string("CPP__") + tag + "__";
		CPP_type = tag + type;
		}

	virtual ~CPP_InitsInfo() { }

	// Returns the name of the C++ global that will hold the items' values
	// at run-time, once initialized.  These are all vectors, for which
	// the generated code accesses a particular item by indexing the vector.
	const std::string& InitsName() const { return base_name; }

	// Returns the name of the C++ global used to hold the table we employ
	// for table-driven initialization.
	std::string InitializersName() const { return base_name + "init"; }

	// Returns the "name" of the given element in the run-time vector
	// associated with this collection of initialization items.  It's not
	// really a name but rather a vector index, so for example Name(12)
	// might return "CPP__Pattern__[12]", but we use the term Name because
	// the representation used to be individualized globals, such as
	// "CPP__Pattern__12".
	std::string Name(int index) const;

	// Returns the name that will correspond to the next item added to
	// this set.
	std::string NextName() const { return Name(size); }

	// The largest initialization cohort of any item in this collection.
	int MaxCohort() const { return static_cast<int>(instances.size()) - 1; }

	// Returns the number of initializations in this collection that below
	// to the given cohort c.
	int CohortSize(int c) const { return c > MaxCohort() ? 0 : instances[c].size(); }

	// Returns the C++ type associated with this collection's run-time vector.
	// This might be, for example, "PatternVal"
	const std::string& CPPType() const { return CPP_type; }

	// Sets the associated C++ type.
	virtual void SetCPPType(std::string ct) { CPP_type = std::move(ct); }

	// Returns the type associated with the table used for initialization
	// (i.e., this is the type of the global returned by InitializersName()).
	std::string InitsType() const { return inits_type; }

	// Add a new initialization instance to the collection.
	void AddInstance(std::shared_ptr<CPP_InitInfo> g);

	// Emit code to populate the table used to initialize this collection.
	void GenerateInitializers(CPPCompile* c);

protected:
	// Computes offset_set - see below.
	void BuildOffsetSet(CPPCompile* c);

	// Returns a declaration suitable for the run-time vector that holds
	// the initialized items in the collection.
	std::string Declare() const;

	// For a given cohort, generates the associated table elements for
	// creating it.
	void BuildCohort(CPPCompile* c, std::vector<std::shared_ptr<CPP_InitInfo>>& cohort);

	// Given the initialization type and initializers for with a given
	// cohort element, build the associated table element.
	virtual void BuildCohortElement(CPPCompile* c, std::string init_type,
	                                std::vector<std::string>& ivs);

	// Total number of initializers.
	int size = 0;

	// Each cohort is represented by a vector whose elements correspond
	// to the initialization information for a single item.  This variable
	// holds a vector of cohorts, indexed by the number of the cohort.
	// (Note, some cohorts may be empty.)
	std::vector<std::vector<std::shared_ptr<CPP_InitInfo>>> instances;

	// Each cohort has associated with it a vector of offsets, specifying
	// positions in the run-time vector of the items in the cohort.
	//
	// We reduce each such vector to an index into the collection of
	// such vectors (as managed by an IndicesManager - see below).
	//
	// Once we've done that reduction, we can represent each cohort
	// using a single index, and thus all of the cohorts using a vector
	// of indices.  We then reduce *that* vector to a single index,
	// again using the IndicesManager.  We store that single index
	// in the "offset_set" variable.
	int offset_set = 0;

	// Tag used to distinguish a particular collection of constants.
	std::string tag;

	// C++ name for this collection of constants.
	std::string base_name;

	// C++ type associated with a single instance of these constants.
	std::string CPP_type;

	// C++ type associated with the collection of initializers.
	std::string inits_type;
	};

// A class for a collection of initialization items for which each item
// has a "custom" initializer (that is, a bespoke C++ object, rather than
// a simple C++ type or a vector of indices).
class CPP_CustomInitsInfo : public CPP_InitsInfo
	{
public:
	CPP_CustomInitsInfo(std::string _tag, std::string _type)
		: CPP_InitsInfo(std::move(_tag), std::move(_type))
		{
		BuildInitType();
		}

	void SetCPPType(std::string ct) override
		{
		CPP_InitsInfo::SetCPPType(std::move(ct));
		BuildInitType();
		}

private:
	void BuildInitType() { inits_type = std::string("CPP_CustomInits<") + CPPType() + ">"; }
	};

// A class for a collection of initialization items corresponding to "basic"
// constants, i.e., those that can be represented either directly as C++
// constants, or as indices into a vector of C++ objects.
class CPP_BasicConstInitsInfo : public CPP_CustomInitsInfo
	{
public:
	// In the following, if "c_type" is non-empty then it specifes the
	// C++ type used to directly represent the constant.  If empty, it
	// indicates that we instead use an index into a separate vector.
	CPP_BasicConstInitsInfo(std::string _tag, std::string type, std::string c_type)
		: CPP_CustomInitsInfo(std::move(_tag), std::move(type))
		{
		if ( c_type.empty() )
			inits_type = std::string("CPP_") + tag + "Consts";
		else
			inits_type = std::string("CPP_BasicConsts<") + CPP_type + ", " + c_type + ", " + tag +
			             "Val>";
		}

	void BuildCohortElement(CPPCompile* c, std::string init_type,
	                        std::vector<std::string>& ivs) override;
	};

// A class for a collection of initialization items that are defined using
// other initialization items.
class CPP_CompoundInitsInfo : public CPP_InitsInfo
	{
public:
	CPP_CompoundInitsInfo(std::string _tag, std::string type)
		: CPP_InitsInfo(std::move(_tag), std::move(type))
		{
		if ( tag == "Type" )
			// These need a refined version of CPP_IndexedInits
			// in order to build different types dynamically.
			inits_type = "CPP_TypeInits";
		else
			inits_type = std::string("CPP_IndexedInits<") + CPPType() + ">";
		}

	void BuildCohortElement(CPPCompile* c, std::string init_type,
	                        std::vector<std::string>& ivs) override;
	};

// Abstract class for tracking information about a single initialization item.
class CPP_InitInfo
	{
public:
	// No constructor - basic initialization happens when the object is
	// added via AddInstance() to a CPP_InitsInfo object, which in turn
	// will lead to invocation of this object's SetOffset() method.

	virtual ~CPP_InitInfo() { }

	// Associates this item with an initialization collection and run-time
	// vector offset.
	void SetOffset(const CPP_InitsInfo* _inits_collection, int _offset)
		{
		inits_collection = _inits_collection;
		offset = _offset;
		}

	// Returns the offset for this item into the associated run-time vector.
	int Offset() const { return offset; }

	// Returns the name that should be used for referring to this
	// value in the generated code.
	std::string Name() const { return inits_collection->Name(offset); }

	// Returns this item's initialization cohort.
	int InitCohort() const { return init_cohort; }

	// Returns the type used for this initializer.
	virtual std::string InitializerType() const { return "<shouldn't-be-used>"; }

	// Returns values used for creating this value, one element per
	// constructor parameter.
	virtual void InitializerVals(std::vector<std::string>& ivs) const = 0;

protected:
	// Returns an offset (into the run-time vector holding all Zeek
	// constant values) corresponding to the given value.  Registers
	// the constant if needed.
	std::string ValElem(CPPCompile* c, ValPtr v);

	// By default, values have no dependencies on other values
	// being first initialized.  Those that do must increase this
	// value in their constructors.
	int init_cohort = 0;

	// Tracks the collection to which this item belongs.
	const CPP_InitsInfo* inits_collection = nullptr;

	// Offset of this item in the collection, or -1 if no association.
	int offset = -1;
	};

// Information associated with initializing a basic (non-compound) constant.
class BasicConstInfo : public CPP_InitInfo
	{
public:
	BasicConstInfo(std::string _val) : val(std::move(_val)) { }

	void InitializerVals(std::vector<std::string>& ivs) const override { ivs.emplace_back(val); }

private:
	// All we need to track is the C++ representation of the constant.
	std::string val;
	};

// Information associated with initializing a constant whose Val constructor
// takes a string.
class DescConstInfo : public CPP_InitInfo
	{
public:
	DescConstInfo(CPPCompile* c, ValPtr v);

	void InitializerVals(std::vector<std::string>& ivs) const override { ivs.emplace_back(init); }

private:
	std::string init;
	};

class EnumConstInfo : public CPP_InitInfo
	{
public:
	EnumConstInfo(CPPCompile* c, ValPtr v);

	void InitializerVals(std::vector<std::string>& ivs) const override
		{
		ivs.emplace_back(std::to_string(e_type));
		ivs.emplace_back(std::to_string(e_val));
		}

private:
	int e_type; // an index into the enum's Zeek type
	int e_val; // integer value of the enum
	};

class StringConstInfo : public CPP_InitInfo
	{
public:
	StringConstInfo(CPPCompile* c, ValPtr v);

	void InitializerVals(std::vector<std::string>& ivs) const override
		{
		ivs.emplace_back(std::to_string(chars));
		ivs.emplace_back(std::to_string(len));
		}

private:
	int chars; // index into vector of char*'s
	int len; // length of the string
	};

class PatternConstInfo : public CPP_InitInfo
	{
public:
	PatternConstInfo(CPPCompile* c, ValPtr v);

	void InitializerVals(std::vector<std::string>& ivs) const override
		{
		ivs.emplace_back(std::to_string(pattern));
		ivs.emplace_back(std::to_string(is_case_insensitive));
		ivs.emplace_back(std::to_string(is_single_line));
		}

private:
	int pattern; // index into string representation of pattern
	int is_case_insensitive; // case-insensitivity flag, 0 or 1
	int is_single_line; // single-line flag, 0 or 1
	};

class PortConstInfo : public CPP_InitInfo
	{
public:
	PortConstInfo(ValPtr v) : p(static_cast<UnsignedValImplementation*>(v->AsPortVal())->Get()) { }

	void InitializerVals(std::vector<std::string>& ivs) const override
		{
		ivs.emplace_back(std::to_string(p) + "U");
		}

private:
	zeek_uint_t p;
	};

// Abstract class for compound items (those defined in terms of other items).
class CompoundItemInfo : public CPP_InitInfo
	{
public:
	// The first of these is used for items with custom Zeek types,
	// the second when the type is generic/inapplicable.
	CompoundItemInfo(CPPCompile* c, ValPtr v);
	CompoundItemInfo(CPPCompile* _c) : c(_c) { type = -1; }

	void InitializerVals(std::vector<std::string>& ivs) const override
		{
		if ( type >= 0 )
			ivs.emplace_back(std::to_string(type));

		for ( auto& v : vals )
			ivs.push_back(v);
		}

protected:
	CPPCompile* c;
	int type;
	std::vector<std::string> vals; // initialization values
	};

// This next set corresponds to compound Zeek constants of various types.
class ListConstInfo : public CompoundItemInfo
	{
public:
	ListConstInfo(CPPCompile* c, ValPtr v);
	};

class VectorConstInfo : public CompoundItemInfo
	{
public:
	VectorConstInfo(CPPCompile* c, ValPtr v);
	};

class RecordConstInfo : public CompoundItemInfo
	{
public:
	RecordConstInfo(CPPCompile* c, ValPtr v);
	};

class TableConstInfo : public CompoundItemInfo
	{
public:
	TableConstInfo(CPPCompile* c, ValPtr v);
	};

class FileConstInfo : public CompoundItemInfo
	{
public:
	FileConstInfo(CPPCompile* c, ValPtr v);
	};

class FuncConstInfo : public CompoundItemInfo
	{
public:
	FuncConstInfo(CPPCompile* _c, ValPtr v);

	void InitializerVals(std::vector<std::string>& ivs) const override;

private:
	FuncVal* fv;
	};

// Initialization information for single attributes and sets of attributes.
class AttrInfo : public CompoundItemInfo
	{
public:
	AttrInfo(CPPCompile* c, const AttrPtr& attr);
	};

class AttrsInfo : public CompoundItemInfo
	{
public:
	AttrsInfo(CPPCompile* c, const AttributesPtr& attrs);
	};

// Information for initialization a Zeek global.
class GlobalInitInfo : public CPP_InitInfo
	{
public:
	GlobalInitInfo(CPPCompile* c, const ID* g, std::string CPP_name);

	std::string InitializerType() const override { return "CPP_GlobalInit"; }
	void InitializerVals(std::vector<std::string>& ivs) const override;

protected:
	std::string Zeek_name;
	std::string CPP_name;
	int type;
	int attrs;
	std::string val;
	bool exported;
	};

// Information for initializing an item corresponding to a Zeek function
// call, needed to associate complex expressions with attributes.
class CallExprInitInfo : public CPP_InitInfo
	{
public:
	CallExprInitInfo(CPPCompile* c, ExprPtr e, std::string e_name, std::string wrapper_class);

	std::string InitializerType() const override
		{
		return std::string("CPP_CallExprInit<") + wrapper_class + ">";
		}
	void InitializerVals(std::vector<std::string>& ivs) const override { ivs.emplace_back(e_name); }

	// Accessors, since code to initialize these is generated separately
	// from that of most initialization collections.
	const ExprPtr& GetExpr() const { return e; }
	const std::string& Name() const { return e_name; }
	const std::string& WrapperClass() const { return wrapper_class; }

protected:
	ExprPtr e;
	std::string e_name;
	std::string wrapper_class;
	};

// Information for registering the class/function associated with a lambda.
class LambdaRegistrationInfo : public CPP_InitInfo
	{
public:
	LambdaRegistrationInfo(CPPCompile* c, std::string name, FuncTypePtr ft,
	                       std::string wrapper_class, p_hash_type h, bool has_captures);

	std::string InitializerType() const override
		{
		return std::string("CPP_LambdaRegistration<") + wrapper_class + ">";
		}
	void InitializerVals(std::vector<std::string>& ivs) const override;

protected:
	std::string name;
	int func_type;
	std::string wrapper_class;
	p_hash_type h;
	bool has_captures;
	};

// Abstract class for representing information for initializing a Zeek type.
class AbstractTypeInfo : public CPP_InitInfo
	{
public:
	AbstractTypeInfo(CPPCompile* _c, TypePtr _t) : c(_c), t(std::move(_t)) { }

	void InitializerVals(std::vector<std::string>& ivs) const override
		{
		ivs.emplace_back(std::to_string(static_cast<int>(t->Tag())));
		AddInitializerVals(ivs);
		}

	virtual void AddInitializerVals(std::vector<std::string>& ivs) const { }

protected:
	CPPCompile* c;
	TypePtr t; // the type we're initializing
	};

// The following capture information for different Zeek types.
class BaseTypeInfo : public AbstractTypeInfo
	{
public:
	BaseTypeInfo(CPPCompile* _c, TypePtr _t) : AbstractTypeInfo(_c, std::move(_t)) { }
	};

class EnumTypeInfo : public AbstractTypeInfo
	{
public:
	EnumTypeInfo(CPPCompile* _c, TypePtr _t) : AbstractTypeInfo(_c, std::move(_t)) { }

	void AddInitializerVals(std::vector<std::string>& ivs) const override;
	};

class OpaqueTypeInfo : public AbstractTypeInfo
	{
public:
	OpaqueTypeInfo(CPPCompile* _c, TypePtr _t) : AbstractTypeInfo(_c, std::move(_t)) { }

	void AddInitializerVals(std::vector<std::string>& ivs) const override;
	};

class TypeTypeInfo : public AbstractTypeInfo
	{
public:
	TypeTypeInfo(CPPCompile* c, TypePtr _t);

	void AddInitializerVals(std::vector<std::string>& ivs) const override;

private:
	TypePtr tt; // the type referred to by t
	};

class VectorTypeInfo : public AbstractTypeInfo
	{
public:
	VectorTypeInfo(CPPCompile* c, TypePtr _t);

	void AddInitializerVals(std::vector<std::string>& ivs) const override;

private:
	TypePtr yield;
	};

class ListTypeInfo : public AbstractTypeInfo
	{
public:
	ListTypeInfo(CPPCompile* c, TypePtr _t);

	void AddInitializerVals(std::vector<std::string>& ivs) const override;

private:
	const std::vector<TypePtr>& types;
	};

class TableTypeInfo : public AbstractTypeInfo
	{
public:
	TableTypeInfo(CPPCompile* c, TypePtr _t);

	void AddInitializerVals(std::vector<std::string>& ivs) const override;

private:
	int indices;
	TypePtr yield;
	};

class FuncTypeInfo : public AbstractTypeInfo
	{
public:
	FuncTypeInfo(CPPCompile* c, TypePtr _t);

	void AddInitializerVals(std::vector<std::string>& ivs) const override;

private:
	FunctionFlavor flavor;
	TypePtr params;
	TypePtr yield;
	};

class RecordTypeInfo : public AbstractTypeInfo
	{
public:
	RecordTypeInfo(CPPCompile* c, TypePtr _t);

	void AddInitializerVals(std::vector<std::string>& ivs) const override;

private:
	std::vector<std::string> field_names;
	std::vector<TypePtr> field_types;
	std::vector<int> field_attrs;
	};

// Much of the table-driven initialization is based on vectors of indices,
// which we represent as vectors of int's, where each int is used to index a
// global C++ vector.  This class manages such vectors.  In particular, it
// reduces a given vector-of-indices to a single value, itself an index, that
// can be used at run-time to retrieve a reference to the original vector.
//
// Note that the notion recurses: if we have several vector-of-indices, we can
// reduce each to an index, and then take the resulting vector-of-meta-indices
// and reduce it further to an index.  Doing so allows us to concisely refer
// to a potentially large, deep set of indices using a single value - such as
// for CPP_InitsInfo's "offset_set" member variable.

class IndicesManager
	{
public:
	IndicesManager() { }

	// Adds a new vector-of-indices to the collection we're tracking,
	// returning the offset that will be associated with it at run-time.
	int AddIndices(std::vector<int> indices)
		{
		int n = indices_set.size();
		indices_set.emplace_back(std::move(indices));
		return n;
		}

	// Generates the initializations used to construct the managed
	// vectors at run-time.
	void Generate(CPPCompile* c);

private:
	// Each vector-of-indices being tracked.  We could obtain some
	// space and time savings by recognizing duplicate vectors
	// (for example, empty vectors are very common), but as long
	// as the code compiles and executes without undue overhead,
	// this doesn't appear necessary.
	std::vector<std::vector<int>> indices_set;
	};

	} // zeek::detail
