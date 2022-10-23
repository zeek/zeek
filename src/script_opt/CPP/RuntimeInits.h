// See the file "COPYING" in the main distribution directory for copyright.

// Classes for run-time initialization and management of C++ values used
// by the generated code.

// See InitsInfo.h for a discussion of initialization issues and the
// associated strategies for dealing with them.

#include "zeek/Expr.h"
#include "zeek/module_util.h"
#include "zeek/script_opt/CPP/RuntimeInitSupport.h"

#pragma once

namespace zeek::detail
	{

using FileValPtr = IntrusivePtr<FileVal>;
using FuncValPtr = IntrusivePtr<FuncVal>;

class InitsManager;

// An abstract helper class used to access elements of an initialization vector.
// We need the abstraction because InitsManager below needs to be able to refer
// to any of a range of templated classes.
class CPP_AbstractInitAccessor
	{
public:
	virtual ~CPP_AbstractInitAccessor() { }
	virtual ValPtr Get(int index) const { return nullptr; }
	};

// Convenient way to refer to an offset associated with a particular Zeek type.
using CPP_ValElem = std::pair<TypeTag, int>;

// This class groups together all of the vectors needed for run-time
// initialization.  We gather them together into a single object so as
// to avoid wiring in a set of globals that the various initialization
// methods have to know about.
class InitsManager
	{
public:
	InitsManager(std::vector<CPP_ValElem>& _const_vals,
	             std::map<TypeTag, std::shared_ptr<CPP_AbstractInitAccessor>>& _consts,
	             std::vector<std::vector<int>>& _indices, std::vector<const char*>& _strings,
	             std::vector<p_hash_type>& _hashes, std::vector<TypePtr>& _types,
	             std::vector<AttributesPtr>& _attributes, std::vector<AttrPtr>& _attrs,
	             std::vector<CallExprPtr>& _call_exprs)
		: const_vals(_const_vals), consts(_consts), indices(_indices), strings(_strings),
		  hashes(_hashes), types(_types), attributes(_attributes), attrs(_attrs),
		  call_exprs(_call_exprs)
		{
		}

	// Provides generic access to Zeek constant values based on a single
	// index.
	ValPtr ConstVals(int offset) const
		{
		auto& cv = const_vals[offset];
		return Consts(cv.first, cv.second);
		}

	// Retrieves the Zeek constant value for a particular Zeek type.
	ValPtr Consts(TypeTag tag, int index) const { return consts[tag]->Get(index); }

	// Accessors for the sundry initialization vectors, each retrieving
	// a specific element identified by an index/offset.
	const std::vector<int>& Indices(int offset) const { return indices[offset]; }
	const char* Strings(int offset) const
		{
		ASSERT(offset >= 0 && offset < static_cast<int>(strings.size()));
		ASSERT(strings[offset]);
		return strings[offset];
		}
	const p_hash_type Hashes(int offset) const
		{
		ASSERT(offset >= 0 && offset < static_cast<int>(hashes.size()));
		return hashes[offset];
		}
	const TypePtr& Types(int offset) const
		{
		ASSERT(offset >= 0 && offset < static_cast<int>(types.size()));
		ASSERT(types[offset]);
		return types[offset];
		}
	const AttributesPtr& Attributes(int offset) const
		{
		ASSERT(offset >= 0 && offset < static_cast<int>(attributes.size()));
		ASSERT(attributes[offset]);
		return attributes[offset];
		}
	const AttrPtr& Attrs(int offset) const
		{
		ASSERT(offset >= 0 && offset < static_cast<int>(attrs.size()));
		ASSERT(attrs[offset]);
		return attrs[offset];
		}
	const CallExprPtr& CallExprs(int offset) const
		{
		ASSERT(offset >= 0 && offset < static_cast<int>(call_exprs.size()));
		ASSERT(call_exprs[offset]);
		return call_exprs[offset];
		}

private:
	std::vector<CPP_ValElem>& const_vals;
	std::map<TypeTag, std::shared_ptr<CPP_AbstractInitAccessor>>& consts;
	std::vector<std::vector<int>>& indices;
	std::vector<const char*>& strings;
	std::vector<p_hash_type>& hashes;
	std::vector<TypePtr>& types;
	std::vector<AttributesPtr>& attributes;
	std::vector<AttrPtr>& attrs;
	std::vector<CallExprPtr>& call_exprs;
	};

// Manages an initialization vector of the given type.
template <class T> class CPP_Init
	{
public:
	virtual ~CPP_Init() { }

	// Pre-initializes the given element of the vector, if necessary.
	virtual void PreInit(InitsManager* im, std::vector<T>& inits_vec, int offset) const { }

	// Initializes the given element of the vector.
	virtual void Generate(InitsManager* im, std::vector<T>& inits_vec, int offset) const { }
	};

// Abstract class for creating a collection of initializers.  T1 is
// the type of the generated vector, T2 the type of its initializers.
template <class T1, class T2> class CPP_AbstractInits
	{
public:
	CPP_AbstractInits(std::vector<T1>& _inits_vec, int _offsets_set, std::vector<T2> _inits)
		: inits_vec(_inits_vec), offsets_set(_offsets_set), inits(std::move(_inits))
		{
		// Compute how big to make the vector.
		int num_inits = 0;

		for ( const auto& cohort : inits )
			num_inits += cohort.size();

		inits_vec.resize(num_inits);
		}

	// Initialize the given cohort of elements.
	void InitializeCohort(InitsManager* im, int cohort)
		{
		// Get this object's vector-of-vector-of-indices.
		auto& offsets_vec = im->Indices(offsets_set);

		if ( cohort == 0 )
			DoPreInits(im, offsets_vec);

		// Get the vector-of-indices for this cohort.
		auto& cohort_offsets = im->Indices(offsets_vec[cohort]);

		InitializeCohortWithOffsets(im, cohort, cohort_offsets);
		}

protected:
	virtual void InitializeCohortWithOffsets(InitsManager* im, int cohort,
	                                         const std::vector<int>& cohort_offsets)
		{
		}

	// Pre-initialize all elements requiring it.
	virtual void DoPreInits(InitsManager* im, const std::vector<int>& offsets_vec) { }

	// Generate a single element.
	virtual void GenerateElement(InitsManager* im, T2& init, int offset) { }

	// The initialization vector in its entirety.
	std::vector<T1>& inits_vec;

	// A meta-index for retrieving the vector-of-vector-of-indices.
	int offsets_set;

	// Indexed by cohort.
	std::vector<T2> inits;
	};

// Manages an initialization vector that uses "custom" initializers
// (tailored ones rather than initializers based on indexing).
template <class T> using CPP_InitVec = std::vector<std::shared_ptr<CPP_Init<T>>>;
template <class T> class CPP_CustomInits : public CPP_AbstractInits<T, CPP_InitVec<T>>
	{
public:
	CPP_CustomInits(std::vector<T>& _inits_vec, int _offsets_set,
	                std::vector<CPP_InitVec<T>> _inits)
		: CPP_AbstractInits<T, CPP_InitVec<T>>(_inits_vec, _offsets_set, std::move(_inits))
		{
		}

private:
	void DoPreInits(InitsManager* im, const std::vector<int>& offsets_vec) override
		{
		int cohort = 0;
		for ( const auto& co : this->inits )
			{
			auto& cohort_offsets = im->Indices(offsets_vec[cohort]);
			for ( auto i = 0U; i < co.size(); ++i )
				co[i]->PreInit(im, this->inits_vec, cohort_offsets[i]);
			++cohort;
			}
		}

	void InitializeCohortWithOffsets(InitsManager* im, int cohort,
	                                 const std::vector<int>& cohort_offsets) override
		{
		// Loop over the cohort's elements to initialize them.
		auto& co = this->inits[cohort];
		for ( auto i = 0U; i < co.size(); ++i )
			co[i]->Generate(im, this->inits_vec, cohort_offsets[i]);
		}
	};

// Provides access to elements of an initialization vector of the given type.
template <class T> class CPP_InitAccessor : public CPP_AbstractInitAccessor
	{
public:
	CPP_InitAccessor(std::vector<T>& _inits_vec) : inits_vec(_inits_vec) { }

	ValPtr Get(int index) const override { return inits_vec[index]; }

private:
	std::vector<T>& inits_vec;
	};

// A type used for initializations that are based on indices into
// initialization vectors.
using ValElemVec = std::vector<int>;
using ValElemVecVec = std::vector<ValElemVec>;

// Manages an initialization vector of the given type whose elements are
// built up from previously constructed values in other initialization vectors.
template <class T> class CPP_IndexedInits : public CPP_AbstractInits<T, ValElemVecVec>
	{
public:
	CPP_IndexedInits(std::vector<T>& _inits_vec, int _offsets_set,
	                 std::vector<ValElemVecVec> _inits)
		: CPP_AbstractInits<T, ValElemVecVec>(_inits_vec, _offsets_set, std::move(_inits))
		{
		}

protected:
	void InitializeCohortWithOffsets(InitsManager* im, int cohort,
	                                 const std::vector<int>& cohort_offsets) override;

	// Note, in the following we pass in the inits_vec, even though
	// the method will have direct access to it, because we want to
	// use overloading to dispatch to custom generation for different
	// types of values.
	void Generate(InitsManager* im, std::vector<EnumValPtr>& ivec, int offset,
	              ValElemVec& init_vals);
	void Generate(InitsManager* im, std::vector<StringValPtr>& ivec, int offset,
	              ValElemVec& init_vals);
	void Generate(InitsManager* im, std::vector<PatternValPtr>& ivec, int offset,
	              ValElemVec& init_vals);
	void Generate(InitsManager* im, std::vector<ListValPtr>& ivec, int offset,
	              ValElemVec& init_vals) const;
	void Generate(InitsManager* im, std::vector<VectorValPtr>& ivec, int offset,
	              ValElemVec& init_vals) const;
	void Generate(InitsManager* im, std::vector<RecordValPtr>& ivec, int offset,
	              ValElemVec& init_vals) const;
	void Generate(InitsManager* im, std::vector<TableValPtr>& ivec, int offset,
	              ValElemVec& init_vals) const;
	void Generate(InitsManager* im, std::vector<FileValPtr>& ivec, int offset,
	              ValElemVec& init_vals) const;
	void Generate(InitsManager* im, std::vector<FuncValPtr>& ivec, int offset,
	              ValElemVec& init_vals) const;
	void Generate(InitsManager* im, std::vector<AttrPtr>& ivec, int offset,
	              ValElemVec& init_vals) const;
	void Generate(InitsManager* im, std::vector<AttributesPtr>& ivec, int offset,
	              ValElemVec& init_vals) const;

	// The TypePtr initialization vector requires special treatment, since
	// it has to dispatch on subclasses of TypePtr.
	virtual void Generate(InitsManager* im, std::vector<TypePtr>& ivec, int offset,
	                      ValElemVec& init_vals) const
		{
		ASSERT(0);
		}
	};

// A specialization of CPP_IndexedInits that supports initializing based
// on subclasses of TypePtr.
class CPP_TypeInits : public CPP_IndexedInits<TypePtr>
	{
public:
	CPP_TypeInits(std::vector<TypePtr>& _inits_vec, int _offsets_set,
	              std::vector<std::vector<ValElemVec>> _inits)
		: CPP_IndexedInits<TypePtr>(_inits_vec, _offsets_set, _inits)
		{
		}

protected:
	void DoPreInits(InitsManager* im, const std::vector<int>& offsets_vec) override;
	void PreInit(InitsManager* im, int offset, ValElemVec& init_vals);

	void Generate(InitsManager* im, std::vector<TypePtr>& ivec, int offset,
	              ValElemVec& init_vals) const override;

	TypePtr BuildEnumType(InitsManager* im, ValElemVec& init_vals) const;
	TypePtr BuildOpaqueType(InitsManager* im, ValElemVec& init_vals) const;
	TypePtr BuildTypeType(InitsManager* im, ValElemVec& init_vals) const;
	TypePtr BuildVectorType(InitsManager* im, ValElemVec& init_vals) const;
	TypePtr BuildTypeList(InitsManager* im, ValElemVec& init_vals, int offset) const;
	TypePtr BuildTableType(InitsManager* im, ValElemVec& init_vals) const;
	TypePtr BuildFuncType(InitsManager* im, ValElemVec& init_vals) const;
	TypePtr BuildRecordType(InitsManager* im, ValElemVec& init_vals, int offset) const;
	};

// Abstract class for initializing basic (non-compound) constants.  T1 is
// the Zeek type for the constructed constant, T2 is the C++ type of its
// initializer.
//
// In principle we could derive this from CPP_AbstractInits, though to do so
// we'd need to convert the initializers to a vector-of-vector-of-T2, which
// would trade complexity here for complexity in InitsInfo.  So we instead
// keep this class distinct, since at heart it's a simpler set of methods
// and that way we can keep them as such here.
template <class T1, typename T2> class CPP_AbstractBasicConsts
	{
public:
	CPP_AbstractBasicConsts(std::vector<T1>& _inits_vec, int _offsets_set, std::vector<T2> _inits)
		: inits_vec(_inits_vec), offsets_set(_offsets_set), inits(std::move(_inits))
		{
		inits_vec.resize(inits.size());
		}

	void InitializeCohort(InitsManager* im, int cohort)
		{
		ASSERT(cohort == 0);
		auto& offsets_vec = im->Indices(offsets_set);
		auto& cohort_offsets = im->Indices(offsets_vec[cohort]);
		for ( auto i = 0U; i < inits.size(); ++i )
			InitElem(im, cohort_offsets[i], i);
		}

protected:
	virtual void InitElem(InitsManager* im, int offset, int index) { ASSERT(0); }

protected:
	// See CPP_AbstractInits for the nature of these.
	std::vector<T1>& inits_vec;
	int offsets_set;
	std::vector<T2> inits;
	};

// Class for initializing a basic constant of Zeek type T1, using initializers
// of C++ type T2.  T1 is an intrusive pointer to a T3 type; for example, if
// T1 is a BoolValPtr then T3 will be BoolVal.
template <class T1, typename T2, class T3>
class CPP_BasicConsts : public CPP_AbstractBasicConsts<T1, T2>
	{
public:
	CPP_BasicConsts(std::vector<T1>& _inits_vec, int _offsets_set, std::vector<T2> _inits)
		: CPP_AbstractBasicConsts<T1, T2>(_inits_vec, _offsets_set, std::move(_inits))
		{
		}

	void InitElem(InitsManager* /* im */, int offset, int index) override
		{
		this->inits_vec[offset] = make_intrusive<T3>(this->inits[index]);
		}
	};

// Specific classes for basic constants that use string-based constructors.
class CPP_AddrConsts : public CPP_AbstractBasicConsts<AddrValPtr, int>
	{
public:
	CPP_AddrConsts(std::vector<AddrValPtr>& _inits_vec, int _offsets_set, std::vector<int> _inits)
		: CPP_AbstractBasicConsts<AddrValPtr, int>(_inits_vec, _offsets_set, std::move(_inits))
		{
		}

	void InitElem(InitsManager* im, int offset, int index) override
		{
		auto s = im->Strings(this->inits[index]);
		this->inits_vec[offset] = make_intrusive<AddrVal>(s);
		}
	};

class CPP_SubNetConsts : public CPP_AbstractBasicConsts<SubNetValPtr, int>
	{
public:
	CPP_SubNetConsts(std::vector<SubNetValPtr>& _inits_vec, int _offsets_set,
	                 std::vector<int> _inits)
		: CPP_AbstractBasicConsts<SubNetValPtr, int>(_inits_vec, _offsets_set, std::move(_inits))
		{
		}

	void InitElem(InitsManager* im, int offset, int index) override
		{
		auto s = im->Strings(this->inits[index]);
		this->inits_vec[offset] = make_intrusive<SubNetVal>(s);
		}
	};

// Class for initializing a Zeek global.  These don't go into an initialization
// vector, so we use void* as the underlying type.
class CPP_GlobalInit : public CPP_Init<void*>
	{
public:
	CPP_GlobalInit(IDPtr& _global, const char* _name, int _type, int _attrs, int _val,
	               bool _exported)
		: CPP_Init<void*>(), global(_global), name(_name), type(_type), attrs(_attrs), val(_val),
		  exported(_exported)
		{
		}

	void Generate(InitsManager* im, std::vector<void*>& /* inits_vec */,
	              int /* offset */) const override;

protected:
	IDPtr& global;
	const char* name;
	int type;
	int attrs;
	int val;
	bool exported;
	};

// Abstract class for constructing a CallExpr to evaluate a Zeek expression.
class CPP_AbstractCallExprInit : public CPP_Init<CallExprPtr>
	{
public:
	CPP_AbstractCallExprInit() : CPP_Init<CallExprPtr>() { }
	};

// Constructs a CallExpr that calls a given CPPFunc subclass.
template <class T> class CPP_CallExprInit : public CPP_AbstractCallExprInit
	{
public:
	CPP_CallExprInit(CallExprPtr& _e_var) : CPP_AbstractCallExprInit(), e_var(_e_var) { }

	void Generate(InitsManager* /* im */, std::vector<CallExprPtr>& inits_vec,
	              int offset) const override
		{
		auto wrapper_class = make_intrusive<T>();
		auto func_val = make_intrusive<FuncVal>(wrapper_class);
		auto func_expr = make_intrusive<ConstExpr>(func_val);
		auto empty_args = make_intrusive<ListExpr>();

		e_var = make_intrusive<CallExpr>(func_expr, empty_args);
		inits_vec[offset] = e_var;
		}

private:
	// Where to store the expression once we've built it.
	CallExprPtr& e_var;
	};

// Abstract class for registering a lambda defined in terms of a CPPStmt.
class CPP_AbstractLambdaRegistration : public CPP_Init<void*>
	{
public:
	CPP_AbstractLambdaRegistration() : CPP_Init<void*>() { }
	};

// Registers a lambda defined in terms of a given CPPStmt subclass.
template <class T> class CPP_LambdaRegistration : public CPP_AbstractLambdaRegistration
	{
public:
	CPP_LambdaRegistration(const char* _name, int _func_type, p_hash_type _h, bool _has_captures)
		: CPP_AbstractLambdaRegistration(), name(_name), func_type(_func_type), h(_h),
		  has_captures(_has_captures)
		{
		}

	void Generate(InitsManager* im, std::vector<void*>& inits_vec, int offset) const override
		{
		auto l = make_intrusive<T>(name);
		auto& ft = im->Types(func_type);
		register_lambda__CPP(l, h, name, ft, has_captures);
		}

protected:
	const char* name;
	int func_type;
	p_hash_type h;
	bool has_captures;
	};

// Constructs at run-time a mapping between abstract record field offsets used
// when compiling a set of scripts to their concrete offsets (which might differ
// from those during compilation due to loading of other scripts that extend
// various records).
class CPP_FieldMapping
	{
public:
	CPP_FieldMapping(int _rec, std::string _field_name, int _field_type, int _field_attrs)
		: rec(_rec), field_name(std::move(_field_name)), field_type(_field_type),
		  field_attrs(_field_attrs)
		{
		}

	int ComputeOffset(InitsManager* im) const;

private:
	int rec; // index to retrieve the record's type
	std::string field_name; // which field this offset pertains to
	int field_type; // the field's type, in case we have to construct it
	int field_attrs; // the same for the field's attributes
	};

// Constructs at run-time a mapping between abstract enum values used when
// compiling a set of scripts to their concrete values (which might differ
// from those during compilation due to loading of other scripts that extend
// the enum).
class CPP_EnumMapping
	{
public:
	CPP_EnumMapping(int _e_type, std::string _e_name) : e_type(_e_type), e_name(std::move(_e_name))
		{
		}

	int ComputeOffset(InitsManager* im) const;

private:
	int e_type; // index to EnumType
	std::string e_name; // which enum constant for that type
	};

// Looks up a BiF of the given name, making it available to compiled
// code via a C++ global.
class CPP_LookupBiF
	{
public:
	CPP_LookupBiF(zeek::Func*& _bif_func, std::string _bif_name)
		: bif_func(_bif_func), bif_name(std::move(_bif_name))
		{
		}

	void ResolveBiF() const { bif_func = lookup_bif__CPP(bif_name.c_str()); }

protected:
	zeek::Func*& bif_func; // where to store the pointer to the BiF
	std::string bif_name; // the BiF's name
	};

// Information needed to register a compiled function body (which makes it
// available to substitute for the body's AST).  The compiler generates
// code that loops over a vector of these to perform the registrations.
struct CPP_RegisterBody
	{
	CPP_RegisterBody(std::string _func_name, void* _func, int _type_signature, int _priority,
	                 p_hash_type _h, std::vector<std::string> _events)
		: func_name(std::move(_func_name)), func(_func), type_signature(_type_signature),
		  priority(_priority), h(_h), events(std::move(_events))
		{
		}

	std::string func_name; // name of the function
	void* func; // pointer to C++
	int type_signature;
	int priority;
	p_hash_type h;
	std::vector<std::string> events;
	};

// Helper function that takes a (large) array of int's and from them
// constructs the corresponding vector-of-vector-of-indices.  Each
// vector-of-indices is represented first by an int specifying its
// size, and then that many int's for its values.  We recognize the
// end of the array upon encountering a "size" entry of -1.
extern void generate_indices_set(int* inits, std::vector<std::vector<int>>& indices_set);

	} // zeek::detail
