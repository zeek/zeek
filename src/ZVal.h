// See the file "COPYING" in the main distribution directory for copyright.

// Values used in ZAM execution.

#pragma once

#include "Dict.h"
#include "Expr.h"
#include <unordered_set>


// A single instance of a ZAM aggregate.  Note that multiple instances
// may share the same underlying ZAMAggrInstantiation.
class ZAMVector;
class ZAMRecord;

class IterInfo;

typedef std::vector<IntrusivePtr<Val>> val_vec;

// A bit of this mirrors BroValUnion, but BroValUnion captures low-level
// representation whereas we aim to keep Val structure for more complex
// Val's.
//
// Ideally we'd use IntrusivePtr's for memory management, but we can't
// given we have a union and thus on destruction C++ doesn't know which
// member flavor to destruct.  See the comment below re shadowing in
// the ZAM frame.
union ZAMValUnion {
	// Constructor for hand-populating the values.
	ZAMValUnion() { void_val = nullptr; }

	// Construct from a given Bro value with a given type.
	ZAMValUnion(IntrusivePtr<Val> v, BroType* t);

	// True if when interpreting the value as having the given type,
	// it's a nil pointer.
	bool IsNil(const BroType* t) const;

	// Convert to a Bro value.
	IntrusivePtr<Val> ToVal(BroType* t) const;

	// Conversion between ZAM and interpreted forms of vectors.
	IntrusivePtr<VectorVal> ToVector(BroType* t) const;

	// Used for bool, int.
	bro_int_t int_val;

	// Used for count, counter.
	bro_uint_t uint_val;

	// Used for double, time, interval.  While IntervalVal's are
	// distinct, we can readily recover them given type information.
	double double_val;

	// For these types, we assume we have ownership of the value, so
	// they need to be explicitly deleted prior to reassignment.
	BroString* string_val;
	IPAddr* addr_val;
	IPPrefix* subnet_val;
	ZAMVector* vector_val;
	ZAMRecord* record_val;

	// The types are all variants of Val (or BroType).  For memory
	// management, we use Ref/Unref.
	BroFile* file_val;
	Func* func_val;
	ListVal* list_val;
	OpaqueVal* opaque_val;
	PatternVal* re_val;
	TableVal* table_val;
	BroType* type_val;

	// Used for direct "any" values.
	Val* any_val;

	// Used for the compiler to hold opaque items.  Memory management
	// is explicit in the operations accessing it.
	val_vec* vvec;

	// Used for managing "for" loops.  Implicit memory management.
	IterInfo* iter_info;

	// Used for loading/spilling globals; also, local vectors.
	ID* id_val;

	// Only used when we clear pointers on entry, and that's just
	// to lazily avoid doing a switch like IsNil() does.
	void* void_val;
};

// True if a given type is one that we treat internally as an "any" type.
extern bool IsAny(const BroType* t);
// Same for vector-of-any.
extern bool IsAnyVec(const BroType* t);

// Convenience functions for getting to these.
inline bool IsAny(const IntrusivePtr<BroType>& t) { return IsAny(t.get()); }
inline bool IsAny(const Expr* e) { return IsAny(e->Type()); }

inline bool IsAnyVec(const IntrusivePtr<BroType>& t) { return IsAnyVec(t.get()); }
inline bool IsAnyVec(const Expr* e) { return IsAnyVec(e->Type()); }

// True if a given type is one for which we manage the associated
// memory internally.
bool IsManagedType(const BroType* t);
inline bool IsManagedType(const IntrusivePtr<BroType>& t)
	{ return IsManagedType(t.get()); }
inline bool IsManagedType(const Expr* e) { return IsManagedType(e->Type()); }

// Deletes a managed value.
extern void DeleteManagedType(ZAMValUnion& v, const BroType* t);


typedef vector<ZAMValUnion> ZVU_vec;

// Class used to manage aggregates.  Supports sync'ing them with associated
// Val*'s (if any), and enables sharing of them between multiple ZAM values.
//
// The base class manages a ZVU_vec.  Its values might be homogeneous if
// it reflects a Zeek vector, or heterogeneous if it reflects a Zeek record.

class ZAMAggrInstantiation : public BroObj {
public:
	ZAMAggrInstantiation(Val* _v, int n)
	: zvec(n)
		{
		aggr_val = _v;

		if ( aggr_val )
			Ref(aggr_val);
		}

	virtual ~ZAMAggrInstantiation()
		{
		if ( aggr_val )
			Unref(aggr_val);
		}

protected:
	// The associated Zeek interpreter value.  We track this just
	// for convenience, so we don't have to build a new Val* when
	// converting to a Val.
	Val* aggr_val;

	// The underlying set of ZAM values.
	ZVU_vec zvec;
};

class ZAM_vector : public ZAMAggrInstantiation {
public:
	ZAM_vector(VectorVal* _v, BroType* yt, int n = 0)
		: ZAMAggrInstantiation(_v, n)
		{
		vv = _v;
		if ( yt )
			{
			general_yt = yt;
			managed_yt = IsManagedType(yt) ? yt : nullptr;
			}
		else
			general_yt = managed_yt = nullptr;
		}

	~ZAM_vector()
		{
		if ( managed_yt )
			DeleteMembers();
		}

	BroType* ManagedYieldType() const	{ return managed_yt; }
	BroType* GeneralYieldType() const	{ return general_yt; }

	void SetGeneralYieldType(BroType* yt)
		{
		if ( ! general_yt )
			{
			general_yt = yt;
			if ( IsManagedType(yt) )
				managed_yt = yt;
			}
		}

	int Size() const		{ return zvec.size(); }

	const ZVU_vec& ConstVec() const	{ return zvec; }
	ZVU_vec& ModVec()		{ return zvec; }

	// Used when access to the underlying vector is for initialization.
	ZVU_vec& InitVec()		{ return zvec; }

	IntrusivePtr<VectorVal> VecVal()	{ return {NewRef{}, vv}; }
	void SetVecVal(VectorVal* _vv)		{ vv = _vv; vv->Ref(); }

	ZAMValUnion& Lookup(int n)
		{
		return zvec[n];
		}

	// Sets the given element, doing deletions and deep-copies
	// for managed types.
	void SetElement(int n, ZAMValUnion& v)
		{
		if ( zvec.size() <= n )
			GrowVector(n + 1);

		if ( managed_yt )
			SetManagedElement(n, v);
		else
			zvec[n] = v;
		}

	void Insert(unsigned int index, ZAMValUnion& element)
		{
		ZVU_vec::iterator it;

		if ( index < zvec.size() )
			{
			it = std::next(zvec.begin(), index);
			DeleteIfManaged(index);
			}
		else
			it = zvec.end();

		zvec.insert(it, element);
		}

	void Remove(unsigned int index)
		{
		DeleteIfManaged(index);
		auto it = std::next(zvec.begin(), index);
		zvec.erase(it);
		}

	void Resize(unsigned int new_num_elements)
		{
		zvec.reserve(new_num_elements);
		zvec.resize(new_num_elements);
		}

protected:
	void SetManagedElement(int n, ZAMValUnion& v);
	void GrowVector(int size);

	void DeleteMembers();

	// Deletes the given element if necessary.
	void DeleteIfManaged(int n)
		{
		if ( managed_yt )
			DeleteManagedType(zvec[n], managed_yt);
		}

	VectorVal* vv;	// our own copy of aggr_val, with the right type

	// The yield type of the vector elements.  Only non-nil if they
	// are managed types.
	BroType* managed_yt;

	// The yield type of the vector elements, whether or not it's
	// managed.  We use a lengthier name to make sure we never
	// confuse this with managed_yt.
	BroType* general_yt;

	// Whether the base type of the vector is one for which we need
	// to do explicit memory management.
	bool is_managed;
};

class ZAM_record : public ZAMAggrInstantiation {
public:
	ZAM_record(RecordVal* _v, RecordType* _rt);

	~ZAM_record()
		{
		DeleteManagedMembers();
		}

	int Size() const		{ return zvec.size(); }

	IntrusivePtr<RecordVal> ToRecordVal();

	void Assign(unsigned int field, ZAMValUnion v)
		{
		if ( IsInRecord(field) && IsManaged(field) )
			Delete(field);

		zvec[field] = v;

		auto mask = 1UL << field;
		is_in_record |= mask;
		}

	ZAMValUnion& Lookup(unsigned int field, bool& error)
		{
		error = false;

		if ( ! IsInRecord(field) && ! SetToDefault(field) )
			error = true;

		return zvec[field];
		}

	IntrusivePtr<Val> NthField(unsigned int field)
		{
		bool error;
		auto f = Lookup(field, error);

		if ( error )
			return nullptr;

		return f.ToVal(FieldType(field));
		}

	void DeleteField(unsigned int field)
		{
		if ( IsInRecord(field) && IsManaged(field) )
			DeleteManagedType(zvec[field], FieldType(field));

		auto mask = 1UL << field;
		is_in_record &= ~mask;
		}

	bool HasField(unsigned int field)
		{
		return IsInRecord(field);
		}

	void SetRecordType(RecordType* _rt)
		{
		rt = _rt;
		is_managed = rt->ManagedFields();
		}

	void Grow(unsigned int new_size)
		{
		zvec.resize(new_size);
		}

	ZRM_flags OffsetMask(unsigned int offset) const
		{ return 1UL << offset; }

	bool IsInRecord(unsigned int offset) const
		{ return (is_in_record & OffsetMask(offset)) != 0; }
	bool IsManaged(unsigned int offset) const
		{ return (is_managed & OffsetMask(offset)) != 0; }

	BroType* FieldType(int field) const	{ return rt->FieldType(field); }

protected:
	bool SetToDefault(unsigned int field);

	// Removes the given field.
	void Delete(unsigned int field)
		{ DeleteManagedType(zvec[field], FieldType(field)); }

	void DeleteManagedMembers();

	RecordVal* rv;	// our own copy of aggr_val, with the right type

	// And a handy pointer to its type.
	RecordType* rt;

	// Whether a given field exists (for optional fields).
	ZRM_flags is_in_record;

	// Whether a given field requires explicit memory management.
	ZRM_flags is_managed;
};


// An individual instance of a ZAM vector aggregate, which potentially
// shares the underlying instantiation of that value with other instances.

class ZAMVector {
public:
	ZAMVector(IntrusivePtr<ZAM_vector> _vec);

	ZAMVector* ShallowCopy()
		{
		return new ZAMVector(vec);
		}

	int Size() const		{ return vec->Size(); }
	void Resize(int n) const	{ vec->ModVec().resize(n); }

	const ZVU_vec& ConstVec() const	{ return vec->ConstVec(); }
	const IntrusivePtr<ZAM_vector>& ConstVecPtr() const	{ return vec; }

	ZVU_vec& ModVec()			{ return vec->ModVec(); }
	IntrusivePtr<ZAM_vector>& ModVecPtr()	{ return vec; }

	void SetElement(int n, ZAMValUnion& v)
		{ ModVecPtr()->SetElement(n, v); }

	BroType* YieldType() const	{ return yield_type; }
	BroType* ManagedYieldType() const
		{ return vec->ManagedYieldType(); }

	void SetYieldType(BroType* yt)
		{
		if ( ! yield_type )
			{
			yield_type = yt;
			vec->SetGeneralYieldType(yt);
			}
		}

	IntrusivePtr<VectorVal> VecVal()	{ return vec->VecVal(); }
	void SetVecVal(VectorVal* vv)		{ vec->SetVecVal(vv); }

protected:
	IntrusivePtr<ZAM_vector> vec;

	// The actual yield type of the vector, if we've had a chance to
	// observe it.  Necessary for "vector of any".  Non-const because
	// we need to be able to ref it.
	BroType* yield_type;
};


// An individual instance of a ZAM record aggregate, which potentially
// shares the underlying instantiation of that value with other instances.

class ZAMRecord {
public:
	ZAMRecord(IntrusivePtr<ZAM_record> _zr);

	ZAMRecord* ShallowCopy()
		{
		return new ZAMRecord(zr);
		}

	IntrusivePtr<RecordVal> ToRecordVal()
		{ return zr->ToRecordVal(); }

	void Assign(int field, ZAMValUnion v)	{ zr->Assign(field, v); }

	// error is true iff the field isn't in the record.
	ZAMValUnion& Lookup(int field, bool& error)
		{ return zr->Lookup(field, error); }

	void DeleteField(int field)		{ zr->DeleteField(field); }
	bool HasField(int field)		{ return zr->HasField(field); }
	BroType* FieldType(int field)		{ return zr->FieldType(field); }

protected:
	IntrusivePtr<ZAM_record> zr;
};

// Information used to iterate over aggregates.  It's a hodge-podge since
// it's meant to support every type of aggregate & loop.
class IterInfo {
public:
	IterInfo()	{ c = nullptr; }
	~IterInfo()	{ if ( c ) loop_vals->StopIteration(c); }

	// If we're looping over a table:
	const TableVal* tv = nullptr;

	// The raw values being looped over
	const PDict<TableEntryVal>* loop_vals = nullptr;

	// Iterator status.  Always gets deleted, so non-table/set
	// iteration instructions need to set it to nil.
	IterCookie* c = nullptr;

	// Frame slots of iteration variables, such as "[v1, v2, v3] in aggr".
	// These are used for iterating over vectors and strings, too
	// (well, the first slot is).
	vector<int> loop_vars;

	// Their types.
	vector<BroType*> loop_var_types;

	// Type associated with the "value" entry, for "k, v in aggr"
	// iteration.
	BroType* value_var_type = nullptr;

	// If we're iterating over vectors, points to the raw vector ...
	IntrusivePtr<ZAM_vector> vv = nullptr;

	// ... unless it's a vector of any (sigh):
	vector<Val*>* any_vv = nullptr;

	// The vector's type & yield.
	VectorType* vec_type = nullptr;
	BroType* yield_type = nullptr;

	// String we're iterating over.
	BroString* s = nullptr;

	// Counter of where we are in the iteration.
	bro_uint_t iter;
	bro_uint_t n;	// we loop from 0 ... n-1
};

// Converts between VectorVals and ZAM vectors.
extern ZAMVector* to_ZAM_vector(const IntrusivePtr<Val>& vec);
extern IntrusivePtr<ZAM_vector> to_raw_ZAM_vector(const IntrusivePtr<Val>& vec);

// Likewise for RecordVals, but due to lazy loading, no need for "raw"
// vectors.
extern ZAMRecord* to_ZAM_record(const IntrusivePtr<Val>& rec);
