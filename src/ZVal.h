// See the file "COPYING" in the main distribution directory for copyright.

// Values used in ZAM execution.

#pragma once

#include "Dict.h"
#include "Expr.h"
#include <unordered_set>


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
	ZAMValUnion() { managed_val = nullptr; }

	// Construct from a given Bro value with a given type.
	ZAMValUnion(IntrusivePtr<Val> v, BroType* t);

	// True if when interpreting the value as having the given type,
	// it's a nil pointer.
	bool IsNil(const BroType* t) const;

	// Convert to a Bro value.
	IntrusivePtr<Val> ToVal(BroType* t) const;

	// Used for bool, int.
	bro_int_t int_val;

	// Used for count, counter.
	bro_uint_t uint_val;

	// Used for double, time, interval.  While IntervalVal's are
	// distinct, we can readily recover them given type information.
	double double_val;

	// The types are all variants of Val (or BroType).  For memory
	// management, we use Ref/Unref.
	StringVal* string_val;
	AddrVal* addr_val;
	SubNetVal* subnet_val;
	BroFile* file_val;
	Func* func_val;
	ListVal* list_val;
	OpaqueVal* opaque_val;
	PatternVal* re_val;
	TableVal* table_val;
	RecordVal* record_val;
	VectorVal* vector_val;
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

	// Used for generic access to managed objects.
	BroObj* managed_val;
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
// extern void DeleteManagedType(ZAMValUnion& v, const BroType* t);
inline void DeleteManagedType(ZAMValUnion& v, const BroType* t)
	{
	Unref(v.managed_val);
	}
inline void DeleteAndZeroManagedType(ZAMValUnion& v, const BroType* t)
	{
	Unref(v.managed_val);
	v.managed_val = nullptr;
	}


typedef vector<ZAMValUnion> ZVU_vec;

class ZAM_vector {
public:
	ZAM_vector(VectorVal* _vv, BroType* yt, int n = 0)
	: zvec(n)
		{
		vv = _vv;

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

	BroType* YieldType() const	{ return general_yt; }

	void SetYieldType(BroType* yt)
		{
		if ( ! general_yt )
			{
			general_yt = yt;
			if ( IsManagedType(yt) )
				managed_yt = yt;
			}
		}

	bool IsManagedYieldType() const	{ return managed_yt != nullptr; }

	int Size() const		{ return zvec.size(); }

	const ZVU_vec& ConstVec() const	{ return zvec; }
	ZVU_vec& ModVec()		{ return zvec; }

	// Used when access to the underlying vector is for initialization.
	ZVU_vec& InitVec(unsigned int size)
		{
		// Note, could use reserve() here to avoid pre-initializing
		// the elements.  It's not clear to me whether that suffices
		// for being able to safely assign to elements beyond the
		// nominal end of the vector rather than having to use
		// push_back.  Seems it ought to ...
		zvec.resize(size);
		return zvec;
		}

	ZAMValUnion& Lookup(int n)
		{
		return zvec[n];
		}

	// Sets the given element, with accompanying memory management.
	void SetElement(int n, ZAMValUnion& v)
		{
		if ( zvec.size() <= n )
			GrowVector(n + 1);

		if ( managed_yt )
			DeleteManagedType(zvec[n], managed_yt);
			// SetManagedElement(n, v);

		zvec[n] = v;
		}

	void Insert(unsigned int index, ZAMValUnion& element)
		{
		ZVU_vec::iterator it;

		if ( index < zvec.size() )
			{
			it = std::next(zvec.begin(), index);
			if ( managed_yt )
				DeleteIfManaged(index);
			}
		else
			it = zvec.end();

		zvec.insert(it, element);
		}

	void Remove(unsigned int index)
		{
		if ( managed_yt )
			DeleteIfManaged(index);

		auto it = std::next(zvec.begin(), index);
		zvec.erase(it);
		}

	void Resize(unsigned int new_num_elements)
		{
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

	// The underlying set of ZAM values.
	ZVU_vec zvec;

	// The associated main value.
	VectorVal* vv;

	// The yield type of the vector elements.  Only non-nil if they
	// are managed types.
	BroType* managed_yt;

	// The yield type of the vector elements, whether or not it's
	// managed.  We use a lengthier name to make sure we never
	// confuse this with managed_yt.
	BroType* general_yt;
};

class ZAM_record {
public:
	ZAM_record(RecordVal* _v, RecordType* _rt);

	~ZAM_record()
		{
		DeleteManagedMembers();
		}

	int Size() const		{ return zvec.size(); }

	void Assign(unsigned int field, ZAMValUnion v)
		{
		if ( IsInRecord(field) && IsManaged(field) )
			Unref(zvec[field].managed_val);
			// Delete(field);

		zvec[field] = v;

		auto mask = 1UL << field;
		is_in_record |= mask;
		}

	// Direct access to fields for assignment or clearing.  *The caller
	// is expected to deal with memory management.*
	ZAMValUnion& SetField(unsigned int field)
		{
		is_in_record |= (1UL << field);
		return zvec[field];
		}
	void ClearField(unsigned int field)
		{ is_in_record &= ~(1UL << field); }

	// Used for a slight speed gain in RecordType::Create().
	void RefField(unsigned int field)
		{ ::Ref(zvec[field].managed_val); }

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
			Unref(zvec[field].managed_val);
			// DeleteManagedType(zvec[field], FieldType(field));

		auto mask = 1UL << field;
		is_in_record &= ~mask;
		}

	bool HasField(unsigned int field)
		{
		return IsInRecord(field);
		}

	ZRM_flags OffsetMask(unsigned int offset) const
		{ return 1UL << offset; }

	bool IsInRecord(unsigned int offset) const
		{ return (is_in_record & OffsetMask(offset)) != 0; }
	bool IsManaged(unsigned int offset) const
		{ return (is_managed & OffsetMask(offset)) != 0; }

protected:
	friend class RecordVal;

	BroType* FieldType(int field) const	{ return rt->FieldType(field); }

	bool SetToDefault(unsigned int field);

	void Grow(unsigned int new_size)
		{
		zvec.resize(new_size);
		}

	// Removes the given field.
	// The current definition takes advantage of the fact that
	// we know that DeleteManagedType() ignores the type provided to it.
	void Delete(unsigned int field)
		// { DeleteManagedType(zvec[field], FieldType(field)); }
		{ DeleteManagedType(zvec[field], nullptr); }

	void DeleteManagedMembers();

	// The underlying set of ZAM values.
	ZVU_vec zvec;

	// The associated main value.
	RecordVal* rv;

	// And a handy pointer to its type.
	RecordType* rt;

	// Whether a given field exists (for optional fields).
	ZRM_flags is_in_record;

	// Whether a given field requires explicit memory management.
	ZRM_flags is_managed;
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
	ZAM_vector* vv = nullptr;

	// The vector's type & yield.
	VectorType* vec_type = nullptr;
	BroType* yield_type = nullptr;

	// String we're iterating over.
	const BroString* s = nullptr;

	// Counter of where we are in the iteration.
	bro_uint_t iter;
	bro_uint_t n;	// we loop from 0 ... n-1
};
