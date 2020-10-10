// See the file "COPYING" in the main distribution directory for copyright.

// Values used in ZAM execution, and also for representing records and
// vectors during interpreter execution.

#pragma once

#include "Dict.h"
#include "Expr.h"
#include <unordered_set>


// Only needed for compiled code.
class IterInfo;

typedef std::vector<IntrusivePtr<Val>> val_vec;

// A bit of this mirrors BroValUnion, but BroValUnion captures low-level
// representation whereas we aim to keep Val structure for more complex
// Val's.
//
// Ideally we'd use IntrusivePtr's for memory management, but we can't
// given we have a union and thus on destruction C++ doesn't know which
// member flavor to destruct.
//
// Note that a ZAMValUnion by itself is ambiguous: it doesn't track its
// type.  This makes them consume less memory and cheaper to copy.  It
// does however require a separate way to determine the type.  Generally
// this is doable using surrounding context, or can be statically determined
// in the case of optimization/compilation.
//
// An alternative would be to use std::variant, but (1) it tracks the
// variant type, and (2) it won't allow access to the managed_val member,
// which not only simplifies memory management but also is required for
// sharing of ZAM frame slots.
union ZAMValUnion {
	// Constructor for hand-populating the values.
	ZAMValUnion() { managed_val = nullptr; }

	// Construct from a given Bro value with a given type.
	ZAMValUnion(IntrusivePtr<Val> v, const IntrusivePtr<BroType>& t);

	// True if when interpreting the value as having the given type,
	// it's a nil pointer.
	bool IsNil(const IntrusivePtr<BroType>& t) const;

	// Convert to a Bro value.
	IntrusivePtr<Val> ToVal(const IntrusivePtr<BroType>& t) const;

	// Used for bool, int, enum.
	bro_int_t int_val;

	// Used for count, counter, port.
	bro_uint_t uint_val;

	// Used for double, time, interval.
	double double_val;

	// The types are all variants of Val, BroType, or more fundamentally
	// BroObj.  They are raw pointers rather than IntrusivePtr's because
	// unions can't contain the latter.  For memory management, we use
	// Ref/Unref.
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

	// Used by the compiler for managing "for" loops.  Implicit
	// memory management.
	IterInfo* iter_info;

	// Used for generic access to managed (reference-counted) objects.
	BroObj* managed_val;
};

// True if a given type is one for which we manage the associated
// memory internally.
bool IsManagedType(const IntrusivePtr<BroType>& t);

// Deletes a managed value.
inline void DeleteManagedType(ZAMValUnion& v)
	{
	Unref(v.managed_val);
	}


typedef vector<ZAMValUnion> ZVU_vec;

class ZAM_vector {
public:
	// In the following, we use a bare pointer for the VectorVal
	// due to tricky memory management concerns, namely that ZAM_vector's
	// point to their VectorVal's and VectorVal's point to their
	// ZAM_vector's.
	ZAM_vector(VectorVal* _vv, IntrusivePtr<BroType> yt, int n = 0)
	: zvec(n)
		{
		vv = _vv;

		if ( yt )
			{
			managed_yt = IsManagedType(yt) ? yt : nullptr;
			general_yt = std::move(yt);
			}
		else
			general_yt = managed_yt = nullptr;
		}

	~ZAM_vector()
		{
		if ( managed_yt )
			DeleteMembers();
		}

	IntrusivePtr<BroType> YieldType() 		{ return general_yt; }
	const IntrusivePtr<BroType>& YieldType() const	{ return general_yt; }

	void SetYieldType(IntrusivePtr<BroType> yt)
		{
		if ( ! general_yt || general_yt->Tag() == TYPE_ANY ||
		     general_yt->Tag() == TYPE_VOID )
			{
			managed_yt = IsManagedType(yt) ? yt : nullptr;
			general_yt = std::move(yt);
			}
		}

	bool IsManagedYieldType() const	{ return managed_yt != nullptr; }

	unsigned int Size() const	{ return zvec.size(); }

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
	void SetElement(unsigned int n, ZAMValUnion& v)
		{
		if ( zvec.size() <= n )
			GrowVector(n + 1);

		if ( managed_yt )
			DeleteManagedType(zvec[n]);

		zvec[n] = v;
		}

	// Sets the given element to a copy of the given ZAMValUnion.
	// The difference between this and SetElement() is that here
	// we do Ref()'ing of the underlying value if it's a managed
	// type.  This isn't necessary for the case where 'v' has been
	// newly constructed, but is necessary if we're copying an
	// existing 'v'.
	//
	// Returns true on success, false if 'v' has never been set to
	// a value (which we can only tell for managed types).
	bool CopyElement(unsigned int n, const ZAMValUnion& v)
		{
		if ( zvec.size() <= n )
			GrowVector(n + 1);

		if ( managed_yt )
			return SetManagedElement(n, v);

		zvec[n] = v;
		return true;
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
	bool SetManagedElement(int n, const ZAMValUnion& v);
	void GrowVector(int size);

	void DeleteMembers();

	// Deletes the given element if necessary.
	void DeleteIfManaged(int n)
		{
		if ( managed_yt )
			DeleteManagedType(zvec[n]);
		}

	// The underlying set of ZAM values.
	ZVU_vec zvec;

	// The associated main value.  A raw pointer for reasons explained
	// above.
	VectorVal* vv;

	// The yield type of the vector elements.  Only non-nil if they
	// are managed types.
	IntrusivePtr<BroType> managed_yt;

	// The yield type of the vector elements, whether or not it's
	// managed.  We use a lengthier name to make sure we never
	// confuse this with managed_yt.
	IntrusivePtr<BroType> general_yt;
};

class ZAM_record {
public:
	// Similarly to ZAM_vector, we use a bare pointer for the RecordVal
	// to simplify the memory management given the pointer cycle.
	ZAM_record(RecordVal* _v, const IntrusivePtr<RecordType>& _rt);

	~ZAM_record()
		{
		DeleteManagedMembers();
		}

	unsigned int Size() const	{ return zvec.size(); }

	void Assign(unsigned int field, ZAMValUnion v)
		{
		if ( IsInRecord(field) && IsManaged(field) )
			Unref(zvec[field].managed_val);

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

	IntrusivePtr<BroType> FieldType(int field) const
		{ return {NewRef{}, rt->FieldType(field)}; }

	bool SetToDefault(unsigned int field);

	void Grow(unsigned int new_size)
		{
		zvec.resize(new_size);
		}

	// Removes the given field.
	void Delete(unsigned int field)
		{ DeleteManagedType(zvec[field]); }

	void DeleteManagedMembers();

	// The underlying set of ZAM values.
	ZVU_vec zvec;

	// The associated main value.
	RecordVal* rv;

	// And a handy pointer to its type.
	const IntrusivePtr<RecordType>& rt;

	// Whether a given field exists (for optional fields).
	ZRM_flags is_in_record;

	// Whether a given field requires explicit memory management.
	ZRM_flags is_managed;
};
