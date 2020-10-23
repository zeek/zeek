// See the file "COPYING" in the main distribution directory for copyright.

// Values used in ZAM execution, and also for representing records and
// vectors during interpreter execution.

#pragma once

#include <unordered_set>

#include "Dict.h"
#include "Expr.h"
#include "IntrusivePtr.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(StringVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(AddrVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(SubNetVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(File, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Func, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(ListVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(OpaqueVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(PatternVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(TableVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(RecordVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(VectorVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Type, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Val, zeek);

namespace zeek {

// Only needed for compiled code.
class IterInfo;

typedef std::vector<zeek::ValPtr> val_vec;

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
	ZAMValUnion() { double_val = 0.0; }

	// Construct from a given Val with a given type.  The type
	// is separate to accommodate "any" values.
	ZAMValUnion(zeek::ValPtr v, const zeek::TypePtr& t);

	/**
	 * Tests whether, when interpreting the value as having the given
	 * type, it's a nil pointer.
	 * @param t  the type to use in interpreting the ZAMValUnion.
	 * @return  True if the value is nil given that type, false otherwise.
	 */
	bool IsNil(const zeek::TypePtr& t) const;

	/**
	 * Return a Val object corresponding to this ZAMValUnion.  If
	 * the value is managed, then the result is the same underlying
	 * value.  If not managed, then the result is newly constructed.
	 * @param t  the type to use in interpreting the ZAMValUnion.
	 * @return  a ValPtr reflecting the value.
	 */
	zeek::ValPtr ToVal(const zeek::TypePtr& t) const;

	// Used for bool, int, enum.
	bro_int_t int_val;

	// Used for count, counter, port.
	bro_uint_t uint_val;

	// Used for double, time, interval.
	double double_val;

	// The types are all variants of Val, zeek::Type, or more fundamentally
	// zeek::Obj.  They are raw pointers rather than IntrusivePtr's because
	// unions can't contain the latter.  For memory management, we use
	// Ref/Unref.
	zeek::StringVal* string_val;
	zeek::AddrVal* addr_val;
	zeek::SubNetVal* subnet_val;
	zeek::File* file_val;
	zeek::Func* func_val;
	zeek::ListVal* list_val;
	zeek::OpaqueVal* opaque_val;
	zeek::PatternVal* re_val;
	zeek::TableVal* table_val;
	zeek::RecordVal* record_val;
	zeek::VectorVal* vector_val;
	zeek::Type* type_val;

	// Used for direct "any" values.
	zeek::Val* any_val;

	// Used for the compiler to hold opaque items.  Memory management
	// is explicit in the operations accessing it.
	val_vec* vvec;

	// Used by the compiler for managing "for" loops.  Implicit
	// memory management.
	IterInfo* iter_info;

	// Used for generic access to managed (reference-counted) objects.
	zeek::Obj* managed_val;
};

/**
 * Tests whether a given type is one for which we manage the associated
 * memory internally.
 * @param t  the type we want to test for management.
 * @return  true if the type is managed, false otherwise.
 */
bool IsManagedType(const zeek::TypePtr& t);

/**
 * Deletes a managed value.
 * @param v  The ZAMValUnion who's managed value should be deleted.
 */
inline void DeleteManagedType(ZAMValUnion& v)
	{
	Unref(v.managed_val);
	}

// The following can be set to point to a boolean that will be set
// to true if a run-time error associated with ZAMValUnion's occurs.
//
// We use this somewhat clunky coupling to enable isolating ZVal from
// ZAM compiler specifics.
inline bool* zval_error_addr = nullptr;

typedef std::vector<ZAMValUnion> ZVU_vec;

// We need to declare here the external functions that need low-level
// ZAM_vector access.
namespace BifFunc {
extern zeek::detail::BifReturnVal
		sort_bif(zeek::detail::Frame* frame, const zeek::Args*);
}

class ZAM_vector {
public:
	// In the following, we use a bare pointer for the VectorVal
	// due to tricky memory management concerns, namely that ZAM_vector's
	// point to their VectorVal's and VectorVal's point to their
	// ZAM_vector's.
	ZAM_vector(zeek::VectorVal* _vv, zeek::TypePtr yt, int n = 0)
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

	zeek::TypePtr YieldType() 		{ return general_yt; }
	const zeek::TypePtr& YieldType() const	{ return general_yt; }

	/**
	 * Sets the vector's yield type to be the given type, unless the
	 * vector already has a concrete yield type.
	 * @param yt  The yield type to set for the vector.
	 */
	void SetYieldType(zeek::TypePtr yt)
		{
		if ( ! general_yt || general_yt->Tag() == zeek::TYPE_ANY ||
		     general_yt->Tag() == zeek::TYPE_VOID )
			{
			managed_yt = IsManagedType(yt) ? yt : nullptr;
			general_yt = std::move(yt);
			}
		}

	/**
	 * Returns whether the yield type of the vector is managed.
	 * @return  True if the yield type of the vector is managed.
	 */
	bool IsManagedYieldType() const	{ return managed_yt != nullptr; }

	/**
	 * Returns the number of elements in the vector.
	 * @return  The number of elements in the vector.
	 */
	unsigned int Size() const	{ return zvec.size(); }

	/**
	 * Provides immutable access to the underlying vector.
	 * @return  A constant reference to the underlying vector.
	 */
	const ZVU_vec& ConstVec() const	{ return zvec; }

	/**
	 * Appends the given value to the end of the vector.
	 * @param v  The value to append.
	 */
	void Append(ZAMValUnion v)	{ zvec.push_back(v); }

	/**
	 * Obtains mutable access to the underlying vector, in the context
	 * of first initializing it.
	 * @param size  How many elements the vector will initially hold.
	 * @return  A mutable reference to the underlying vector.
	 */
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

	/**
	 * Provides mutable access to a given element of the vector.
	 * @param n  Which element in the vector (0-based).
	 * @return  A mutable reference to the given element.
	 */
	ZAMValUnion& Lookup(int n)
		{
		return zvec[n];
		}

	/**
	 * Sets the given vector element to the given value, with
	 * accompanying memory management.
	 * @param n  Which element in the vector (0-based).
	 * @param v  The value to set the element to.
	 */
	void SetElement(unsigned int n, ZAMValUnion& v)
		{
		if ( zvec.size() <= n )
			GrowVector(n + 1);

		if ( managed_yt )
			DeleteManagedType(zvec[n]);

		zvec[n] = v;
		}

	/**
	 * Sets the given element to a copy of the given ZAMValUnion.
	 * The difference between this and SetElement() is that here
	 * we do Ref()'ing of the underlying value if it's a managed
	 * type.  This isn't necessary for the case where 'v' has been
	 * newly constructed, but is necessary if we're copying an
	 * existing 'v'.
	 * @param n  Which element in the vector (0-based).
	 * @param v  The value to set the element to, with manual Ref()'ing.
	 * @return  True on success, false if 'v' has never been set to
	 * a value (which we can only tell for managed types).
	 */
	bool CopyElement(unsigned int n, const ZAMValUnion& v)
		{
		if ( zvec.size() <= n )
			GrowVector(n + 1);

		if ( managed_yt )
			return SetManagedElement(n, v);

		zvec[n] = v;
		return true;
		}

	/**
	 * Inserts the given value at the given index in the vector.
	 * @param index  Which element in the vector (0-based).
	 * @param element  The value to set the element to.
	 */
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

	/**
	 * Removes the given element from the vector.
	 * @param index  Which element in the vector (0-based).
	 */
	void Remove(unsigned int index)
		{
		if ( managed_yt )
			DeleteIfManaged(index);

		auto it = std::next(zvec.begin(), index);
		zvec.erase(it);
		}

	/**
	 * Resizes the vector to contain the given number of elements.
	 * @param new_num_elements  Number of elements the vector should have.
	 */
	void Resize(unsigned int new_num_elements)
		{
		zvec.resize(new_num_elements);
		}

protected:
	// Direct, mutable access to the underlying vector.  Used to provide
	// low-level functions (sorting, compiled vectorized arithmetic
	// operations) with fast access.

	friend zeek::detail::BifReturnVal
		zeek::BifFunc::sort_bif(zeek::detail::Frame* frame,
					const zeek::Args*);

	ZVU_vec& ModVec()		{ return zvec; }


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
	zeek::VectorVal* vv;

	// The yield type of the vector elements.  Only non-nil if they
	// are managed types.
	zeek::TypePtr managed_yt;

	// The yield type of the vector elements, whether or not it's
	// managed.  We use a lengthier name to make sure we never
	// confuse this with managed_yt.
	zeek::TypePtr general_yt;
};

class ZAM_record {
public:
	// Similarly to ZAM_vector, we use a bare pointer for the RecordVal
	// to simplify the memory management given the pointer cycle.
	ZAM_record(zeek::RecordVal* _v, zeek::RecordTypePtr _rt);

	~ZAM_record()
		{
		DeleteManagedMembers();
		}

	/**
	 * Returns the number of fields in the record.
	 * @return  The number of fields in the record.
	 */
	unsigned int Size() const	{ return zvec.size(); }

	/**
	 * Assigns the given record field to the given value.
	 * @param field  Which field in the record to assign to.
	 * @param v  The value to set the element to.
	 */
	void Assign(unsigned int field, ZAMValUnion v)
		{
		if ( IsInRecord(field) && IsManaged(field) )
			Unref(zvec[field].managed_val);

		zvec[field] = v;
		is_in_record[field] = true;
		}

	/**
	 * Provides direct raw access to one of the record's fields
	 * for assignment purposes.  *The caller is expected to deal
	 * with memory management.*
	 * @param field  Which field in the record to access.
	 * @return  A mutable reference to the given field.
	 */
	ZAMValUnion& SetField(unsigned int field)
		{
		is_in_record[field] = true;
		return zvec[field];
		}

	/**
	 * Increases the reference count for the given field.  Included
	 * as it provides a slight speed gain in RecordType::Create()
	 * (a pending change).
	 * @param field  Which field in the record to reference.
	 */
	void RefField(unsigned int field)
		{ zeek::Ref(zvec[field].managed_val); }

	/**
	 * Returns (access to) the given record field, if available.
	 * @param field  Which field in the record to access.
	 * @param error  A boolean reference used to indicate an error
	 *               if the field does not exist in the record.
	 * @return  A mutable reference to the given field.
	 */
	ZAMValUnion& Lookup(unsigned int field, bool& error)
		{
		error = false;

		if ( ! IsInRecord(field) && ! SetToDefault(field) )
			error = true;

		return zvec[field];
		}

	/**
	 * Returns a ValPtr corresponding to value of the given record field,
	 * if available.
	 * @param field  Which field in the record to access.
	 * @return  A ValPtr corresponding to the given field, or a nil
	 *          if the field is not set in the record.
	 */
	zeek::ValPtr NthField(unsigned int field)
		{
		bool error;
		auto f = Lookup(field, error);

		if ( error )
			return nullptr;

		return f.ToVal(FieldType(field));
		}

	/**
	 * Deletes the given field from the record.
	 * @param field  Which field in the record to access.
	 */
	void DeleteField(unsigned int field)
		{
		if ( IsInRecord(field) && IsManaged(field) )
			Unref(zvec[field].managed_val);

		is_in_record[field] = false;
		}

	/**
	 * Tests whether the given field is present in the record.
	 * @param field  Which field in the record to access.
	 * @return  True if the field is present, false if not.
	 */
	bool HasField(unsigned int field)
		{
		return IsInRecord(field);
		}

protected:
	friend class zeek::RecordVal;

	bool IsInRecord(unsigned int offset) const
		{ return is_in_record[offset]; }
	bool IsManaged(unsigned int offset) const
		{ return is_managed[offset]; }

	zeek::TypePtr FieldType(int field) const
		{ return rt->GetFieldType(field); }

	bool SetToDefault(unsigned int field);

	void Grow(unsigned int new_size)
		{
		zvec.resize(new_size);
		is_in_record.resize(new_size);
		}

	// Removes the given field.
	void Delete(unsigned int field)
		{ DeleteManagedType(zvec[field]); }

	void DeleteManagedMembers();

	// The underlying set of ZAM values.
	ZVU_vec zvec;

	// The associated main value.
	zeek::RecordVal* rv;

	// And a handy pointer to its type.
	zeek::RecordTypePtr rt;

	// Whether a given field exists (for optional fields).
	std::vector<bool> is_in_record;

	// Whether a given field requires explicit memory management.
	const std::vector<bool>& is_managed;
};

}
