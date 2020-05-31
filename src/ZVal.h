// See the file "COPYING" in the main distribution directory for copyright.

// Values used in ZAM execution.

#pragma once

#include "Dict.h"
#include "Expr.h"
#include <unordered_set>


// Manager of a single internal/Val* aggregate pairing.
class ZAMAggregateMgr;

// Tracks all such managers.
typedef std::unordered_set<ZAMAggregateMgr*> ZAM_tracker_type;

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
	ZAMValUnion(Val* v, BroType* t, ZAM_tracker_type* tracker,
			const BroObj* o, bool& error_flag);

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
	ZAMVectorMgr* vector_val;

	// The types are all variants of Val (or BroType).  For memory
	// management, in the AM frame we shadow these with IntrusivePtr's.
	// Thus we do not unref these on reassignment.
	BroFile* file_val;
	Func* func_val;
	ListVal* list_val;
	OpaqueVal* opaque_val;
	PatternVal* re_val;
	RecordVal* record_val;
	TableVal* table_val;
	BroType* type_val;

	// Used both for direct "any" values and for "vector of any".
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


// Class used to manage vectors - only needed to support sync'ing them
// with Val*'s.

// The underlying "raw" vector.
class ZAM_vector {
public:
	ZAM_vector(const BroType* _t)	{ t = _t; }
	ZAM_vector(const BroType* _t, int n) : zvec(n)	{ t = _t; }

	~ZAM_vector()	{ if ( t ) DeleteMembers(); }

	vector<ZAMValUnion> zvec;

	// Sets the given element, doing deletions and deep-copies
	// for managed types.
	void SetElement(int n, ZAMValUnion& v)
		{
		if ( zvec.size() <= n )
			GrowVector(n + 1);

		if ( t )
			SetManagedElement(n, v);
		else
			zvec[n] = v;
		}

	// The type of the vector elements.  Only non-nil if they
	// are managed types.
	const BroType* t;

protected:
	void SetManagedElement(int n, ZAMValUnion& v);
	void GrowVector(int size);

	void DeleteMembers();

	// Deletes the given element if necessary.
	void DeleteIfManaged(int n)
		{
		if ( t )
			DeleteManagedType(zvec[n], t);
		}
};

class ZAMAggregateMgr {
public:
	ZAMAggregateMgr(ZAM_tracker_type* tracker, Val* aggr_val);
	virtual ~ZAMAggregateMgr();

	// Copy back the internal aggregate to the associated value.
	virtual void Spill() = 0;

	// Reload the internal aggregate from the associated value.
	virtual void Freshen() = 0;

protected:
	// This would be in the destructor but it needs to call virtual
	// functions, so instead derived classes need to call it from
	// their own destructors.
	void Finish();

	ZAM_tracker_type* tracker;
	Val* aggr_val;
};

class ZAMVectorMgr : public ZAMAggregateMgr {
public:
	ZAMVectorMgr(std::shared_ptr<ZAM_vector> _vec, VectorVal* _v,
			ZAM_tracker_type* tracker);
	~ZAMVectorMgr() override;

	ZAMVectorMgr* ShallowCopy()
		{
		return new ZAMVectorMgr(vec, v, nullptr);
		}

	const std::shared_ptr<ZAM_vector>& ConstVec() const	{ return vec; }
	std::shared_ptr<ZAM_vector>& ModVec()	
		{ is_clean = false; return vec; }

	BroType* YieldType() const	{ return yield_type; }
	BroType* ManagedYieldType() const
		{ return is_managed ? yield_type : nullptr; }

	void SetYieldType(BroType* yt)
		{
		if ( ! yield_type )
			{
			yield_type = yt;
			is_managed = IsManagedType(yt);
			if ( is_managed )
				vec->t = yt;
			}
		}

	IntrusivePtr<VectorVal> VecVal()	{ return {NewRef{}, v}; }
	void SetVecVal(VectorVal* vv)	 	{ aggr_val = v = vv; v->Ref(); }

	bool IsManaged() const	{ return is_managed; }

	bool IsClean() const	{ return is_clean || ! v; }

	void Spill() override;
	void Freshen() override;

protected:
	std::shared_ptr<ZAM_vector> vec;
	VectorVal* v;	// our own copy of aggr_val, with the right type

	// The actual yield type of the vector, if we've had a chance to
	// observe it.  Necessary for "vector of any".  Non-const because
	// we need to be able to ref it.
	BroType* yield_type;

	// Whether the base type of the vector is one for which we need
	// to do explicit memory management.
	bool is_managed;

	// Whether the local vector is unmodified since we created it.
	bool is_clean;
};

// Information used to iterate over aggregates.  It's a hodge-podge since
// it's meant to support every type of aggregate & loop.  Only a BroObj
// so we can make intrusive pointers for memory management.
class IterInfo : public BroObj {
public:
	IterInfo()	{ c = nullptr; }
	~IterInfo()	{ if ( c ) loop_vals->StopIteration(c); }

	// If we're looping over a table:
	TableVal* tv = nullptr;

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
	std::shared_ptr<ZAM_vector> vv = nullptr;

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
extern ZAMVectorMgr* to_ZAM_vector(Val* vec, ZAM_tracker_type* tracker,
					bool track_val);
extern std::shared_ptr<ZAM_vector> to_raw_ZAM_vector(Val* vec,
						ZAM_tracker_type* tracker);
