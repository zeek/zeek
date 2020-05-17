// See the file "COPYING" in the main distribution directory for copyright.

// Values used in ZAM execution.

#pragma once

#include "Expr.h"
#include <unordered_set>


class ZAMVectorMgr;
struct IterInfo;

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
	ZAMValUnion(Val* v, BroType* t, const BroObj* o, bool& error_flag);

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

	// Used for managing "for" loops.  Explicit memory management.
	IterInfo* iter_info;

	// Used for loading/spilling globals; also, local vectors.
	ID* id_val;

	// Only used when we clear pointers on entry, and that's just
	// to lazily avoid doing a switch like IsNil() does.
	void* void_val;
};

// True if a given type is one that we treat internally as an "any" type.
extern bool IsAny(const BroType* t);

// Convenience functions for getting to this.
inline bool IsAny(const IntrusivePtr<BroType>& t) { return IsAny(t.get()); }
inline bool IsAny(const Expr* e) { return IsAny(e->Type()); }

// True if a given type is one for which we manage the associated
// memory internally.
bool IsManagedType(const BroType* t);
inline bool IsManagedType(const IntrusivePtr<BroType>& t)
	{ return IsManagedType(t.get()); }
inline bool IsManagedType(const Expr* e) { return IsManagedType(e->Type()); }

// Deletes a managed value.
void DeleteManagedType(ZAMValUnion& v, const BroType* t);


// Class used to manage vectors - only needed to support sync'ing them
// with Val*'s.

// The underlying "raw" vector.
typedef vector<ZAMValUnion> ZAM_vector;

class ZAMVectorMgr {
public:
	ZAMVectorMgr(std::shared_ptr<ZAM_vector> _vec, VectorVal* _v);
	~ZAMVectorMgr();

	ZAMVectorMgr* ShallowCopy()
		{
		return new ZAMVectorMgr(vec, v);
		}

	const std::shared_ptr<ZAM_vector>& ConstVec() const	{ return vec; }
	std::shared_ptr<ZAM_vector>& ModVec()	
		{ is_clean = false; return vec; }

	BroType* YieldType() const	{ return yield_type; }
	void SetYieldType(BroType* yt)	{ yield_type = yt; }

	IntrusivePtr<VectorVal> VecVal()	{ return {NewRef{}, v}; }
	void SetVecVal(VectorVal* vv)	 	{ v = vv; v->Ref(); }

	bool IsClean() const	{ return is_clean || ! v; }

	// Copy back the internal vector the associated value.
	void Spill();

	// Reload the internal vector from the associated value.
	void Freshen();

protected:
	std::shared_ptr<ZAM_vector> vec;
	VectorVal* v;

	// The actual yield type of the vector, if we've had a chance to
	// observe it.  Necessary for "vector of any".
	BroType* yield_type;

	// Whether the local vector is unmodified since we created it.
	bool is_clean;
};

// Information used to iterate over aggregates.  It's a hodge-podge since
// it's meant to support every type of aggregate & loop.
struct IterInfo {
	// If we're looping over a table:
	TableVal* tv;

	// The raw values being looped over
	const PDict<TableEntryVal>* loop_vals;

	// Iterator status.  Always gets deleted, so non-table/set
	// iteration instructions need to set it to nil.
	IterCookie* c;

	// Frame slots of iteration variables, such as "[v1, v2, v3] in aggr".
	// These are used for iterating over vectors and strings, too
	// (well, the first slot is).
	vector<int> loop_vars;

	// Their types.
	vector<BroType*> loop_var_types;

	// Type associated with the "value" entry, for "k, v in aggr"
	// iteration.
	BroType* value_var_type;

	// If we're iterating over vectors, points to the raw vector ...
	std::shared_ptr<ZAM_vector> vv;

	// ... unless it's a vector of any (sigh):
	vector<Val*>* any_vv;

	// The vector's type & yield.
	VectorType* vec_type;
	BroType* yield_type;

	// String we're iterating over.
	BroString* s;

	// Counter of where we are in the iteration.
	bro_uint_t iter;
	bro_uint_t n;	// we loop from 0 ... n-1
};

// Tracks the managers of internal/Val* vector pairings.
typedef std::unordered_set<ZAMVectorMgr*> ZAM_tracker_type;

// For the currently executing function, tracks the active ZAMVectorMgr's
// that are associated with Val*'s.  We define this in a global so that
// ZAMVectorMgr objects can access it without having to pass it all the
// way down in the myriad ZAMValUnion constructor invocations.  OTOH,
// this means we have to be careful to keep it consistent whenever
// control flow potentially goes into another ZAM, which
// currently means we need to restore it any time we invoke the interpreter.
extern ZAM_tracker_type* curr_ZAM_VM_Tracker;

// Converts between VectorVals and ZAM vectors.
extern ZAMVectorMgr* to_ZAM_vector(Val* vec, bool track_val);
extern std::shared_ptr<ZAM_vector> to_raw_ZAM_vector(Val* vec);

extern void grow_vector(ZAM_vector& vec, int new_size);
