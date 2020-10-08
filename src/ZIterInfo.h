// See the file "COPYING" in the main distribution directory for copyright.

// Information needed for ZAM loop iterations.  Isolated here, rather than
// bundling in ZVal.h, to enable ZVal to stand alone separate from other ZAM
// internals.

#pragma once


// The information ist a hodge-podge since it's meant to support every
// type of aggregate & loop.
class IterInfo {
public:
	IterInfo()	{ c = nullptr;	/* clear the cookie */ }
	~IterInfo()	{ if ( c ) loop_vals->StopIteration(c); }

	// If we're looping over a table:
	const TableVal* tv = nullptr;

	// The raw values being looped over.
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

	// If we're iterating over a vector, points to the raw vector.
	ZAM_vector* vv = nullptr;

	// The vector's type & yield.
	VectorType* vec_type = nullptr;
	BroType* yield_type = nullptr;

	// String we're iterating over.
	const BroString* s = nullptr;

	// Counter of where we are in the iteration.
	bro_uint_t iter;	// initialized to 0 at start of loop
	bro_uint_t n;	// we loop from 0 ... n-1
};
