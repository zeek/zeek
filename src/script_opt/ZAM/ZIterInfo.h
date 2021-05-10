// See the file "COPYING" in the main distribution directory for copyright.

// Information needed for ZAM loop iterations.

#pragma once

#include "zeek/Val.h"

namespace zeek::detail {

// The information is a hodge-podge since it's meant to support every
// type of aggregate & loop.
class IterInfo {
public:
	IterInfo()	{ }

	// If we're looping over a table:
	const TableVal* tv = nullptr;

	std::optional<DictIterator> tbl_iter;
	std::optional<DictIterator> tbl_end;

	// Frame slots of iteration variables, such as "[v1, v2, v3] in aggr".
	// These are used for iterating over vectors and strings, too
	// (well, the first slot is).
	std::vector<int> loop_vars;

	// Their types.
	std::vector<TypePtr> loop_var_types;

	// Type associated with the "value" entry, for "k, v in aggr"
	// iteration.
	TypePtr value_var_type = nullptr;

	// If we're iterating over a vector, points to it.
	std::vector<std::optional<ZVal>>* vv = nullptr;

	// The vector's type & yield.
	VectorTypePtr vec_type = nullptr;
	TypePtr yield_type = nullptr;

	// String we're iterating over.
	const String* s = nullptr;

	// Counter of where we are in the iteration.
	bro_uint_t iter;	// initialized to 0 at start of loop
	bro_uint_t n;	// we loop from 0 ... n-1
};

} // namespace zeek::detail
