#pragma once

#include <unordered_map>

#include "zeek/IntrusivePtr.h"

namespace zeek
	{

class Val;
using ValPtr = zeek::IntrusivePtr<Val>;

namespace detail
	{

// For internal use by the Val::Clone() methods.
struct CloneState
	{
	// Caches a cloned value for later reuse during the same
	// cloning operation. For recursive types, call this *before*
	// descending down.
	ValPtr NewClone(Val* src, ValPtr dst);

	std::unordered_map<Val*, Val*> clones;
	};

	} // namespace detail
	} // namespace zeek
