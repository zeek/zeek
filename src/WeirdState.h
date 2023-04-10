// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

namespace zeek::detail
	{

struct WeirdState
	{
	WeirdState() = default;
	uint64_t count = 0;
	double sampling_start_time = 0;
	};

using WeirdStateMap = std::unordered_map<std::string, WeirdState>;

bool PermitWeird(WeirdStateMap& wsm, const char* name, uint64_t threshold, uint64_t rate,
                 double duration);

	} // namespace zeek::detail
