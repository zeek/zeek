// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/zeek-config.h"

#include "zeek/Tag.h"

namespace zeek::logging
	{

using Tag [[deprecated("Remove in v5.1. Use zeek::Tag.")]] = zeek::Tag;

	} // namespace zeek::logging
