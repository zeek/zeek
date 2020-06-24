// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <vector>
#include "BroList.h"

class Val;

namespace zeek {

template <class T> class IntrusivePtr;
using Args = std::vector<zeek::IntrusivePtr<Val>>;

/**
 * Converts a legacy-style argument list for use in modern Zeek function
 * calling or event queueing APIs.
 * @param vl  the argument list to convert, the returned value takes ownership
 * of a reference to each element in the list
 * @return  the converted argument list
 *
 */
Args val_list_to_args(const val_list& vl);

} // namespace zeek
