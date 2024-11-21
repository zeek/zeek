// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <vector>

#include "zeek/ZeekList.h"

namespace zeek {

class VectorVal;
class RecordType;
template<class T>
class IntrusivePtr;

using ValPtr = IntrusivePtr<Val>;
using VectorValPtr = IntrusivePtr<VectorVal>;
using RecordTypePtr = IntrusivePtr<RecordType>;

using Args = std::vector<ValPtr>;

/**
 * Converts a legacy-style argument list for use in modern Zeek function
 * calling or event queueing APIs.
 * @param vl  the argument list to convert, the returned value takes ownership
 * of a reference to each element in the list
 * @return  the converted argument list
 *
 */
[[deprecated("Remove in v8.1. Convert users to produce zeek::Args directly.")]]
Args val_list_to_args(const ValPList& vl);

/**
 * Creates a vector of "call_argument" meta data describing the arguments to
 * function/event invocation.
 *
 * @param vals call arguments
 * @param types function parameters
 * @return vector of script-level type "call_argument_vector"
 */
VectorValPtr MakeCallArgumentVector(const Args& vals, const RecordTypePtr& types);

/**
 * Creates an empty "call_argument_vector" vector.
 *
 * @return empty vector of script-level type "call_argument_vector"
 */
VectorValPtr MakeEmptyCallArgumentVector();

} // namespace zeek
