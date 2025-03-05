// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/IntrusivePtr.h"

namespace zeek {
class EnumVal;
using EnumValPtr = IntrusivePtr<EnumVal>;

namespace storage {

/**
 * A collection of EnumValPtrs for the default set of result codes in the storage framework.
 * should be kept up-to-date with the Storage::ReturnCodes script-level enum.
 */
class ReturnCodes {
public:
    static void Initialize();
    static void Cleanup();

    static EnumValPtr SUCCESS;
    static EnumValPtr VAL_TYPE_MISMATCH;
    static EnumValPtr KEY_TYPE_MISMATCH;
    static EnumValPtr NOT_CONNECTED;
    static EnumValPtr TIMEOUT;
    static EnumValPtr CONNECTION_LOST;
    static EnumValPtr OPERATION_FAILED;
    static EnumValPtr KEY_NOT_FOUND;
    static EnumValPtr KEY_EXISTS;
    static EnumValPtr FAILED_TO_CONNECT;
    static EnumValPtr FAILED_TO_DISCONNECT;
    static EnumValPtr FAILED_TO_INITIALIZE;
};

} // namespace storage
} // namespace zeek
