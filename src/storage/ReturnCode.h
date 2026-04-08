// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/zeek-config.h"

#include "zeek/IntrusivePtr.h"

namespace zeek {
class EnumVal;
using EnumValPtr = IntrusivePtr<EnumVal>;

namespace storage {

/**
 * A collection of EnumValPtrs for the default set of result codes in the storage framework.
 * should be kept up-to-date with the Storage::ReturnCodes script-level enum.
 */
class ReturnCode final {
public:
    static void Initialize();
    static void Cleanup();

    ZEEK_IMPORT_DATA static EnumValPtr SUCCESS;
    ZEEK_IMPORT_DATA static EnumValPtr VAL_TYPE_MISMATCH;
    ZEEK_IMPORT_DATA static EnumValPtr KEY_TYPE_MISMATCH;
    ZEEK_IMPORT_DATA static EnumValPtr NOT_CONNECTED;
    ZEEK_IMPORT_DATA static EnumValPtr TIMEOUT;
    ZEEK_IMPORT_DATA static EnumValPtr CONNECTION_LOST;
    ZEEK_IMPORT_DATA static EnumValPtr OPERATION_FAILED;
    ZEEK_IMPORT_DATA static EnumValPtr KEY_NOT_FOUND;
    ZEEK_IMPORT_DATA static EnumValPtr KEY_EXISTS;
    ZEEK_IMPORT_DATA static EnumValPtr CONNECTION_FAILED;
    ZEEK_IMPORT_DATA static EnumValPtr DISCONNECTION_FAILED;
    ZEEK_IMPORT_DATA static EnumValPtr INITIALIZATION_FAILED;
    ZEEK_IMPORT_DATA static EnumValPtr IN_PROGRESS;
    ZEEK_IMPORT_DATA static EnumValPtr SERIALIZATION_FAILED;
    ZEEK_IMPORT_DATA static EnumValPtr UNSERIALIZATION_FAILED;
};

} // namespace storage
} // namespace zeek
