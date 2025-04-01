// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/ReturnCode.h"

#include "zeek/Val.h"

namespace zeek::storage {

EnumValPtr ReturnCode::SUCCESS;
EnumValPtr ReturnCode::VAL_TYPE_MISMATCH;
EnumValPtr ReturnCode::KEY_TYPE_MISMATCH;
EnumValPtr ReturnCode::NOT_CONNECTED;
EnumValPtr ReturnCode::TIMEOUT;
EnumValPtr ReturnCode::CONNECTION_LOST;
EnumValPtr ReturnCode::OPERATION_FAILED;
EnumValPtr ReturnCode::KEY_NOT_FOUND;
EnumValPtr ReturnCode::KEY_EXISTS;
EnumValPtr ReturnCode::CONNECTION_FAILED;
EnumValPtr ReturnCode::DISCONNECTION_FAILED;
EnumValPtr ReturnCode::INITIALIZATION_FAILED;
EnumValPtr ReturnCode::IN_PROGRESS;
EnumValPtr ReturnCode::SERIALIZATION_FAILED;
EnumValPtr ReturnCode::UNSERIALIZATION_FAILED;

void ReturnCode::Initialize() {
    static const auto& return_code_type = zeek::id::find_type<zeek::EnumType>("Storage::ReturnCode");

    auto tmp = return_code_type->Lookup("Storage::SUCCESS");
    SUCCESS = return_code_type->GetEnumVal(tmp);

    tmp = return_code_type->Lookup("Storage::VAL_TYPE_MISMATCH");
    VAL_TYPE_MISMATCH = return_code_type->GetEnumVal(tmp);

    tmp = return_code_type->Lookup("Storage::KEY_TYPE_MISMATCH");
    KEY_TYPE_MISMATCH = return_code_type->GetEnumVal(tmp);

    tmp = return_code_type->Lookup("Storage::NOT_CONNECTED");
    NOT_CONNECTED = return_code_type->GetEnumVal(tmp);

    tmp = return_code_type->Lookup("Storage::TIMEOUT");
    TIMEOUT = return_code_type->GetEnumVal(tmp);

    tmp = return_code_type->Lookup("Storage::CONNECTION_LOST");
    CONNECTION_LOST = return_code_type->GetEnumVal(tmp);

    tmp = return_code_type->Lookup("Storage::OPERATION_FAILED");
    OPERATION_FAILED = return_code_type->GetEnumVal(tmp);

    tmp = return_code_type->Lookup("Storage::KEY_NOT_FOUND");
    KEY_NOT_FOUND = return_code_type->GetEnumVal(tmp);

    tmp = return_code_type->Lookup("Storage::KEY_EXISTS");
    KEY_EXISTS = return_code_type->GetEnumVal(tmp);

    tmp = return_code_type->Lookup("Storage::CONNECTION_FAILED");
    CONNECTION_FAILED = return_code_type->GetEnumVal(tmp);

    tmp = return_code_type->Lookup("Storage::DISCONNECTION_FAILED");
    DISCONNECTION_FAILED = return_code_type->GetEnumVal(tmp);

    tmp = return_code_type->Lookup("Storage::INITIALIZATION_FAILED");
    INITIALIZATION_FAILED = return_code_type->GetEnumVal(tmp);

    tmp = return_code_type->Lookup("Storage::IN_PROGRESS");
    IN_PROGRESS = return_code_type->GetEnumVal(tmp);

    tmp = return_code_type->Lookup("Storage::SERIALIZATION_FAILED");
    SERIALIZATION_FAILED = return_code_type->GetEnumVal(tmp);

    tmp = return_code_type->Lookup("Storage::UNSERIALIZATION_FAILED");
    UNSERIALIZATION_FAILED = return_code_type->GetEnumVal(tmp);
}

void ReturnCode::Cleanup() {
    SUCCESS.reset();
    VAL_TYPE_MISMATCH.reset();
    KEY_TYPE_MISMATCH.reset();
    NOT_CONNECTED.reset();
    TIMEOUT.reset();
    CONNECTION_LOST.reset();
    OPERATION_FAILED.reset();
    KEY_NOT_FOUND.reset();
    KEY_EXISTS.reset();
    CONNECTION_FAILED.reset();
    DISCONNECTION_FAILED.reset();
    INITIALIZATION_FAILED.reset();
    IN_PROGRESS.reset();
    SERIALIZATION_FAILED.reset();
    UNSERIALIZATION_FAILED.reset();
}

} // namespace zeek::storage
