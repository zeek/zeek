// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/ReturnCodes.h"

#include "zeek/Val.h"

namespace zeek::storage {

EnumValPtr ReturnCodes::SUCCESS;
EnumValPtr ReturnCodes::VAL_TYPE_MISMATCH;
EnumValPtr ReturnCodes::KEY_TYPE_MISMATCH;
EnumValPtr ReturnCodes::NOT_CONNECTED;
EnumValPtr ReturnCodes::TIMEOUT;
EnumValPtr ReturnCodes::CONNECTION_LOST;
EnumValPtr ReturnCodes::OPERATION_FAILED;
EnumValPtr ReturnCodes::KEY_NOT_FOUND;
EnumValPtr ReturnCodes::KEY_EXISTS;
EnumValPtr ReturnCodes::FAILED_TO_CONNECT;
EnumValPtr ReturnCodes::FAILED_TO_DISCONNECT;
EnumValPtr ReturnCodes::FAILED_TO_INITIALIZE;

void ReturnCodes::Initialize() {
    static const auto& return_code_type = zeek::id::find_type<zeek::EnumType>("Storage::ReturnCodes");

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

    tmp = return_code_type->Lookup("Storage::FAILED_TO_CONNECT");
    FAILED_TO_CONNECT = return_code_type->GetEnumVal(tmp);

    tmp = return_code_type->Lookup("Storage::FAILED_TO_DISCONNECT");
    FAILED_TO_DISCONNECT = return_code_type->GetEnumVal(tmp);

    tmp = return_code_type->Lookup("Storage::FAILED_TO_INITIALIZE");
    FAILED_TO_INITIALIZE = return_code_type->GetEnumVal(tmp);
}

void ReturnCodes::Cleanup() {
    SUCCESS.reset();
    VAL_TYPE_MISMATCH.reset();
    KEY_TYPE_MISMATCH.reset();
    NOT_CONNECTED.reset();
    TIMEOUT.reset();
    CONNECTION_LOST.reset();
    OPERATION_FAILED.reset();
    KEY_NOT_FOUND.reset();
    KEY_EXISTS.reset();
    FAILED_TO_CONNECT.reset();
    FAILED_TO_DISCONNECT.reset();
    FAILED_TO_INITIALIZE.reset();
}

} // namespace zeek::storage
