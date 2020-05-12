// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "Val.h"
#include "Type.h"
#include "IntrusivePtr.h"

namespace zeek { namespace vars { namespace detail {
void init();
}}}

namespace zeek { namespace vars {

// Common Types
extern IntrusivePtr<RecordType> conn_id;
extern IntrusivePtr<RecordType> endpoint;
extern IntrusivePtr<RecordType> connection;
extern IntrusivePtr<RecordType> fa_file;
extern IntrusivePtr<RecordType> fa_metadata;
extern IntrusivePtr<EnumType> transport_proto;
extern IntrusivePtr<TableType> string_set;
extern IntrusivePtr<TableType> string_array;
extern IntrusivePtr<TableType> count_set;
extern IntrusivePtr<VectorType> string_vec;
extern IntrusivePtr<VectorType> index_vec;

}} // namespace zeek::vars
