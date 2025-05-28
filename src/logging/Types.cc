// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/logging/Types.h"

#include "zeek/Desc.h"
#include "zeek/Type.h"
#include "zeek/Val.h"

namespace zeek::logging::detail {

LogWriteHeader::LogWriteHeader(EnumValPtr arg_stream_id, EnumValPtr arg_writer_id, std::string arg_filter_name,
                               std::string arg_path)
    : stream_id(std::move(arg_stream_id)),
      writer_id(std::move(arg_writer_id)),
      filter_name(std::move(arg_filter_name)),
      path(std::move(arg_path)) {
    stream_name = obj_desc_short(stream_id.get());
    writer_name = obj_desc_short(writer_id.get());
}

bool LogWriteHeader::PopulateEnumVals() {
    static const auto& stream_id_type = zeek::id::find_type<zeek::EnumType>("Log::ID");
    static const auto& writer_id_type = zeek::id::find_type<zeek::EnumType>("Log::Writer");

    if ( stream_name.empty() || writer_name.empty() )
        return false;

    auto sid = stream_id_type->Lookup(stream_name);
    if ( sid < 0 )
        return false;

    auto wid = writer_id_type->Lookup(writer_name);
    if ( wid < 0 )
        return false;

    stream_id = stream_id_type->GetEnumVal(sid);
    writer_id = writer_id_type->GetEnumVal(wid);

    return true;
}

} // namespace zeek::logging::detail
