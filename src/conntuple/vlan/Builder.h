// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/conntuple/Builder.h"
#include "zeek/plugin/Plugin.h"

namespace zeek::plugin::Zeek_Conntuple_VLAN {

class Builder : public conntuple::Builder {
public:
    ConnTuplePtr GetTuple(const Packet* pkt) override;

    zeek::detail::ConnKeyPtr GetKey(const ConnTuple& tuple) override;
    zeek::detail::ConnKeyPtr GetKey(Val* v) override;

    void FillConnIdVal(detail::ConnKeyPtr key, RecordValPtr& tuple) override;

    static zeek::conntuple::BuilderPtr Instantiate() { return std::make_unique<Builder>(); }
};

} // namespace zeek::plugin::Zeek_Conntuple_VLAN
