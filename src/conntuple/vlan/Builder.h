// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/conntuple/Builder.h"
#include "zeek/plugin/Plugin.h"

namespace zeek::plugin::Zeek_Conntuple_VLAN {

class Builder : public conntuple::Builder {
public:
    virtual zeek::ConnKeyPtr NewConnKey() override;
    virtual zeek::ConnKeyPtr FromVal(const zeek::ValPtr& v) override;
};

} // namespace zeek::plugin::Zeek_Conntuple_VLAN
