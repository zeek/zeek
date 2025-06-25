#pragma once

#include "zeek/IntrusivePtr.h"
#include "zeek/conn_key/Factory.h"
#include "zeek/packet_analysis/protocol/ip/conn_key/fivetuple/Factory.h"

namespace zeek {
class Val;
using ValPtr = zeek::IntrusivePtr<Val>;
} // namespace zeek

namespace btest::plugin::Demo_Foo {

class FooFactory : public zeek::conn_key::fivetuple::Factory {
public:
    static zeek::conn_key::FactoryPtr Instantiate();

protected:
    zeek::ConnKeyPtr DoNewConnKey() const override;
    zeek::expected<zeek::ConnKeyPtr, std::string> DoConnKeyFromVal(const zeek::Val& v) const override;

private:
};

} // namespace btest::plugin::Demo_Foo
