
#pragma once

#include <string>

#include "zeek/OpaqueVal.h"
#include "zeek/Type.h"

namespace btest::type {

class NanoTimeOpaqueType;
using NanoTimeOpaqueTypePtr = zeek::IntrusivePtr<NanoTimeOpaqueType>;


/**
 * A hashable opaque type storing time as nanoseconds.
 */
class NanoTimeOpaqueType : public zeek::OpaqueType {
public:
    NanoTimeOpaqueType() : zeek::OpaqueType("NanoTime") {}
    bool SupportsHashing() const override { return true; }

    bool HashSingleValue(const zeek::detail::CompositeHash* ch, zeek::detail::HashKey& hk, const zeek::Val* v,
                         bool type_check, bool singleton) const override;
    bool RecoverValFromHash(const zeek::detail::CompositeHash* ch, const zeek::detail::HashKey& hk, zeek::ValPtr* pval,
                            bool singleton) const override;
    bool ReserveHashKeySize(const zeek::detail::CompositeHash* ch, zeek::detail::HashKey& hk, const zeek::Val* v,
                            bool type_check, bool calc_static_size, bool singleton) const override;

    virtual bool CanCastTo(const zeek::Type* t) const override;

    virtual zeek::ValPtr CastValueTo(const zeek::ValPtr& v, const zeek::Type* t, std::string& err) const override;

    virtual zeek::ValPtr DefaultVal() const override;

    static NanoTimeOpaqueTypePtr type_ptr;
    static zeek::detail::IDPtr id_ptr;
};


class NanoTimeVal : public zeek::OpaqueVal {
public:
    NanoTimeVal(uint64_t nanos) : zeek::OpaqueVal(NanoTimeOpaqueType::type_ptr), nanos(nanos) {}

    const char* OpaqueName() const override { return "NanoTime"; }

private:
    friend class NanoTimeOpaqueType;
    uint64_t nanos;
};


} // namespace btest::type
