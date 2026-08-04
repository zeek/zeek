#include "NanoTime.h"

#include <zeek/CompHash.h>
#include <zeek/Hash.h>
#include <cstdint>

using namespace btest::type;

NanoTimeOpaqueTypePtr NanoTimeOpaqueType::type_ptr;

bool NanoTimeOpaqueType::HashSingleValue(const zeek::detail::CompositeHash* ch, zeek::detail::HashKey& hk,
                                         const zeek::Val* v, bool type_check, bool singleton) const {
    fprintf(stderr, "HashSingeValue\n");
    auto nv = static_cast<const NanoTimeVal*>(v);
    hk.Write("nanoseconds", nv->nanos); // NanoTimeOpaqueType is private friend

    return true;
}

bool NanoTimeOpaqueType::RecoverValFromHash(const zeek::detail::CompositeHash* ch, const zeek::detail::HashKey& hk,
                                            zeek::ValPtr* pval, bool singleton) const {
    fprintf(stderr, "RecoverValFromHash\n");
    uint64_t nanos;

    hk.Read("nanoseconds", nanos); // this can hard abort, but hey.

    *pval = zeek::make_intrusive<NanoTimeVal>(nanos);

    return true;
}

bool NanoTimeOpaqueType::ReserveHashKeySize(const zeek::detail::CompositeHash* ch, zeek::detail::HashKey& hk,
                                            const zeek::Val* v, bool type_check, bool calc_static_size,
                                            bool singleton) const {
    fprintf(stderr, "ReserveHashKeySize\n");
    hk.ReserveType<uint64_t>("nanotime");
    return true;
}

bool NanoTimeOpaqueType::CanCastTo(const zeek::Type* t) const {
    return t->Tag() == zeek::TYPE_COUNT || t->Tag() == zeek::TYPE_TIME;
}

zeek::ValPtr NanoTimeOpaqueType::CastValueTo(const zeek::ValPtr& v, const zeek::Type* t, std::string& err) const {
    auto nv = zeek::cast_intrusive<NanoTimeVal>(v); // is this safe?
    if ( t->Tag() == zeek::TYPE_COUNT )
        return zeek::val_mgr->Count(nv->nanos);
    else if ( t->Tag() == zeek::TYPE_TIME )
        return zeek::make_intrusive<zeek::TimeVal>(static_cast<double>(nv->nanos) / 1000000000.0);

    return nullptr;
}
