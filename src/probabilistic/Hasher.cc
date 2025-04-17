// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/probabilistic/Hasher.h"

#include <highwayhash/sip_hash.h>
#include <openssl/evp.h>
#include <typeinfo>

#include "zeek/Var.h"
#include "zeek/broker/Data.h"
#include "zeek/digest.h"

namespace zeek::probabilistic::detail {

Hasher::seed_t Hasher::MakeSeed(const void* data, size_t size) {
    u_char buf[ZEEK_SHA256_DIGEST_LENGTH];
    seed_t tmpseed;
    auto* ctx = zeek::detail::hash_init(zeek::detail::Hash_SHA256);

    assert(sizeof(tmpseed) == 16);

    static auto global_hash_seed = id::find_val<StringVal>("global_hash_seed");

    if ( data )
        zeek::detail::hash_update(ctx, data, size);

    else if ( global_hash_seed->Len() > 0 )
        zeek::detail::hash_update(ctx, global_hash_seed->Bytes(), global_hash_seed->Len());

    else {
        unsigned int first_seed = util::detail::initial_seed();
        zeek::detail::hash_update(ctx, &first_seed, sizeof(first_seed));
    }

    zeek::detail::hash_final(ctx, buf);
    memcpy(&tmpseed, buf, sizeof(tmpseed)); // Use the first bytes as seed.
    return tmpseed;
}

Hasher::digest_vector Hasher::Hash(const zeek::detail::HashKey* key) const { return Hash(key->Key(), key->Size()); }

Hasher::Hasher(size_t arg_k, seed_t arg_seed) {
    k = arg_k;
    seed = arg_seed;
}

std::optional<BrokerData> Hasher::Serialize() const {
    BrokerListBuilder builder;
    builder.Reserve(4);
    builder.AddCount(static_cast<unsigned>(Type()));
    builder.AddCount(k);
    builder.AddCount(seed.h[0]);
    builder.AddCount(seed.h[1]);
    return std::move(builder).Build();
}

std::unique_ptr<Hasher> Hasher::Unserialize(BrokerDataView data) {
    if ( ! data.IsList() )
        return nullptr;

    auto v = data.ToList();

    if ( v.Size() != 4 || ! are_all_counts(v[0], v[1], v[2], v[3]) )
        return nullptr;

    auto [type, k, h1, h2] = to_count(v[0], v[1], v[2], v[3]);

    std::unique_ptr<Hasher> hasher;

    switch ( type ) {
        case Default: hasher.reset(new DefaultHasher(k, {h1, h2})); break;

        case Double: hasher.reset(new DoubleHasher(k, {h1, h2})); break;

        default: break;
    }

    // Note that the derived classed don't hold any further state of
    // their own. They reconstruct all their information from their
    // constructors' arguments.

    return hasher;
}

UHF::UHF() { memset(&seed, 0, sizeof(seed)); }

UHF::UHF(Hasher::seed_t arg_seed) { seed = arg_seed; }

// This function is almost equivalent to HashKey::HashBytes except that it
// does not depend on global state and that we mix in the seed multiple
// times.
Hasher::digest UHF::hash(const void* x, size_t n) const {
    static_assert(std::is_same_v<highwayhash::SipHashState::Key, decltype(seed.h)>,
                  "Seed value is not the same type as highwayhash key");
    return highwayhash::SipHash(seed.h, reinterpret_cast<const char*>(x), n);
}

DefaultHasher::DefaultHasher(size_t k, Hasher::seed_t seed) : Hasher(k, seed) {
    for ( size_t i = 1; i <= k; ++i ) {
        seed_t s = Seed();
        s.h[0] += util::detail::prng(i);
        hash_functions.emplace_back(s);
    }
}

Hasher::digest_vector DefaultHasher::Hash(const void* x, size_t n) const {
    digest_vector h(K(), 0);

    for ( size_t i = 0; i < h.size(); ++i )
        h[i] = hash_functions[i](x, n);

    return h;
}

DefaultHasher* DefaultHasher::Clone() const { return new DefaultHasher(*this); }

bool DefaultHasher::Equals(const Hasher* other) const {
    if ( typeid(*this) != typeid(*other) )
        return false;

    const DefaultHasher* o = static_cast<const DefaultHasher*>(other);
    return hash_functions == o->hash_functions;
}

DoubleHasher::DoubleHasher(size_t k, seed_t seed)
    : Hasher(k, seed), h1(seed + util::detail::prng(1)), h2(seed + util::detail::prng(2)) {}

Hasher::digest_vector DoubleHasher::Hash(const void* x, size_t n) const {
    digest d1 = h1(x, n);
    digest d2 = h2(x, n);
    digest_vector h(K(), 0);

    for ( size_t i = 0; i < h.size(); ++i )
        h[i] = d1 + i * d2;

    return h;
}

DoubleHasher* DoubleHasher::Clone() const { return new DoubleHasher(*this); }

bool DoubleHasher::Equals(const Hasher* other) const {
    if ( typeid(*this) != typeid(*other) )
        return false;

    const DoubleHasher* o = static_cast<const DoubleHasher*>(other);
    return h1 == o->h1 && h2 == o->h2;
}

} // namespace zeek::probabilistic::detail
