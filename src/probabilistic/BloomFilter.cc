// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/probabilistic/BloomFilter.h"

#include <cinttypes>
#include <cmath>
#include <limits>

#include "zeek/Reporter.h"
#include "zeek/broker/Data.h"
#include "zeek/probabilistic/CounterVector.h"
#include "zeek/util.h"

namespace zeek::probabilistic {

BloomFilter::BloomFilter() { hasher = nullptr; }

BloomFilter::BloomFilter(const detail::Hasher* arg_hasher) { hasher = arg_hasher; }

BloomFilter::~BloomFilter() { delete hasher; }

std::optional<BrokerData> BloomFilter::SerializeData() const {
    auto h = hasher->Serialize();

    if ( ! h )
        return std::nullopt; // Cannot serialize

    auto d = DoSerializeData();

    if ( ! d )
        return std::nullopt; // Cannot serialize

    BrokerListBuilder builder;
    builder.Reserve(3);
    builder.Add(static_cast<uint64_t>(Type()));
    builder.Add(std::move(*h));
    builder.Add(std::move(*d));
    return std::move(builder).Build();
}

std::unique_ptr<BloomFilter> BloomFilter::UnserializeData(BrokerDataView data) {
    if ( ! data.IsList() )
        return nullptr;

    auto v = data.ToList();

    if ( v.Size() != 3 || ! v[0].IsCount() )
        return nullptr;

    std::unique_ptr<BloomFilter> bf;

    switch ( v[0].ToCount() ) {
        case Basic: bf.reset(new BasicBloomFilter()); break;

        case Counting: bf.reset(new CountingBloomFilter()); break;

        default: reporter->Error("found invalid bloom filter type"); return nullptr;
    }

    if ( ! bf->DoUnserializeData(v[2]) )
        return nullptr;

    bf->hasher = detail::Hasher::Unserialize(v[1]).release();

    if ( ! bf->hasher )
        return nullptr;

    return bf;
}

broker::expected<broker::data> BloomFilter::DoSerialize() const {
    return {broker::make_error(broker::ec::serialization_failed)};
}

bool BloomFilter::DoUnserialize(const broker::data&) { return false; }

std::optional<BrokerData> BloomFilter::DoSerializeData() const {
    if ( auto res = DoSerialize() ) {
        return BrokerData{std::move(*res)};
    }
    return std::nullopt;
}

bool BloomFilter::DoUnserializeData(BrokerDataView data) {
    return DoUnserialize(zeek::detail::BrokerDataAccess::Unbox(data));
}

size_t BasicBloomFilter::M(double fp, size_t capacity) {
    double ln2 = std::log(2);
    return std::ceil(-(capacity * std::log(fp) / ln2 / ln2));
}

size_t BasicBloomFilter::K(size_t cells, size_t capacity) {
    double frac = static_cast<double>(cells) / static_cast<double>(capacity);
    return std::ceil(frac * std::log(2));
}

bool BasicBloomFilter::Empty() const { return bits->AllZero(); }

void BasicBloomFilter::Clear() { bits->Reset(); }

bool BasicBloomFilter::Merge(const BloomFilter* other) {
    if ( typeid(*this) != typeid(*other) )
        return false;

    const BasicBloomFilter* o = static_cast<const BasicBloomFilter*>(other);

    if ( ! hasher->Equals(o->hasher) ) {
        reporter->Error("incompatible hashers in BasicBloomFilter merge");
        return false;
    }

    else if ( bits->Size() != o->bits->Size() ) {
        reporter->Error("different bitvector size in BasicBloomFilter merge");
        return false;
    }

    (*bits) |= *o->bits;

    return true;
}

BasicBloomFilter* BasicBloomFilter::Intersect(const BloomFilter* other) const {
    if ( typeid(*this) != typeid(*other) )
        return nullptr;

    const BasicBloomFilter* o = static_cast<const BasicBloomFilter*>(other);

    if ( ! hasher->Equals(o->hasher) ) {
        reporter->Error("incompatible hashers in BasicBloomFilter intersect");
        return nullptr;
    }

    else if ( bits->Size() != o->bits->Size() ) {
        reporter->Error("different bitvector size in BasicBloomFilter intersect");
        return nullptr;
    }

    auto copy = Clone();
    (*copy->bits) &= *o->bits;

    return copy;
}

BasicBloomFilter* BasicBloomFilter::Clone() const {
    BasicBloomFilter* copy = new BasicBloomFilter();

    copy->hasher = hasher->Clone();
    copy->bits = new detail::BitVector(*bits);

    return copy;
}

std::string BasicBloomFilter::InternalState() const { return util::fmt("%" PRIu64, bits->Hash()); }

BasicBloomFilter::BasicBloomFilter() { bits = nullptr; }

BasicBloomFilter::BasicBloomFilter(const detail::Hasher* hasher, size_t cells) : BloomFilter(hasher) {
    bits = new detail::BitVector(cells);
}

BasicBloomFilter::~BasicBloomFilter() { delete bits; }

void BasicBloomFilter::Add(const zeek::detail::HashKey* key) {
    detail::Hasher::digest_vector h = hasher->Hash(key);

    for ( unsigned long long i : h )
        bits->Set(i % bits->Size());
}

bool BasicBloomFilter::Decrement(const zeek::detail::HashKey* key) {
    // operation not supported by basic bloom filter
    return false;
}

size_t BasicBloomFilter::Count(const zeek::detail::HashKey* key) const {
    detail::Hasher::digest_vector h = hasher->Hash(key);

    for ( unsigned long long i : h ) {
        if ( ! (*bits)[i % bits->Size()] )
            return 0;
    }

    return 1;
}

std::optional<BrokerData> BasicBloomFilter::DoSerializeData() const { return bits->Serialize(); }

bool BasicBloomFilter::DoUnserializeData(BrokerDataView data) {
    auto b = detail::BitVector::Unserialize(data);
    if ( ! b )
        return false;

    bits = b.release();
    return true;
}

CountingBloomFilter::CountingBloomFilter() { cells = nullptr; }

CountingBloomFilter::CountingBloomFilter(const detail::Hasher* hasher, size_t arg_cells, size_t width)
    : BloomFilter(hasher) {
    cells = new detail::CounterVector(width, arg_cells);
}

CountingBloomFilter::~CountingBloomFilter() { delete cells; }

bool CountingBloomFilter::Empty() const { return cells->AllZero(); }

void CountingBloomFilter::Clear() { cells->Reset(); }

bool CountingBloomFilter::Merge(const BloomFilter* other) {
    if ( typeid(*this) != typeid(*other) )
        return false;

    const CountingBloomFilter* o = static_cast<const CountingBloomFilter*>(other);

    if ( ! hasher->Equals(o->hasher) ) {
        reporter->Error("incompatible hashers in CountingBloomFilter merge");
        return false;
    }

    else if ( cells->Size() != o->cells->Size() ) {
        reporter->Error("different bitvector size in CountingBloomFilter merge");
        return false;
    }

    (*cells) |= *o->cells;

    return true;
}

BasicBloomFilter* CountingBloomFilter::Intersect(const BloomFilter* other) const {
    if ( typeid(*this) != typeid(*other) )
        return nullptr;

    const CountingBloomFilter* o = static_cast<const CountingBloomFilter*>(other);

    if ( ! hasher->Equals(o->hasher) ) {
        reporter->Error("incompatible hashers in CountingBloomFilter merge");
        return nullptr;
    }

    else if ( cells->Size() != o->cells->Size() ) {
        reporter->Error("different bitvector size in CountingBloomFilter merge");
        return nullptr;
    }

    auto outbf = new BasicBloomFilter(hasher->Clone(), cells->Size());
    *outbf->bits |= cells->ToBitVector();
    *outbf->bits &= o->cells->ToBitVector();

    return outbf;
}

CountingBloomFilter* CountingBloomFilter::Clone() const {
    CountingBloomFilter* copy = new CountingBloomFilter();

    copy->hasher = hasher->Clone();
    copy->cells = new detail::CounterVector(*cells);

    return copy;
}

std::string CountingBloomFilter::InternalState() const { return util::fmt("%" PRIu64, cells->Hash()); }

// TODO: Use partitioning in add/count to allow for reusing CMS bounds.
void CountingBloomFilter::Add(const zeek::detail::HashKey* key) {
    detail::Hasher::digest_vector h = hasher->Hash(key);

    for ( unsigned long long i : h )
        cells->Increment(i % cells->Size());
}

bool CountingBloomFilter::Decrement(const zeek::detail::HashKey* key) {
    // Only decrement if a member.
    if ( Count(key) == 0 )
        return false;

    detail::Hasher::digest_vector h = hasher->Hash(key);

    for ( unsigned long long i : h )
        cells->Decrement(i % cells->Size());

    return true;
}

size_t CountingBloomFilter::Count(const zeek::detail::HashKey* key) const {
    detail::Hasher::digest_vector h = hasher->Hash(key);

    detail::CounterVector::size_type min = std::numeric_limits<detail::CounterVector::size_type>::max();

    for ( unsigned long long i : h ) {
        detail::CounterVector::size_type cnt = cells->Count(i % cells->Size());
        if ( cnt < min )
            min = cnt;
    }

    return min;
}

std::optional<BrokerData> CountingBloomFilter::DoSerializeData() const { return cells->Serialize(); }

bool CountingBloomFilter::DoUnserializeData(BrokerDataView data) {
    auto c = detail::CounterVector::Unserialize(data);
    if ( ! c )
        return false;

    cells = c.release();
    return true;
}

} // namespace zeek::probabilistic
