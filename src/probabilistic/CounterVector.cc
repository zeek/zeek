// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/probabilistic/CounterVector.h"

#include <cassert>
#include <limits>
#include <memory>

#include "zeek/broker/Data.h"
#include "zeek/probabilistic/BitVector.h"

namespace zeek::probabilistic::detail {

CounterVector::CounterVector(size_t arg_width, size_t cells) {
    bits = new BitVector(arg_width * cells);
    width = arg_width;
}

CounterVector::CounterVector(const CounterVector& other) {
    bits = new BitVector(*other.bits);
    width = other.width;
}

CounterVector::~CounterVector() { delete bits; }

bool CounterVector::Increment(size_type cell, count_type value) {
    assert(cell < Size());
    assert(value != 0);

    size_t lsb = cell * width;
    bool carry = false;

    for ( size_t i = 0; i < width; ++i ) {
        bool b1 = (*bits)[lsb + i];
        bool b2 = value & (1 << i);
        (*bits)[lsb + i] = b1 ^ b2 ^ carry;
        carry = (b1 && b2) || (carry && (b1 != b2));
    }

    if ( carry ) {
        for ( size_t i = 0; i < width; ++i )
            bits->Set(lsb + i);
    }

    return ! carry;
}

bool CounterVector::Decrement(size_type cell, count_type value) {
    assert(cell < Size());
    assert(value != 0);

    value = ~value + 1; // A - B := A + ~B + 1
    bool carry = false;
    size_t lsb = cell * width;

    for ( size_t i = 0; i < width; ++i ) {
        bool b1 = (*bits)[lsb + i];
        bool b2 = value & (1 << i);
        (*bits)[lsb + i] = b1 ^ b2 ^ carry;
        carry = (b1 && b2) || (carry && (b1 != b2));
    }

    return carry;
}

bool CounterVector::AllZero() const { return bits->AllZero(); }

void CounterVector::Reset() { bits->Reset(); }

CounterVector::count_type CounterVector::Count(size_type cell) const {
    assert(cell < Size());

    size_t cnt = 0, order = 1;
    size_t lsb = cell * width;

    for ( size_t i = lsb; i < lsb + width; ++i, order <<= 1 )
        if ( (*bits)[i] )
            cnt |= order;

    return cnt;
}

CounterVector::size_type CounterVector::Size() const { return bits->Size() / width; }

size_t CounterVector::Width() const { return width; }

size_t CounterVector::Max() const {
    return std::numeric_limits<size_t>::max() >> (std::numeric_limits<size_t>::digits - width);
}

CounterVector& CounterVector::Merge(const CounterVector& other) {
    assert(Size() == other.Size());
    assert(Width() == other.Width());

    for ( size_t cell = 0; cell < Size(); ++cell ) {
        size_t lsb = cell * width;
        bool carry = false;

        for ( size_t i = 0; i < width; ++i ) {
            bool b1 = (*bits)[lsb + i];
            bool b2 = (*other.bits)[lsb + i];
            (*bits)[lsb + i] = b1 ^ b2 ^ carry;
            carry = (b1 && b2) || (carry && (b1 != b2));
        }

        if ( carry ) {
            for ( size_t i = 0; i < width; ++i )
                bits->Set(lsb + i);
        }
    }

    return *this;
}

BitVector CounterVector::ToBitVector() const {
    auto newbits = BitVector(Size());

    for ( size_t cell = 0; cell < Size(); ++cell ) {
        size_t lsb = cell * width;
        bool set = false;

        for ( size_t i = 0; i < width; ++i )
            set |= (*bits)[lsb + 1];

        newbits[cell] = set;
    }

    return newbits;
}

CounterVector& CounterVector::operator|=(const CounterVector& other) { return Merge(other); }

CounterVector operator|(const CounterVector& x, const CounterVector& y) {
    CounterVector cv(x);
    return cv |= y;
}

uint64_t CounterVector::Hash() const { return bits->Hash(); }

std::optional<BrokerData> CounterVector::Serialize() const {
    auto b = bits->Serialize();
    if ( ! b )
        return std::nullopt; // Cannot serialize

    BrokerListBuilder builder;
    builder.Reserve(2);
    builder.AddCount(width);
    builder.Add(std::move(*b));
    return std::move(builder).Build();
}

std::unique_ptr<CounterVector> CounterVector::Unserialize(BrokerDataView data) {
    if ( ! data.IsList() )
        return nullptr;

    auto v = data.ToList();
    if ( v.Size() < 2 || ! v[0].IsCount() )
        return nullptr;

    auto width = v[0].ToCount();
    auto bits = BitVector::Unserialize(v[1]);

    if ( ! bits )
        return nullptr;

    auto cv = std::unique_ptr<CounterVector>{new CounterVector};
    cv->width = width;
    cv->bits = bits.release();
    return cv;
}

} // namespace zeek::probabilistic::detail
