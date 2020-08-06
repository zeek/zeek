// See the file "COPYING" in the main distribution directory for copyright.

#include "BloomFilter.h"

#include <cmath>
#include <limits>

#include <broker/data.hh>
#include <broker/error.hh>

#include "CounterVector.h"

#include "../util.h"
#include "../Reporter.h"

namespace zeek::probabilistic {

BloomFilter::BloomFilter()
	{
	hasher = nullptr;
	}

BloomFilter::BloomFilter(const detail::Hasher* arg_hasher)
	{
	hasher = arg_hasher;
	}

BloomFilter::~BloomFilter()
	{
	delete hasher;
	}

broker::expected<broker::data> BloomFilter::Serialize() const
	{
	auto h = hasher->Serialize();

	if ( ! h )
		return broker::ec::invalid_data; // Cannot serialize

	auto d = DoSerialize();

	if ( ! d )
		return broker::ec::invalid_data; // Cannot serialize

	return {broker::vector{static_cast<uint64_t>(Type()), std::move(*h), std::move(*d)}};
	}

std::unique_ptr<BloomFilter> BloomFilter::Unserialize(const broker::data& data)
	{
	auto v = caf::get_if<broker::vector>(&data);

	if ( ! (v && v->size() == 3) )
		return nullptr;

	auto type = caf::get_if<uint64_t>(&(*v)[0]);
	if ( ! type )
		return nullptr;

	auto hasher_ = detail::Hasher::Unserialize((*v)[1]);
	if ( ! hasher_ )
		return nullptr;

	std::unique_ptr<BloomFilter> bf;

	switch ( *type ) {
	case Basic:
		bf = std::unique_ptr<BloomFilter>(new BasicBloomFilter());
		break;

	case Counting:
		bf = std::unique_ptr<BloomFilter>(new CountingBloomFilter());
		break;
	}

	if ( ! bf->DoUnserialize((*v)[2]) )
		return nullptr;

	bf->hasher = hasher_.release();
	return bf;
	}

size_t BasicBloomFilter::M(double fp, size_t capacity)
	{
	double ln2 = std::log(2);
	return std::ceil(-(capacity * std::log(fp) / ln2 / ln2));
	}

size_t BasicBloomFilter::K(size_t cells, size_t capacity)
	{
	double frac = static_cast<double>(cells) / static_cast<double>(capacity);
	return std::ceil(frac * std::log(2));
	}

bool BasicBloomFilter::Empty() const
	{
	return bits->AllZero();
	}

void BasicBloomFilter::Clear()
	{
	bits->Reset();
	}

bool BasicBloomFilter::Merge(const BloomFilter* other)
	{
	if ( typeid(*this) != typeid(*other) )
		return false;

	const BasicBloomFilter* o = static_cast<const BasicBloomFilter*>(other);

	if ( ! hasher->Equals(o->hasher) )
		{
		zeek::reporter->Error("incompatible hashers in BasicBloomFilter merge");
		return false;
		}

	else if ( bits->Size() != o->bits->Size() )
		{
		zeek::reporter->Error("different bitvector size in BasicBloomFilter merge");
		return false;
		}

	(*bits) |= *o->bits;

	return true;
	}

BasicBloomFilter* BasicBloomFilter::Clone() const
	{
	BasicBloomFilter* copy = new BasicBloomFilter();

	copy->hasher = hasher->Clone();
	copy->bits = new detail::BitVector(*bits);

	return copy;
	}

std::string BasicBloomFilter::InternalState() const
	{
	return zeek::util::fmt("%" PRIu64, bits->Hash());
	}

BasicBloomFilter::BasicBloomFilter()
	{
	bits = nullptr;
	}

BasicBloomFilter::BasicBloomFilter(const detail::Hasher* hasher, size_t cells)
	: BloomFilter(hasher)
	{
	bits = new detail::BitVector(cells);
	}

BasicBloomFilter::~BasicBloomFilter()
	{
	delete bits;
	}

void BasicBloomFilter::Add(const zeek::detail::HashKey* key)
	{
	detail::Hasher::digest_vector h = hasher->Hash(key);

	for ( size_t i = 0; i < h.size(); ++i )
		bits->Set(h[i] % bits->Size());
	}

size_t BasicBloomFilter::Count(const zeek::detail::HashKey* key) const
	{
	detail::Hasher::digest_vector h = hasher->Hash(key);

	for ( size_t i = 0; i < h.size(); ++i )
		{
		if ( ! (*bits)[h[i] % bits->Size()] )
			return 0;
		}

	return 1;
	}

broker::expected<broker::data> BasicBloomFilter::DoSerialize() const
	{
	auto b = bits->Serialize();
	return b;
	}

bool BasicBloomFilter::DoUnserialize(const broker::data& data)
	{
	auto b = detail::BitVector::Unserialize(data);
	if ( ! b )
		return false;

	bits = b.release();
	return true;
	}

CountingBloomFilter::CountingBloomFilter()
	{
	cells = nullptr;
	}

CountingBloomFilter::CountingBloomFilter(const detail::Hasher* hasher,
                                         size_t arg_cells, size_t width)
	: BloomFilter(hasher)
	{
	cells = new detail::CounterVector(width, arg_cells);
	}

CountingBloomFilter::~CountingBloomFilter()
	{
	delete cells;
	}

bool CountingBloomFilter::Empty() const
	{
	return cells->AllZero();
	}

void CountingBloomFilter::Clear()
	{
	cells->Reset();
	}

bool CountingBloomFilter::Merge(const BloomFilter* other)
	{
	if ( typeid(*this) != typeid(*other) )
		return false;

	const CountingBloomFilter* o = static_cast<const CountingBloomFilter*>(other);

	if ( ! hasher->Equals(o->hasher) )
		{
		zeek::reporter->Error("incompatible hashers in CountingBloomFilter merge");
		return false;
		}

	else if ( cells->Size() != o->cells->Size() )
		{
		zeek::reporter->Error("different bitvector size in CountingBloomFilter merge");
		return false;
		}

	(*cells) |= *o->cells;

	return true;
	}

CountingBloomFilter* CountingBloomFilter::Clone() const
	{
	CountingBloomFilter* copy = new CountingBloomFilter();

	copy->hasher = hasher->Clone();
	copy->cells = new detail::CounterVector(*cells);

	return copy;
	}

std::string CountingBloomFilter::InternalState() const
	{
	return zeek::util::fmt("%" PRIu64, cells->Hash());
	}

// TODO: Use partitioning in add/count to allow for reusing CMS bounds.
void CountingBloomFilter::Add(const zeek::detail::HashKey* key)
	{
	detail::Hasher::digest_vector h = hasher->Hash(key);

	for ( size_t i = 0; i < h.size(); ++i )
		cells->Increment(h[i] % cells->Size());
	}

size_t CountingBloomFilter::Count(const zeek::detail::HashKey* key) const
	{
	detail::Hasher::digest_vector h = hasher->Hash(key);

	detail::CounterVector::size_type min =
		std::numeric_limits<detail::CounterVector::size_type>::max();

	for ( size_t i = 0; i < h.size(); ++i )
		{
		detail::CounterVector::size_type cnt = cells->Count(h[i] % cells->Size());
		if ( cnt  < min )
			min = cnt;
		}

	return min;
	}

broker::expected<broker::data> CountingBloomFilter::DoSerialize() const
	{
	auto c = cells->Serialize();
	return c;
	}

bool CountingBloomFilter::DoUnserialize(const broker::data& data)
	{
	auto c = detail::CounterVector::Unserialize(data);
	if ( ! c )
		return false;

	cells = c.release();
	return true;
	}

} // namespace zeek::probabilistic
