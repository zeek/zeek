// See the file "COPYING" in the main distribution directory for copyright.

#include "Hasher.h"

#include <typeinfo>

#include <openssl/evp.h>

#include "NetVar.h"
#include "Var.h"
#include "digest.h"
#include "highwayhash/sip_hash.h"

#include <broker/data.hh>

namespace zeek::probabilistic::detail {

Hasher::seed_t Hasher::MakeSeed(const void* data, size_t size)
	{
	u_char buf[SHA256_DIGEST_LENGTH];
	seed_t tmpseed;
	EVP_MD_CTX* ctx = zeek::detail::hash_init(zeek::detail::Hash_SHA256);

	assert(sizeof(tmpseed) == 16);

	static auto global_hash_seed = zeek::id::find_val<zeek::StringVal>("global_hash_seed");

	if ( data )
		zeek::detail::hash_update(ctx, data, size);

	else if ( global_hash_seed->Len() > 0 )
		zeek::detail::hash_update(ctx, global_hash_seed->Bytes(), global_hash_seed->Len());

	else
		{
		unsigned int first_seed = zeek::util::initial_seed();
		zeek::detail::hash_update(ctx, &first_seed, sizeof(first_seed));
		}

	zeek::detail::hash_final(ctx, buf);
	memcpy(&tmpseed, buf, sizeof(tmpseed)); // Use the first bytes as seed.
	return tmpseed;
	}

Hasher::digest_vector Hasher::Hash(const zeek::detail::HashKey* key) const
	{
	return Hash(key->Key(), key->Size());
	}

Hasher::Hasher(size_t arg_k, seed_t arg_seed)
	{
	k = arg_k;
	seed = arg_seed;
	}

broker::expected<broker::data> Hasher::Serialize() const
	{
	return {broker::vector{
		static_cast<uint64_t>(Type()), static_cast<uint64_t>(k),
		seed.h[0], seed.h[1] }};
	}

std::unique_ptr<Hasher> Hasher::Unserialize(const broker::data& data)
	{
	auto v = caf::get_if<broker::vector>(&data);

	if ( ! (v && v->size() == 4) )
		return nullptr;

	auto type = caf::get_if<uint64_t>(&(*v)[0]);
	auto k = caf::get_if<uint64_t>(&(*v)[1]);
	auto h1 = caf::get_if<uint64_t>(&(*v)[2]);
	auto h2 = caf::get_if<uint64_t>(&(*v)[3]);

	if ( ! (type && k && h1 && h2) )
		return nullptr;

	std::unique_ptr<Hasher> hasher;

	switch ( *type ) {
	case Default:
		hasher = std::unique_ptr<Hasher>(new DefaultHasher(*k, {*h1, *h2}));
		break;

	case Double:
		hasher = std::unique_ptr<Hasher>(new DoubleHasher(*k, {*h1, *h2}));
		break;
	}

	// Note that the derived classed don't hold any further state of
	// their own. They reconstruct all their information from their
	// constructors' arguments.

	return hasher;
	}

UHF::UHF()
	{
	memset(&seed, 0, sizeof(seed));
	}

UHF::UHF(Hasher::seed_t arg_seed)
	{
	seed = arg_seed;
	}

// This function is almost equivalent to HashKey::HashBytes except that it
// does not depend on global state and that we mix in the seed multiple
// times.
Hasher::digest UHF::hash(const void* x, size_t n) const
	{
	static_assert(std::is_same<highwayhash::SipHashState::Key, decltype(seed.h)>::value, "Seed value is not the same type as highwayhash key");
	return highwayhash::SipHash(seed.h, reinterpret_cast<const char*>(x), n);
	}

DefaultHasher::DefaultHasher(size_t k, Hasher::seed_t seed)
	: Hasher(k, seed)
	{
	for ( size_t i = 1; i <= k; ++i )
		{
		seed_t s = Seed();
		s.h[0] += zeek::util::prng(i);
		hash_functions.push_back(UHF(s));
		}
	}

Hasher::digest_vector DefaultHasher::Hash(const void* x, size_t n) const
	{
	digest_vector h(K(), 0);

	for ( size_t i = 0; i < h.size(); ++i )
		h[i] = hash_functions[i](x, n);

	return h;
	}

DefaultHasher* DefaultHasher::Clone() const
	{
	return new DefaultHasher(*this);
	}

bool DefaultHasher::Equals(const Hasher* other) const
	{
	if ( typeid(*this) != typeid(*other) )
		return false;

	const DefaultHasher* o = static_cast<const DefaultHasher*>(other);
	return hash_functions == o->hash_functions;
	}

DoubleHasher::DoubleHasher(size_t k, seed_t seed)
	: Hasher(k, seed), h1(seed + zeek::util::prng(1)), h2(seed + zeek::util::prng(2))
	{
	}

Hasher::digest_vector DoubleHasher::Hash(const void* x, size_t n) const
	{
	digest d1 = h1(x, n);
	digest d2 = h2(x, n);
	digest_vector h(K(), 0);

	for ( size_t i = 0; i < h.size(); ++i )
		h[i] = d1 + i * d2;

	return h;
	}

DoubleHasher* DoubleHasher::Clone() const
	{
	return new DoubleHasher(*this);
	}

bool DoubleHasher::Equals(const Hasher* other) const
	{
	if ( typeid(*this) != typeid(*other) )
		return false;

	const DoubleHasher* o = static_cast<const DoubleHasher*>(other);
	return h1 == o->h1 && h2 == o->h2;
	}

} // namespace zeek::probabilistic::detail
