// See the file "COPYING" in the main distribution directory for copyright.

#include <typeinfo>
#include <openssl/md5.h>

#include "Hasher.h"
#include "NetVar.h"
#include "Serializer.h"
#include "digest.h"
#include "siphash24.h"

using namespace probabilistic;

Hasher::seed_t Hasher::MakeSeed(const void* data, size_t size)
	{
	u_char buf[SHA256_DIGEST_LENGTH];
	seed_t tmpseed;
	SHA256_CTX ctx;
	sha256_init(&ctx);

	assert(sizeof(tmpseed) == 16);

	if ( data )
		sha256_update(&ctx, data, size);

	else if ( global_hash_seed && global_hash_seed->Len() > 0 )
		sha256_update(&ctx, global_hash_seed->Bytes(), global_hash_seed->Len());

	else
		{
		unsigned int first_seed = initial_seed();
		sha256_update(&ctx, &first_seed, sizeof(first_seed));
		}

	sha256_final(&ctx, buf);
	memcpy(&tmpseed, buf, sizeof(tmpseed)); // Use the first bytes as seed.
	return tmpseed;
	}

Hasher::digest_vector Hasher::Hash(const HashKey* key) const
	{
	return Hash(key->Key(), key->Size());
	}

bool Hasher::Serialize(SerialInfo* info) const
	{
	return SerialObj::Serialize(info);
	}

Hasher* Hasher::Unserialize(UnserialInfo* info)
	{
	return reinterpret_cast<Hasher*>(SerialObj::Unserialize(info, SER_HASHER));
	}

bool Hasher::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_HASHER, SerialObj);

	if ( ! SERIALIZE(static_cast<uint16>(k)) )
		return false;

	if ( ! SERIALIZE(static_cast<uint64>(seed.h1)) )
		return false;

	return SERIALIZE(static_cast<uint64>(seed.h2));
	}

bool Hasher::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(SerialObj);

	uint16 serial_k;
	if ( ! UNSERIALIZE(&serial_k) )
		return false;

	k = serial_k;
	assert(k > 0);

	seed_t serial_seed;
	if ( ! UNSERIALIZE(&serial_seed.h1) )
		return false;

	if ( ! UNSERIALIZE(&serial_seed.h2) )
		return false;

	seed = serial_seed;

	return true;
	}

Hasher::Hasher(size_t arg_k, seed_t arg_seed)
	{
	k = arg_k;
	seed = arg_seed;
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
	assert(sizeof(Hasher::seed_t) == SIPHASH_KEYLEN);

	if ( n <= UHASH_KEY_SIZE )
		{
		hash_t outdigest;
		siphash(&outdigest, reinterpret_cast<const uint8_t*>(x), n, reinterpret_cast<const uint8_t*>(&seed));
		return outdigest;
		}

	unsigned char d[16];
	MD5(reinterpret_cast<const unsigned char*>(x), n, d);

	const unsigned char* s = reinterpret_cast<const unsigned char*>(&seed);
	for ( size_t i = 0; i < 16; ++i )
		d[i] ^= s[i % sizeof(seed)];

	MD5(d, 16, d);

	return *reinterpret_cast<const Hasher::digest*>(d);
	}

DefaultHasher::DefaultHasher(size_t k, Hasher::seed_t seed)
	: Hasher(k, seed)
	{
	for ( size_t i = 1; i <= k; ++i )
		{
		seed_t s = Seed();
		s.h1 += bro_prng(i);
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

IMPLEMENT_SERIAL(DefaultHasher, SER_DEFAULTHASHER)

bool DefaultHasher::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_DEFAULTHASHER, Hasher);

	// Nothing to do here, the base class has all we need serialized already.
	return true;
	}

bool DefaultHasher::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Hasher);

	hash_functions.clear();
	for ( size_t i = 0; i < K(); ++i )
		{
		Hasher::seed_t s = Seed();
		s.h1 += bro_prng(i);
		hash_functions.push_back(UHF(s));
		}

	return true;
	}

DoubleHasher::DoubleHasher(size_t k, seed_t seed)
	: Hasher(k, seed), h1(seed + bro_prng(1)), h2(seed + bro_prng(2))
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

IMPLEMENT_SERIAL(DoubleHasher, SER_DOUBLEHASHER)

bool DoubleHasher::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_DOUBLEHASHER, Hasher);

	// Nothing to do here, the base class has all we need serialized already.
	return true;
	}

bool DoubleHasher::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Hasher);

	h1 = UHF(Seed() + bro_prng(1));
	h2 = UHF(Seed() + bro_prng(2));

	return true;
	}
