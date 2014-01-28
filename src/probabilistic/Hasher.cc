// See the file "COPYING" in the main distribution directory for copyright.

#include <typeinfo>
#include <openssl/md5.h>

#include "Hasher.h"
#include "NetVar.h"
#include "digest.h"
#include "Serializer.h"

using namespace probabilistic;

uint64 Hasher::MakeSeed(const void* data, size_t size)
	{
	u_char buf[SHA256_DIGEST_LENGTH];
	uint64 tmpseed;
	SHA256_CTX ctx;
	sha256_init(&ctx);

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

	return SERIALIZE(static_cast<uint64>(seed));
	}

bool Hasher::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(SerialObj);

	uint16 serial_k;
	if ( ! UNSERIALIZE(&serial_k) )
		return false;

	k = serial_k;
	assert(k > 0);

	uint64 serial_seed;
	if ( ! UNSERIALIZE(&serial_seed) )
		return false;

	seed = serial_seed;

	return true;
	}

Hasher::Hasher(size_t arg_k, size_t arg_seed)
	{
	k = arg_k;
	seed = arg_seed;
	}

UHF::UHF(size_t arg_seed)
	: h(arg_seed)
	{
	seed = arg_seed;
	}

// This function is almost equivalent to HashKey::HashBytes except that it
// does not depend on global state and that we mix in the seed multiple
// times.
Hasher::digest UHF::hash(const void* x, size_t n) const
	{
	if ( n <= UHASH_KEY_SIZE )
		return n == 0 ? 0 : h(x, n);

	unsigned char d[16];
	MD5(reinterpret_cast<const unsigned char*>(x), n, d);

	const unsigned char* s = reinterpret_cast<const unsigned char*>(&seed);
	for ( size_t i = 0; i < 16; ++i )
		d[i] ^= s[i % sizeof(seed)];

	MD5(d, 16, d);

	return d[0];
	}

DefaultHasher::DefaultHasher(size_t k, size_t seed)
	: Hasher(k, seed)
	{
	for ( size_t i = 1; i <= k; ++i )
		hash_functions.push_back(UHF(Seed() + bro_prng(i)));
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
		hash_functions.push_back(UHF(Seed() + bro_prng(i)));

	return true;
	}

DoubleHasher::DoubleHasher(size_t k, size_t seed)
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
