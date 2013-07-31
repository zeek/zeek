// See the file "COPYING" in the main distribution directory for copyright.

#include <typeinfo>

#include "Hasher.h"
#include "digest.h"
#include "Serializer.h"

using namespace probabilistic;

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

	return SERIALIZE_STR(name.c_str(), name.size());
	}

bool Hasher::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(SerialObj);

	uint16 serial_k;
	if ( ! UNSERIALIZE(&serial_k) )
		return false;

	k = serial_k;
	assert(k > 0);

	const char* serial_name;
	if ( ! UNSERIALIZE_STR(&serial_name, 0) )
		return false;

	name = serial_name;
	delete [] serial_name;

	return true;
	}

Hasher::Hasher(size_t k, const std::string& arg_name)
	: k(k)
	{
	k = k;
	name = arg_name;
	}


UHF::UHF(size_t seed, const std::string& extra)
	: h(compute_seed(seed, extra))
	{
	}

Hasher::digest UHF::hash(const void* x, size_t n) const
	{
	assert(n <= UHASH_KEY_SIZE);
	return n == 0 ? 0 : h(x, n);
	}

size_t UHF::compute_seed(size_t seed, const std::string& extra)
	{
	u_char buf[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;
	sha256_init(&ctx);

	if ( extra.empty() )
		{
		unsigned int first_seed = initial_seed();
		sha256_update(&ctx, &first_seed, sizeof(first_seed));
		}

	else
		sha256_update(&ctx, extra.c_str(), extra.size());

	sha256_update(&ctx, &seed, sizeof(seed));
	sha256_final(&ctx, buf);

	// Take the first sizeof(size_t) bytes as seed.
	return *reinterpret_cast<size_t*>(buf);
	}

DefaultHasher::DefaultHasher(size_t k, const std::string& name)
	: Hasher(k, name)
	{
	for ( size_t i = 0; i < k; ++i )
		hash_functions.push_back(UHF(i, name));
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
		hash_functions.push_back(UHF(i, Name()));

	return true;
	}

DoubleHasher::DoubleHasher(size_t k, const std::string& name)
	: Hasher(k, name), h1(1, name), h2(2, name)
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

	h1 = UHF(1, Name());
	h2 = UHF(2, Name());

	return true;
	}
