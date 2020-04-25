// See the file "COPYING" in the main distribution directory for copyright.

/***
 * This file contains functions to generate hashes used keyed hash functions.
 * Keyed hash functions make it difficult/impossible to find information about the
 * output of a hash when the key is unknown to the attacker. This fact holds, even
 * when the input value us known.
 *
 * We use these kinds of hashes heavily internally - e.g. for scriptland hash generation.
 * It is important that these hashes are not easily guessable to prevent complexity attacks.
 *
 * The HashKey class is the actual class that is used to generate Hash keys that are used internally,
 * e.g. for lookups in hash-tables; the Hashes are also used for connection ID generation.
 *
 * This means that the hashes created by most functions in this file will be different each run, unless
 * a seed file is used. There are a few functions that create hashes that are static over runs
 * and use an installation-wide seed value; these are specifically called out.
 */

#pragma once

#include "util.h" // for bro_int_t

#include <stdlib.h>

class BroString;

// to allow bro_md5_hmac access to the hmac seed
#include "ZeekArgs.h"
class Val;
class Frame;
namespace BifFunc {
	extern Val* bro_md5_hmac(Frame* frame, const zeek::Args*);
}

typedef uint64_t hash_t;
typedef uint64_t hash64_t;
typedef uint64_t hash128_t[2];
typedef uint64_t hash256_t[4];

class KeyedHash {
public:
	constexpr static int SEED_INIT_SIZE = 20;
	static void InitializeSeeds(const std::array<uint32_t, SEED_INIT_SIZE>& seed_data);
	static bool IsInitialized() { return seeds_initialized; }

	static hash64_t Hash64(const void* bytes, uint64_t size);
	static void Hash128(const void* bytes, uint64_t size, hash128_t* result);
	static void Hash256(const void* bytes, uint64_t size, hash256_t* result);

	static hash64_t StaticHash64(const void* bytes, uint64_t size);
	static void StaticHash128(const void* bytes, uint64_t size, hash128_t* result);
	static void StaticHash256(const void* bytes, uint64_t size, hash256_t* result);
private:
	// actually HHKey
	alignas(32) inline static uint64_t shared_highwayhash_key[4];
	// actually HH_U64, which has the same type
	alignas(16) inline static unsigned long long shared_siphash_key[2];
	inline static uint8_t shared_hmac_md5_key[16];
	inline static bool seeds_initialized = false;

	friend void hmac_md5(size_t size, const unsigned char* bytes, unsigned char digest[16]);
	friend Val* BifFunc::bro_md5_hmac(Frame* frame, const zeek::Args*);
};

typedef enum {
	HASH_KEY_INT,
	HASH_KEY_DOUBLE,
	HASH_KEY_STRING
#define NUM_HASH_KEYS (int(HASH_KEY_STRING) + 1)
} HashKeyTag;

class HashKey {
public:
	explicit HashKey(bro_int_t i);
	explicit HashKey(bro_uint_t u);
	explicit HashKey(uint32_t u);
	HashKey(const uint32_t u[], int n);
	explicit HashKey(double d);
	explicit HashKey(const void* p);
	explicit HashKey(const char* s);
	explicit HashKey(const BroString* s);
	~HashKey()
		{
		if ( is_our_dynamic )
			delete [] (char *) key;
		}

	// Create a HashKey given all of its components.  "key" is assumed
	// to be dynamically allocated and to now belong to this HashKey
	// (to delete upon destruct'ing).  If "copy_key" is true, it's
	// first copied.
	//
	// The calling sequence here is unusual (normally key would be
	// first) to avoid possible ambiguities with the next constructor,
	// which is the more commonly used one.
	HashKey(int copy_key, void* key, int size);

	// Same, but automatically copies the key.
	HashKey(const void* key, int size, hash_t hash);

	// Builds a key from the given chunk of bytes.
	HashKey(const void* bytes, int size);

	// Create a Hashkey given all of its components *without*
	// copying the key and *without* taking ownership.  Note that
	// "dont_copy" is a type placeholder to differentiate this member
	// function from the one above; its value is not used.
	HashKey(const void* key, int size, hash_t hash, bool dont_copy);

	// Hands over the key to the caller.  This means that if the
	// key is our dynamic, we give it to the caller and mark it
	// as not our dynamic.  If initially it's not our dynamic,
	// we give them a copy of it.
	void* TakeKey();

	const void* Key() const	{ return key; }
	int Size() const	{ return size; }
	hash_t Hash() const	{ return hash; }

	unsigned int MemoryAllocation() const	{ return padded_sizeof(*this) + pad_size(size); }

	static hash_t HashBytes(const void* bytes, int size);
protected:
	void* CopyKey(const void* key, int size) const;

	union {
		bro_int_t i;
		uint32_t u32;
		double d;
		const void* p;
	} key_u;

	void* key;
	hash_t hash;
	int size;
	bool is_our_dynamic = false;
};

extern void init_hash_function();
