// See the file "COPYING" in the main distribution directory for copyright.

/***
 * This file contains functions to generate hashes used keyed hash functions.
 * Keyed hash functions make it difficult/impossible to find information about the
 * output of a hash when the key is unknown to the attacker. This fact holds, even
 * when the input value is known.
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

#include <stdlib.h>

#include "zeek/util.h" // for bro_int_t

// to allow bro_md5_hmac access to the hmac seed
#include "zeek/ZeekArgs.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(Frame, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(BifReturnVal, zeek::detail);

namespace zeek { class String; }

namespace zeek::BifFunc {
	extern zeek::detail::BifReturnVal md5_hmac_bif(zeek::detail::Frame* frame, const zeek::Args*);
}

namespace zeek::detail {

typedef uint64_t hash_t;
typedef uint64_t hash64_t;
typedef uint64_t hash128_t[2];
typedef uint64_t hash256_t[4];

class KeyedHash {
public:
	/**
	 * Generate a 64 bit digest hash.
	 *
	 * This hash is seeded with random data, unless the ZEEK_SEED_FILE environment
	 * variable is set. Thus, typically every node will return a different hash
	 * after every restart.
	 *
	 * This should be used for internal hashes that do not have to be stable over
	 * the cluster/runs - like, e.g. connection ID generation.
	 *
	 * @param bytes Bytes to hash
	 *
	 * @param size Size of bytes
	 *
	 * @returns 64 bit digest hash
	 */
	static hash64_t Hash64(const void* bytes, uint64_t size);

	/**
	 * Generate a 128 bit digest hash.
	 *
	 * This hash is seeded with random data, unless the ZEEK_SEED_FILE environment
	 * variable is set. Thus, typically every node will return a different hash
	 * after every restart.
	 *
	 * This should be used for internal hashes that do not have to be stable over
	 * the cluster/runs - like, e.g. connection ID generation.
	 *
	 * @param bytes Bytes to hash
	 *
	 * @param size Size of bytes
	 *
	 * @param result Result of the hashing operation.
	 */
	static void Hash128(const void* bytes, uint64_t size, hash128_t* result);

	/**
	 * Generate a 256 bit digest hash.
	 *
	 * This hash is seeded with random data, unless the ZEEK_SEED_FILE environment
	 * variable is set. Thus, typically every node will return a different hash
	 * after every restart.
	 *
	 * This should be used for internal hashes that do not have to be stable over
	 * the cluster/runs - like, e.g. connection ID generation.
	 *
	 * @param bytes Bytes to hash
	 *
	 * @param size Size of bytes
	 *
	 * @param result Result of the hashing operation.
	 */
	static void Hash256(const void* bytes, uint64_t size, hash256_t* result);

	/**
	 * Generates a installation-specific 64 bit hash.
	 *
	 * This function generates a 64 bit digest hash, which is stable over a cluster
	 * or a restart.
	 *
	 * To be more exact - the seed value for this hash is generated from the script-level
	 * :zeek:see:`digest_salt` constant. The seeds are stable as long as this value
	 * is not changed.
	 *
	 * This should be used for hashes that have to remain stable over the entire
	 * cluster. An example are file IDs, which have to be stable over several workers.
	 *
	 * @param bytes Bytes to hash
	 *
	 * @param size Size of bytes
	 *
	 * @returns 64 bit digest hash
	 */
	static hash64_t StaticHash64(const void* bytes, uint64_t size);

	/**
	 * Generates a installation-specific 128 bit hash.
	 *
	 * This function generates a 128 bit digest hash, which is stable over a cluster
	 * or a restart.
	 *
	 * To be more exact - the seed value for this hash is generated from the script-level
	 * :zeek:see:`digest_salt` constant. The seeds are stable as long as this value
	 * is not changed.
	 *
	 * This should be used for hashes that have to remain stable over the entire
	 * cluster. An example are file IDs, which have to be stable over several workers.
	 *
	 * @param bytes Bytes to hash
	 *
	 * @param size Size of bytes
	 *
	 * @param result Result of the hashing operation.
	 */
	static void StaticHash128(const void* bytes, uint64_t size, hash128_t* result);

	/**
	 * Generates a installation-specific 256 bit hash.
	 *
	 * This function generates a 128 bit digest hash, which is stable over a cluster
	 * or a restart.
	 *
	 * To be more exact - the seed value for this hash is generated from the script-level
	 * :zeek:see:`digest_salt` constant. The seeds are stable as long as this value
	 * is not changed.
	 *
	 * This should be used for hashes that have to remain stable over the entire
	 * cluster. An example are file IDs, which have to be stable over several workers.
	 *
	 * @param bytes Bytes to hash
	 *
	 * @param size Size of bytes
	 *
	 * @param result Result of the hashing operation.
	 */
	static void StaticHash256(const void* bytes, uint64_t size, hash256_t* result);

	/**
	 * Size of the initial seed
	 */
	constexpr static int SEED_INIT_SIZE = 20;

	/**
	 * Initialize the (typically process-specific) seeds. This function is indirectly
	 * called from main, during early initialization.
	 *
	 * @param seed_data random data used as an initial seed
	 */
	static void InitializeSeeds(const std::array<uint32_t, SEED_INIT_SIZE>& seed_data);

	/**
	 * Returns true if the process-specific seeds have been initialized
	 *
	 * @return True if the seeds are initialized
	 */
	static bool IsInitialized() { return seeds_initialized; }

	/**
	 * Initializes the static hash seeds using the script-level
	 * :zeek:see:`digest_salt` constant.
	 */
	static void InitOptions();

private:
	// actually HHKey. This key changes each start (unless a seed is specified)
	alignas(32) static uint64_t shared_highwayhash_key[4];
	// actually HHKey. This key is installation specific and sourced from the digest_salt script-level const.
	alignas(32) static uint64_t cluster_highwayhash_key[4];
	// actually HH_U64, which has the same type. This key changes each start (unless a seed is specified)
	alignas(16) static unsigned long long shared_siphash_key[2];
	// This key changes each start (unless a seed is specified)
	inline static uint8_t shared_hmac_md5_key[16];
	inline static bool seeds_initialized = false;

	friend void util::detail::hmac_md5(size_t size, const unsigned char* bytes, unsigned char digest[16]);
	friend BifReturnVal BifFunc::md5_hmac_bif(zeek::detail::Frame* frame, const Args*);
};

typedef enum {
	HASH_KEY_INT,
	HASH_KEY_DOUBLE,
	HASH_KEY_STRING
} HashKeyTag;

constexpr int NUM_HASH_KEYS = HASH_KEY_STRING + 1;

class HashKey {
public:
	explicit HashKey(bro_int_t i);
	explicit HashKey(bro_uint_t u);
	explicit HashKey(uint32_t u);
	HashKey(const uint32_t u[], int n);
	explicit HashKey(double d);
	explicit HashKey(const void* p);
	explicit HashKey(const char* s);
	explicit HashKey(const String* s);
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

	unsigned int MemoryAllocation() const	{ return padded_sizeof(*this) + util::pad_size(size); }

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

} // namespace zeek::detail
