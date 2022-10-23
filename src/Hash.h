// See the file "COPYING" in the main distribution directory for copyright.

/***
 * This file contains functions to generate hashes using keyed hash functions.
 * Keyed hash functions make it difficult/impossible to find information about the
 * output of a hash when the key is unknown to the attacker. This fact holds, even
 * when the input value is known.
 *
 * We use these kinds of hashes heavily internally - e.g. for scriptland hash generation.
 * It is important that these hashes are not easily guessable to prevent complexity attacks.
 *
 * The HashKey class is the actual class that is used to generate Hash keys that are used
 * internally, e.g. for lookups in hash-tables and connection ID generation.
 *
 * This means that the hashes created by most functions in this file will be different each run,
 * unless a seed file is used. There are a few functions that create hashes that are static over
 * runs and use an installation-wide seed value; these are specifically called out.
 */

#pragma once

#include <cstdlib>

#include "zeek/util.h" // for zeek_int_t

// to allow md5_hmac_bif access to the hmac seed
#include "zeek/ZeekArgs.h"

namespace zeek
	{

class String;
class ODesc;

	}

namespace zeek::detail
	{

class Frame;
class BifReturnVal;

	}

namespace zeek::BifFunc
	{
extern zeek::detail::BifReturnVal md5_hmac_bif(zeek::detail::Frame* frame, const zeek::Args*);
	}

namespace zeek::detail
	{

using hash_t = uint64_t;
using hash64_t = uint64_t;
using hash128_t = uint64_t[2];
using hash256_t = uint64_t[4];

class KeyedHash
	{
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
	// actually HHKey. This key is installation specific and sourced from the digest_salt
	// script-level const.
	alignas(32) static uint64_t cluster_highwayhash_key[4];
	// actually HH_U64, which has the same type. This key changes each start (unless a seed is
	// specified)
	alignas(16) static unsigned long long shared_siphash_key[2];
	// This key changes each start (unless a seed is specified)
	inline static uint8_t shared_hmac_md5_key[16];
	inline static bool seeds_initialized = false;

	friend void util::detail::hmac_md5(size_t size, const unsigned char* bytes,
	                                   unsigned char digest[16]);
	friend BifReturnVal BifFunc::md5_hmac_bif(zeek::detail::Frame* frame, const Args*);
	};

enum HashKeyTag
	{
	HASH_KEY_INT,
	HASH_KEY_DOUBLE,
	HASH_KEY_STRING
	};

constexpr int NUM_HASH_KEYS = HASH_KEY_STRING + 1;

class HashKey
	{
public:
	explicit HashKey() { }
	explicit HashKey(bool b);
	explicit HashKey(int i);
	explicit HashKey(zeek_int_t bi);
	explicit HashKey(zeek_uint_t bu);
	explicit HashKey(uint32_t u);
	HashKey(const uint32_t u[], size_t n);
	explicit HashKey(double d);
	explicit HashKey(const void* p);
	explicit HashKey(const char* s); // No copying, no ownership
	explicit HashKey(const String* s); // No copying, no ownership

	// Builds a key from the given chunk of bytes. Copies the data.
	HashKey(const void* bytes, size_t size);

	// Create a HashKey given all of its components. Copies the key.
	HashKey(const void* key, size_t size, hash_t hash);

	// Create a Hashkey given all of its components *without*
	// copying the key and *without* taking ownership.  Note that
	// "dont_copy" is a type placeholder to differentiate this member
	// function from the one above; its value is not used.
	HashKey(const void* key, size_t size, hash_t hash, bool dont_copy);

	// Copy constructor. Always copies the key.
	HashKey(const HashKey& other);

	// Move constructor. Takes ownership of the key.
	HashKey(HashKey&& other) noexcept;

	// Destructor
	~HashKey();

	// Hands over the key to the caller.  This means that if the
	// key is our dynamic, we give it to the caller and mark it
	// as not our dynamic.  If initially it's not our dynamic,
	// we give them a copy of it.
	void* TakeKey();

	const void* Key() const { return key; }
	size_t Size() const { return size; }
	hash_t Hash() const;

	static hash_t HashBytes(const void* bytes, size_t size);

	// A HashKey is "allocated" when the underlying key points somewhere
	// other than our internal key_u union. This is almost like
	// is_our_dynamic, but remains true also after TakeKey().
	bool IsAllocated() const
		{
		return (key != nullptr && key != reinterpret_cast<const char*>(&key_u));
		}

	// Buffer size reservation. Repeated calls to these methods
	// incrementally build up the eventual buffer size to be allocated via
	// Allocate().
	template <typename T> void ReserveType(const char* tag) { Reserve(tag, sizeof(T), sizeof(T)); }
	void Reserve(const char* tag, size_t addl_size, size_t alignment = 0);

	// Allocates the reserved amount of memory
	void Allocate();

	// Incremental writes into an allocated HashKey. The tags give context
	// to what's being written and are only used in debug-build log streams.
	// When true, the alignment boolean will cause write-marker alignment to
	// the size of the item being written, otherwise writes happen directly
	// at the current marker.
	void Write(const char* tag, bool b);
	void Write(const char* tag, int i, bool align = true);
	void Write(const char* tag, zeek_int_t bi, bool align = true);
	void Write(const char* tag, zeek_uint_t bu, bool align = true);
	void Write(const char* tag, uint32_t u, bool align = true);
	void Write(const char* tag, double d, bool align = true);

	void Write(const char* tag, const void* bytes, size_t n, size_t alignment = 0);

	// For writes that copy directly into the allocated buffer, this method
	// advances the write marker without modifying content.
	void SkipWrite(const char* tag, size_t n);

	// Aligns the write marker to the next multiple of the given alignment size.
	void AlignWrite(size_t alignment);

	// Bounds check: if the buffer does not have at least n bytes available
	// to write into, triggers an InternalError.
	void EnsureWriteSpace(size_t n) const;

	// Reads don't modify our internal state except for the read offset
	// pointer. To blend in more seamlessly with the rest of Zeek we keep
	// reads a const operation.
	void ResetRead() const { read_size = 0; }

	// Incremental reads from an allocated HashKey. As with writes, the
	// tags are only used  for debug-build logging, and alignment prior
	// to the read of the item is controlled by the align boolean.
	void Read(const char* tag, bool& b) const;
	void Read(const char* tag, int& i, bool align = true) const;
	void Read(const char* tag, zeek_int_t& bi, bool align = true) const;
	void Read(const char* tag, zeek_uint_t& bu, bool align = true) const;
	void Read(const char* tag, uint32_t& u, bool align = true) const;
	void Read(const char* tag, double& d, bool align = true) const;

	void Read(const char* tag, void* out, size_t n, size_t alignment = 0) const;

	// These mirror the corresponding write methods above.
	void SkipRead(const char* tag, size_t n) const;
	void AlignRead(size_t alignment) const;
	void EnsureReadSpace(size_t n) const;

	void* KeyAtWrite() { return static_cast<void*>(key + write_size); }
	const void* KeyAtRead() const { return static_cast<void*>(key + read_size); }
	const void* KeyEnd() const { return static_cast<void*>(key + size); }

	void Describe(ODesc* d) const;

	bool operator==(const HashKey& other) const;
	bool operator!=(const HashKey& other) const;

	bool Equal(const void* other_key, size_t other_size, hash_t other_hash) const;

	// Copy operator. Always copies the key.
	HashKey& operator=(const HashKey& other);

	// Move operator. Takes ownership of the key.
	HashKey& operator=(HashKey&& other) noexcept;

protected:
	char* CopyKey(const char* key, size_t size) const;

	// Payload setters for types stored directly in the key_u union. These
	// adjust the size and write_size markers to indicate a full buffer, and
	// use the key_u union for storage.
	void Set(bool b);
	void Set(int i);
	void Set(zeek_int_t bi);
	void Set(zeek_uint_t bu);
	void Set(uint32_t u);
	void Set(double d);
	void Set(const void* p);

		union {
		bool b;
		int i;
		zeek_int_t bi;
		uint32_t u32;
		double d;
		const void* p;
		} key_u;

	char* key = nullptr;
	mutable hash_t hash = 0;
	size_t size = 0;
	bool is_our_dynamic = false;
	size_t write_size = 0;
	mutable size_t read_size = 0;
	};

extern void init_hash_function();

	} // namespace zeek::detail
