// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <vector>

#include "Hash.h"

class Dictionary;
class IterCookie;

// Default number of hash buckets in dictionary.  The dictionary will increase the size
// of the hash table as needed.
constexpr uint32_t HASH_MASK = 0xFFFFFFFF; //only lower 32 bits.

// These four variables can be used to build different targets with -Dxxx for performance
// or for debugging purposes.

// When incrementally resizing and remapping, it remaps DICT_REMAP_ENTRIES each step. Use
// 2 for debug. 16 is best for a release build.
#ifndef DICT_REMAP_ENTRIES
constexpr uint8_t DICT_REMAP_ENTRIES = 16;
#endif

// Load factor = 1 - 0.5 ^ LOAD_FACTOR_BITS. 0.75 is the optimal value for release builds.
#ifndef DICT_LOAD_FACTOR_BITS
constexpr uint8_t DICT_LOAD_FACTOR_BITS = 2;
#endif

// Default number of hash buckets in dictionary.  The dictionary will
// increase the size of the hash table as needed.
#ifndef DEFAULT_DICT_SIZE
constexpr uint8_t DEFAULT_DICT_SIZE = 0;
#endif

// When log2_buckets > DICT_THRESHOLD_BITS, DICT_LOAD_FACTOR_BITS becomes effective.
// Basically if dict size < 2^DICT_THRESHOLD_BITS + n, we size up only if necessary.
#ifndef DICT_THRESHOLD_BITS
constexpr uint8_t DICT_THRESHOLD_BITS = 3;
#endif

// The value of an iteration cookie is the bucket and offset within the
// bucket at which to start looking for the next value to return.
constexpr uint16_t TOO_FAR_TO_REACH = 0xFFFF;
constexpr uint16_t MAX_KEY_SIZE = 0xFFFF;

enum dict_order { ORDERED, UNORDERED };

// Type for function to be called when deleting elements.
typedef void (*dict_delete_func)(void*);

// A dict_delete_func that just calls delete.
extern void generic_delete_func(void*);

/**
 * An entry stored in the dictionary.
 */
class DictEntry{
public:

#ifdef DEBUG
	int bucket = 0;
#endif

	// Distance from the expected position in the table. 0xFFFF means that the entry is empty.
	uint16_t distance = TOO_FAR_TO_REACH;

	// The size of the key. Less than 8 bytes we'll store directly in the entry, otherwise we'll
	// store it as a pointer. This avoids extra allocations if we can help it.
	uint16_t key_size = 0;

	// Lower 4 bytes of the 8-byte hash, which is used to calculate the position in the table.
	uint32_t hash = 0;

	void* value = nullptr;
	union{
		char key_here[8]; //hold key len<=8. when over 8, it's a pointer to real keys.
		char* key;
	};

	DictEntry(void* arg_key, int key_size = 0, hash_t hash = 0, void* value = nullptr,
	          int16_t d = TOO_FAR_TO_REACH, bool copy_key = false)
		: distance(d), key_size(key_size), hash((uint32_t)hash), value(value)
		{
		if ( key_size <= 8 )
			{
			memcpy(key_here, arg_key, key_size);
			if ( ! copy_key )
				delete (char*)arg_key; //own the arg_key, now don't need it.
			}
		else
			{
			if ( copy_key )
				{
				key = new char[key_size];
				memcpy(key, arg_key, key_size);
				}
			else
				{
				key = (char*)arg_key;
				}
			}
		}

	bool Empty() const	{ return distance == TOO_FAR_TO_REACH; }
	void SetEmpty()
		{
		distance = TOO_FAR_TO_REACH;
#ifdef DEBUG

		hash = 0;
		key = nullptr;
		value = nullptr;
		key_size = 0;
		bucket = 0;
#endif//DEBUG
		}

	void Clear()
		{
		if( key_size > 8 )
			delete key;
		SetEmpty();
		}

	const char* GetKey() const { return key_size <= 8? key_here : key; }

	bool Equal(const char* arg_key, int arg_key_size, hash_t arg_hash) const
		{//only 40-bit hash comparison.
		return ( 0 == ((hash ^ arg_hash) & HASH_MASK) )
			&& key_size == arg_key_size && 0 == memcmp(GetKey(), arg_key, key_size);
		}
	bool operator==(const DictEntry& r) const
		{
		return Equal(r.GetKey(), r.key_size, r.hash);
		}
	bool operator!=(const DictEntry& r) const
		{
		return ! Equal(r.GetKey(), r.key_size, r.hash);
		}
};

/**
 * A dictionary type that uses clustered hashing, a variation of Robinhood/Open Addressing
 * hashing. The following posts help to understand the implementation:
 * - https://jasonlue.github.io/algo/2019/08/20/clustered-hashing.html
 * - https://jasonlue.github.io/algo/2019/08/27/clustered-hashing-basic-operations.html
 * - https://jasonlue.github.io/algo/2019/09/03/clustered-hashing-incremental-resize.html
 * - https://jasonlue.github.io/algo/2019/09/10/clustered-hashing-modify-on-iteration.html
 *
 * The dictionary is effectively a hashmap from hashed keys to values. The dictionary owns
 * the keys but not the values. The dictionary size will be bounded at around 100K. 1M
 * entries is the absolute limit. Only Connections use that many entries, and that is rare.
 */
class Dictionary{
public:
	explicit Dictionary(dict_order ordering = UNORDERED, int initial_size = DEFAULT_DICT_SIZE);
	~Dictionary();

	// Member functions for looking up a key, inserting/changing its
	// contents, and deleting it.  These come in two flavors: one
	// which takes a HashKey, and the other which takes a raw key,
	// its size, and its (unmodulated) hash.
	//lookup may move the key to right place if in the old zone to speed up the next lookup.
	void* Lookup(const HashKey* key) const;
	void* Lookup(const void* key, int key_size, hash_t h) const;

	// Returns previous value, or 0 if none.
	void* Insert(HashKey* key, void* val)
		{ return Insert(key->TakeKey(), key->Size(), key->Hash(), val, false); }

	// If copy_key is true, then the key is copied, otherwise it's assumed
	// that it's a heap pointer that now belongs to the Dictionary to
	// manage as needed.
	void* Insert(void* key, int key_size, hash_t hash, void* val, bool copy_key);

	// Removes the given element.  Returns a pointer to the element in
	// case it needs to be deleted.  Returns 0 if no such element exists.
	// If dontdelete is true, the key's bytes will not be deleted.
	void* Remove(const HashKey* key)
		{ return Remove(key->Key(), key->Size(), key->Hash()); }
	void* Remove(const void* key, int key_size, hash_t hash, bool dont_delete = false);

	// Number of entries.
	int Length() const
		{ return num_entries; }

	// Largest it's ever been.
	int MaxLength() const
		{ return max_entries; }

	// Total number of entries ever.
	uint64_t NumCumulativeInserts() const
		{ return cum_entries; }

	// True if the dictionary is ordered, false otherwise.
	int IsOrdered() const	{ return order != nullptr; }

	// If the dictionary is ordered then returns the n'th entry's value;
	// the second method also returns the key.  The first entry inserted
	// corresponds to n=0.
	//
	// Returns nil if the dictionary is not ordered or if "n" is out
	// of range.
	void* NthEntry(int n) const
		{
		const void* key;
		int key_len;
		return NthEntry(n, key, key_len);
		}
	void* NthEntry(int n, const void*& key, int& key_len) const;

	// To iterate through the dictionary, first call InitForIteration()
	// to get an "iteration cookie".  The cookie can then be handed
	// to NextEntry() to get the next entry in the iteration and update
	// the cookie.  If NextEntry() indicates no more entries, it will
	// also delete the cookie, or the cookie can be manually deleted
	// prior to this if no longer needed.
	//
	// Unexpected results will occur if the elements of
	// the dictionary are changed between calls to NextEntry() without
	// first calling InitForIteration().
	//
	// If return_hash is true, a HashKey for the entry is returned in h,
	// which should be delete'd when no longer needed.
	IterCookie* InitForIteration() const;
	void* NextEntry(HashKey*& h, IterCookie*& cookie, bool return_hash) const;
	void StopIteration(IterCookie* cookie) const;

	void SetDeleteFunc(dict_delete_func f)		{ delete_func = f; }

	// With a robust cookie, it is safe to change the dictionary while
	// iterating. This means that (i) we will eventually visit all
	// unmodified entries as well as all entries added during iteration,
	// and (ii) we won't visit any still-unseen entries which are getting
	// removed. (We don't get this for free, so only use it if
	// necessary.)
	void MakeRobustCookie(IterCookie* cookie);

	// Remove all entries.
	void Clear();

	unsigned int MemoryAllocation() const;
	constexpr float GetThreshold() const { return 1.0 - 1.0 / (1<<DICT_LOAD_FACTOR_BITS);}

	/// The capacity of the table, Buckets + Overflow Size.
	int Capacity(bool expected=false) const;

	//Debugging
#ifdef DEBUG
	void AssertValid() const;
#endif//DEBUG
	void Dump(int level=0) const;
	void DistanceStats(int& max_distance, int* distances=0, int num_distances=0) const;
	void DumpKeys() const;

private:
	friend IterCookie;

	/// Buckets of the table, not including overflow size.
	int Buckets(bool expected=false) const;

	//bucket math
	int Log2(int num) const;
	int ThresholdEntries() const;

	// Used to improve the distribution of the original hash.
	hash_t FibHash(hash_t h) const;

	// Maps a hash to the appropriate n-bit table bucket.
	int BucketByHash(hash_t h, int bit) const;

	// Given a position of a non-empty item in the table, find the related bucket.
	int BucketByPosition(int position) const;

	// Given a bucket of a non-empty item in the table,. find the head of its cluster
	// for that position. If not found, return -1 and correct expected_position to the
	// value it's supposed to be, if expected_position isn't a nullptr..
	int HeadOfClusterByBucket(int bucket) const;

	// Given a bucket of a non-empty item in the table, find the tail of its cluster
	int TailOfClusterByBucket(int bucket) const;

	// Given a bucket of a non-empty item in the table, find the end of its cluster.
	// The end should be equal to tail+1 if tail exists. Otherwise it's the tail of
	// the just-smaller cluster + 1.
	int EndOfClusterByBucket(int bucket) const;

	// Given a position of a non-empty item in the table, find the head of its cluster.
	int HeadOfClusterByPosition(int position) const;

	// Given a position of a non-empty item in the table, find the tail of its cluster.
	int TailOfClusterByPosition(int position) const;

	// Given a position of a non-empty item in the table, find the end of its cluster.
	// The end should be equal to tail+1 if tail exists. Otherwise it's the tail of
	// the just-smaller cluster + 1.
	int EndOfClusterByPosition(int position) const;

	// Given a position of a non-empty item in the table, find the offset of it within
	// its cluster.
	int OffsetInClusterByPosition(int position) const;

	// Next non-empty item position in the table.
	int Next(int i) const;

	void Init();

	//Iteration
	IterCookie* InitForIterationNonConst();
	void* NextEntryNonConst(HashKey*& h, IterCookie*& cookie, bool return_hash);
	void StopIterationNonConst(IterCookie* cookie);

	//Lookup
	int LinearLookupIndex(const void* key, int key_size, hash_t hash) const;
	int LookupIndex(const void* key, int key_size, hash_t hash, int* insert_position = nullptr,
		int* insert_distance = nullptr);
	int LookupIndex(const void* key, int key_size, hash_t hash, int begin, int end,
		int* insert_position = nullptr, int* insert_distance  = nullptr);

	/// Insert entry, Adjust cookies when necessary.
	void InsertRelocateAndAdjust(DictEntry& entry, int insert_position);

	/// insert entry into position, relocate other entries when necessary.
	void InsertAndRelocate(DictEntry& entry, int insert_position, int* last_affected_position = nullptr);

	/// Adjust Cookies on Insert.
	void AdjustOnInsert(IterCookie* c, const DictEntry& entry, int insert_position, int last_affected_position);

	///Remove, Relocate & Adjust cookies.
	DictEntry RemoveRelocateAndAdjust(int position);

	///Remove & Relocate
	DictEntry RemoveAndRelocate(int position, int* last_affected_position = nullptr);

	///Adjust safe cookies after Removal of entry at position.
	void AdjustOnRemove(IterCookie* c, const DictEntry& entry, int position, int last_affected_position);

	bool Remapping() const { return remap_end >= 0;} //remap in reverse order.

	///One round of remap.
	void Remap();

	// Remap an item in position to a new position. Returns true if the relocation was
	// successful, false otherwise. new_position will be set to the new position if a
	// pointer is provided to store the new value.
	bool Remap(int position, int* new_position = nullptr);

	void SizeUp();

	//alligned on 8-bytes with 4-leading bytes. 7*8=56 bytes a dictionary.

	// when sizeup but the current mapping is in progress. the current mapping will be ignored
	// as it will be remapped to new dict size anyway. however, the missed count is recorded
	// for lookup. if position not found for a key in the position of dict of current size, it
	// still could be in the position of dict of previous N sizes.
	unsigned char remaps = 0;
	unsigned char log2_buckets = 0;

	// Pending number of iterators on the Dict, including both robust and non-robust.
	// This is used to avoid remapping if there are any active iterators.
	unsigned short num_iterators = 0;

	// The last index to be remapped.
	int remap_end = -1;

	int num_entries = 0;
	int max_entries = 0;

	uint64_t cum_entries = 0;
	dict_delete_func delete_func = nullptr;
	DictEntry* table = nullptr;
	std::vector<IterCookie*>* cookies = nullptr;

	// Order means the order of insertion. means no deletion until exit. will be inefficient.
	std::vector<DictEntry>* order = nullptr;
};

/*
 * Template specialization of Dictionary that stores pointers for values.
 */
template<typename T>
class PDict : public Dictionary {
public:
	explicit PDict(dict_order ordering = UNORDERED, int initial_size = 0) :
		Dictionary(ordering, initial_size) {}
	T* Lookup(const char* key) const
		{
		HashKey h(key);
		return (T*) Dictionary::Lookup(&h);
		}
	T* Lookup(const HashKey* key) const
		{ return (T*) Dictionary::Lookup(key); }
	T* Insert(const char* key, T* val)
		{
		HashKey h(key);
		return (T*) Dictionary::Insert(&h, (void*) val);
		}
	T* Insert(HashKey* key, T* val)
		{ return (T*) Dictionary::Insert(key, (void*) val); }
	T* NthEntry(int n) const
		{ return (T*) Dictionary::NthEntry(n); }
	T* NthEntry(int n, const char*& key) const
		{
		int key_len;
		return (T*) Dictionary::NthEntry(n, (const void*&) key, key_len);
		}
	T* NextEntry(IterCookie*& cookie) const
		{
		HashKey* h;
		return (T*) Dictionary::NextEntry(h, cookie, false);
		}
	T* NextEntry(HashKey*& h, IterCookie*& cookie) const
		{ return (T*) Dictionary::NextEntry(h, cookie, true); }
	T* RemoveEntry(const HashKey* key)
		{ return (T*) Remove(key->Key(), key->Size(), key->Hash()); }
};
