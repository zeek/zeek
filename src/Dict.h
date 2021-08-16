// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <vector>
#include <memory>

#include "zeek/Hash.h"

// Type for function to be called when deleting elements.
typedef void (*dict_delete_func)(void*);

namespace zeek {

class IterCookie;
class Dictionary;

enum DictOrder { ORDERED, UNORDERED };

// A dict_delete_func that just calls delete.
extern void generic_delete_func(void*);

namespace detail {

class DictEntry;

// Default number of hash buckets in dictionary.  The dictionary will increase the size
// of the hash table as needed.
constexpr uint32_t HASH_MASK = 0xFFFFFFFF; //only lower 32 bits.

// These four variables can be used to build different targets with -Dxxx for performance
// or for debugging purposes.

// When incrementally resizing and remapping, it remaps DICT_REMAP_ENTRIES each step. Use
// 2 for debug. 16 is best for a release build.
constexpr uint8_t DICT_REMAP_ENTRIES = 16;

// Load factor = 1 - 0.5 ^ LOAD_FACTOR_BITS. 0.75 is the optimal value for release builds.
constexpr uint8_t DICT_LOAD_FACTOR_BITS = 2;

// Default number of hash buckets in dictionary.  The dictionary will
// increase the size of the hash table as needed.
constexpr uint8_t DEFAULT_DICT_SIZE = 0;

// When log2_buckets > DICT_THRESHOLD_BITS, DICT_LOAD_FACTOR_BITS becomes effective.
// Basically if dict size < 2^DICT_THRESHOLD_BITS + n, we size up only if necessary.
constexpr uint8_t DICT_THRESHOLD_BITS = 3;

// The value of an iteration cookie is the bucket and offset within the
// bucket at which to start looking for the next value to return.
constexpr uint16_t TOO_FAR_TO_REACH = 0xFFFF;

/**
 * An entry stored in the dictionary.
 */
class DictEntry {
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
	union {
		char key_here[8]; //hold key len<=8. when over 8, it's a pointer to real keys.
		char* key;
	};

	DictEntry(void* arg_key, int key_size = 0, hash_t hash = 0, void* value = nullptr,
	          int16_t d = TOO_FAR_TO_REACH, bool copy_key = false)
		: distance(d), key_size(key_size), hash((uint32_t)hash), value(value)
		{
		if ( ! arg_key )
			return;

		if ( key_size <= 8 )
			{
			memcpy(key_here, arg_key, key_size);
			if ( ! copy_key )
				delete [] (char*)arg_key; //own the arg_key, now don't need it.
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
			delete [] key;
		SetEmpty();
		}

	const char* GetKey() const { return key_size <= 8 ? key_here : key; }
	std::unique_ptr<detail::HashKey> GetHashKey() const
		{
		return std::make_unique<detail::HashKey>(GetKey(), key_size, hash);
		}

	template <typename T>
	T GetValue() const { return static_cast<T>(value); }

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

} // namespace detail

class DictIterator {
public:
	using value_type = detail::DictEntry;
	using reference = detail::DictEntry&;
	using pointer = detail::DictEntry*;
	using difference_type = std::ptrdiff_t;
	using iterator_category = std::forward_iterator_tag;

	DictIterator() = default;
	~DictIterator();

	DictIterator(const DictIterator& that);
	DictIterator& operator=(const DictIterator& that);
	DictIterator(DictIterator&& that);
	DictIterator& operator=(DictIterator&& that);

	reference operator*() { return *curr; }
	pointer operator->() { return curr; }

	DictIterator& operator++();
	DictIterator operator++(int) { auto temp(*this); ++*this; return temp; }

	bool operator==( const DictIterator& that ) const { return curr == that.curr; }
	bool operator!=( const DictIterator& that ) const { return !(*this == that); }

private:

	friend class Dictionary;

	DictIterator(const Dictionary* d, detail::DictEntry* begin, detail::DictEntry* end);

	Dictionary* dict = nullptr;
	detail::DictEntry* curr = nullptr;
	detail::DictEntry* end = nullptr;
};

class RobustDictIterator {
public:
	using value_type = detail::DictEntry;
	using reference = detail::DictEntry&;
	using pointer = detail::DictEntry*;
	using difference_type = std::ptrdiff_t;
	using iterator_category = std::forward_iterator_tag;

	RobustDictIterator() : curr(nullptr) {}
	RobustDictIterator(Dictionary* d);
	RobustDictIterator(const RobustDictIterator& other);
	RobustDictIterator(RobustDictIterator&& other);
 	~RobustDictIterator();

	reference operator*() { return curr; }
	pointer operator->() { return &curr; }

	RobustDictIterator& operator++();
	RobustDictIterator operator++(int) { auto temp(*this); ++*this; return temp; }

	bool operator==( const RobustDictIterator& that ) const { return curr == that.curr; }
	bool operator!=( const RobustDictIterator& that ) const { return !(*this == that); }

private:
	friend class Dictionary;

	void Complete();

	// Tracks the new entries inserted while iterating.
	std::vector<detail::DictEntry>* inserted = nullptr;

	// Tracks the entries already visited but were moved across the next iteration
	// point due to an insertion.
	std::vector<detail::DictEntry>* visited = nullptr;

	detail::DictEntry curr;
	Dictionary* dict = nullptr;
	int next = -1;
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
class Dictionary {
public:
	explicit Dictionary(DictOrder ordering = UNORDERED, int initial_size = detail::DEFAULT_DICT_SIZE);
	~Dictionary();

	// Member functions for looking up a key, inserting/changing its
	// contents, and deleting it.  These come in two flavors: one
	// which takes a zeek::detail::HashKey, and the other which takes a raw key,
	// its size, and its (unmodulated) hash.
	//lookup may move the key to right place if in the old zone to speed up the next lookup.
	void* Lookup(const detail::HashKey* key) const;
	void* Lookup(const void* key, int key_size, detail::hash_t h) const;

	// Returns previous value, or 0 if none.
	// If iterators_invalidated is supplied, its value is set to true
	// if the removal may have invalidated any existing iterators.
	void* Insert(detail::HashKey* key, void* val, bool* iterators_invalidated = nullptr)
		{ return Insert(key->TakeKey(), key->Size(), key->Hash(), val, false, iterators_invalidated); }

	// If copy_key is true, then the key is copied, otherwise it's assumed
	// that it's a heap pointer that now belongs to the Dictionary to
	// manage as needed.
	// If iterators_invalidated is supplied, its value is set to true
	// if the removal may have invalidated any existing iterators.
	void* Insert(void* key, int key_size, detail::hash_t hash, void* val, bool copy_key, bool* iterators_invalidated = nullptr);

	// Removes the given element.  Returns a pointer to the element in
	// case it needs to be deleted.  Returns 0 if no such element exists.
	// If dontdelete is true, the key's bytes will not be deleted.
	// If iterators_invalidated is supplied, its value is set to true
	// if the removal may have invalidated any existing iterators.
	void* Remove(const detail::HashKey* key, bool* iterators_invalidated = nullptr)
		{ return Remove(key->Key(), key->Size(), key->Hash(), false, iterators_invalidated); }
	void* Remove(const void* key, int key_size, detail::hash_t hash, bool dont_delete = false, bool* iterators_invalidated = nullptr);

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
	[[deprecated("Remove in v5.1. Use begin() and the standard-library-compatible version of iteration.")]]
	IterCookie* InitForIteration() const;
	[[deprecated("Remove in v5.1. Use begin() and the standard-library-compatible version of iteration.")]]
	void* NextEntry(detail::HashKey*& h, IterCookie*& cookie, bool return_hash) const;
	[[deprecated("Remove in v5.1. Use begin() and the standard-library-compatible version of iteration.")]]
	void StopIteration(IterCookie* cookie) const;

	void SetDeleteFunc(dict_delete_func f)		{ delete_func = f; }

	// With a robust cookie, it is safe to change the dictionary while
	// iterating. This means that (i) we will eventually visit all
	// unmodified entries as well as all entries added during iteration,
	// and (ii) we won't visit any still-unseen entries which are getting
	// removed. (We don't get this for free, so only use it if
	// necessary.)
	[[deprecated("Remove in v5.1. Use begin_robust() and the standard-library-compatible version of iteration.")]]
	void MakeRobustCookie(IterCookie* cookie);

	// Remove all entries.
	void Clear();

	[[deprecated("Remove in v5.1. MemoryAllocation() is deprecated and will be removed. See GHI-572.")]]
	size_t MemoryAllocation() const;

	/// The capacity of the table, Buckets + Overflow Size.
	int Capacity(bool expected = false) const;

	//Debugging
#ifdef DEBUG
	void AssertValid() const;
#endif//DEBUG
	void Dump(int level=0) const;
	void DistanceStats(int& max_distance, int* distances = 0, int num_distances = 0) const;
	void DumpKeys() const;

	// Type traits needed for some of the std algorithms to work
	using value_type = detail::DictEntry;
	using pointer = detail::DictEntry*;
	using const_pointer = const detail::DictEntry*;

	// Iterator support
	using iterator = DictIterator;
	using const_iterator = const iterator;
	using reverse_iterator = std::reverse_iterator<iterator>;
	using const_reverse_iterator = std::reverse_iterator<const_iterator>;

	iterator begin() { return { this, table, table + Capacity() }; }
	iterator end() { return { this, table + Capacity(), table + Capacity() }; }
	const_iterator begin() const { return { this, table, table + Capacity() }; }
	const_iterator end() const { return { this, table + Capacity(), table + Capacity() }; }
	const_iterator cbegin() { return { this, table, table + Capacity() }; }
	const_iterator cend() { return { this, table + Capacity(), table + Capacity() }; }

	RobustDictIterator begin_robust() { return MakeRobustIterator(); }
	RobustDictIterator end_robust() { return RobustDictIterator(); }

private:
	friend zeek::IterCookie;
	friend zeek::DictIterator;
	friend zeek::RobustDictIterator;

	/// Buckets of the table, not including overflow size.
	int Buckets(bool expected = false) const;

	//bucket math
	int Log2(int num) const;
	int ThresholdEntries() const;

	// Used to improve the distribution of the original hash.
	detail::hash_t FibHash(detail::hash_t h) const;

	// Maps a hash to the appropriate n-bit table bucket.
	int BucketByHash(detail::hash_t h, int bit) const;

	// Given a position of a non-empty item in the table, find the related bucket.
	int BucketByPosition(int position) const;

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

	// Iteration
	[[deprecated("Remove in v5.1. Use begin() and the standard-library-compatible version of iteration.")]]
	IterCookie* InitForIterationNonConst();
	[[deprecated("Remove in v5.1. Use begin() and the standard-library-compatible version of iteration.")]]
	void* NextEntryNonConst(detail::HashKey*& h, IterCookie*& cookie, bool return_hash);
	[[deprecated("Remove in v5.1. Use begin() and the standard-library-compatible version of iteration.")]]
	void StopIterationNonConst(IterCookie* cookie);

	//Lookup
	int LinearLookupIndex(const void* key, int key_size, detail::hash_t hash) const;
	int LookupIndex(const void* key, int key_size, detail::hash_t hash, int* insert_position = nullptr,
		int* insert_distance = nullptr);
	int LookupIndex(const void* key, int key_size, detail::hash_t hash, int begin, int end,
		int* insert_position = nullptr, int* insert_distance  = nullptr);

	/// Insert entry, Adjust cookies when necessary.
	void InsertRelocateAndAdjust(detail::DictEntry& entry, int insert_position);

	/// insert entry into position, relocate other entries when necessary.
	void InsertAndRelocate(detail::DictEntry& entry, int insert_position, int* last_affected_position = nullptr);

	/// Adjust Cookies on Insert.
	[[deprecated("Remove in v5.1. Use the standard-library-compatible version of iteration and the version that takes a RobustDictIterator.")]]
	void AdjustOnInsert(IterCookie* c, const detail::DictEntry& entry, int insert_position, int last_affected_position);
	void AdjustOnInsert(RobustDictIterator* c, const detail::DictEntry& entry,
	                    int insert_position, int last_affected_position);

	///Remove, Relocate & Adjust cookies.
	detail::DictEntry RemoveRelocateAndAdjust(int position);

	///Remove & Relocate
	detail::DictEntry RemoveAndRelocate(int position, int* last_affected_position = nullptr);

	///Adjust safe cookies after Removal of entry at position.
	[[deprecated("Remove in v5.1. Use the standard-library-compatible version of iteration and the version that takes a RobustDictIterator.")]]
	void AdjustOnRemove(IterCookie* c, const detail::DictEntry& entry, int position, int last_affected_position);
	void AdjustOnRemove(RobustDictIterator* c, const detail::DictEntry& entry,
	                    int position, int last_affected_position);

	bool Remapping() const { return remap_end >= 0;} //remap in reverse order.

	///One round of remap.
	void Remap();

	// Remap an item in position to a new position. Returns true if the relocation was
	// successful, false otherwise. new_position will be set to the new position if a
	// pointer is provided to store the new value.
	bool Remap(int position, int* new_position = nullptr);

	void SizeUp();

	bool HaveOnlyRobustIterators() const
		{
		return (num_iterators == 0) || ((cookies ? cookies->size() : 0) + (iterators ? iterators->size() : 0) == num_iterators);
		}

	RobustDictIterator MakeRobustIterator();
	detail::DictEntry GetNextRobustIteration(RobustDictIterator* iter);

	void IncrIters()	{ ++num_iterators; }
	void DecrIters()	{ --num_iterators; }

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
	detail::DictEntry* table = nullptr;
	std::vector<IterCookie*>* cookies = nullptr;
	std::vector<RobustDictIterator*>* iterators = nullptr;

	// Order means the order of insertion. means no deletion until exit. will be inefficient.
	std::vector<detail::DictEntry>* order = nullptr;
};

/*
 * Template specialization of Dictionary that stores pointers for values.
 */
template<typename T>
class PDict : public Dictionary {
public:
	explicit PDict(DictOrder ordering = UNORDERED, int initial_size = 0) :
		Dictionary(ordering, initial_size) {}
	T* Lookup(const char* key) const
		{
		detail::HashKey h(key);
		return (T*) Dictionary::Lookup(&h);
		}
	T* Lookup(const detail::HashKey* key) const
		{ return (T*) Dictionary::Lookup(key); }
	T* Insert(const char* key, T* val, bool* iterators_invalidated = nullptr)
		{
		detail::HashKey h(key);
		return (T*) Dictionary::Insert(&h, (void*) val, iterators_invalidated);
		}
	T* Insert(detail::HashKey* key, T* val, bool* iterators_invalidated = nullptr)
		{ return (T*) Dictionary::Insert(key, (void*) val, iterators_invalidated); }
	T* NthEntry(int n) const
		{ return (T*) Dictionary::NthEntry(n); }
	T* NthEntry(int n, const char*& key) const
		{
		int key_len;
		return (T*) Dictionary::NthEntry(n, (const void*&) key, key_len);
		}
	[[deprecated("Remove in v5.1. Use the standard-library-compatible version of iteration.")]]
	T* NextEntry(IterCookie*& cookie) const
		{
		detail::HashKey* h;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
		return (T*) Dictionary::NextEntry(h, cookie, false);
#pragma GCC diagnostic pop
		}
	[[deprecated("Remove in v5.1. Use the standard-library-compatible version of iteration.")]]
	T* NextEntry(detail::HashKey*& h, IterCookie*& cookie) const
		{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
		return (T*) Dictionary::NextEntry(h, cookie, true);
#pragma GCC diagnostic pop
		}
	T* RemoveEntry(const detail::HashKey* key, bool* iterators_invalidated = nullptr)
		{ return (T*) Remove(key->Key(), key->Size(), key->Hash(), false, iterators_invalidated); }
	T* RemoveEntry(const detail::HashKey& key, bool* iterators_invalidated = nullptr)
		{ return (T*) Remove(key.Key(), key.Size(), key.Hash(), false, iterators_invalidated); }
};

} // namespace zeek
