// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <memory>
#include <vector>

#include "zeek/Hash.h"
#include "zeek/Reporter.h"

// Type for function to be called when deleting elements.
using dict_delete_func = void (*)(void*);

#if defined(DEBUG) && defined(ZEEK_DICT_DEBUG)
#define ASSERT_VALID(o) o->AssertValid()
#define ASSERT_EQUAL(a, b) ASSERT(a == b)
#else
#define ASSERT_VALID(o)
#define ASSERT_EQUAL(a, b)
#endif // DEBUG

namespace zeek
	{

template <typename T> class Dictionary;

enum DictOrder
	{
	ORDERED,
	UNORDERED
	};

// A dict_delete_func that just calls delete.
extern void generic_delete_func(void*);

namespace detail
	{

// Default number of hash buckets in dictionary.  The dictionary will increase the size
// of the hash table as needed.
constexpr uint32_t HASH_MASK = 0xFFFFFFFF; // only lower 32 bits.

// These four variables can be used to build different targets with -Dxxx for performance
// or for debugging purposes.

// When incrementally resizing and remapping, it remaps DICT_REMAP_ENTRIES each step. Use
// 2 for debug. 16 is best for a release build.
constexpr uint8_t DICT_REMAP_ENTRIES = 16;

// 100 for size < 1 << DICT_THRESHOLD_BITS + DICT_THRESHOLD_BITS;
// 75 for larger sizes
// 25 for min load factor.
constexpr int MIN_DICT_LOAD_FACTOR_100 = 25;
constexpr int DICT_LOAD_FACTOR_100 = 75;

// when space_distance is greater than SPACE_DISTANCE_THRESHOLD, double the size unless the load
// factor is already lower than MIN_DICT_LOAD_FACTOR_100.
constexpr int SPACE_DISTANCE_THRESHOLD = 32;

// To ignore occasional faraway spaces. only when space_distance_samples are above
// MIN_SPACE_DISTANCE_SAMPLES, we consider space_distance is not by chance.
constexpr int MIN_SPACE_DISTANCE_SAMPLES = 128;

// Default number of hash buckets in dictionary.  The dictionary will
// increase the size of the hash table as needed.
constexpr uint8_t DEFAULT_DICT_SIZE = 0;

// When log2_buckets > DICT_THRESHOLD_BITS, DICT_LOAD_FACTOR_BITS becomes effective.
// Basically if dict size < 2^DICT_THRESHOLD_BITS + DICT_THRESHOLD_BITS, we size up only if
// necessary.
constexpr uint8_t DICT_THRESHOLD_BITS = 3;

// The value of an iteration cookie is the bucket and offset within the
// bucket at which to start looking for the next value to return.
constexpr uint16_t TOO_FAR_TO_REACH = 0xFFFF;

/**
 * An entry stored in the dictionary.
 */
template <typename T> class DictEntry
	{
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

	T* value = nullptr;
		union {
		char key_here[8]; // hold key len<=8. when over 8, it's a pointer to real keys.
		char* key;
		};

	DictEntry(void* arg_key, int key_size = 0, hash_t hash = 0, T* value = nullptr,
	          int16_t d = TOO_FAR_TO_REACH, bool copy_key = false)
		: distance(d), key_size(key_size), hash((uint32_t)hash), value(value)
		{
		if ( ! arg_key )
			return;

		if ( key_size <= 8 )
			{
			memcpy(key_here, arg_key, key_size);
			if ( ! copy_key )
				delete[](char*) arg_key; // own the arg_key, now don't need it.
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

	bool Empty() const { return distance == TOO_FAR_TO_REACH; }
	void SetEmpty()
		{
		distance = TOO_FAR_TO_REACH;
#ifdef DEBUG

		hash = 0;
		key = nullptr;
		value = nullptr;
		key_size = 0;
		bucket = 0;
#endif // DEBUG
		}

	void Clear()
		{
		if ( key_size > 8 )
			delete[] key;
		SetEmpty();
		}

	const char* GetKey() const { return key_size <= 8 ? key_here : key; }
	std::unique_ptr<detail::HashKey> GetHashKey() const
		{
		return std::make_unique<detail::HashKey>(GetKey(), key_size, hash);
		}

	bool Equal(const char* arg_key, int arg_key_size, hash_t arg_hash) const
		{ // only 40-bit hash comparison.
		return (0 == ((hash ^ arg_hash) & HASH_MASK)) && key_size == arg_key_size &&
		       0 == memcmp(GetKey(), arg_key, key_size);
		}

	template <typename V>
	[[deprecated("Remove in v6.1. Access the value in the entry directly.")]] T* GetValue() const
		{
		static_assert(std::is_same_v<T*, V>, "Type of DictEntry and type requested are different");
		return value;
		}

	bool operator==(const DictEntry& r) const { return Equal(r.GetKey(), r.key_size, r.hash); }
	bool operator!=(const DictEntry& r) const { return ! Equal(r.GetKey(), r.key_size, r.hash); }
	};

using DictEntryVec = std::vector<detail::HashKey>;

	} // namespace detail

template <typename T> class DictIterator
	{
public:
	using value_type = detail::DictEntry<T>;
	using reference = detail::DictEntry<T>&;
	using pointer = detail::DictEntry<T>*;
	using difference_type = std::ptrdiff_t;
	using iterator_category = std::forward_iterator_tag;

	DictIterator() = default;
	~DictIterator()
		{
		if ( dict )
			{
			assert(dict->num_iterators > 0);
			dict->DecrIters();
			}
		}

	DictIterator(const DictIterator& that)
		{
		if ( this == &that )
			return;

		if ( dict )
			{
			assert(dict->num_iterators > 0);
			dict->DecrIters();
			}

		dict = that.dict;
		curr = that.curr;
		end = that.end;
		ordered_iter = that.ordered_iter;

		dict->IncrIters();
		}

	DictIterator& operator=(const DictIterator& that)
		{
		if ( this == &that )
			return *this;

		if ( dict )
			{
			assert(dict->num_iterators > 0);
			dict->DecrIters();
			}

		dict = that.dict;
		curr = that.curr;
		end = that.end;
		ordered_iter = that.ordered_iter;

		dict->IncrIters();

		return *this;
		}

	DictIterator(DictIterator&& that) noexcept
		{
		if ( this == &that )
			return;

		if ( dict )
			{
			assert(dict->num_iterators > 0);
			dict->DecrIters();
			}

		dict = that.dict;
		curr = that.curr;
		end = that.end;
		ordered_iter = that.ordered_iter;

		that.dict = nullptr;
		}

	DictIterator& operator=(DictIterator&& that) noexcept
		{
		if ( this == &that )
			return *this;

		if ( dict )
			{
			assert(dict->num_iterators > 0);
			dict->DecrIters();
			}

		dict = that.dict;
		curr = that.curr;
		end = that.end;
		ordered_iter = that.ordered_iter;

		that.dict = nullptr;

		return *this;
		}

	reference operator*()
		{
		if ( dict->IsOrdered() )
			{
			// TODO: how does this work if ordered_iter == end(). LookupEntry will return a nullptr,
			// which the dereference will fail on. That's undefined behavior, correct? Is that any
			// different than if the unordered version returns a dereference of it's end?
			auto e = dict->LookupEntry(*ordered_iter);
			return *e;
			}

		return *curr;
		}
	reference operator*() const
		{
		if ( dict->IsOrdered() )
			{
			auto e = dict->LookupEntry(*ordered_iter);
			return *e;
			}

		return *curr;
		}
	pointer operator->()
		{
		if ( dict->IsOrdered() )
			return dict->LookupEntry(*ordered_iter);

		return curr;
		}
	pointer operator->() const
		{
		if ( dict->IsOrdered() )
			return dict->LookupEntry(*ordered_iter);

		return curr;
		}

	DictIterator& operator++()
		{
		if ( dict->IsOrdered() )
			++ordered_iter;
		else
			{
			// The non-robust case is easy. Just advance the current position forward until you
			// find one isn't empty and isn't the end.
			do
				{
				++curr;
				} while ( curr != end && curr->Empty() );
			}

		return *this;
		}

	DictIterator operator++(int)
		{
		auto temp(*this);
		++*this;
		return temp;
		}

	bool operator==(const DictIterator& that) const
		{
		if ( dict != that.dict )
			return false;

		if ( dict->IsOrdered() )
			return ordered_iter == that.ordered_iter;

		return curr == that.curr;
		}

	bool operator!=(const DictIterator& that) const { return ! (*this == that); }

private:
	friend class Dictionary<T>;

	DictIterator(const Dictionary<T>* d, detail::DictEntry<T>* begin, detail::DictEntry<T>* end)
		: curr(begin), end(end)
		{
		// Cast away the constness so that the number of iterators can be modified in the
		// dictionary. This does violate the constness guarantees of const-begin()/end() and
		// cbegin()/cend(), but we're not modifying the actual data in the collection, just a
		// counter in the wrapper of the collection.
		dict = const_cast<Dictionary<T>*>(d);

		// Make sure that we're starting on a non-empty element.
		while ( curr != end && curr->Empty() )
			++curr;

		dict->IncrIters();
		}

	DictIterator(const Dictionary<T>* d, detail::DictEntryVec::iterator iter) : ordered_iter(iter)
		{
		// Cast away the constness so that the number of iterators can be modified in the
		// dictionary. This does violate the constness guarantees of const-begin()/end() and
		// cbegin()/cend(), but we're not modifying the actual data in the collection, just a
		// counter in the wrapper of the collection.
		dict = const_cast<Dictionary<T>*>(d);
		dict->IncrIters();
		}

	Dictionary<T>* dict = nullptr;
	detail::DictEntry<T>* curr = nullptr;
	detail::DictEntry<T>* end = nullptr;
	detail::DictEntryVec::iterator ordered_iter;
	};

template <typename T> class RobustDictIterator
	{
public:
	using value_type = detail::DictEntry<T>;
	using reference = detail::DictEntry<T>&;
	using pointer = detail::DictEntry<T>*;
	using difference_type = std::ptrdiff_t;
	using iterator_category = std::forward_iterator_tag;

	RobustDictIterator() : curr(nullptr) { }

	RobustDictIterator(Dictionary<T>* d) : curr(nullptr), dict(d)
		{
		next = -1;
		inserted = new std::vector<detail::DictEntry<T>>();
		visited = new std::vector<detail::DictEntry<T>>();

		dict->IncrIters();
		dict->iterators->push_back(this);

		// Advance the iterator one step so that we're at the first element.
		curr = dict->GetNextRobustIteration(this);
		}

	RobustDictIterator(const RobustDictIterator& other) : curr(nullptr)
		{
		dict = nullptr;

		if ( other.dict )
			{
			next = other.next;
			inserted = new std::vector<detail::DictEntry<T>>();
			visited = new std::vector<detail::DictEntry<T>>();

			if ( other.inserted )
				std::copy(other.inserted->begin(), other.inserted->end(),
				          std::back_inserter(*inserted));

			if ( other.visited )
				std::copy(other.visited->begin(), other.visited->end(),
				          std::back_inserter(*visited));

			dict = other.dict;
			dict->IncrIters();
			dict->iterators->push_back(this);

			curr = other.curr;
			}
		}

	RobustDictIterator(RobustDictIterator&& other) noexcept : curr(nullptr)
		{
		dict = nullptr;

		if ( other.dict )
			{
			next = other.next;
			inserted = other.inserted;
			visited = other.visited;

			dict = other.dict;
			dict->iterators->push_back(this);
			dict->iterators->erase(
				std::remove(dict->iterators->begin(), dict->iterators->end(), &other),
				dict->iterators->end());
			other.dict = nullptr;

			curr = std::move(other.curr);
			}
		}

	~RobustDictIterator() { Complete(); }

	reference operator*() { return curr; }
	pointer operator->() { return &curr; }

	RobustDictIterator& operator++()
		{
		curr = dict->GetNextRobustIteration(this);
		return *this;
		}

	RobustDictIterator operator++(int)
		{
		auto temp(*this);
		++*this;
		return temp;
		}

	bool operator==(const RobustDictIterator& that) const { return curr == that.curr; }
	bool operator!=(const RobustDictIterator& that) const { return ! (*this == that); }

private:
	friend class Dictionary<T>;

	void Complete()
		{
		if ( dict )
			{
			assert(dict->num_iterators > 0);
			dict->DecrIters();

			dict->iterators->erase(
				std::remove(dict->iterators->begin(), dict->iterators->end(), this),
				dict->iterators->end());

			delete inserted;
			delete visited;

			inserted = nullptr;
			visited = nullptr;
			dict = nullptr;
			}
		}

	// Tracks the new entries inserted while iterating.
	std::vector<detail::DictEntry<T>>* inserted = nullptr;

	// Tracks the entries already visited but were moved across the next iteration
	// point due to an insertion.
	std::vector<detail::DictEntry<T>>* visited = nullptr;

	detail::DictEntry<T> curr;
	Dictionary<T>* dict = nullptr;
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
template <typename T> class Dictionary
	{
public:
	explicit Dictionary(DictOrder ordering = UNORDERED,
	                    int initial_size = detail::DEFAULT_DICT_SIZE)
		{
		if ( initial_size > 0 )
			{
			// If an initial size is specified, init the table right away. Otherwise wait until the
			// first insertion to init.
			SetLog2Buckets(static_cast<uint16_t>(std::log2(initial_size)));
			Init();
			}

		if ( ordering == ORDERED )
			order = std::make_unique<std::vector<detail::HashKey>>();
		}

	~Dictionary() { Clear(); }

	// Member functions for looking up a key, inserting/changing its
	// contents, and deleting it.  These come in two flavors: one
	// which takes a zeek::detail::HashKey, and the other which takes a raw key,
	// its size, and its (unmodulated) hash.
	// lookup may move the key to right place if in the old zone to speed up the next lookup.
	T* Lookup(const detail::HashKey* key) const
		{
		return Lookup(key->Key(), key->Size(), key->Hash());
		}

	T* Lookup(const void* key, int key_size, detail::hash_t h) const
		{
		if ( auto e = LookupEntry(key, key_size, h) )
			return e->value;

		return nullptr;
		}

	T* Lookup(const char* key) const
		{
		detail::HashKey h(key);
		return Dictionary<T>::Lookup(&h);
		}

	// Returns previous value, or 0 if none.
	// If iterators_invalidated is supplied, its value is set to true
	// if the removal may have invalidated any existing iterators.
	T* Insert(detail::HashKey* key, T* val, bool* iterators_invalidated = nullptr)
		{
		return Insert(key->TakeKey(), key->Size(), key->Hash(), val, false, iterators_invalidated);
		}

	// If copy_key is true, then the key is copied, otherwise it's assumed
	// that it's a heap pointer that now belongs to the Dictionary to
	// manage as needed.
	// If iterators_invalidated is supplied, its value is set to true
	// if the removal may have invalidated any existing iterators.
	T* Insert(void* key, int key_size, detail::hash_t hash, T* val, bool copy_key,
	          bool* iterators_invalidated = nullptr)
		{
		ASSERT_VALID(this);

		// Initialize the table if it hasn't been done yet. This saves memory storing a bunch
		// of empty dicts.
		if ( ! table )
			Init();

		T* v = nullptr;

		// Look to see if this key is already in the table. If found, insert_position is the
		// position of the existing element. If not, insert_position is where it'll be inserted
		// and insert_distance is the distance of the key for the position.
		int insert_position = -1, insert_distance = -1;
		int position = LookupIndex(key, key_size, hash, &insert_position, &insert_distance);
		if ( position >= 0 )
			{
			v = table[position].value;
			table[position].value = val;
			if ( ! copy_key )
				delete[](char*) key;

			if ( iterators && ! iterators->empty() )
				// need to set new v for iterators too.
				for ( auto c : *iterators )
					{
					// Check to see if this iterator points at the entry we're replacing. The
					// iterator keeps a copy of the element, so we need to update it too.
					if ( **c == table[position] )
						(*c)->value = val;

					// Check if any of the inserted elements in this iterator point at the entry
					// being replaced. Update those too.
					auto it = std::find(c->inserted->begin(), c->inserted->end(), table[position]);
					if ( it != c->inserted->end() )
						it->value = val;
					}
			}
		else
			{
			if ( ! HaveOnlyRobustIterators() )
				{
				if ( iterators_invalidated )
					*iterators_invalidated = true;
				else
					reporter->InternalWarning(
						"Dictionary::Insert() possibly caused iterator invalidation");
				}

			// Do this before the actual insertion since creating the DictEntry is going to delete
			// the key data. We need a copy of it first.
			if ( order )
				order->emplace_back(detail::HashKey{key, static_cast<size_t>(key_size), hash});

			// Allocate memory for key if necessary. Key is updated to reflect internal key if
			// necessary.
			detail::DictEntry<T> entry(key, key_size, hash, val, insert_distance, copy_key);
			InsertRelocateAndAdjust(entry, insert_position);

			num_entries++;
			cum_entries++;
			if ( max_entries < num_entries )
				max_entries = num_entries;
			if ( num_entries > ThresholdEntries() )
				SizeUp();

			// if space_distance is too great, performance decreases. we need to sizeup for
			// performance.
			else if ( space_distance_samples > detail::MIN_SPACE_DISTANCE_SAMPLES &&
			          static_cast<uint64_t>(space_distance_sum) >
			              static_cast<uint64_t>(space_distance_samples) *
			                  detail::SPACE_DISTANCE_THRESHOLD &&
			          static_cast<int>(num_entries) >
			              detail::MIN_DICT_LOAD_FACTOR_100 * Capacity() / 100 )
				SizeUp();
			}

		// Remap after insert can adjust asap to shorten period of mixed table.
		// TODO: however, if remap happens right after size up, then it consumes more cpu for this
		// cycle, a possible hiccup point.
		if ( Remapping() )
			Remap();
		ASSERT_VALID(this);
		return v;
		}

	T* Insert(const char* key, T* val, bool* iterators_invalidated = nullptr)
		{
		detail::HashKey h(key);
		return Insert(&h, val, iterators_invalidated);
		}

	// Removes the given element.  Returns a pointer to the element in
	// case it needs to be deleted.  Returns 0 if no such element exists.
	// If dontdelete is true, the key's bytes will not be deleted.
	// If iterators_invalidated is supplied, its value is set to true
	// if the removal may have invalidated any existing iterators.
	T* Remove(const detail::HashKey* key, bool* iterators_invalidated = nullptr)
		{
		return Remove(key->Key(), key->Size(), key->Hash(), false, iterators_invalidated);
		}
	T* Remove(const void* key, int key_size, detail::hash_t hash, bool dont_delete = false,
	          bool* iterators_invalidated = nullptr)
		{ // cookie adjustment: maintain inserts here. maintain next in lower level version.
		ASSERT_VALID(this);

		ASSERT(! dont_delete); // this is a poorly designed flag. if on, the internal has nowhere to
		                       // return and memory is lost.

		int position = LookupIndex(key, key_size, hash);
		if ( position < 0 )
			return nullptr;

		if ( ! HaveOnlyRobustIterators() )
			{
			if ( iterators_invalidated )
				*iterators_invalidated = true;
			else
				reporter->InternalWarning(
					"Dictionary::Remove() possibly caused iterator invalidation");
			}

		detail::DictEntry<T> entry = RemoveRelocateAndAdjust(position);
		num_entries--;
		ASSERT(num_entries >= 0);
		// e is about to be invalid. remove it from all references.
		if ( order )
			{
			for ( auto it = order->begin(); it != order->end(); ++it )
				{
				if ( it->Equal(key, key_size, hash) )
					{
					it = order->erase(it);
					break;
					}
				}
			}

		T* v = entry.value;
		entry.Clear();
		ASSERT_VALID(this);
		return v;
		}

	// TODO: these came from PDict. They could probably be deprecated and removed in favor of
	// just using Remove().
	T* RemoveEntry(const detail::HashKey* key, bool* iterators_invalidated = nullptr)
		{
		return Remove(key->Key(), key->Size(), key->Hash(), false, iterators_invalidated);
		}
	T* RemoveEntry(const detail::HashKey& key, bool* iterators_invalidated = nullptr)
		{
		return Remove(key.Key(), key.Size(), key.Hash(), false, iterators_invalidated);
		}

	// Number of entries.
	int Length() const { return num_entries; }

	// Largest it's ever been.
	int MaxLength() const { return max_entries; }

	// Total number of entries ever.
	uint64_t NumCumulativeInserts() const { return cum_entries; }

	// True if the dictionary is ordered, false otherwise.
	int IsOrdered() const { return order != nullptr; }

	// If the dictionary is ordered then returns the n'th entry's value;
	// the second method also returns the key.  The first entry inserted
	// corresponds to n=0.
	//
	// Returns nil if the dictionary is not ordered or if "n" is out
	// of range.
	T* NthEntry(int n) const
		{
		const void* key;
		int key_len;
		return NthEntry(n, key, key_len);
		}

	T* NthEntry(int n, const void*& key, int& key_size) const
		{
		if ( ! order || n < 0 || n >= Length() )
			return nullptr;

		auto& hk = order->at(n);
		auto entry = Lookup(&hk);

		key = hk.Key();
		key_size = hk.Size();
		return entry;
		}

	T* NthEntry(int n, const char*& key) const
		{
		int key_len;
		return NthEntry(n, (const void*&)key, key_len);
		}

	void SetDeleteFunc(dict_delete_func f) { delete_func = f; }

	// Remove all entries.
	void Clear()
		{
		if ( table )
			{
			for ( int i = Capacity() - 1; i >= 0; i-- )
				{
				if ( table[i].Empty() )
					continue;
				if ( delete_func )
					delete_func(table[i].value);
				table[i].Clear();
				}
			free(table);
			table = nullptr;
			}

		if ( order )
			order.reset();

		if ( iterators )
			{
			delete iterators;
			iterators = nullptr;
			}
		log2_buckets = 0;
		num_iterators = 0;
		remaps = 0;
		remap_end = -1;
		num_entries = 0;
		max_entries = 0;
		}

	/// The capacity of the table, Buckets + Overflow Size.
	int Capacity() const { return table ? bucket_capacity : 0; }
	int ExpectedCapacity() const { return bucket_capacity; }

	// Debugging
#define DUMPIF(f)                                                                                  \
	if ( f )                                                                                       \
	Dump(1)

#ifdef ZEEK_DICT_DEBUG
	void AssertValid() const
		{
		bool valid = true;
		int n = num_entries;

		if ( table )
			for ( int i = Capacity() - 1; i >= 0; i-- )
				if ( ! table[i].Empty() )
					n--;

		valid = (n == 0);
		ASSERT(valid);
		DUMPIF(! valid);

		// entries must clustered together
		for ( int i = 1; i < Capacity(); i++ )
			{
			if ( ! table || table[i].Empty() )
				continue;

			if ( table[i - 1].Empty() )
				{
				valid = (table[i].distance == 0);
				ASSERT(valid);
				DUMPIF(! valid);
				}
			else
				{
				valid = (table[i].bucket >= table[i - 1].bucket);
				ASSERT(valid);
				DUMPIF(! valid);

				if ( table[i].bucket == table[i - 1].bucket )
					{
					valid = (table[i].distance == table[i - 1].distance + 1);
					ASSERT(valid);
					DUMPIF(! valid);
					}
				else
					{
					valid = (table[i].distance <= table[i - 1].distance);
					ASSERT(valid);
					DUMPIF(! valid);
					}
				}
			}
		}
#endif // ZEEK_DICT_DEBUG

	void Dump(int level = 0) const
		{
		int key_size = 0;
		for ( int i = 0; i < Capacity(); i++ )
			{
			if ( table[i].Empty() )
				continue;
			key_size += zeek::util::pad_size(table[i].key_size);
			if ( ! table[i].value )
				continue;
			}

#define DICT_NUM_DISTANCES 5
		int distances[DICT_NUM_DISTANCES];
		int max_distance = 0;
		DistanceStats(max_distance, distances, DICT_NUM_DISTANCES);
		printf("cap %'7d ent %'7d %'-7d load %.2f max_dist %2d key/ent %3d lg "
		       "%2d remaps %1d remap_end %4d ",
		       Capacity(), Length(), MaxLength(), (double)Length() / (table ? Capacity() : 1),
		       max_distance, key_size / (Length() ? Length() : 1), log2_buckets, remaps, remap_end);
		if ( Length() > 0 )
			{
			for ( int i = 0; i < DICT_NUM_DISTANCES - 1; i++ )
				printf("[%d]%2d%% ", i, 100 * distances[i] / Length());
			printf("[%d+]%2d%% ", DICT_NUM_DISTANCES - 1,
			       100 * distances[DICT_NUM_DISTANCES - 1] / Length());
			}
		else
			printf("\n");

		printf("\n");
		if ( level >= 1 )
			{
			printf("%-10s %1s %-10s %-4s %-4s %-10s %-18s %-2s\n", "Index", "*", "Bucket", "Dist",
			       "Off", "Hash", "FibHash", "KeySize");
			for ( int i = 0; i < Capacity(); i++ )
				if ( table[i].Empty() )
					printf("%'10d \n", i);
				else
					printf("%'10d %1s %'10d %4d %4d 0x%08x 0x%016" PRIx64 "(%3d) %2d\n", i,
					       (i <= remap_end ? "*" : ""), BucketByPosition(i), (int)table[i].distance,
					       OffsetInClusterByPosition(i), uint(table[i].hash),
					       FibHash(table[i].hash), (int)FibHash(table[i].hash) & 0xFF,
					       (int)table[i].key_size);
			}
		}

	void DistanceStats(int& max_distance, int* distances = 0, int num_distances = 0) const
		{
		max_distance = 0;
		for ( int i = 0; i < num_distances; i++ )
			distances[i] = 0;

		for ( int i = 0; i < Capacity(); i++ )
			{
			if ( table[i].Empty() )
				continue;
			if ( table[i].distance > max_distance )
				max_distance = table[i].distance;
			if ( num_distances <= 0 || ! distances )
				continue;
			if ( table[i].distance >= num_distances - 1 )
				distances[num_distances - 1]++;
			else
				distances[table[i].distance]++;
			}
		}

	void DumpKeys() const
		{
		if ( ! table )
			return;

		char key_file[100];
		// Detect string or binary from first key.
		int i = 0;
		while ( table[i].Empty() && i < Capacity() )
			i++;

		bool binary = false;
		const char* key = table[i].GetKey();
		for ( int j = 0; j < table[i].key_size; j++ )
			if ( ! isprint(key[j]) )
				{
				binary = true;
				break;
				}
		int max_distance = 0;

		DistanceStats(max_distance);
		if ( binary )
			{
			char key = char(random() % 26) + 'A';
			sprintf(key_file, "%d.%d-%c.key", Length(), max_distance, key);
			std::ofstream f(key_file, std::ios::binary | std::ios::out | std::ios::trunc);
			for ( int idx = 0; idx < Capacity(); idx++ )
				if ( ! table[idx].Empty() )
					{
					int key_size = table[idx].key_size;
					f.write((const char*)&key_size, sizeof(int));
					f.write(table[idx].GetKey(), table[idx].key_size);
					}
			}
		else
			{
			char key = char(random() % 26) + 'A';
			sprintf(key_file, "%d.%d-%d.ckey", Length(), max_distance, key);
			std::ofstream f(key_file, std::ios::out | std::ios::trunc);
			for ( int idx = 0; idx < Capacity(); idx++ )
				if ( ! table[idx].Empty() )
					{
					std::string s((char*)table[idx].GetKey(), table[idx].key_size);
					f << s << std::endl;
					}
			}
		}

	// Type traits needed for some of the std algorithms to work
	using value_type = detail::DictEntry<T>;
	using pointer = detail::DictEntry<T>*;
	using const_pointer = const detail::DictEntry<T>*;

	// Iterator support
	using iterator = DictIterator<T>;
	using const_iterator = const iterator;
	using reverse_iterator = std::reverse_iterator<iterator>;
	using const_reverse_iterator = std::reverse_iterator<const_iterator>;

	iterator begin()
		{
		if ( IsOrdered() )
			return {this, order->begin()};

		return {this, table, table + Capacity()};
		}
	iterator end()
		{
		if ( IsOrdered() )
			return {this, order->end()};

		return {this, table + Capacity(), table + Capacity()};
		}
	const_iterator begin() const
		{
		if ( IsOrdered() )
			return {this, order->begin()};

		return {this, table, table + Capacity()};
		}
	const_iterator end() const
		{
		if ( IsOrdered() )
			return {this, order->end()};

		return {this, table + Capacity(), table + Capacity()};
		}
	const_iterator cbegin()
		{
		if ( IsOrdered() )
			return {this, order->begin()};

		return {this, table, table + Capacity()};
		}
	const_iterator cend()
		{
		if ( IsOrdered() )
			return {this, order->end()};

		return {this, table + Capacity(), table + Capacity()};
		}

	RobustDictIterator<T> begin_robust() { return MakeRobustIterator(); }
	RobustDictIterator<T> end_robust() { return RobustDictIterator<T>(); }

private:
	friend zeek::DictIterator<T>;
	friend zeek::RobustDictIterator<T>;

	void SetLog2Buckets(int value)
		{
		log2_buckets = value;
		bucket_count = 1 << log2_buckets;
		bucket_capacity = (1 << log2_buckets) + log2_buckets;
		}

	/// Buckets of the table, not including overflow size.
	int Buckets() const { return table ? bucket_count : 0; }

	// bucket math
	uint32_t ThresholdEntries() const
		{
		// Increase the size of the dictionary when it is 75% full. However, when the dictionary
		// is small ( bucket_capacity <= 2^3+3=11 elements ), only resize it when it's 100% full.
		// The dictionary will always resize when the current insertion causes it to be full. This
		// ensures that the current insertion should always be successful.
		int capacity = Capacity();
		if ( log2_buckets <= detail::DICT_THRESHOLD_BITS )
			return capacity;
		return capacity * detail::DICT_LOAD_FACTOR_100 / 100;
		}

	// Used to improve the distribution of the original hash.
	detail::hash_t FibHash(detail::hash_t h) const
		{
		// GoldenRatio phi = (sqrt(5)+1)/2 = 1.6180339887...
		// 1/phi = phi - 1
		h &= detail::HASH_MASK;
		h *= 11400714819323198485llu; // 2^64/phi
		return h;
		}

	// Maps a hash to the appropriate n-bit table bucket.
	int BucketByHash(detail::hash_t h, int bit) const
		{
		ASSERT(bit >= 0);
		if ( ! bit )
			return 0; //<< >> breaks on  64.

#ifdef DICT_NO_FIB_HASH
		detail::hash_t hash = h;
#else
		detail::hash_t hash = FibHash(h);
#endif

		int m = 64 - bit;
		hash <<= m;
		hash >>= m;

		return hash;
		}

	// Given a position of a non-empty item in the table, find the related bucket.
	int BucketByPosition(int position) const
		{
		ASSERT(table && position >= 0 && position < Capacity() && ! table[position].Empty());
		return position - table[position].distance;
		}

	// Given a bucket of a non-empty item in the table, find the end of its cluster.
	// The end should be equal to tail+1 if tail exists. Otherwise it's the tail of
	// the just-smaller cluster + 1.
	int EndOfClusterByBucket(int bucket) const
		{
		ASSERT(bucket >= 0 && bucket < Buckets());
		int i = bucket;
		int current_cap = Capacity();
		while ( i < current_cap && ! table[i].Empty() && BucketByPosition(i) <= bucket )
			i++;
		return i;
		}

	// Given a position of a non-empty item in the table, find the head of its cluster.
	int HeadOfClusterByPosition(int position) const
		{
		// Finding the first entry in the bucket chain.
		ASSERT(0 <= position && position < Capacity() && ! table[position].Empty());

		// Look backward for the first item with the same bucket as myself.
		int bucket = BucketByPosition(position);
		int i = position;
		while ( i >= bucket && BucketByPosition(i) == bucket )
			i--;

		return i == bucket ? i : i + 1;
		}

	// Given a position of a non-empty item in the table, find the tail of its cluster.
	int TailOfClusterByPosition(int position) const
		{
		ASSERT(0 <= position && position < Capacity() && ! table[position].Empty());

		int bucket = BucketByPosition(position);
		int i = position;
		int current_cap = Capacity();
		while ( i < current_cap && ! table[i].Empty() && BucketByPosition(i) == bucket )
			i++; // stop just over the tail.

		return i - 1;
		}

	// Given a position of a non-empty item in the table, find the end of its cluster.
	// The end should be equal to tail+1 if tail exists. Otherwise it's the tail of
	// the just-smaller cluster + 1.
	int EndOfClusterByPosition(int position) const { return TailOfClusterByPosition(position) + 1; }

	// Given a position of a non-empty item in the table, find the offset of it within
	// its cluster.
	int OffsetInClusterByPosition(int position) const
		{
		ASSERT(0 <= position && position < Capacity() && ! table[position].Empty());
		int head = HeadOfClusterByPosition(position);
		return position - head;
		}

	// Next non-empty item position in the table, starting at the specified position.
	int Next(int position) const
		{
		ASSERT(table && -1 <= position && position < Capacity());

		int current_cap = Capacity();
		do
			{
			position++;
			} while ( position < current_cap && table[position].Empty() );

		return position;
		}

	void Init()
		{
		ASSERT(! table);
		table = (detail::DictEntry<T>*)malloc(sizeof(detail::DictEntry<T>) * ExpectedCapacity());
		for ( int i = Capacity() - 1; i >= 0; i-- )
			table[i].SetEmpty();
		}

	// Lookup
	int LinearLookupIndex(const void* key, int key_size, detail::hash_t hash) const
		{
		auto current_cap = Capacity();
		for ( int i = 0; i < current_cap; i++ )
			if ( ! table[i].Empty() && table[i].Equal((const char*)key, key_size, hash) )
				return i;
		return -1;
		}

	// Lookup position for all possible table_sizes caused by remapping. Remap it immediately
	// if not in the middle of iteration.
	int LookupIndex(const void* key, int key_size, detail::hash_t hash,
	                int* insert_position = nullptr, int* insert_distance = nullptr)
		{
		ASSERT_VALID(this);
		if ( ! table )
			return -1;

		int bucket = BucketByHash(hash, log2_buckets);
#ifdef ZEEK_DICT_DEBUG
		int linear_position = LinearLookupIndex(key, key_size, hash);
#endif // ZEEK_DICT_DEBUG
		int position = LookupIndex(key, key_size, hash, bucket, Capacity(), insert_position,
		                           insert_distance);
		if ( position >= 0 )
			{
			ASSERT_EQUAL(position, linear_position); // same as linearLookup
			return position;
			}

		for ( int i = 1; i <= remaps; i++ )
			{
			int prev_bucket = BucketByHash(hash, log2_buckets - i);
			if ( prev_bucket <= remap_end )
				{
				// possibly here. insert_position & insert_distance returned on failed lookup is
				// not valid in previous table_sizes.
				position = LookupIndex(key, key_size, hash, prev_bucket, remap_end + 1);
				if ( position >= 0 )
					{
					ASSERT_EQUAL(position, linear_position); // same as linearLookup
					// remap immediately if no iteration is on.
					if ( ! num_iterators )
						{
						Remap(position, &position);
						ASSERT_EQUAL(position, LookupIndex(key, key_size, hash));
						}
					return position;
					}
				}
			}
		// not found
#ifdef ZEEK_DICT_DEBUG
		if ( linear_position >= 0 )
			{ // different. stop and try to see whats happening.
			ASSERT(false);
			// rerun the function in debugger to track down the bug.
			LookupIndex(key, key_size, hash);
			}
#endif // ZEEK_DICT_DEBUG
		return -1;
		}

	// Returns the position of the item if it exists. Otherwise returns -1, but set the insert
	// position/distance if required. The starting point for the search may not be the bucket
	// for the current table size since this method is also used to search for an item in the
	// previous table size.
	int LookupIndex(const void* key, int key_size, detail::hash_t hash, int begin, int end,
	                int* insert_position = nullptr, int* insert_distance = nullptr)
		{
		ASSERT(begin >= 0 && begin < Buckets());
		int i = begin;
		for ( ; i < end && ! table[i].Empty() && BucketByPosition(i) <= begin; i++ )
			if ( BucketByPosition(i) == begin && table[i].Equal((char*)key, key_size, hash) )
				return i;

		// no such cluster, or not found in the cluster.
		if ( insert_position )
			*insert_position = i;

		if ( insert_distance )
			{
			*insert_distance = i - begin;

			if ( *insert_distance >= detail::TOO_FAR_TO_REACH )
				reporter->FatalErrorWithCore("Dictionary (size %d) insertion distance too far: %d",
				                             Length(), *insert_distance);
			}

		return -1;
		}

	/// Insert entry, Adjust iterators when necessary.
	void InsertRelocateAndAdjust(detail::DictEntry<T>& entry, int insert_position)
		{
/// e.distance is adjusted to be the one at insert_position.
#ifdef DEBUG
		entry.bucket = BucketByHash(entry.hash, log2_buckets);
#endif // DEBUG
		int last_affected_position = insert_position;
		InsertAndRelocate(entry, insert_position, &last_affected_position);
		space_distance_sum += last_affected_position - insert_position;
		space_distance_samples++;

		// If remapping in progress, adjust the remap_end to step back a little to cover the new
		// range if the changed range straddles over remap_end.
		if ( Remapping() && insert_position <= remap_end && remap_end < last_affected_position )
			{ //[i,j] range changed. if map_end in between. then possibly old entry pushed down
			  // across
			  // map_end.
			remap_end = last_affected_position; // adjust to j on the conservative side.
			}

		if ( iterators && ! iterators->empty() )
			for ( auto c : *iterators )
				AdjustOnInsert(c, entry, insert_position, last_affected_position);
		}

	/// insert entry into position, relocate other entries when necessary.
	void InsertAndRelocate(detail::DictEntry<T>& entry, int insert_position,
	                       int* last_affected_position = nullptr)
		{ /// take out the head of cluster and append to the end of the cluster.
		while ( true )
			{
			if ( insert_position >= Capacity() )
				{
				ASSERT(insert_position == Capacity());
				SizeUp(); // copied all the items to new table. as it's just copying without
				          // remapping, insert_position is now empty.
				table[insert_position] = entry;
				if ( last_affected_position )
					*last_affected_position = insert_position;
				return;
				}
			if ( table[insert_position].Empty() )
				{ // the condition to end the loop.
				table[insert_position] = entry;
				if ( last_affected_position )
					*last_affected_position = insert_position;
				return;
				}

			// the to-be-swapped-out item appends to the end of its original cluster.
			auto t = table[insert_position];
			int next = EndOfClusterByPosition(insert_position);
			t.distance += next - insert_position;

			// swap
			table[insert_position] = entry;
			entry = t;
			insert_position = next; // append to the end of the current cluster.
			}
		}

	/// Adjust Iterators on Insert.
	void AdjustOnInsert(RobustDictIterator<T>* c, const detail::DictEntry<T>& entry,
	                    int insert_position, int last_affected_position)
		{
		// See note in Dictionary::AdjustOnInsert() above.
		c->inserted->erase(std::remove(c->inserted->begin(), c->inserted->end(), entry),
		                   c->inserted->end());
		c->visited->erase(std::remove(c->visited->begin(), c->visited->end(), entry),
		                  c->visited->end());

		if ( insert_position < c->next )
			c->inserted->push_back(entry);
		if ( insert_position < c->next && c->next <= last_affected_position )
			{
			int k = TailOfClusterByPosition(c->next);
			ASSERT(k >= 0 && k < Capacity());
			c->visited->push_back(table[k]);
			}
		}

	/// Remove, Relocate & Adjust iterators.
	detail::DictEntry<T> RemoveRelocateAndAdjust(int position)
		{
		int last_affected_position = position;
		detail::DictEntry<T> entry = RemoveAndRelocate(position, &last_affected_position);

#ifdef ZEEK_DICT_DEBUG
		// validation: index to i-1 should be continuous without empty spaces.
		for ( int k = position; k < last_affected_position; k++ )
			ASSERT(! table[k].Empty());
#endif // ZEEK_DICT_DEBUG

		if ( iterators && ! iterators->empty() )
			for ( auto c : *iterators )
				AdjustOnRemove(c, entry, position, last_affected_position);

		return entry;
		}

	/// Remove & Relocate
	detail::DictEntry<T> RemoveAndRelocate(int position, int* last_affected_position = nullptr)
		{
		// fill the empty position with the tail of the cluster of position+1.
		ASSERT(position >= 0 && position < Capacity() && ! table[position].Empty());

		detail::DictEntry<T> entry = table[position];
		while ( true )
			{
			if ( position == Capacity() - 1 || table[position + 1].Empty() ||
			     table[position + 1].distance == 0 )
				{
				// no next cluster to fill, or next position is empty or next position is already in
				// perfect bucket.
				table[position].SetEmpty();
				if ( last_affected_position )
					*last_affected_position = position;
				return entry;
				}
			int next = TailOfClusterByPosition(position + 1);
			table[position] = table[next];
			table[position].distance -= next - position; // distance improved for the item.
			position = next;
			}

		return entry;
		}

	/// Adjust safe iterators after Removal of entry at position.
	void AdjustOnRemove(RobustDictIterator<T>* c, const detail::DictEntry<T>& entry, int position,
	                    int last_affected_position)
		{
		// See note in Dictionary::AdjustOnInsert() above.
		c->inserted->erase(std::remove(c->inserted->begin(), c->inserted->end(), entry),
		                   c->inserted->end());
		c->visited->erase(std::remove(c->visited->begin(), c->visited->end(), entry),
		                  c->visited->end());

		if ( position < c->next && c->next <= last_affected_position )
			{
			int moved = HeadOfClusterByPosition(c->next - 1);
			if ( moved < position )
				moved = position;
			c->inserted->push_back(table[moved]);
			}

		// if not already the end of the dictionary, adjust next to a valid one.
		if ( c->next < Capacity() && table[c->next].Empty() )
			c->next = Next(c->next);

		if ( c->curr == entry )
			{
			if ( c->next >= 0 && c->next < Capacity() && ! table[c->next].Empty() )
				c->curr = table[c->next];
			else
				c->curr = detail::DictEntry<T>(nullptr); // -> c == end_robust()
			}
		}

	bool Remapping() const { return remap_end >= 0; } // remap in reverse order.

	/// One round of remap.
	void Remap()
		{
		/// since remap should be very fast. take more at a time.
		/// delay Remap when cookie is there. hard to handle cookie iteration while size changes.
		/// remap from bottom up.
		/// remap creates two parts of the dict: [0,remap_end] (remap_end, ...]. the former is mixed
		/// with old/new entries; the latter contains all new entries.
		///
		if ( num_iterators > 0 )
			return;

		int left = detail::DICT_REMAP_ENTRIES;
		while ( remap_end >= 0 && left > 0 )
			{
			if ( ! table[remap_end].Empty() && Remap(remap_end) )
				left--;
			else //< successful Remap may increase remap_end in the case of SizeUp due to insert. if
			     // so,
			     // remap_end need to be worked on again.
				remap_end--;
			}
		if ( remap_end < 0 )
			remaps = 0; // done remapping.
		}

	// Remap an item in position to a new position. Returns true if the relocation was
	// successful, false otherwise. new_position will be set to the new position if a
	// pointer is provided to store the new value.
	bool Remap(int position, int* new_position = nullptr)
		{
		ASSERT_VALID(this);
		/// Remap changes item positions by remove() and insert(). to avoid excessive operation.
		/// avoid it when safe iteration is in progress.
		ASSERT(! iterators || iterators->empty());
		int current = BucketByPosition(position); // current bucket
		int expected = BucketByHash(table[position].hash, log2_buckets); // expected bucket in new
		                                                                 // table.
		// equal because 1: it's a new item, 2: it's an old item, but new bucket is the same as old.
		// 50% of old items act this way due to fibhash.
		if ( current == expected )
			return false;
		detail::DictEntry<T> entry = RemoveAndRelocate(
			position); // no iteration cookies to adjust, no need for last_affected_position.
#ifdef DEBUG
		entry.bucket = expected;
#endif // DEBUG

		// find insert position.
		int insert_position = EndOfClusterByBucket(expected);
		if ( new_position )
			*new_position = insert_position;
		entry.distance = insert_position - expected;
		InsertAndRelocate(
			entry,
			insert_position); // no iteration cookies to adjust, no need for last_affected_position.
		ASSERT_VALID(this);
		return true;
		}

	void SizeUp()
		{
		int prev_capacity = Capacity();
		SetLog2Buckets(log2_buckets + 1);

		int capacity = Capacity();
		table = (detail::DictEntry<T>*)realloc(table, capacity * sizeof(detail::DictEntry<T>));
		for ( int i = prev_capacity; i < capacity; i++ )
			table[i].SetEmpty();

		// REmap from last to first in reverse order. SizeUp can be triggered by 2 conditions, one
		// of which is that the last space in the table is occupied and there's nowhere to put new
		// items. In this case, the table doubles in capacity and the item is put at the
		// prev_capacity position with the old hash. We need to cover this item (?).
		remap_end = prev_capacity; // prev_capacity instead of prev_capacity-1.

		// another remap starts.
		remaps++; // used in Lookup() to cover SizeUp with incomplete remaps.
		ASSERT(remaps <= log2_buckets); // because we only sizeUp, one direction. we know the
		                                // previous log2_buckets.
		// reset performance metrics.
		space_distance_sum = 0;
		space_distance_samples = 0;
		}

	/**
	 * Retrieves a pointer to a full DictEntry in the table based on a hash key.
	 *
	 * @param key the key to lookup.
	 * @return A pointer to the entry or a nullptr if no entry has a matching key.
	 */
	detail::DictEntry<T>* LookupEntry(const detail::HashKey& key)
		{
		return LookupEntry(key.Key(), key.Size(), key.Hash());
		}

	/**
	 * Retrieves a pointer to a full DictEntry in the table based on key data.
	 *
	 * @param key the key to lookup
	 * @param key_size the size of the key data
	 * @param h a hash of the key data.
	 * @return A pointer to the entry or a nullptr if no entry has a matching key.
	 */
	detail::DictEntry<T>* LookupEntry(const void* key, int key_size, detail::hash_t h) const
		{
		// Look up possibly modifies the entry. Why? if the entry is found but not positioned
		// according to the current dict (so it's before SizeUp), it will be moved to the right
		// position so next lookup is fast.
		Dictionary* d = const_cast<Dictionary*>(this);
		int position = d->LookupIndex(key, key_size, h);
		return position >= 0 ? &(table[position]) : nullptr;
		}

	bool HaveOnlyRobustIterators() const
		{
		return (num_iterators == 0) || ((iterators ? iterators->size() : 0) == num_iterators);
		}

	RobustDictIterator<T> MakeRobustIterator()
		{
		if ( IsOrdered() )
			reporter->InternalError(
				"RobustIterators are not currently supported for ordered dictionaries");

		if ( ! iterators )
			iterators = new std::vector<RobustDictIterator<T>*>;

		return {this};
		}

	detail::DictEntry<T> GetNextRobustIteration(RobustDictIterator<T>* iter)
		{
		// If there's no table in the dictionary, then the iterator needs to be
		// cleaned up because it's not pointing at anything.
		if ( ! table )
			{
			iter->Complete();
			return detail::DictEntry<T>(nullptr); // end of iteration
			}

		// If there are any inserted entries, return them first.
		// That keeps the list small and helps avoiding searching
		// a large list when deleting an entry.
		if ( iter->inserted && ! iter->inserted->empty() )
			{
			// Return the last one. Order doesn't matter,
			// and removing from the tail is cheaper.
			detail::DictEntry<T> e = iter->inserted->back();
			iter->inserted->pop_back();
			return e;
			}

		// First iteration.
		if ( iter->next < 0 )
			iter->next = Next(-1);

		if ( iter->next < Capacity() && table[iter->next].Empty() )
			{
			// [Robin] I believe this means that the table has resized in a way
			// that we're now inside the overflow area where elements are empty,
			// because elsewhere empty slots aren't allowed. Assuming that's right,
			// then it means we'll always be at the end of the table now and could
			// also just set `next` to capacity. However, just to be sure, we
			// instead reuse logic from below to move forward "to a valid position"
			// and then double check, through an assertion in debug mode, that it's
			// actually the end. If this ever triggered, the above assumption would
			// be wrong (but the Next() call would probably still be right).
			iter->next = Next(iter->next);
			ASSERT(iter->next == Capacity());
			}

		// Filter out visited keys.
		int capacity = Capacity();
		if ( iter->visited && ! iter->visited->empty() )
			// Filter out visited entries.
			while ( iter->next < capacity )
				{
				ASSERT(! table[iter->next].Empty());
				auto it = std::find(iter->visited->begin(), iter->visited->end(),
				                    table[iter->next]);
				if ( it == iter->visited->end() )
					break;
				iter->visited->erase(it);
				iter->next = Next(iter->next);
				}

		if ( iter->next >= capacity )
			{
			iter->Complete();
			return detail::DictEntry<T>(nullptr); // end of iteration
			}

		ASSERT(! table[iter->next].Empty());
		detail::DictEntry<T> e = table[iter->next];

		// prepare for next time.
		iter->next = Next(iter->next);
		return e;
		}

	void IncrIters() { ++num_iterators; }
	void DecrIters() { --num_iterators; }

	// aligned on 8-bytes with 4-leading bytes. 7*8=56 bytes a dictionary.

	// when sizeup but the current mapping is in progress. the current mapping will be ignored
	// as it will be remapped to new dict size anyway. however, the missed count is recorded
	// for lookup. if position not found for a key in the position of dict of current size, it
	// still could be in the position of dict of previous N sizes.
	uint16_t remaps = 0;
	uint16_t log2_buckets = 0;
	uint32_t bucket_capacity = 1;
	uint32_t bucket_count = 1;

	// Pending number of iterators on the Dict, including both robust and non-robust.
	// This is used to avoid remapping if there are any active iterators.
	uint16_t num_iterators = 0;

	// The last index to be remapped.
	int32_t remap_end = -1;

	uint32_t num_entries = 0;
	uint32_t max_entries = 0;
	uint64_t cum_entries = 0;
	uint32_t space_distance_samples = 0;
	// how far the space is
	int64_t space_distance_sum = 0;

	dict_delete_func delete_func = nullptr;
	detail::DictEntry<T>* table = nullptr;
	std::vector<RobustDictIterator<T>*>* iterators = nullptr;

	// Ordered dictionaries keep the order based on some criteria, by default the order of
	// insertion. We only store a copy of the keys here for memory savings and for safety
	// around reallocs and such.
	std::unique_ptr<detail::DictEntryVec> order;
	};

template <typename T> using PDict = Dictionary<T>;

	} // namespace zeek
