// See the file "COPYING" in the main distribution directory for copyright.

#ifdef USE_OPEN_DICT

#include "OpenDict.cc"

#else//USE_OPEN_DICT

#include "zeek-config.h"

#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

#include "3rdparty/doctest.h"

#include "Dict.h"
#include "Reporter.h"

// If the mean bucket length exceeds the following then Insert() will
// increase the size of the hash table.
constexpr double DEFAULT_DENSITY_THRESH = 3.0;

// Threshold above which we do not try to ensure that the hash size
// is prime.
constexpr int PRIME_THRESH = 1000;

// Default number of hash buckets in dictionary.  The dictionary will
// increase the size of the hash table as needed.
constexpr int DEFAULT_DICT_SIZE = 16;

namespace zeek {
namespace detail {

class DictEntry {
public:
	DictEntry(void* k, int l, hash_t h, void* val) : key(k), len(l), hash(h), value(val) {}

	~DictEntry()
		{
		delete [] (char*) key;
		}

	void* key;
	int len;
	hash_t hash;
	void* value;
};

} //namespace detail

// The value of an iteration cookie is the bucket and offset within the
// bucket at which to start looking for the next value to return.
class IterCookie {
public:
	IterCookie(int b, int o) : bucket(b), offset(o) {}

	int bucket, offset;
	zeek::PList<detail::DictEntry>** ttbl = nullptr;
	const int* num_buckets_p = nullptr;
	zeek::PList<detail::DictEntry> inserted;	// inserted while iterating
};

} // namespace zeek

TEST_SUITE_BEGIN("Dict");

TEST_CASE("dict construction")
	{
	zeek::PDict<int> dict;
	CHECK(dict.IsOrdered() == false);
	CHECK(dict.Length() == 0);

	zeek::PDict<int> dict2(zeek::ORDERED);
	CHECK(dict2.IsOrdered() == true);
	CHECK(dict2.Length() == 0);
	}

TEST_CASE("dict operation")
	{
	zeek::PDict<uint32_t> dict;

	uint32_t val = 10;
	uint32_t key_val = 5;

	HashKey* key = new HashKey(key_val);
	dict.Insert(key, &val);
	CHECK(dict.Length() == 1);

	HashKey* key2 = new HashKey(key_val);
	uint32_t* lookup = dict.Lookup(key2);
	CHECK(*lookup == val);

	dict.Remove(key2);
	CHECK(dict.Length() == 0);
	uint32_t* lookup2 = dict.Lookup(key2);
	CHECK(lookup2 == (uint32_t*)nullptr);
	delete key2;

	CHECK(dict.MaxLength() == 1);
	CHECK(dict.NumCumulativeInserts() == 1);

	dict.Insert(key, &val);
	dict.Remove(key);

	CHECK(dict.MaxLength() == 1);
	CHECK(dict.NumCumulativeInserts() == 2);

	uint32_t val2 = 15;
	uint32_t key_val2 = 25;
	key2 = new HashKey(key_val2);

	dict.Insert(key, &val);
	dict.Insert(key2, &val2);
	CHECK(dict.Length() == 2);
	CHECK(dict.NumCumulativeInserts() == 4);

	dict.Clear();
	CHECK(dict.Length() == 0);

	delete key;
	delete key2;
	}

TEST_CASE("dict nthentry")
	{
	zeek::PDict<uint32_t> unordered(zeek::UNORDERED);
	zeek::PDict<uint32_t> ordered(zeek::ORDERED);

	uint32_t val = 15;
	uint32_t key_val = 5;
	HashKey* okey = new HashKey(key_val);
	HashKey* ukey = new HashKey(key_val);

	uint32_t val2 = 10;
	uint32_t key_val2 = 25;
	HashKey* okey2 = new HashKey(key_val2);
	HashKey* ukey2 = new HashKey(key_val2);

	unordered.Insert(ukey, &val);
	unordered.Insert(ukey2, &val2);

	ordered.Insert(okey, &val);
	ordered.Insert(okey2, &val2);

	// NthEntry returns null for unordered dicts
	uint32_t* lookup = unordered.NthEntry(0);
	CHECK(lookup == (uint32_t*)nullptr);

	// Ordered dicts are based on order of insertion, nothing about the
	// data itself
	lookup = ordered.NthEntry(0);
	CHECK(*lookup == 15);

	delete okey;
	delete okey2;
	delete ukey;
	delete ukey2;
	}

TEST_CASE("dict iteration")
	{
	zeek::PDict<uint32_t> dict;

	uint32_t val = 15;
	uint32_t key_val = 5;
	HashKey* key = new HashKey(key_val);

	uint32_t val2 = 10;
	uint32_t key_val2 = 25;
	HashKey* key2 = new HashKey(key_val2);

	dict.Insert(key, &val);
	dict.Insert(key2, &val2);

	HashKey* it_key;
	zeek::IterCookie* it = dict.InitForIteration();
	CHECK(it != nullptr);
	int count = 0;

	while ( uint32_t* entry = dict.NextEntry(it_key, it) )
		{
		if ( count == 0 )
			{
			CHECK(it_key->Hash() == key2->Hash());
			CHECK(*entry == 10);
			}
		else
			{
			CHECK(it_key->Hash() == key->Hash());
			CHECK(*entry == 15);
			}
		count++;

		delete it_key;
		}

	delete key;
	delete key2;
	}

TEST_SUITE_END();

namespace zeek {

Dictionary::Dictionary(DictOrder ordering, int initial_size)
	{
	if ( ordering == ORDERED )
		order = new zeek::PList<detail::DictEntry>;

	if ( initial_size > 0 )
		Init(initial_size);
	}

Dictionary::~Dictionary()
	{
	DeInit();
	delete order;
	}

void Dictionary::Clear()
	{
	DeInit();
	tbl = nullptr;
	tbl2 = nullptr;
	num_entries = 0;
	num_entries2 = 0;
	}

void Dictionary::DeInit()
	{
	if ( ! tbl )
		return;

	for ( int i = 0; i < num_buckets; ++i )
		if ( tbl[i] )
			{
			zeek::PList<detail::DictEntry>* chain = tbl[i];
			for ( const auto& e : *chain )
				{
				if ( delete_func )
					delete_func(e->value);
				delete e;
				}

			delete chain;
			}

	delete [] tbl;
	tbl = nullptr;

	if ( ! tbl2 )
		return;

	for ( int i = 0; i < num_buckets2; ++i )
		if ( tbl2[i] )
			{
			zeek::PList<detail::DictEntry>* chain = tbl2[i];
			for ( const auto& e : *chain )
				{
				if ( delete_func )
					delete_func(e->value);
				delete e;
				}

			delete chain;
			}

	delete [] tbl2;
	tbl2 = nullptr;
	}

void* Dictionary::Lookup(const void* key, int key_size, hash_t hash) const
	{
	if ( ! tbl && ! tbl2 )
		return nullptr;

	hash_t h;
	zeek::PList<detail::DictEntry>* chain;

	// Figure out which hash table to look in.
	h = hash % num_buckets;
	if ( ! tbl2 || h >= tbl_next_ind )
		chain = tbl[h];
	else
		chain = tbl2[hash % num_buckets2];

	if ( chain )
		{
		for ( const auto& entry : *chain )
			{
			if ( entry->hash == hash && entry->len == key_size &&
			     ! memcmp(key, entry->key, key_size) )
				return entry->value;
			}
		}

	return nullptr;
	}

void* Dictionary::Insert(void* key, int key_size, hash_t hash, void* val,
				bool copy_key)
	{
	if ( ! tbl )
		Init(DEFAULT_DICT_SIZE);

	detail::DictEntry* new_entry = new detail::DictEntry(key, key_size, hash, val);
	void* old_val = Insert(new_entry, copy_key);

	if ( old_val )
		{
		// We didn't need the new detail::DictEntry, the key was already
		// present.
		delete new_entry;
		}
	else if ( order )
		order->push_back(new_entry);

	// Resize logic.
	if ( tbl2 )
		MoveChains();
	else if ( num_entries >= thresh_entries )
		StartChangeSize(num_buckets * 2 + 1);

	return old_val;
	}

void* Dictionary::Remove(const void* key, int key_size, hash_t hash,
				bool dont_delete)
	{
	if ( ! tbl && ! tbl2 )
		return nullptr;

	hash_t h;
	zeek::PList<detail::DictEntry>* chain;
	int* num_entries_ptr;

	// Figure out which hash table to look in
	h = hash % num_buckets;
	if ( ! tbl2 || h >= tbl_next_ind )
		{
		chain = tbl[h];
		num_entries_ptr = &num_entries;
		}
	else
		{
		chain = tbl2[hash % num_buckets2];
		num_entries_ptr = &num_entries2;
		}

	if ( ! chain )
		return nullptr;

	size_t chain_length = chain->length();

	for ( auto i = 0u; i < chain_length; ++i )
		{
		detail::DictEntry* entry = (*chain)[i];

		if ( entry->hash == hash && entry->len == key_size &&
		     ! memcmp(key, entry->key, key_size) )
			{
			void* entry_value = DoRemove(entry, h, chain, i);

			if ( dont_delete )
				entry->key = nullptr;

			delete entry;
			--*num_entries_ptr;
			return entry_value;
			}
		}

	return nullptr;
	}

void* Dictionary::DoRemove(detail::DictEntry* entry, hash_t h,
				zeek::PList<detail::DictEntry>* chain, int chain_offset)
	{
	void* entry_value = entry->value;

	chain->remove_nth(chain_offset);
	if ( order )
		order->remove(entry);

	// Adjust existing cookies.
	for ( const auto& c : cookies )
		{
		// Is the affected bucket the current one?
		if ( (unsigned int) c->bucket == h )
			{
			if ( c->offset > chain_offset )
				--c->offset;

			// The only other important case here occurs when we
			// are deleting the current entry which
			// simultaniously happens to be the last one in this
			// bucket. This means that we would have to move on
			// to the next non-empty bucket. Fortunately,
			// NextEntry() will do exactly the right thing in
			// this case. :-)
			}

		// This item may have been inserted during this iteration.
		if ( (unsigned int) c->bucket > h )
			c->inserted.remove(entry);
		}

	return entry_value;
	}

void* Dictionary::NthEntry(int n, const void*& key, int& key_len) const
	{
	if ( ! order || n < 0 || n >= Length() )
		return nullptr;

	detail::DictEntry* entry = (*order)[n];
	key = entry->key;
	key_len = entry->len;
	return entry->value;
	}

IterCookie* Dictionary::InitForIteration() const
	{
	return new IterCookie(0, 0);
	}

void Dictionary::StopIteration(IterCookie* cookie) const
	{
	delete cookie;
	}

void* Dictionary::NextEntry(HashKey*& h, IterCookie*& cookie, int return_hash) const
	{
	if ( ! tbl && ! tbl2 )
		{
		const_cast<zeek::PList<IterCookie>*>(&cookies)->remove(cookie);
		delete cookie;
		cookie = nullptr;
		return nullptr;
		}

	// If there are any inserted entries, return them first.
	// That keeps the list small and helps avoiding searching
	// a large list when deleting an entry.

	detail::DictEntry* entry;

	if ( cookie->inserted.length() )
		{
		// Return the last one. Order doesn't matter,
		// and removing from the tail is cheaper.
		entry = cookie->inserted.remove_nth(cookie->inserted.length()-1);
		if ( return_hash )
			h = new HashKey(entry->key, entry->len, entry->hash);

		return entry->value;
		}

	int b = cookie->bucket;
	int o = cookie->offset;
	zeek::PList<detail::DictEntry>** ttbl;
	const int* num_buckets_p;

	if ( ! cookie->ttbl )
		{
		// XXX maybe we could update cookie->b from tbl_next_ind here?
		cookie->ttbl = tbl;
		cookie->num_buckets_p = &num_buckets;
		}

	ttbl = cookie->ttbl;
	num_buckets_p = cookie->num_buckets_p;

	if ( ttbl[b] && ttbl[b]->length() > o )
		{
		entry = (*ttbl[b])[o];
		++cookie->offset;
		if ( return_hash )
			h = new HashKey(entry->key, entry->len, entry->hash);
		return entry->value;
		}

	++b;	// Move on to next non-empty bucket.
	while ( b < *num_buckets_p && (! ttbl[b] || ttbl[b]->length() == 0) )
		++b;

	if ( b >= *num_buckets_p )
		{
		// If we're resizing, we need to search the 2nd table too.
		if ( ttbl == tbl && tbl2 )
			{
			cookie->ttbl = tbl2;
			cookie->num_buckets_p = &num_buckets2;
			cookie->bucket = 0;
			cookie->offset = 0;
			return Dictionary::NextEntry(h, cookie, return_hash);
			}

		// All done.

		// FIXME: I don't like removing the const here. But is there
		// a better way?
		const_cast<zeek::PList<IterCookie>*>(&cookies)->remove(cookie);
		delete cookie;
		cookie = nullptr;
		return nullptr;
		}

	entry = (*ttbl[b])[0];
	if ( return_hash )
		h = new HashKey(entry->key, entry->len, entry->hash);

	cookie->bucket = b;
	cookie->offset = 1;

	return entry->value;
	}

void Dictionary::Init(int size)
	{
	num_buckets = NextPrime(size);
	tbl = new zeek::PList<detail::DictEntry>*[num_buckets];

	for ( int i = 0; i < num_buckets; ++i )
		tbl[i] = nullptr;

	max_num_entries = num_entries = 0;
	SetDensityThresh(DEFAULT_DENSITY_THRESH);
	}

void Dictionary::Init2(int size)
	{
	num_buckets2 = NextPrime(size);
	tbl2 = new zeek::PList<detail::DictEntry>*[num_buckets2];

	for ( int i = 0; i < num_buckets2; ++i )
		tbl2[i] = nullptr;

	max_num_entries2 = num_entries2 = 0;
	}

// private
void* Dictionary::Insert(detail::DictEntry* new_entry, bool copy_key)
	{
	if ( ! tbl )
		Init(DEFAULT_DICT_SIZE);

	zeek::PList<detail::DictEntry>** ttbl;
	int* num_entries_ptr;
	int* max_num_entries_ptr;
	hash_t h = new_entry->hash % num_buckets;

	// We must be careful when we are in the middle of resizing.
	// If the new entry hashes to a bucket in the old table we
	// haven't moved yet, we need to put it in the old table. If
	// we didn't do it this way, we would sometimes have to
	// search both tables which is probably more expensive.

	if ( ! tbl2 || h >= tbl_next_ind )
		{
		ttbl = tbl;
		num_entries_ptr = &num_entries;
		max_num_entries_ptr = &max_num_entries;
		}
	else
		{
		ttbl = tbl2;
		h = new_entry->hash % num_buckets2;
		num_entries_ptr = &num_entries2;
		max_num_entries_ptr = &max_num_entries2;
		}

	zeek::PList<detail::DictEntry>* chain = ttbl[h];

	int n = new_entry->len;

	if ( chain )
		{
		for ( int i = 0; i < chain->length(); ++i )
			{
			detail::DictEntry* entry = (*chain)[i];

			if ( entry->hash == new_entry->hash &&
			     entry->len == n &&
			     ! memcmp(entry->key, new_entry->key, n) )
				{
				void* old_value = entry->value;
				entry->value = new_entry->value;
				return old_value;
				}
			}
		}
	else
		// Create new chain.
		chain = ttbl[h] = new zeek::PList<detail::DictEntry>;

	// If we got this far, then we couldn't use an existing copy
	// of the key, so make a new one if necessary.
	if ( copy_key )
		{
		void* old_key = new_entry->key;
		new_entry->key = (void*) new char[n];
		memcpy(new_entry->key, old_key, n);
		delete (char*) old_key;
		}

	// We happen to know (:-() that appending is more efficient
	// on lists than prepending.
	chain->push_back(new_entry);

	++cumulative_entries;
	if ( *max_num_entries_ptr < ++*num_entries_ptr )
		*max_num_entries_ptr = *num_entries_ptr;

	// For ongoing iterations: If we already passed the bucket where this
	// entry was put, add it to the cookie's list of inserted entries.
	for ( const auto& c : cookies )
		{
		if ( h < (unsigned int) c->bucket )
			c->inserted.push_back(new_entry);
		}

	return nullptr;
	}

int Dictionary::NextPrime(int n) const
	{
	if ( (n & 0x1) == 0 )
		// Even.
		++n;

	if ( n > PRIME_THRESH )
		// Too expensive to test for primality, just stick with it.
		return n;

	while ( ! IsPrime(n) )
		n += 2;

	return n;
	}

bool Dictionary::IsPrime(int n) const
	{
	for ( int j = 3; j * j <= n; ++j )
		if ( n % j == 0 )
			return false;

	return true;
	}

void Dictionary::StartChangeSize(int new_size)
	{
	// Only start resizing if there isn't any iteration in progress.
	if ( ! cookies.empty() )
		return;

	if ( tbl2 )
		reporter->InternalError("Dictionary::StartChangeSize() tbl2 not NULL");

	Init2(new_size);

	tbl_next_ind = 0;

	// Preserve threshold density
	SetDensityThresh2(DensityThresh());
	}

void Dictionary::MoveChains()
	{
	// Do not change current distribution if there an ongoing iteration.
	if ( ! cookies.empty() )
		return;

	// Attempt to move this many entries (must do at least 2)
	int num = 8;

	do
		{
		zeek::PList<detail::DictEntry>* chain = tbl[tbl_next_ind++];

		if ( ! chain )
			continue;

		tbl[tbl_next_ind - 1] = nullptr;

		for ( const auto& elem : *chain )
			{
			Insert(elem, false);
			--num_entries;
			--num;
			}

		delete chain;
		}
	while ( num > 0 && int(tbl_next_ind) < num_buckets );

	if ( int(tbl_next_ind) >= num_buckets )
		FinishChangeSize();
	}

void Dictionary::FinishChangeSize()
	{
	// Cheap safety check.
	if ( num_entries != 0 )
		reporter->InternalError(
		    "Dictionary::FinishChangeSize: num_entries is %d\n",
		    num_entries);

	for ( int i = 0; i < num_buckets; ++i )
		delete tbl[i];
	delete [] tbl;

	tbl = tbl2;
	tbl2 = nullptr;

	num_buckets = num_buckets2;
	num_entries = num_entries2;
	max_num_entries = max_num_entries2;
	den_thresh = den_thresh2;
	thresh_entries = thresh_entries2;

	num_buckets2 = 0;
	num_entries2 = 0;
	max_num_entries2 = 0;
	den_thresh2 = 0;
	thresh_entries2 = 0;
	}

unsigned int Dictionary::MemoryAllocation() const
	{
	int size = padded_sizeof(*this);

	if ( ! tbl )
		return size;

	for ( int i = 0; i < num_buckets; ++i )
		if ( tbl[i] )
			{
			zeek::PList<detail::DictEntry>* chain = tbl[i];
			for ( const auto& c : *chain )
				size += padded_sizeof(detail::DictEntry) + pad_size(c->len);
			size += chain->MemoryAllocation();
			}

	size += pad_size(num_buckets * sizeof(zeek::PList<detail::DictEntry>*));

	if ( order )
		size += order->MemoryAllocation();

	if ( tbl2 )
		{
		for ( int i = 0; i < num_buckets2; ++i )
			if ( tbl2[i] )
				{
				zeek::PList<detail::DictEntry>* chain = tbl2[i];
				for ( const auto& c : *chain )
					size += padded_sizeof(detail::DictEntry) + pad_size(c->len);
				size += chain->MemoryAllocation();
				}

		size += pad_size(num_buckets2 * sizeof(zeek::PList<detail::DictEntry>*));
		}

	return size;
	}

void generic_delete_func(void* v)
	{
	free(v);
	}

} // namespace zeek

TEST_SUITE_END();

#endif//USE_OPEN_DICT
