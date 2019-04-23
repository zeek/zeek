// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

#include "Dict.h"
#include "Reporter.h"

// If the mean bucket length exceeds the following then Insert() will
// increase the size of the hash table.
#define DEFAULT_DENSITY_THRESH 3.0

// Threshold above which we do not try to ensure that the hash size
// is prime.
#define PRIME_THRESH 1000

// Default number of hash buckets in dictionary.  The dictionary will
// increase the size of the hash table as needed.
#define DEFAULT_DICT_SIZE 16

class DictEntry {
public:
	DictEntry(void* k, int l, hash_t h, void* val)
		{ key = k; len = l; hash = h; value = val; }

	~DictEntry()
		{
		delete [] (char*) key;
		}

	void* key;
	int len;
	hash_t hash;
	void* value;
};

// The value of an iteration cookie is the bucket and offset within the
// bucket at which to start looking for the next value to return.
class IterCookie {
public:
	IterCookie(int b, int o)
		{
		bucket = b;
		offset = o;
		ttbl = 0;
		num_buckets_p = 0;
		}

	int bucket, offset;
	PList(DictEntry)** ttbl;
	const int* num_buckets_p;
	PList(DictEntry) inserted;	// inserted while iterating
};

Dictionary::Dictionary(dict_order ordering, int initial_size)
	{
	tbl = 0;
	tbl2 = 0;

	if ( ordering == ORDERED )
		order = new PList(DictEntry);
	else
		order = 0;

	delete_func = 0;
	tbl_next_ind = 0;

	cumulative_entries = 0;
	num_buckets = num_entries = max_num_entries = thresh_entries = 0;
	den_thresh = 0;
	num_buckets2 = num_entries2 = max_num_entries2 = thresh_entries2 = 0;
	den_thresh2 = 0;

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
	tbl = 0;
	tbl2 = 0;
	}

void Dictionary::DeInit()
	{
	if ( ! tbl )
		return;

	for ( int i = 0; i < num_buckets; ++i )
		if ( tbl[i] )
			{
			PList(DictEntry)* chain = tbl[i];
			loop_over_list(*chain, j)
				{
				DictEntry* e = (*chain)[j];
				if ( delete_func )
					delete_func(e->value);
				delete e;
				}

			delete chain;
			}

	delete [] tbl;

	if ( tbl2 == 0 )
		return;

	for ( int i = 0; i < num_buckets2; ++i )
		if ( tbl2[i] )
			{
			PList(DictEntry)* chain = tbl2[i];
			loop_over_list(*chain, j)
				{
				DictEntry* e = (*chain)[j];
				if ( delete_func )
					delete_func(e->value);
				delete e;
				}

			delete chain;
			}

	delete [] tbl2;
	tbl2 = 0;
	}

void* Dictionary::Lookup(const void* key, int key_size, hash_t hash) const
	{
	if ( ! tbl && ! tbl2 )
		return 0;

	hash_t h;
	PList(DictEntry)* chain;

	// Figure out which hash table to look in.
	h = hash % num_buckets;
	if ( ! tbl2 || h >= tbl_next_ind )
		chain = tbl[h];
	else
		chain = tbl2[hash % num_buckets2];

	if ( chain )
		{
		for ( int i = 0; i < chain->length(); ++i )
			{
			DictEntry* entry = (*chain)[i];

			if ( entry->hash == hash && entry->len == key_size &&
			     ! memcmp(key, entry->key, key_size) )
				return entry->value;
			}
		}

	return 0;
	}

void* Dictionary::Insert(void* key, int key_size, hash_t hash, void* val,
				int copy_key)
	{
	if ( ! tbl )
		Init(DEFAULT_DICT_SIZE);

	DictEntry* new_entry = new DictEntry(key, key_size, hash, val);
	void* old_val = Insert(new_entry, copy_key);

	if ( old_val )
		{
		// We didn't need the new DictEntry, the key was already
		// present.
		delete new_entry;
		}
	else if ( order )
		order->append(new_entry);

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
		return 0;

	hash_t h;
	PList(DictEntry)* chain;
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
		return 0;

	for ( int i = 0; i < chain->length(); ++i )
		{
		DictEntry* entry = (*chain)[i];

		if ( entry->hash == hash && entry->len == key_size &&
		     ! memcmp(key, entry->key, key_size) )
			{
			void* entry_value = DoRemove(entry, h, chain, i);

			if ( dont_delete )
				entry->key = 0;

			delete entry;
			--*num_entries_ptr;
			return entry_value;
			}
		}

	return 0;
	}

void* Dictionary::DoRemove(DictEntry* entry, hash_t h,
				PList(DictEntry)* chain, int chain_offset)
	{
	void* entry_value = entry->value;

	chain->remove_nth(chain_offset);
	if ( order )
		order->remove(entry);

	// Adjust existing cookies.
	loop_over_list(cookies, i)
		{
		IterCookie* c = cookies[i];

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
		return 0;

	DictEntry* entry = (*order)[n];
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
		const_cast<PList(IterCookie)*>(&cookies)->remove(cookie);
		delete cookie;
		cookie = 0;
		return 0;
		}

	// If there are any inserted entries, return them first.
	// That keeps the list small and helps avoiding searching
	// a large list when deleting an entry.

	DictEntry* entry;

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
	PList(DictEntry)** ttbl;
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
		const_cast<PList(IterCookie)*>(&cookies)->remove(cookie);
		delete cookie;
		cookie = 0;
		return 0;
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
	tbl = new PList(DictEntry)*[num_buckets];

	for ( int i = 0; i < num_buckets; ++i )
		tbl[i] = 0;

	max_num_entries = num_entries = 0;
	SetDensityThresh(DEFAULT_DENSITY_THRESH);
	}

void Dictionary::Init2(int size)
	{
	num_buckets2 = NextPrime(size);
	tbl2 = new PList(DictEntry)*[num_buckets2];

	for ( int i = 0; i < num_buckets2; ++i )
		tbl2[i] = 0;

	max_num_entries2 = num_entries2 = 0;
	}

// private
void* Dictionary::Insert(DictEntry* new_entry, int copy_key)
	{
	if ( ! tbl )
		Init(DEFAULT_DICT_SIZE);

	PList(DictEntry)** ttbl;
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

	PList(DictEntry)* chain = ttbl[h];

	int n = new_entry->len;

	if ( chain )
		{
		for ( int i = 0; i < chain->length(); ++i )
			{
			DictEntry* entry = (*chain)[i];

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
		chain = ttbl[h] = new PList(DictEntry);

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
	chain->append(new_entry);

	++cumulative_entries;
	if ( *max_num_entries_ptr < ++*num_entries_ptr )
		*max_num_entries_ptr = *num_entries_ptr;

	// For ongoing iterations: If we already passed the bucket where this
	// entry was put, add it to the cookie's list of inserted entries.
	loop_over_list(cookies, i)
		{
		IterCookie* c = cookies[i];
		if ( h < (unsigned int) c->bucket )
			c->inserted.append(new_entry);
		}

	return 0;
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

int Dictionary::IsPrime(int n) const
	{
	for ( int j = 3; j * j <= n; ++j )
		if ( n % j == 0 )
			return 0;

	return 1;
	}

void Dictionary::StartChangeSize(int new_size)
	{
	// Only start resizing if there isn't any iteration in progress.
	if ( cookies.length() > 0 )
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
	if ( cookies.length() > 0 )
		return;

	// Attempt to move this many entries (must do at least 2)
	int num = 8;

	do
		{
		PList(DictEntry)* chain = tbl[tbl_next_ind++];

		if ( ! chain )
			continue;

		tbl[tbl_next_ind - 1] = 0;

		for ( int j = 0; j < chain->length(); ++j )
			{
			Insert((*chain)[j], 0);
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
	tbl2 = 0;

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
			PList(DictEntry)* chain = tbl[i];
			loop_over_list(*chain, j)
				size += padded_sizeof(DictEntry) + pad_size((*chain)[j]->len);
			size += chain->MemoryAllocation();
			}

	size += pad_size(num_buckets * sizeof(PList(DictEntry)*));

	if ( order )
		size += order->MemoryAllocation();

	if ( tbl2 )
		{
		for ( int i = 0; i < num_buckets2; ++i )
			if ( tbl2[i] )
				{
				PList(DictEntry)* chain = tbl2[i];
				loop_over_list(*chain, j)
					size += padded_sizeof(DictEntry) + pad_size((*chain)[j]->len);
				size += chain->MemoryAllocation();
				}

		size += pad_size(num_buckets2 * sizeof(PList(DictEntry)*));
		}

	return size;
	}

void generic_delete_func(void* v)
	{
	free(v);
	}
