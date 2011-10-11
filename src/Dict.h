// See the file "COPYING" in the main distribution directory for copyright.

#ifndef dict_h
#define dict_h

#include "List.h"
#include "Hash.h"

class Dictionary;
class DictEntry;
class IterCookie;

declare(PList,DictEntry);
declare(PList,IterCookie);

// Default number of hash buckets in dictionary.  The dictionary will
// increase the size of the hash table as needed.
#define DEFAULT_DICT_SIZE 16

// Type indicating whether the dictionary should keep track of the order
// of insertions.
typedef enum { ORDERED, UNORDERED } dict_order;

// Type for function to be called when deleting elements.
typedef void (*dict_delete_func)(void*);

// A dict_delete_func that just calls delete.
extern void generic_delete_func(void*);

class Dictionary {
public:
	Dictionary(dict_order ordering = UNORDERED,
			int initial_size = DEFAULT_DICT_SIZE);
	virtual ~Dictionary();

	// Member functions for looking up a key, inserting/changing its
	// contents, and deleting it.  These come in two flavors: one
	// which takes a HashKey, and the other which takes a raw key,
	// its size, and its (unmodulated) hash.
	void* Lookup(const HashKey* key) const
		{ return Lookup(key->Key(), key->Size(), key->Hash()); }
	void* Lookup(const void* key, int key_size, hash_t hash) const;

	// Returns previous value, or 0 if none.
	void* Insert(HashKey* key, void* val)
		{
		return Insert(key->TakeKey(), key->Size(), key->Hash(), val, 0);
		}
	// If copy_key is true, then the key is copied, otherwise it's assumed
	// that it's a heap pointer that now belongs to the Dictionary to
	// manage as needed.
	void* Insert(void* key, int key_size, hash_t hash, void* val,
			int copy_key);

	// Removes the given element.  Returns a pointer to the element in
	// case it needs to be deleted.  Returns 0 if no such element exists.
	// If dontdelete is true, the key's bytes will not be deleted.
	void* Remove(const HashKey* key)
		{ return Remove(key->Key(), key->Size(), key->Hash()); }
	void* Remove(const void* key, int key_size, hash_t hash,
				bool dont_delete = false);

	// Number of entries.
	int Length() const
		{ return tbl2 ? num_entries + num_entries2 : num_entries; }

	// Largest it's ever been.
	int MaxLength() const
		{
		return tbl2 ?
			max_num_entries + max_num_entries2 : max_num_entries;
		}

	// True if the dictionary is ordered, false otherwise.
	int IsOrdered() const		{ return order != 0; }

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
	void* NextEntry(HashKey*& h, IterCookie*& cookie, int return_hash) const;
	void* NextEntry(const void*& key, int& key_len, IterCookie*& cookie)
		const;
	void StopIteration(IterCookie* cookie) const;

	void SetDeleteFunc(dict_delete_func f)		{ delete_func = f; }

	// With a robust cookie, it is safe to change the dictionary while
	// iterating. This means that (i) we will eventually visit all
	// unmodified entries as well as all entries added during iteration,
	// and (ii) we won't visit any still-unseen entries which are getting
	// removed. (We don't get this for free, so only use it if
	// necessary.)
	void MakeRobustCookie(IterCookie* cookie)
		{ cookies.append(cookie); }

	// Remove all entries.
	void Clear();

	unsigned int MemoryAllocation() const;

private:
	void Init(int size);
	void Init2(int size);	// initialize second table for resizing
	void DeInit();

	// Internal version of Insert().
	void* Insert(DictEntry* entry, int copy_key);

	void* DoRemove(DictEntry* entry, hash_t h,
			PList(DictEntry)* chain, int chain_offset);

	int NextPrime(int n) const;
	int IsPrime(int n) const;
	void StartChangeSize(int new_size);
	void FinishChangeSize(void);
	void MoveChains(void);

	// The following get and set the "density" threshold - if the
	// average hash chain length exceeds this threshold, the
	// table will be resized.  The default value is 3.0.
	double DensityThresh() const	{ return den_thresh; }

	void SetDensityThresh(double thresh)
		{
		den_thresh = thresh;
		thresh_entries = int(thresh * double(num_buckets));
		}

	// Same for the second table, when resizing.
	void SetDensityThresh2(double thresh)
		{
		den_thresh2 = thresh;
		thresh_entries2 = int(thresh * double(num_buckets2));
		}

	// Normally we only have tbl.
	// When we're resizing, we'll have tbl (old) and tbl2 (new)
	// tbl_next_ind keeps track of how much we've moved to tbl2
	// (it's the next index we're going to move).
	PList(DictEntry)** tbl;
	int num_buckets;
	int num_entries;
	int max_num_entries;
	double den_thresh;
	int thresh_entries;

	// Resizing table (replicates tbl above).
	PList(DictEntry)** tbl2;
	int num_buckets2;
	int num_entries2;
	int max_num_entries2;
	double den_thresh2;
	int thresh_entries2;

	hash_t tbl_next_ind;

	PList(DictEntry)* order;
	dict_delete_func delete_func;

	PList(IterCookie) cookies;
};


#define PDict(type) type ## PDict
#define PDictdeclare(type)	\
class PDict(type) : public Dictionary {	\
public:	\
	PDict(type)(dict_order ordering = UNORDERED,	\
			int initial_size = DEFAULT_DICT_SIZE) :	\
		Dictionary(ordering, initial_size) {}	\
	type* Lookup(const char* key) const	\
		{	\
		HashKey h(key);	\
		return (type*) Dictionary::Lookup(&h);	\
		}	\
	type* Lookup(const HashKey* key) const	\
		{ return (type*) Dictionary::Lookup(key); }	\
	type* Insert(const char* key, type* val)	\
		{	\
		HashKey h(key);	\
		return (type*) Dictionary::Insert(&h, (void*) val);	\
		}	\
	type* Insert(HashKey* key, type* val)	\
		{ return (type*) Dictionary::Insert(key, (void*) val); }\
	type* NthEntry(int n) const	\
		{ return (type*) Dictionary::NthEntry(n); }	\
	type* NthEntry(int n, const char*& key) const	\
		{	\
		int key_len;	\
		return (type*) Dictionary::NthEntry(n, (const void*&) key,\
							key_len);	\
		}	\
	type* NextEntry(IterCookie*& cookie) const	\
		{	\
		HashKey* h; \
		return (type*) Dictionary::NextEntry(h, cookie, 0);	\
		} \
	type* NextEntry(HashKey*& h, IterCookie*& cookie) const	\
		{ return (type*) Dictionary::NextEntry(h, cookie, 1); } \
	type* RemoveEntry(const HashKey* key)	\
		{ return (type*) Remove(key->Key(), key->Size(),	\
					key->Hash()); } \
}

#endif
