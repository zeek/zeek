// See the file "COPYING" in the main distribution directory for copyright.
//Clustered Hashing, a variation of Robinhood Hashing/Open Addressing Hashing.
//Ref following post links to help understand the implementation
//https://jasonlue.github.io/algo/2019/08/20/clustered-hashing.html
//https://jasonlue.github.io/algo/2019/08/27/clustered-hashing-basic-operations.html
//https://jasonlue.github.io/algo/2019/09/03/clustered-hashing-incremental-resize.html
//https://jasonlue.github.io/algo/2019/09/10/clustered-hashing-modify-on-iteration.html

#ifndef odict_h
#define odict_h

#include <vector>
#include "Hash.h"
#include <climits>
class Dictionary;
class DictEntry;
class IterCookie;

// Default number of hash buckets in dictionary.  The dictionary will
// increase the size of the hash table as needed.
#define HASH_MASK 0xFFFFffff //only lower 32 bits.

//micros here are used to build different targets with -Dxxx to compare for performance or for debug purposes.
//when incremental resizing, remapping, it remaps DICT_REMAP_ENTRIES at step.
#ifndef DICT_REMAP_ENTRIES
#define DICT_REMAP_ENTRIES 16 //2 for debug. 16 is best for release. move how many at a time when remapping.
#endif//DICT_REMAP_ENTRIES

#ifndef DICT_LOAD_FACTOR_BITS //give option to define it at command line
#define DICT_LOAD_FACTOR_BITS  2//LOAD_FACTOR = 1 - 1/2^LOAD_FACTOR_BITS .75 is the optimal load factor.
#endif //LOAD_FACTOR_BITS

//when log2_buckets > DICT_THRESHOLD_BITS, DICT_LOAD_FACTOR_BITS becomes effective.
//basicly it means if dict size < 2^DICT_THRESHOLD_BITS+n, size up only if necessary (the last entry can't hold new key).
#ifndef DICT_THRESHOLD_BITS
#define DICT_THRESHOLD_BITS 3
#endif

// of insertions.
typedef enum { ORDERED, UNORDERED } dict_order;

// Type for function to be called when deleting elements.
typedef void (*dict_delete_func)(void*);

// A dict_delete_func that just calls delete.
extern void generic_delete_func(void*);
// The value of an iteration cookie is the bucket and offset within the
// bucket at which to start looking for the next value to return.
#define TOO_FAR_TO_REACH 0xFFFF
#define MAX_KEY_SIZE 0XFFFF
struct DictEntry{//24 bytes. perfectly alligned. always own the key. but not the value.
	#ifdef DEBUG
	int bucket;//for easy debugging
	#endif//DEBUG
	uint16_t distance; //<from expected position. all 1's means empty. max distance 64K-2
	uint16_t key_size; //the length of the key. <=8 will be embedded directly. otherwise a pointer 8K max enough?
	uint32_t hash; //lower 4-byte of the 8-byte long hash. the part to calculate position in the table.

	void* value; //for Bro, value is always a pointer. 
	union{
		char key_here[8]; //hold key len<=8. when over 8, it's a pointer to real keys.
		char* key;
	};

	DictEntry(void* arg_key, int key_size=0, hash_t hash=0, void* value=0, int16_t d=TOO_FAR_TO_REACH, int copy_key=0) 
	: distance(d), key_size(key_size), hash((uint32_t)hash), value(value)
		{
		#ifdef DEBUG
		bucket = 0;
		#endif//DEBUG
		if( key_size <= 8)
		{				
			memcpy(key_here, arg_key, key_size);
			if(!copy_key)
				delete (char*)arg_key; //own the arg_key, now don't need it.
		}
		else
		{
			if( copy_key )
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
	bool Empty() {return distance == TOO_FAR_TO_REACH;}
	void SetEmpty()
		{
		distance = TOO_FAR_TO_REACH;
		#ifdef DEBUG
		hash = 0;
		key = NULL;
		value = NULL;
		key_size = 0;
		bucket = 0;
		#endif//DEBUG
		}

	//if with no intent to release key memory, call SetEmpty instead. key pointer is shared when moving around.
	void Clear() 
	{//SetEmpty & release memory if allocated.
		if(key_size > 8)
			delete key;
		SetEmpty();
	}
	const char* GetKey() const {return key_size <= 8? key_here : key;}
	bool Equal(const char* arg_key, int arg_key_size, hash_t arg_hash) const
	{//only 40-bit hash comparison.
		return (0 == ((hash ^ arg_hash) & HASH_MASK)) 
			&& key_size == arg_key_size && 0 == memcmp(GetKey(), arg_key, key_size);
	}
	bool operator==(const DictEntry& r) const
	{
		return Equal(r.GetKey(), r.key_size, r.hash);
	}
	bool operator!=(const DictEntry& r) const
	{
		return !Equal(r.GetKey(), r.key_size, r.hash);
	}
};

struct IterCookie;

// Default number of hash buckets in dictionary.  The dictionary will
// increase the size of the hash table as needed.
#ifndef DEFAULT_DICT_SIZE
#define DEFAULT_DICT_SIZE 0
#endif//DEFAULT_DICT_SIZE
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
		{ return Insert(key->TakeKey(), key->Size(), key->Hash(), val, 0);}
	// If copy_key is true, then the key is copied, otherwise it's assumed
	// that it's a heap pointer that now belongs to the Dictionary to
	// manage as needed. 
	void* Insert(void* key, int key_size, hash_t hash, void* val, int copy_key);

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
	float GetThreshold() const { return 1.0 - 1.0 / (1<<DICT_LOAD_FACTOR_BITS);} 

	/// Buckets of the table, not including overflow size.
	int Buckets(bool expected=false) const;
	/// The capacity of the table, Buckets + Overflow Size.
	int Capacity(bool expected=false) const;
/////////////////////////////////////////////////////////////////////////////
private:
	friend IterCookie;
	//bucket math
	int Log2(int num) const;
	int ThresholdEntries() const; 

	hash_t FibHash(hash_t h) const; //to improve the distribution of original hash.
	///map h to n-bit table bucket.
	int BucketByHash(hash_t h, int bit) const;
	//given position of non-empty item in the table, find my bucket.
	int BucketByPosition(int position) const;

	///given position of an non-empty item in the table, find the head of cluster, 
	///if not found, return -1 and set expected_position to be the position it's supposed to be if expected_position is not NULL. 
	int HeadOfClusterByBucket(int bucket) const;
	///given position of an non-empty item in the table, find the tail of its cluster
	int TailOfClusterByBucket(int bucket) const;
	///given position of an non-empty item in the table. find the end of its cluster. 
	///end = tail + 1 if tail exists. otherwise the tail of just smaller cluster + 1.
	int EndOfClusterByBucket(int bucket) const;

	///given position of an non-empty item in the table, find the head of its cluster
	int HeadOfClusterByPosition(int position) const;
	///given position of an non-empty item in the table, find the tail of its cluster
	int TailOfClusterByPosition(int position) const;
	///given position of an non-empty item in the table. find the end of its cluster. 
	///end = tail + 1 if tail exists. otherwise the tail of just smaller cluster + 1.
	int EndOfClusterByPosition(int position) const;
	///given position of an non-empty item in the table, find the offset of me in its cluster
	int OffsetInClusterByPosition(int position) const;

	///Next non-empty item position
	int Next(int i) const;

	void Init();

	//Iteration
	IterCookie* InitForIterationNonConst();
	void* NextEntryNonConst(HashKey*& h, IterCookie*& cookie, int return_hash);
	void StopIterationNonConst(IterCookie* cookie);
	//Lookup
	int LinearLookupIndex(const void* key, int key_size, hash_t hash) const;
	int LookupIndex(const void* key, int key_size, hash_t hash, int* insert_position = NULL, int* insert_distance = NULL);
	int LookupIndex(const void* key, int key_size, hash_t hash, int begin, int end, int* insert_position = NULL, int* insert_distance  = NULL);

	/// Insert entry, Adjust cookies when necessary.
	void InsertRelocateAndAdjust(DictEntry& entry, int insert_position);
	/// insert entry into position, relocate other entries when necessary.
	void InsertAndRelocate(DictEntry& entry, int insert_position, int* last_affected_position = NULL);
	/// Adjust Cookies on Insert.
	void AdjustOnInsert(IterCookie* c, const DictEntry& entry, int insert_position, int last_affected_position);

	///Remove, Relocate & Adjust cookies.
	DictEntry RemoveRelocateAndAdjust(int position);
	///Remove & Relocate
	DictEntry RemoveAndRelocate(int position, int* last_affected_position = NULL);
	///Adjust safe cookies after Removal of entry at position.
	void AdjustOnRemove(IterCookie* c, const DictEntry& entry, int position, int last_affected_position);

	bool Remapping() const { return remap_end >= 0;} //remap in reverse order.
	///One round of remap.
	void Remap(); 

	///Remap item in [position]
	///Returns true if actual relocation happend. false on noop.
	bool Remap(int position, int* new_position = NULL);
	void SizeUp();

	//the dictionary size will be bounded at around 100K. 1M is absolute limit. only Connections use so many entries.
	//alligned on 8-bytes with 4-leading bytes. 7*8=56 bytes a dictionary.

	//when sizeup but the current mapping is in progress. the current mapping will be ignored as it will be remapped to new dict size anyway. 
	//however, the missed count is recorded for lookup. if position not found for a key in the position of dict of current size, it still could be in the position of dict of previous N sizes.
	unsigned char remaps; 
	unsigned char log2_buckets; 
	unsigned short num_iterators; //pending iterators on the dict. including robust and non-rubust. to avoid remap when any iterators active.
	int remap_end;//the last index to be remapped

	int num_entries;
	int max_entries;

	uint64_t cum_entries;
	dict_delete_func delete_func;
	DictEntry* table;
	vector<IterCookie*>* cookies;
	vector<DictEntry>* order;//order means the order of insertion. means no deletion until exit. will be inefficient. 
public:
	//Debugging
#ifdef DEBUG
	void AssertValid() const;
#endif//DEBUG
	void Dump(int level=0) const;
	void DistanceStats(int& max_distance, int* distances=0, int num_distances=0) const;
	void DumpKeys() const;
};

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
		return (T*) Dictionary::NextEntry(h, cookie, 0);
		}
	T* NextEntry(HashKey*& h, IterCookie*& cookie) const
		{ return (T*) Dictionary::NextEntry(h, cookie, 1); }
	T* RemoveEntry(const HashKey* key)
		{ return (T*) Remove(key->Key(), key->Size(), key->Hash()); }
};

#endif//odict_h
