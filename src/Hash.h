// See the file "COPYING" in the main distribution directory for copyright.

#ifndef hash_h
#define hash_h

#include <stdlib.h>

#include "BroString.h"

#define UHASH_KEY_SIZE 36

typedef uint64 hash_t;

typedef enum {
	HASH_KEY_INT,
	HASH_KEY_DOUBLE,
	HASH_KEY_STRING
#define NUM_HASH_KEYS (int(HASH_KEY_STRING) + 1)
} HashKeyTag;

class HashKey {
public:
	HashKey(bro_int_t i);
	HashKey(bro_uint_t u);
	HashKey(uint32 u);
	HashKey(const uint32 u[], int n);
	HashKey(double d);
	HashKey(const void* p);
	HashKey(const char* s);
	HashKey(const BroString* s);
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
		uint32 u32;
		double d;
		const void* p;
	} key_u;

	void* key;
	int is_our_dynamic;
	int size, hash;
};

extern void init_hash_function();

#endif
