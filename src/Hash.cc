// $Id: Hash.cc 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

// The hash function works as follows:
//
// 1) For short data we have a number of universal hash functions:
// UHASH_CW (ax + b (mod p)), H3, Dietzfelbinger and UMAC_NH (UMAC_NH is
// not as strongly universal as the others, but probably enough). All
// these functions require number of random bits linear to the data
// length. And we use them for data no longer than UHASH_KEY_SIZE.
// They are faster than HMAC/MD5 used for longer data, and most hash
// operations are on short data.
//
// 2) As a fall-back, we use HMAC/MD5 (keyed MD5) for data of arbitrary
// length. MD5 is used as a scrambling scheme so that it is difficult
// for the adversary to construct conflicts, though I do not know if
// HMAC/MD5 is provably universal.

#include "config.h"

#include "Hash.h"

// Define *one* of the following as the universal hash function family to use.

// #define USE_DIETZFELBINGER	// TwoWise
#define USE_H3
// #define USE_UHASH_CW
// #define USE_UMAC_NH

int hash_cnt_all = 0, hash_cnt_uhash = 0;

#if defined(USE_DIETZFELBINGER)

#include "TwoWise.h"
const TwoWise* two_wise = 0;

#elif defined(USE_H3)

#include "H3.h"
const H3<hash_t, UHASH_KEY_SIZE>* h3;

#elif defined(USE_UHASH_CW)

// The Carter-Wegman family of universal hash functions.
// f(x) = (sum(a_i * x_i) mod p) mod N
// where p is a prime number between N and 2N.
// Here N = 2^32.

class UHashCW {
	typedef uint32 word_t;
public:
	UHashCW(int arg_max_key_size)
		{
		max_num_words = (arg_max_key_size + sizeof(word_t) - 1) /
				sizeof(word_t);

		a = new word_t[max_num_words + 1];
		x = new word_t[max_num_words + 1];

		for ( int i = 0; i < max_num_words + 1; ++i )
			a[i] = rand32bit();

		b = rand64bit();
		}

	~UHashCW()
		{
		delete [] a;
		delete [] x;
		}

	uint32 hash(int len, const u_char* data) const
		{
		int xlen = (len + sizeof(word_t) - 1) / sizeof(word_t);
		ASSERT(xlen <= max_num_words);

		x[xlen] = 0;
		x[xlen-1] = 0;	// pad with 0

		memcpy(static_cast<void *>(x), data, len);

		uint64 h = b;
		for ( int i = 0; i < xlen; ++i )
			h += (static_cast<uint64>(x[i]) * a[i]);

		h += static_cast<uint64>(len) * a[xlen];

		// h = h % kPrime
		//
		// Here we use a trick given that h is a Mersenne prime:
		//
		// Let K = 2^61. Let h = a * K + b.
		// Thus, h = a * (K-1) + (a + b).

		h = (h & kPrime) + (h >> 61);
		if ( h >= kPrime )
			h -= kPrime;

		// h = h % 2^32
		return static_cast<uint32>(0xffffffffUL & h);
		}

protected:
	static const uint64 kPrime = (static_cast<uint64>(1) << 61) - 1;

	int max_num_words;
	word_t* a;
	uint64 b;
	word_t* x;
};

const UHashCW* uhash_cw = 0;

#elif defined(USE_UMAC_NH)

// Use the NH hash function proposed in UMAC.
// (See http://www.cs.ucdavis.edu/~rogaway/umac/)
//
// Essentially, it is computed as:
//
//	H = (x_0 +_16 k_0) * (x_1 +_16 k_1) +
//		(x_2 +_16 k_2) * (x_3 +_16 k_3) + ...
//
// where {k_i} are keys for universal hashing,
// {x_i} are data words, and +_16 means plus mod 2^16.
//
// This is faster than UHASH_CW because no modulo operation
// is needed.  But note that it is 2^-16 universal, while the
// other universal functions are (almost) 2^-32 universal.
//
// Note: UMAC now has a code release under a BSD-like license, and we may want
// to consider using it instead of our home-grown code.

#ifndef DEBUG
#error "UMAC/NH is experimental code."
#endif

class UMacNH {
	// NH uses 16-bit words
	typedef uint16 word_t;
public:
	UMacNH(int arg_max_key_size)
		{
		max_num_words = (arg_max_key_size + sizeof(word_t) - 1) /
				sizeof(word_t);

		// Make max_num_words 2n+1
		if ( max_num_words % 2 == 0 )
			++max_num_words;

		a = new word_t[max_num_words + 1];
		x = new word_t[max_num_words + 1];

		for ( int i = 0; i < max_num_words + 1; ++i )
			a[i] = rand16bit();
		}

	~UMacNH()
		{
		delete [] a;
		delete [] x;
		}

	uint32 hash(int len, const u_char* data) const
		{
		int xlen = (len + sizeof(word_t) - 1) / sizeof(word_t);
		if ( xlen % 2 == 0 )
			++xlen;

		ASSERT(xlen <= max_num_words);

		x[xlen] = len;
		x[xlen-1] = 0;	// pad with 0
		if ( xlen >= 2 )
			x[xlen-2] = 0;

		memcpy(static_cast<void *>(x), data, len);

		uint32 h = 0;
		for ( int i = 0; i <= xlen; i += 2 )
			h += (static_cast<uint32>(x[i] + a[i]) *
			      static_cast<uint32>(x[i+1] + a[i+1]));

		return h;
		}

protected:
	int max_num_words;
	word_t* a;
	word_t* x;
};

const UMacNH* umac_nh = 0;

#else

#ifdef DEBUG
#error "No universal hash function is used."
#endif

#endif

void init_hash_function()
	{
	// Make sure we have already called init_random_seed().
	ASSERT(hmac_key_set);

	// Both Dietzfelbinger and H3 use random() to generate keys
	// -- is it strong enough?
#if defined(USE_DIETZFELBINGER)
	two_wise = new TwoWise((UHASH_KEY_SIZE + 3) >> 2);
#elif defined(USE_H3)
	h3 = new H3<hash_t, UHASH_KEY_SIZE>();
#elif defined(USE_UHASH_CW)
	uhash_cw = new UHashCW(UHASH_KEY_SIZE);
#elif defined(USE_UMAC_NH)
	umac_nh = new UMacNH(UHASH_KEY_SIZE);
#endif
	}

HashKey::HashKey(bro_int_t i)
	{
	key_u.i = i;
	key = (void*) &key_u;
	size = sizeof(i);
	hash = HashBytes(key, size);
	is_our_dynamic = 0;
	}

HashKey::HashKey(bro_uint_t u)
	{
	key_u.i = bro_int_t(u);
	key = (void*) &key_u;
	size = sizeof(u);
	hash = HashBytes(key, size);
	is_our_dynamic = 0;
	}

#ifdef USE_INT64

HashKey::HashKey(uint32 u)
	{
	key_u.u32 = u;
	key = (void*) &key_u;
	size = sizeof(u);
	hash = HashBytes(key, size);
	is_our_dynamic = 0;
	}

#endif // USE_INT64

HashKey::HashKey(const uint32 u[], int n)
	{
	size = n * sizeof(u[0]);
	key = (void*) u;
	hash = HashBytes(key, size);
	is_our_dynamic = 0;
	}

HashKey::HashKey(double d)
	{
	union {
		double d;
		int i[2];
	} u;

	key_u.d = u.d = d;
	key = (void*) &key_u;
	size = sizeof(d);
	hash = HashBytes(key, size);
	is_our_dynamic = 0;
	}

HashKey::HashKey(const void* p)
	{
	key_u.p = p;
	key = (void*) &key_u;
	size = sizeof(p);
	hash = HashBytes(key, size);
	is_our_dynamic = 0;
	}

HashKey::HashKey(const char* s)
	{
	size = strlen(s);	// note - skip final \0
	key = (void*) s;
	hash = HashBytes(key, size);
	is_our_dynamic = 0;
	}

HashKey::HashKey(const BroString* s)
	{
	size = s->Len();
	key = (void*) s->Bytes();
	hash = HashBytes(key, size);
	is_our_dynamic = 0;
	}

HashKey::HashKey(int copy_key, void* arg_key, int arg_size)
	{
	size = arg_size;
	is_our_dynamic = 1;

	if ( copy_key )
		{
		key = (void*) new char[size];
		memcpy(key, arg_key, size);
		}
	else
		key = arg_key;

	hash = HashBytes(key, size);
	}

HashKey::HashKey(const void* arg_key, int arg_size, hash_t arg_hash)
	{
	size = arg_size;
	hash = arg_hash;
	key = CopyKey(arg_key, size);
	is_our_dynamic = 1;
	}

HashKey::HashKey(const void* arg_key, int arg_size, hash_t arg_hash,
		bool /* dont_copy */)
	{
	size = arg_size;
	hash = arg_hash;
	key = const_cast<void*>(arg_key);
	is_our_dynamic = 0;
	}

HashKey::HashKey(const void* bytes, int arg_size)
	{
	size = arg_size;
	key = CopyKey(bytes, size);
	hash = HashBytes(key, size);
	is_our_dynamic = 1;
	}

void* HashKey::TakeKey()
	{
	if ( is_our_dynamic )
		{
		is_our_dynamic = 0;
		return key;
		}
	else
		return CopyKey(key, size);
	}

void* HashKey::CopyKey(const void* k, int s) const
	{
	void* k_copy = (void*) new char[s];
	memcpy(k_copy, k, s);
	return k_copy;
	}

hash_t HashKey::HashBytes(const void* bytes, int size)
	{
	++hash_cnt_all;

	if ( size <= UHASH_KEY_SIZE )
		{
		const uint8* b = reinterpret_cast<const uint8*>(bytes);
		++hash_cnt_uhash;
#if defined(USE_DIETZFELBINGER)
		return two_wise->Hash(size, b);
#elif defined(USE_H3)
		// H3 doesn't check if size is zero
		return ( size == 0 ) ? 0 : (*h3)(bytes, size);
#elif defined(USE_UHASH_CW)
		return uhash_cw->hash(size, b);
#elif defined(USE_UMAC_NH)
		return umac_nh->hash(size, b);
#else
		--hash_cnt_uhash;
#endif
		}

	// Fall back to HMAC/MD5 for longer data (which is usually rare).
	hash_t digest[16];
	hmac_md5(size, (unsigned char*) bytes, (unsigned char*) digest);
	return digest[0];
	}
